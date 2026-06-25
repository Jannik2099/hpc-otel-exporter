//! Uploading finished per-cgroup pprof profiles to Pyroscope via its push API.

use anyhow::{Context, Result, anyhow};
use prost::Message;

use super::CpuProfile;
use super::proto::push;

/// Pyroscope's `__name__` for CPU profiles.
const PROFILE_NAME: &str = "process_cpu";

/// The upload half of the profiler: cheap to clone, holds no symbolization
/// state, and is the only thing moved into the spawned push task.
#[derive(Clone)]
pub(crate) struct Pusher {
    client: reqwest::Client,
    base_url: String,
    hostname: String,
}

impl Pusher {
    pub(crate) fn new(base_url: String, hostname: String) -> Self {
        let pyroscope_token = std::env::var("PYROSCOPE_BEARER_TOKEN").ok();
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(pyroscope_token) = pyroscope_token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", pyroscope_token))
                    .unwrap(),
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        Pusher {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            hostname,
        }
    }

    /// Push a batch of per-cgroup profiles to Pyroscope via the
    /// `push.v1.PusherService/Push` RPC, using the Connect protocol's unary
    /// protobuf encoding (a plain `POST` whose body is the serialized request
    /// message). One [`RawProfileSeries`](push::RawProfileSeries) is sent per
    /// cgroup, distinguished by labels.
    pub(crate) async fn push(&self, profiles: Vec<CpuProfile>) -> Result<()> {
        if profiles.is_empty() {
            return Ok(());
        }

        let series = profiles
            .into_iter()
            .map(|p| {
                let mut labels = vec![
                    label("__name__", PROFILE_NAME),
                    // Grafana groups profiles by service_name, so use the cgroup
                    // (i.e. the SLURM job / workload) as the service.
                    label("service_name", &p.cgroup_name),
                    label("exporter", "hpc-otel-exporter"),
                    label("hostname", &self.hostname),
                ];
                // SLURM job identity, mirroring the IO/metadata metric attributes
                // (Pyroscope label values are strings).
                if let Some(slurm) = &p.slurm {
                    labels.push(label("slurm.job_id", &slurm.job_id.to_string()));
                    if let Some(uid) = slurm.uid {
                        labels.push(label("uid", &uid.to_string()));
                    }
                }
                push::RawProfileSeries {
                    labels,
                    samples: vec![push::RawSample {
                        raw_profile: gzip(&p.data),
                        id: uuid::Uuid::now_v7().to_string(),
                    }],
                }
            })
            .collect();
        let request = push::PushRequest { series };

        let url = format!("{}/push.v1.PusherService/Push", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/proto")
            .header("Connect-Protocol-Version", "1")
            .body(request.encode_to_vec())
            .send()
            .await
            .context("posting profiles to Pyroscope")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Pyroscope push returned {status}: {body}"));
        }
        Ok(())
    }
}

fn label(name: &str, value: &str) -> push::LabelPair {
    push::LabelPair {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

/// Gzip-compress pprof bytes, as required by the pprof format and expected by
/// Pyroscope's `raw_profile` field.
fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // Writing to an in-memory buffer is infallible.
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}
