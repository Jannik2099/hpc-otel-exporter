//! Optional self-profiling: runs the `pyroscope` crate's in-process SIGPROF
//! sampler so the exporter's *own* CPU usage is profiled and pushed to Pyroscope.
//! This is unrelated to [`crate::profiling`], which profiles the *target* HPC
//! jobs; this only exists to debug the exporter itself, behind the `pyroscope`
//! Cargo feature.

use std::collections::HashMap;

use anyhow::Result;
use opentelemetry_sdk::Resource;
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
use pyroscope::pyroscope::{PyroscopeAgent, PyroscopeAgentBuilder, PyroscopeAgentRunning};

/// Rewrite an OTel resource/attribute key into a valid Pyroscope tag key.
///
/// Pyroscope (like Prometheus) only accepts tag keys matching `[a-zA-Z0-9_]+`
/// and reserves the `__` prefix, whereas OTel uses dotted keys like
/// `service.name`. Map every other character to `_` (so `service.name` becomes
/// `service_name`) and prefix a leading digit with `_`.
fn sanitize_tag_key(key: &str) -> String {
    let mut out: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Start the in-process Pyroscope agent, tagging every self-profile with the
/// shared OTel resource attributes
pub fn setup_pyroscope(
    url: &str,
    resource: &Resource,
) -> Result<PyroscopeAgent<PyroscopeAgentRunning>> {
    let pyroscope_token = std::env::var("PYROSCOPE_BEARER_TOKEN").ok();
    let mut headers = HashMap::new();
    if let Some(pyroscope_token) = pyroscope_token {
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", pyroscope_token),
        );
    }

    let owned_tags: Vec<(String, String)> = resource
        .iter()
        .filter(|(key, _)| key.as_str() != "service.name") // Pyroscope sets this itself
        .map(|(key, value)| (sanitize_tag_key(key.as_str()), value.as_str().into_owned()))
        .collect();
    let tags: Vec<(&str, &str)> = owned_tags
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    // Configure Pyroscope Agent
    let agent = PyroscopeAgentBuilder::new(
        url,
        "hpc-otel-exporter",
        97, // sample rate in Hz
        "pyroscope-rs",
        env!("CARGO_PKG_VERSION"),
        pprof_backend(PprofConfig { sample_rate: 97 }, BackendConfig::default()),
    )
    .http_headers(headers)
    .tags(tags)
    .build()?;

    Ok(agent.start()?)
}
