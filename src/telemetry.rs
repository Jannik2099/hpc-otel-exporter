use dashmap::DashMap;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundHistogram, Histogram, MeterProvider};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream,
};
use rustc_hash::{FxBuildHasher, FxHashSet};
use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct SharedExporter(Arc<MetricExporter>);

impl PushMetricExporter for SharedExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        self.0.export(metrics).await
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown(&self) -> OTelSdkResult {
        // Do not shutdown the shared exporter when a single reader shuts down.
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        self.0.temporality()
    }
}

use crate::bindings;

/// Metric instruments tied to a single cgroup's [`SdkMeterProvider`].
struct CgroupMetrics {
    name: String,
    provider: SdkMeterProvider,
    duration_histogram: Histogram<u64>,
    size_histogram: Histogram<u64>,
}

struct BoundCgroupMetrics {
    duration_histogram: BoundHistogram<u64>,
    size_histogram: BoundHistogram<u64>,
}

/// Manages one [`SdkMeterProvider`] per cgroup.
///
/// Each provider carries hostname as a *resource* attribute, while per-event
/// attributes (`cgroup.id`, `io_type`) are recorded on the histograms as metric
/// attributes. When a cgroup disappears from the system the
/// corresponding provider is shut down and removed, so stale series are no
/// longer exported.
pub struct IoMetrics {
    cgroups: DashMap<u64, CgroupMetrics, FxBuildHasher>,
    attrs_to_metrics: DashMap<(u64, bool, u64), BoundCgroupMetrics, FxBuildHasher>,
    resource: Resource,
    exporter: SharedExporter,
}

impl IoMetrics {
    /// Create a new (empty) `IoMetrics` manager.
    /// Providers are created lazily on the first event for each cgroup.
    pub fn new() -> Self {
        let mut buf = [0u8; 4096];
        let _ = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        let hostname = CStr::from_bytes_until_nul(&buf)
            .unwrap_or_else(|_| CStr::from_bytes_with_nul(b"unknown\0").unwrap())
            .to_str()
            .unwrap_or("unknown")
            .to_owned();

        let exporter = MetricExporter::builder()
            .with_tonic()
            .with_protocol(Protocol::Grpc)
            .build()
            .expect("failed to create OTLP metric exporter");

        Self {
            cgroups: DashMap::default(),
            attrs_to_metrics: DashMap::default(),
            resource: Resource::builder()
                .with_attributes([KeyValue::new("host.name", hostname)])
                .build(),
            exporter: SharedExporter(Arc::new(exporter)),
        }
    }

    /// Record an IO event. If this is the first event for the cgroup, a new
    /// [`SdkMeterProvider`] is created on the fly.
    pub fn record(&self, event: &bindings::IOEvent) {
        if event.fs_magic.is_ephemeral_fs() {
            return;
        }

        let metrics = self
            .cgroups
            .entry(event.cgroup_id)
            .or_insert_with(|| self.create_cgroup_metrics(event.cgroup_id));

        let duration_ns = event
            .time_info
            .end_time
            .saturating_sub(event.time_info.start_time);

        let io_type = (event.num_bytes_transferred & 0b10000000000000000000000000000000) != 0;
        let io_type_name = if io_type { "write" } else { "read" };
        let fs_magic = event.fs_magic as u64;

        let histograms = self
            .attrs_to_metrics
            .entry((event.cgroup_id, io_type, fs_magic))
            .or_insert_with(|| {
                let mut attrs = vec![
                    KeyValue::new("io.type", io_type_name),
                    KeyValue::new("cgroup.name", metrics.name.clone()),
                    KeyValue::new("fs.magic", format!("{:#x}", fs_magic)),
                ];
                if let Some(fs_name) = event.fs_magic.magic_to_pretty_name() {
                    attrs.push(KeyValue::new("fs.type", fs_name));
                }
                // see opentelemetry-sdk sort_and_dedup
                attrs.sort_unstable_by(|a, b| a.key.cmp(&b.key));
                attrs.dedup_by(|a, b| a.key == b.key);
                let duration_histogram = metrics.duration_histogram.bind(&attrs);
                let size_histogram = metrics.size_histogram.bind(&attrs);
                BoundCgroupMetrics {
                    duration_histogram,
                    size_histogram,
                }
            });

        histograms.duration_histogram.record(duration_ns);
        histograms
            .size_histogram
            .record((event.num_bytes_transferred & 0b01111111111111111111111111111111) as u64);
    }

    /// Walk `/sys/fs/cgroup`, collect all live cgroup inode numbers, and shut
    /// down + remove providers whose cgroup no longer exists.
    pub fn cleanup_dead_cgroups(&self) {
        let live = collect_live_cgroup_ids();
        let dead: Vec<u64> = self
            .cgroups
            .iter()
            .map(|elem| *elem.key())
            .filter(|id| !live.contains(id))
            .collect();
        let dead_set: FxHashSet<u64> = dead.iter().copied().collect();

        for id in dead {
            if let Some(cg) = self.cgroups.remove(&id) {
                let name = &cg.1.name;
                log::info!("Removing cgroup {name}");
                if let Err(e) = cg.1.provider.shutdown() {
                    log::warn!("Failed to shut down provider for cgroup {name}: {e}");
                }
            }
        }

        if !dead_set.is_empty() {
            self.attrs_to_metrics
                .retain(|(cgroup_id, _, _), _| !dead_set.contains(cgroup_id));
        }
    }

    fn create_cgroup_metrics(&self, cgroup_id: u64) -> CgroupMetrics {
        let name = resolve_cgroup_name(cgroup_id).unwrap_or_else(|| "unknown".into());

        log::info!("Adding cgroup {name}");

        let duration_view = move |inst: &Instrument| {
            if inst.name() == "io.duration" {
                Stream::builder()
                    .with_aggregation(Aggregation::Base2ExponentialHistogram {
                        max_size: 20,
                        max_scale: 4,
                        record_min_max: true,
                    })
                    .build()
                    .ok()
            } else {
                None
            }
        };

        // View: explicit bucket histogram for io.request_size (64 B – 2 GiB).
        let mut boundaries = Vec::new();
        boundaries.push(0f64);
        for i in 0..=25 {
            boundaries.push(64f64 * (1u64 << i) as f64);
        }
        let size_view = move |inst: &Instrument| {
            if inst.name() == "io.request_size" {
                Stream::builder()
                    .with_aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: boundaries.clone(),
                        record_min_max: true,
                    })
                    .build()
                    .ok()
            } else {
                None
            }
        };

        // Create a new PeriodicReader instance for each SdkMeterProvider
        // but reuse the underlying Grpc connection/configuration.
        let reader = PeriodicReader::builder(self.exporter.clone()).build();

        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(self.resource.clone())
            .with_view(duration_view)
            .with_view(size_view)
            .build();

        let meter = provider.meter("hpc-otel-exporter");

        let duration_histogram = meter
            .u64_histogram("io.duration")
            .with_description("Duration of IO operations")
            .with_unit("ns")
            .build();

        let size_histogram = meter
            .u64_histogram("io.request_size")
            .with_description("Size of IO requests")
            .with_unit("By")
            .build();

        CgroupMetrics {
            name,
            provider,
            duration_histogram,
            size_histogram,
        }
    }
}

fn resolve_cgroup_name(id: u64) -> Option<String> {
    let cgroup_root = Path::new("/sys/fs/cgroup");
    let mut stack = vec![cgroup_root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(meta) = fs::metadata(&current) else {
            continue;
        };
        if meta.ino() == id {
            return current
                .strip_prefix(cgroup_root)
                .unwrap_or(&current)
                .to_string_lossy()
                .into_owned()
                .into();
        }

        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    None
}

fn collect_live_cgroup_ids() -> FxHashSet<u64> {
    walk_cgroup_dir(Path::new("/sys/fs/cgroup"))
}

fn walk_cgroup_dir(dir: &Path) -> FxHashSet<u64> {
    let mut ids = FxHashSet::default();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(meta) = fs::metadata(&current) else {
            continue;
        };
        ids.insert(meta.ino());

        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }

    ids
}
