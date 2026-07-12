//! The vfs_metadata signal: per-cgroup VFS metadata histograms (the duration
//! of namespace/attribute file operations — open, close, create, stat, ...),
//! recorded from the `METADATA_EVENTS` ring buffer the metadata eBPF object
//! (`src/bpf/metadata.bpf.c`, its own skeleton) fills. [`MetadataCollector`]
//! is the signal's [`Collector`] implementation; [`MetadataMetrics`] the
//! recording state.
//!
//! Mirrors [`crate::metrics::io`] but emits a single duration histogram
//! (`vfs.metadata.duration`) keyed by a `vfs.op` attribute, so every operation
//! shares one metric. There is no size component: these ops transfer no bytes.

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundHistogram, Histogram};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
use rustc_hash::{FxBuildHasher, FxHashSet};

use crate::bindings::{self, MetadataEvent, MetadataOp};
use crate::bpf;
use crate::cgroup::{CgroupMeter, CgroupRegistry, CgroupView, PerCgroup};
use crate::collector::{BoxFuture, BuildCtx, Collector, configure_cgroup_rodata};
use crate::metrics::MetricEvent;
use crate::numa::decode_event;

impl MetadataOp {
    /// Stable lowercase name used as the `vfs.op` metric attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            MetadataOp::METADATA_OP_OPEN => "open",
            MetadataOp::METADATA_OP_CLOSE => "close",
            MetadataOp::METADATA_OP_CREATE => "create",
            MetadataOp::METADATA_OP_MKDIR => "mkdir",
            MetadataOp::METADATA_OP_RMDIR => "rmdir",
            MetadataOp::METADATA_OP_UNLINK => "unlink",
            MetadataOp::METADATA_OP_RENAME => "rename",
            MetadataOp::METADATA_OP_LINK => "link",
            MetadataOp::METADATA_OP_SYMLINK => "symlink",
            MetadataOp::METADATA_OP_MKNOD => "mknod",
            MetadataOp::METADATA_OP_GETATTR => "getattr",
            MetadataOp::METADATA_OP_SETATTR => "setattr",
            MetadataOp::METADATA_OP_READDIR => "readdir",
            MetadataOp::METADATA_OP_FSYNC => "fsync",
            MetadataOp::METADATA_OP_GETXATTR => "getxattr",
            MetadataOp::METADATA_OP_SETXATTR => "setxattr",
            MetadataOp::METADATA_OP_LISTXATTR => "listxattr",
            MetadataOp::METADATA_OP_REMOVEXATTR => "removexattr",
            MetadataOp::METADATA_OP_MAX => "unknown",
        }
    }
}

/// The per-provider histogram aggregation the metadata metrics need, contributed
/// to the shared [`CgroupRegistry`] (see [`crate::metrics::io::histogram_views`]
/// for the same pattern on the IO side).
pub fn histogram_views() -> Vec<CgroupView> {
    // Exponential histogram for vfs.metadata.duration.
    let duration_view: CgroupView = Arc::new(|inst: &Instrument| {
        if inst.name() == "vfs.metadata.duration" {
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
    });

    vec![duration_view]
}

/// Per-cgroup metadata instrument, attached to the cgroup's shared [`CgroupMeter`].
struct MetadataCgroup {
    meter: Arc<CgroupMeter>,
    duration_histogram: Histogram<u64>,
}

/// Records the per-cgroup `vfs.metadata.duration` histogram.
///
/// Provider lifetime is owned by the shared [`CgroupRegistry`]; this type holds
/// the instrument (via a [`PerCgroup`]) and its bound attribute sets, and prunes
/// them via [`retain_live`](Self::retain_live) when the registry reports a cgroup
/// gone. The bound sets are keyed by `(cgroup_id, op, fs_magic)`.
pub struct MetadataMetrics {
    cgroups: PerCgroup<MetadataCgroup>,
    attrs_to_metrics: DashMap<(u64, u32, u64), BoundHistogram<u64>, FxBuildHasher>,
}

impl MetadataMetrics {
    /// Create a new (empty) `MetadataMetrics` sharing `registry` for provider
    /// lifetime.
    pub fn new(registry: Arc<CgroupRegistry>) -> Self {
        Self {
            cgroups: PerCgroup::new(registry),
            attrs_to_metrics: DashMap::default(),
        }
    }

    /// Record a metadata event, lazily attaching the instrument to the cgroup's
    /// shared meter on first sight. Events in unresolvable or root cgroups (no
    /// meter) are dropped.
    pub fn record(&self, event: &bindings::MetadataEvent) {
        if event.fs_magic.is_ephemeral_fs() {
            return;
        }

        let metrics = match self
            .cgroups
            .get_or_create(event.cgroup_id, Some(event.tgid), |meter| {
                let duration_histogram = meter
                    .meter
                    .u64_histogram("vfs.metadata.duration")
                    .with_description("Duration of VFS metadata operations")
                    .with_unit("ns")
                    .build();
                MetadataCgroup {
                    meter: Arc::clone(meter),
                    duration_histogram,
                }
            }) {
            Some(m) => m,
            None => return,
        };

        let duration_ns = event
            .time_info
            .end_time
            .saturating_sub(event.time_info.start_time);

        let op = event.op as u32;
        let fs_magic = event.fs_magic as u64;

        // Key bound attribute sets by the canonical (job-aggregated) cgroup id, not
        // the raw event id, so a SLURM job's sub-cgroups share one series.
        let cgroup_id = *metrics.key();

        let histogram = self
            .attrs_to_metrics
            .entry((cgroup_id, op, fs_magic))
            .or_insert_with(|| {
                let mut attrs = vec![
                    KeyValue::new("vfs.op", event.op.as_str()),
                    KeyValue::new("cgroup.name", metrics.meter.name.clone()),
                    KeyValue::new("fs.magic", format!("{:#x}", fs_magic)),
                ];
                if let Some(fs_name) = event.fs_magic.magic_to_pretty_name() {
                    attrs.push(KeyValue::new("fs.type", fs_name));
                }
                // Filter-contributed identity, when any.
                metrics.meter.push_attrs(&mut attrs);
                // see opentelemetry-sdk sort_and_dedup
                attrs.sort_unstable_by(|a, b| a.key.cmp(&b.key));
                attrs.dedup_by(|a, b| a.key == b.key);
                metrics.duration_histogram.bind(&attrs)
            });

        histogram.record(duration_ns);
    }

    /// Drop metadata instruments for cgroups absent from `live` (the registry's
    /// snapshot from [`CgroupRegistry::cleanup_dead_cgroups`]).
    pub fn retain_live(&self, live: &FxHashSet<u64>) {
        self.cgroups.retain_live(live);
        self.attrs_to_metrics
            .retain(|(cgroup_id, _, _), _| live.contains(cgroup_id));
    }
}

/// The vfs_metadata signal: owns the metadata eBPF object and its per-NUMA-node
/// ring registration. Decoded events go down the shared metric channel; the
/// record task and [`MetadataMetrics`] recording live on the shared
/// [`Recorders`] side.
///
/// [`Recorders`]: crate::metrics::Recorders
pub struct MetadataCollector {
    skel: bpf::metadata::MetadataSkel<'static>,
    metrics: Arc<MetadataMetrics>,
    /// Events dropped because the shared record loop fell behind (this signal's
    /// share of shared-channel overflow); reported (and reset) each cleanup tick.
    dropped: Arc<AtomicU64>,
}

impl MetadataCollector {
    /// Open + load the metadata eBPF object, register its rings with the shared
    /// drainer (forwarding decoded events down the shared channel), and register
    /// its [`MetadataMetrics`] with the shared [`Recorders`]. Programs attach
    /// later, via [`Collector::attach`].
    ///
    /// [`Recorders`]: crate::metrics::Recorders
    pub fn new(ctx: &mut BuildCtx) -> anyhow::Result<Self> {
        // The skeleton borrows its open-object storage; leak that storage (one
        // small allocation per enabled signal, for the process lifetime) so the
        // collector can own the skeleton without a self-referential struct.
        let storage = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open_skel = bpf::metadata::MetadataSkelBuilder::default().open(storage)?;
        configure_cgroup_rodata!(open_skel, ctx.v1_hierarchy_id);
        let skel = open_skel.load()?;

        let dropped = Arc::new(AtomicU64::new(0));
        ctx.drainer.register(
            "vfs_metadata_events_node",
            &skel.maps.VFS_METADATA_EVENTS,
            Arc::new(|data| decode_event::<MetadataEvent>(data).map(MetricEvent::Metadata)),
            Arc::clone(&dropped),
        )?;

        let metrics = Arc::new(MetadataMetrics::new(Arc::clone(&ctx.registry)));
        ctx.recorders.metadata = Some(Arc::clone(&metrics));

        Ok(Self {
            skel,
            metrics,
            dropped,
        })
    }
}

impl Collector for MetadataCollector {
    fn attach(&mut self) -> anyhow::Result<()> {
        self.skel.attach()?;
        Ok(())
    }

    fn on_cleanup<'a>(&'a self, live: &'a FxHashSet<u64>) -> BoxFuture<'a> {
        Box::pin(async move {
            self.metrics.retain_live(live);
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            if dropped > 0 {
                log::warn!("vfs_metadata: dropped {dropped} events: record loop fell behind");
            }
        })
    }

    /// No owned task to stop — the shared record task is owned and aborted by
    /// [`crate::app`].
    fn shutdown(&self) {}
}
