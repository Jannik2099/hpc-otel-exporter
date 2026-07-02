//! The io_requests signal: per-cgroup IO histograms (the size and duration of
//! synchronous file IO), recorded from the `EVENTS` ring buffer the IO eBPF
//! object (`src/bpf/io.bpf.c`, its own skeleton) fills. [`IoCollector`] is the
//! signal's [`Collector`] implementation; [`IoMetrics`] is the recording state.

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundHistogram, Histogram};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
use rustc_hash::{FxBuildHasher, FxHashSet};

use crate::bindings::{self, FsMagic, IOEvent};
use crate::bpf;
use crate::cgroup::{CgroupMeter, CgroupRegistry, CgroupView, PerCgroup};
use crate::collector::{
    BoxFuture, BuildCtx, CHANNEL_CAPACITY, Collector, configure_cgroup_rodata,
};
use crate::numa::decode_event;

impl FsMagic {
    pub fn is_ephemeral_fs(self) -> bool {
        matches!(
            self,
            FsMagic::ANON_INODE_FS_MAGIC
                | FsMagic::AUTOFS_SUPER_MAGIC
                | FsMagic::BINFMTFS_MAGIC
                | FsMagic::BPF_FS_MAGIC
                | FsMagic::CGROUP_SUPER_MAGIC
                | FsMagic::CGROUP2_SUPER_MAGIC
                | FsMagic::DEBUGFS_MAGIC
                | FsMagic::DEVFS_SUPER_MAGIC
                | FsMagic::DEVPTS_SUPER_MAGIC
                | FsMagic::EFIVARFS_MAGIC
                | FsMagic::FUTEXFS_SUPER_MAGIC
                | FsMagic::HUGETLBFS_MAGIC
                | FsMagic::MQUEUE_MAGIC
                | FsMagic::PIPEFS_MAGIC
                | FsMagic::PROC_SUPER_MAGIC
                | FsMagic::PSTOREFS_MAGIC
                | FsMagic::RAMFS_MAGIC
                | FsMagic::SECURITYFS_MAGIC
                | FsMagic::SELINUX_MAGIC
                | FsMagic::SMACK_MAGIC
                | FsMagic::SOCKFS_MAGIC
                | FsMagic::SYSFS_MAGIC
                | FsMagic::TMPFS_MAGIC
                | FsMagic::TRACEFS_MAGIC
        )
    }

    pub fn magic_to_pretty_name(self) -> Option<&'static str> {
        match self {
            FsMagic::EXT4_SUPER_MAGIC => Some("ext4"),
            FsMagic::XFS_SUPER_MAGIC => Some("xfs"),
            FsMagic::BTRFS_SUPER_MAGIC => Some("btrfs"),
            FsMagic::F2FS_SUPER_MAGIC => Some("f2fs"),
            FsMagic::NFS_SUPER_MAGIC => Some("nfs"),
            FsMagic::SMB_SUPER_MAGIC => Some("smb"),
            FsMagic::SMB2_MAGIC_NUMBER => Some("smb"),
            FsMagic::OVERLAYFS_SUPER_MAGIC => Some("overlayfs"),
            FsMagic::SQUASHFS_MAGIC => Some("squashfs"),
            FsMagic::FUSE_SUPER_MAGIC => Some("fuse"),
            FsMagic::GPFS_MAGIC => Some("gpfs"),
            FsMagic::LUSTRE_MAGIC => Some("lustre"),
            _ => None,
        }
    }
}

/// The per-provider histogram aggregations the IO metrics need, contributed to the
/// shared [`CgroupRegistry`] (see [`CgroupRegistry::new`]). Because every cgroup's
/// meter provider is shared across features, these views must be registered at
/// provider-build time; returning them here keeps the IO-specific aggregation
/// choices out of the generic registry.
pub fn histogram_views() -> Vec<CgroupView> {
    // Exponential histogram for io.duration.
    let duration_view: CgroupView = Arc::new(|inst: &Instrument| {
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
    });

    // Explicit bucket histogram for io.request_size (64 B – 2 GiB).
    let mut boundaries = vec![0f64];
    for i in 0..=25 {
        boundaries.push(64f64 * (1u64 << i) as f64);
    }
    let size_view: CgroupView = Arc::new(move |inst: &Instrument| {
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
    });

    vec![duration_view, size_view]
}

/// Per-cgroup IO instruments, attached to the cgroup's shared [`CgroupMeter`].
struct IoCgroup {
    meter: Arc<CgroupMeter>,
    duration_histogram: Histogram<u64>,
    size_histogram: Histogram<u64>,
}

struct BoundCgroupMetrics {
    duration_histogram: BoundHistogram<u64>,
    size_histogram: BoundHistogram<u64>,
}

/// Records per-cgroup IO duration/size histograms.
///
/// Provider lifetime is owned by the shared [`CgroupRegistry`]; this type holds the
/// instruments (via a [`PerCgroup`]) and their bound attribute sets, and prunes
/// them via [`retain_live`](Self::retain_live) when the registry reports a cgroup
/// gone.
pub struct IoMetrics {
    cgroups: PerCgroup<IoCgroup>,
    attrs_to_metrics: DashMap<(u64, bool, u64), BoundCgroupMetrics, FxBuildHasher>,
}

impl IoMetrics {
    /// Create a new (empty) `IoMetrics` sharing `registry` for provider lifetime.
    pub fn new(registry: Arc<CgroupRegistry>) -> Self {
        Self {
            cgroups: PerCgroup::new(registry),
            attrs_to_metrics: DashMap::default(),
        }
    }

    /// Record an IO event, lazily attaching IO instruments to the cgroup's shared
    /// meter on first sight. Events in unresolvable or root cgroups (no meter) are
    /// dropped.
    pub async fn record(&self, event: &bindings::IOEvent) {
        if event.fs_magic.is_ephemeral_fs() {
            return;
        }

        let metrics = match self
            .cgroups
            .get_or_create(event.cgroup_id, Some(event.tgid), |meter| {
                let duration_histogram = meter
                    .meter
                    .u64_histogram("io.duration")
                    .with_description("Duration of IO operations")
                    .with_unit("ns")
                    .build();
                let size_histogram = meter
                    .meter
                    .u64_histogram("io.request_size")
                    .with_description("Size of IO requests")
                    .with_unit("By")
                    .build();
                IoCgroup {
                    meter: Arc::clone(meter),
                    duration_histogram,
                    size_histogram,
                }
            })
            .await
        {
            Some(m) => m,
            None => return,
        };

        let duration_ns = event
            .time_info
            .end_time
            .saturating_sub(event.time_info.start_time);

        let io_type = (event.num_bytes_transferred & 0b10000000000000000000000000000000) != 0;
        let io_type_name = if io_type { "write" } else { "read" };
        let fs_magic = event.fs_magic as u64;

        // Key bound attribute sets by the canonical (job-aggregated) cgroup id, not
        // the raw event id, so a SLURM job's sub-cgroups share one series.
        let cgroup_id = *metrics.key();

        let histograms = self
            .attrs_to_metrics
            .entry((cgroup_id, io_type, fs_magic))
            .or_insert_with(|| {
                let mut attrs = vec![
                    KeyValue::new("io.type", io_type_name),
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

    /// Drop IO instruments for cgroups absent from `live` (the registry's snapshot
    /// from [`CgroupRegistry::cleanup_dead_cgroups`]).
    pub fn retain_live(&self, live: &FxHashSet<u64>) {
        self.cgroups.retain_live(live);
        self.attrs_to_metrics
            .retain(|(cgroup_id, _, _), _| live.contains(cgroup_id));
    }
}

/// The io_requests signal: owns the IO eBPF object, its per-NUMA-node ring
/// registration, and the record task feeding [`IoMetrics`].
pub struct IoCollector {
    skel: bpf::io::IoSkel<'static>,
    metrics: Arc<IoMetrics>,
    record_task: tokio::task::JoinHandle<()>,
    /// Events dropped because the record task fell behind; reported (and reset)
    /// each cleanup tick.
    dropped: Arc<AtomicU64>,
}

impl IoCollector {
    /// Open + load the IO eBPF object, register its rings with the shared
    /// drainer, and spawn the record task. Programs attach later, via
    /// [`Collector::attach`].
    pub fn new(ctx: &mut BuildCtx) -> anyhow::Result<Self> {
        // The skeleton borrows its open-object storage; leak that storage (one
        // small allocation per enabled signal, for the process lifetime) so the
        // collector can own the skeleton without a self-referential struct.
        let storage = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open_skel = bpf::io::IoSkelBuilder::default().open(storage)?;
        configure_cgroup_rodata!(open_skel, ctx.v1_hierarchy_id);
        let skel = open_skel.load()?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<IOEvent>(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        ctx.drainer.register("io_events_node", &skel.maps.EVENTS, {
            let dropped = Arc::clone(&dropped);
            Arc::new(move |data| {
                if let Some(event) = decode_event::<IOEvent>(data)
                    && tx.try_send(event).is_err()
                {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            })
        })?;

        let metrics = Arc::new(IoMetrics::new(Arc::clone(&ctx.registry)));
        let record_task = tokio::spawn({
            let metrics = Arc::clone(&metrics);
            async move {
                // Drain in batches to amortize the per-event await overhead;
                // recv_many returning 0 means the draining threads have stopped.
                let mut batch = Vec::with_capacity(1024);
                while rx.recv_many(&mut batch, 1024).await > 0 {
                    for event in batch.drain(..) {
                        metrics.record(&event).await;
                    }
                }
            }
        });

        Ok(Self {
            skel,
            metrics,
            record_task,
            dropped,
        })
    }
}

impl Collector for IoCollector {
    fn attach(&mut self) -> anyhow::Result<()> {
        self.skel.attach()?;
        Ok(())
    }

    fn on_cleanup<'a>(&'a self, live: &'a FxHashSet<u64>) -> BoxFuture<'a> {
        Box::pin(async move {
            self.metrics.retain_live(live);
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            if dropped > 0 {
                log::warn!("io_requests: dropped {dropped} events: record loop fell behind");
            }
        })
    }

    fn shutdown(&self) {
        self.record_task.abort();
    }
}
