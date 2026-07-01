//! Per-cgroup IO histograms: the size and duration of synchronous file IO,
//! recorded from the `EVENTS` ring buffer the IO eBPF program fills.

use std::sync::Arc;

use dashmap::DashMap;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundHistogram, Histogram};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, Stream};
use rustc_hash::{FxBuildHasher, FxHashSet};

use crate::bindings::{self, FsMagic};
use crate::cgroup::{CgroupMeter, CgroupRegistry, CgroupView, PerCgroup};

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
