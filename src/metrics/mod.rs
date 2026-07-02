//! Metric signals: per-cgroup OTel instruments fed by eBPF ringbuffer events.
//!
//! Each signal is its own submodule owning two pieces: a `*Metrics` recording
//! state (a [`PerCgroup`] of its instruments with a `record(event)` hot path
//! and a `retain_live(&live)` pruner) and a `*Collector` — the signal's
//! [`Collector`] implementation that owns the standalone eBPF object, the
//! per-NUMA-node ring registration, and the record task. Adding a metric
//! signal means:
//!
//! 1. write the eBPF side: a standalone `src/bpf/<name>.bpf.c` object (add it
//!    to `BPF_SRCS` in `build.rs`), sharing its event type with userspace via
//!    a header included from `shared.h`,
//! 2. add a submodule here mirroring [`io`]: the recording state plus the
//!    collector; custom histogram aggregations are contributed through a
//!    `histogram_views()` returning [`CgroupView`]s,
//! 3. add a `Signal` variant in [`crate::app`] with its `views()`/`build()`
//!    arms.
//!
//! [`Collector`]: crate::collector::Collector
//! [`PerCgroup`]: crate::cgroup::PerCgroup
//! [`CgroupView`]: crate::cgroup::CgroupView

pub mod io;
pub mod metadata;

pub use io::IoCollector;
pub use metadata::MetadataCollector;
