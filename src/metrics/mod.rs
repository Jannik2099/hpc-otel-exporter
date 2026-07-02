//! Metrics features: per-cgroup OTel instruments fed by eBPF ringbuffer events.
//!
//! Each metric is its own submodule owning a feature struct that holds a
//! [`PerCgroup`] of its instruments, a `record(event)` hot path, and a
//! `retain_live(&live)` pruner. Adding a metric means:
//!
//! 1. write the eBPF side (a `<feature>.bpf.c` fragment + shared event type),
//! 2. add a submodule here with the feature struct,
//! 3. if it needs custom histogram aggregations, expose a `histogram_views()`
//!    returning [`CgroupView`]s and merge them into the registry in [`crate::app`],
//! 4. wire its `record`/`retain_live` into the event loop.
//!
//! [`PerCgroup`]: crate::cgroup::PerCgroup
//! [`CgroupView`]: crate::cgroup::CgroupView

pub mod io;
pub mod metadata;

pub use io::IoCollector;
pub use metadata::MetadataCollector;
