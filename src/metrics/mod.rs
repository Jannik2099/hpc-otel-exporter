//! Metric signals: per-cgroup OTel instruments fed by eBPF ringbuffer events.
//!
//! Each signal is its own submodule owning two pieces: a `*Metrics` recording
//! state (a [`PerCgroup`] of its instruments with a `record(event)` hot path
//! and a `retain_live(&live)` pruner) and a `*Collector` — the signal's
//! [`Collector`] implementation that owns the standalone eBPF object and its
//! per-NUMA-node ring registration. All metric signals share **one** array-backed
//! (crossbeam) queue and a single record thread: each collector's decode callback
//! tags its decoded event as a [`MetricEvent`] and sends it down the shared channel;
//! the [`Recorders`] record loop (owned by [`crate::app`]) dispatches each event to
//! the matching signal's `*Metrics::record`. Adding a metric signal means:
//!
//! 1. write the eBPF side: a standalone `src/bpf/<name>.bpf.c` object (add it
//!    to `BPF_SRCS` in `build.rs`), sharing its event type with userspace via
//!    a header included from `shared.h`,
//! 2. add a submodule here mirroring [`io`]: the recording state plus the
//!    collector; custom histogram aggregations are contributed through a
//!    `histogram_views()` returning [`CgroupView`]s, and a [`MetricEvent`]
//!    variant plus its dispatch arm in [`Recorders::run`],
//! 3. add a `Signal` variant in [`crate::app`] with its `views()`/`build()`
//!    arms.
//!
//! [`Collector`]: crate::collector::Collector
//! [`PerCgroup`]: crate::cgroup::PerCgroup
//! [`CgroupView`]: crate::cgroup::CgroupView

pub mod io;
pub mod metadata;

use std::sync::Arc;

use crossbeam_channel::Receiver;

use crate::bindings::{IOEvent, MetadataEvent};

pub use io::IoCollector;
pub use metadata::MetadataCollector;

/// One decoded metric event, tagged by signal, carried on the single shared
/// channel from the per-NUMA-node draining threads to the record task. The
/// variants wrap the POD event structs the eBPF objects emit; both are `Copy`
/// and one cacheline wide.
pub enum MetricEvent {
    Io(IOEvent),
    Metadata(MetadataEvent),
}

/// The record side of the shared queue: the per-signal recording state for
/// whichever metric signals are enabled. Metric collectors register their
/// `*Metrics` here at build time (through `BuildCtx`); [`crate::app`] then moves
/// this into the single record task via [`run`](Self::run).
#[derive(Default)]
pub struct Recorders {
    pub io: Option<Arc<io::IoMetrics>>,
    pub metadata: Option<Arc<metadata::MetadataMetrics>>,
}

impl Recorders {
    /// Drain the shared channel and dispatch each event to the matching signal's
    /// recorder. Runs on a dedicated blocking thread (see [`crate::app`]): the
    /// channel is an array-backed crossbeam queue whose `recv` never allocates.
    /// Returns when every sender has dropped
    /// (the draining threads have stopped) and the queue is drained.
    pub fn run(self, rx: Receiver<MetricEvent>) {
        while let Ok(event) = rx.recv() {
            match event {
                MetricEvent::Io(e) => {
                    if let Some(m) = &self.io {
                        m.record(&e);
                    }
                }
                MetricEvent::Metadata(e) => {
                    if let Some(m) = &self.metadata {
                        m.record(&e);
                    }
                }
            }
        }
    }
}
