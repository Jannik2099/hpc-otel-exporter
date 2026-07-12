//! The [`Collector`] interface: one implementation per telemetry signal.
//!
//! A signal is a vertical slice — its own standalone eBPF object (see
//! `build.rs`'s `BPF_SRCS`) plus the userspace half that consumes it. A
//! collector *owns* everything signal-specific: the loaded skeleton, its
//! per-NUMA-node ring registration, and its per-cgroup state. Metric signals
//! share one channel and one record task (see [`crate::metrics::Recorders`]).
//! The event loop ([`crate::app`]) only ever
//! sees the trait, so adding a signal never grows the loop body.
//!
//! Construction happens through a [`BuildCtx`]: the collector opens its
//! skeleton (stamping the shared cgroup-mode rodata knobs, see
//! [`configure_cgroup_rodata`]), loads it, registers its per-NUMA-node rings +
//! decode callback with the shared [`DrainerBuilder`] (which owns the channel
//! sender and batches decoded events onto it), and, for metric signals,
//! registers its recording state with the shared [`Recorders`].
//! The app then starts the draining threads and calls [`Collector::attach`] on
//! everyone — rings are always populated before any program can produce an
//! event.

use anyhow::Result;
use rustc_hash::FxHashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::cgroup::CgroupRegistry;
use crate::metrics::{MetricEvent, Recorders};
use crate::numa::DrainerBuilder;

/// Bound on the single shared channel buffering decoded metric events between
/// the per-node draining threads and the record task. On overflow events are
/// dropped (and counted per signal) rather than blocking the draining thread —
/// the same drop-on-full behaviour the kernel ring buffer already has.
pub const CHANNEL_CAPACITY: usize = 1 << 16;

/// An owned, boxed future, so [`Collector`] stays object-safe without an
/// `async-trait` dependency.
pub type BoxFuture<'a, T = ()> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything a collector needs to wire itself up at startup.
pub struct BuildCtx<'a> {
    /// The shared cgroup registry every per-cgroup feature state hangs off.
    pub registry: Arc<CgroupRegistry>,
    /// `Some(hierarchy_id)` when tracking cgroup v1: stamped into each
    /// skeleton's rodata knobs (see `src/bpf/cgroup_id.bpf.h`).
    pub v1_hierarchy_id: Option<i32>,
    /// The shared per-NUMA-node drainer; collectors register their outer
    /// `ARRAY_OF_MAPS` + decode callback here (before any program attaches). It
    /// owns the metric-event channel sender and batches each drained ring's
    /// decoded [`MetricEvent`]s onto it.
    pub drainer: &'a mut DrainerBuilder<MetricEvent>,
    /// The shared record-side state. A metric collector stores its `*Metrics`
    /// here so the single record task can dispatch that signal's events.
    pub recorders: &'a mut Recorders,
}

/// One telemetry signal's userspace half. See the module docs for the
/// construction/attach lifecycle; after that the app drives collectors through
/// exactly these three hooks.
pub trait Collector: Send + Sync {
    /// Attach this signal's eBPF programs. Called once, after every collector
    /// has registered its rings and the draining threads are running.
    fn attach(&mut self) -> Result<()>;

    /// Reconcile per-cgroup state against the registry's `live` snapshot, once
    /// per cleanup tick (this is also where a collector reports its dropped
    /// event count, if any).
    fn on_cleanup<'a>(&'a self, live: &'a FxHashSet<u64>) -> BoxFuture<'a>;

    /// Abort owned background tasks. Called on shutdown, before the draining
    /// threads are joined and the skeletons drop.
    fn shutdown(&self);
}

/// Stamp the shared cgroup-mode rodata knobs (`USE_CGROUPS_V1`,
/// `CGROUP_V1_HID` — see `src/bpf/cgroup_id.bpf.h`) into an open skeleton.
/// A macro because every signal's generated skeleton has its own rodata type,
/// structurally identical but nominally distinct.
macro_rules! configure_cgroup_rodata {
    ($open_skel:expr, $v1_hierarchy_id:expr) => {{
        if let Some(hid) = $v1_hierarchy_id {
            let rodata = $open_skel
                .maps
                .rodata_data
                .as_deref_mut()
                .expect("BPF .rodata section present");
            rodata.USE_CGROUPS_V1 = true;
            rodata.CGROUP_V1_HID = hid;
        }
    }};
}
pub(crate) use configure_cgroup_rodata;
