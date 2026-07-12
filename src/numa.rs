//! Per-NUMA-node ring buffer draining.
//!
//! Event-producing eBPF programs do not write into a single global ring
//! buffer; each writes into the ring buffer for the CPU's local NUMA node (an
//! `ARRAY_OF_MAPS` keyed by `bpf_get_numa_node_id()`, see
//! `src/bpf/numa_ringbuf.bpf.h`). A single global ring made every NUMA domain
//! fight over one reserve spinlock + its cache line across the inter-node
//! interconnect; sharding the ring per node keeps that lock node-local.
//!
//! This module is feature-agnostic: each feature [`register`]s its outer
//! `ARRAY_OF_MAPS` together with a decode callback, and [`DrainerBuilder::start`]
//! then spawns one OS thread per node, pinned to that node's CPUs, that drains
//! every registered feature's ring for that node. Registration:
//!  1. enumerates the machine's NUMA nodes and their CPUs,
//!  2. creates one NUMA-placed ring buffer per node per feature and inserts it
//!     into the feature's outer array — done **before** the programs attach so
//!     the very first event finds a ring for its node.
//!
//! The draining thread does only the NUMA-local work: on a fixed short interval
//! it drains its node's rings a memory-only read, decoding each record and batching it,
//! then flushes each batch down an array-backed (crossbeam) channel, whose
//! `try_send` is an alloc-free atomic push (see [`POLL_INTERVAL`] and
//! [`Flusher`]). Polling on a
//! timer rather than waking on the ring's fd per event keeps drain CPU
//! proportional to the poll rate, not the event rate, and lets the kernel skip
//! wakeups entirely (the producers submit `BPF_RB_NO_WAKEUP`). Anything slow
//! (e.g. `/proc` resolution) belongs on the feature's own task consuming that
//! channel. Keeping the thread pinned to the producing node is the whole point:
//! it ensures the ring's reserve/commit atomics and backing pages stay
//! node-local.
//!
//! [`register`]: DrainerBuilder::register

use std::cell::UnsafeCell;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::Sender;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, RingBuffer, RingBufferBuilder};
use log::{error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::metrics::MetricEvent;

/// Byte size of each per-node ring buffer. MUST stay in sync with
/// `NUMA_RINGBUF_SIZE` in `src/bpf/numa_ringbuf.bpf.h`: the inner-map prototype
/// is created at that size and the kernel's map-in-map compatibility check
/// requires every inserted ring to match the prototype's metadata exactly.
const RINGBUF_SIZE: u32 = 1 << 18; // 256KiB

/// `BPF_F_NUMA_NODE` (uapi/linux/bpf.h): place the ring's pages on a specific
/// NUMA node. Also the only flag `BPF_MAP_TYPE_RINGBUF` permits, so the per-node
/// rings carry exactly this flag to match the prototype's `map_flags`.
const BPF_F_NUMA_NODE: u32 = 1 << 2;

/// Pre-reserved capacity for a draining thread's per-source batch buffer: an
/// upper bound on the records one `consume_raw` can yield from a single ring.
const BATCH_CAP: usize = RINGBUF_SIZE as usize / std::mem::size_of::<MetricEvent>();

/// How long a draining thread sleeps between drains. `consume_raw` is a
/// memory-only read (no syscall), so draining on a timer, rather than waking on
/// the ring's epoll fd per event, keeps drain-thread CPU proportional to the
/// poll rate instead of the event rate, and lets each sweep drain a whole batch
/// in one pass rather than waking per event.
/// 4ms with a ringbuf capacity of 4096 events can handle 1 million events/sec
const POLL_INTERVAL: Duration = Duration::from_millis(4);

/// A feature's decode callback, run on the draining thread for every raw ring
/// payload: turn one raw ring record into a buffered item `T` (or `None` when
/// the payload is too short). Shared behind an `Arc` because the same callback
/// decodes every node's ring for that feature; must stay cheap and non-blocking.
/// Draining collects the decoded items into a per-thread batch and flushes the
/// batch onto the channel in one reserve, see [`DrainerBuilder`].
pub type DecodeFn<T> = Arc<dyn Fn(&[u8]) -> Option<T> + Send + Sync>;

/// Decode a POD event `T` from a raw ring payload, or `None` when the payload
/// is too short. Reads aligned: ring slices are 8B aligned.
pub fn decode_event<T: Copy>(data: &[u8]) -> Option<T> {
    const {
        assert!(
            align_of::<T>() <= 8,
            "decode_event<T>: align_of::<T>() must be <= 8"
        )
    };
    if data.len() < size_of::<T>() {
        return None;
    }
    // Safety: length checked above, and the BPF side only ever submits a `T`
    // into the ring this callback was registered for.
    Some(unsafe { (data.as_ptr() as *const T).read() })
}

/// A NUMA node and the CPUs that belong to it.
struct NumaNode {
    id: u32,
    cpus: Vec<usize>,
}

/// One registered feature's per-node contribution to a draining thread: its ring
/// for that node, its decode callback, and its drop counter.
type NodeSource<T> = (MapHandle, DecodeFn<T>, Arc<AtomicU64>);

/// One registered feature: its per-node rings (index-aligned with the builder's
/// node list), the callback that decodes its payloads, and the counter it bumps
/// when the channel is full and events are dropped.
struct Source<T> {
    rings: Vec<MapHandle>,
    decode: DecodeFn<T>,
    dropped: Arc<AtomicU64>,
}

/// A drain thread's per-source batch buffer, shared (via `Rc`) between the ring
/// callback that fills it during `consume_raw` and the [`Flusher`] that empties
/// it right after.
///
/// Uses `UnsafeCell` rather than `RefCell` to skip a borrow-flag check on the
/// per-event hot path: the two accessors run on the same thread and never
/// overlap. During `consume_raw` libbpf invokes the callback one record at a
/// time, each [`push`](Self::push) taking and releasing a transient `&mut`
/// before the next; the flush's [`get`](Self::get) runs only *after*
/// `consume_raw` has returned, when no callback borrow is live. So no two `&mut`
/// to the buffer ever coexist. `Rc` (not `Arc`) keeps it `!Send`, pinning it to
/// its drain thread.
struct Batch<T>(UnsafeCell<Vec<T>>);

impl<T> Batch<T> {
    fn with_capacity(cap: usize) -> Self {
        Self(UnsafeCell::new(Vec::with_capacity(cap)))
    }

    /// Append one decoded item. Called only from the ring callback.
    ///
    /// # Safety
    /// No other borrow of the buffer may be live. Upheld because callbacks run
    /// sequentially inside `consume_raw` and never concurrently with [`get`].
    ///
    /// [`get`]: Self::get
    unsafe fn push(&self, item: T) {
        // Safety: exclusive, non-overlapping access per the type's invariant.
        unsafe { (*self.0.get()).push(item) };
    }

    /// Exclusive access to the buffer for flushing. Called only after
    /// `consume_raw` returns, when no callback borrow is live.
    ///
    /// # Safety
    /// As [`push`](Self::push): no other borrow may be live.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut Vec<T> {
        // Safety: exclusive, non-overlapping access per the type's invariant.
        unsafe { &mut *self.0.get() }
    }
}

/// One feature's per-thread draining state: the batch buffer its ring callback
/// pushes decoded items into during `consume_raw`, and the drop counter its
/// [`flush`](Self::flush) bumps for events the channel had no room for.
struct Flusher<T> {
    buffer: Rc<Batch<T>>,
    dropped: Arc<AtomicU64>,
}

impl<T> Flusher<T> {
    /// Push the whole batch onto `sender`, then clear it. `sender` is an
    /// array-backed crossbeam channel: `try_send` is an alloc-free atomic push, so
    /// there is no per-event allocation and no reason to reserve the batch up front
    /// (unlike tokio's linked-list mpsc, whose 32-slot blocks were allocated and
    /// freed under this bursty flush pattern). Events that don't fit are dropped
    /// and counted, matching the ring buffer's own drop-on-full behaviour.
    fn flush(&self, sender: &Sender<T>) {
        // Safety: `consume_raw` has returned, so no ring callback (the only other
        // accessor) is running. This is the buffer's sole live borrow.
        let buf = unsafe { self.buffer.get() };
        if buf.is_empty() {
            return;
        }
        let mut dropped = 0u64;
        for item in buf.drain(..) {
            // `try_send` returns the item inside the error; dropping the error
            // drops the event, which is exactly the drop-on-full behaviour we want.
            if sender.try_send(item).is_err() {
                dropped += 1;
            }
        }
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
    }
}

/// Builder collecting every feature's per-node rings before the draining
/// threads start. Features [`register`](Self::register) while wiring up (after
/// their maps are loaded, before their programs attach); [`start`](Self::start)
/// then spawns one pinned draining thread per node covering all of them. Owns
/// the `sender` half of the single shared channel; each draining thread batches
/// decoded events and flushes them down it (see [`Flusher`]).
pub struct DrainerBuilder<T> {
    nodes: Vec<NumaNode>,
    sources: Vec<Source<T>>,
    sender: Sender<T>,
}

impl<T: Send + 'static> DrainerBuilder<T> {
    /// Enumerate the machine's NUMA topology; no rings exist yet. `sender` is the
    /// channel every draining thread's batch is flushed onto.
    pub fn new(sender: Sender<T>) -> Self {
        let nodes = numa_nodes();
        info!(
            "draining {} NUMA node ring buffer(s) ({} total)",
            nodes.len(),
            nodes.iter().map(|n| n.id).max().map_or(0, |m| m + 1)
        );
        Self {
            nodes,
            sources: Vec::new(),
            sender,
        }
    }

    /// Create one NUMA-placed ring buffer per online node for a feature, insert
    /// each into the feature's outer `ARRAY_OF_MAPS`, and record `decode` as the
    /// callback turning those rings' records into buffered items. `dropped` is
    /// the counter bumped for events the channel had no room for. `name` names
    /// the inner rings (visible in `bpftool map list`).
    ///
    /// Must be called **before** the feature's eBPF programs are attached, so
    /// events always find a populated ring for their node.
    pub fn register(
        &mut self,
        name: &str,
        outer: &impl MapCore,
        decode: DecodeFn<T>,
        dropped: Arc<AtomicU64>,
    ) -> Result<()> {
        let mut rings = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            // The rings' pages are placed on the node so its CPUs reserve locally.
            let ring = create_node_ringbuf(name, node.id)?;
            insert_ring(outer, node.id, &ring)?;
            rings.push(ring);
        }
        self.sources.push(Source {
            rings,
            decode,
            dropped,
        });
        Ok(())
    }

    /// Spawn one pinned draining thread per node, each polling every registered
    /// feature's ring for that node. With nothing registered (no event-driven
    /// feature enabled) no threads are spawned.
    pub fn start(self) -> Result<Drainers> {
        let stop = CancellationToken::new();
        let mut threads = Vec::with_capacity(self.nodes.len());

        // Regroup the per-source ring columns into one row per node.
        let mut per_node: Vec<Vec<NodeSource<T>>> = self.nodes.iter().map(|_| Vec::new()).collect();
        for source in self.sources {
            for (slot, ring) in per_node.iter_mut().zip(source.rings) {
                slot.push((
                    ring,
                    Arc::clone(&source.decode),
                    Arc::clone(&source.dropped),
                ));
            }
        }

        for (node, rings) in self.nodes.into_iter().zip(per_node) {
            if rings.is_empty() {
                continue;
            }
            let stop = stop.clone();
            let sender = self.sender.clone();
            let id = node.id;
            let thread = std::thread::Builder::new()
                .name(format!("drain-node{id}"))
                .spawn(move || drain_node(id, &node.cpus, rings, sender, &stop))?;
            threads.push(thread);
        }

        Ok(Drainers { stop, threads })
    }
}

/// Handle to the spawned per-node draining threads; [`shutdown`](Self::shutdown)
/// stops and joins them.
pub struct Drainers {
    stop: CancellationToken,
    threads: Vec<JoinHandle<()>>,
}

impl Drainers {
    /// Signal the draining threads to stop and join them. Any channel senders
    /// captured by the feature callbacks drop as the threads exit, closing the
    /// features' record channels so their record tasks end too.
    pub fn shutdown(self) {
        self.stop.cancel();
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Create a ring buffer placed on NUMA node `node`, matching the inner-map
/// prototype's type/size/flags so the kernel accepts it into the outer array.
fn create_node_ringbuf(name: &str, node: u32) -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as _,
        map_flags: BPF_F_NUMA_NODE,
        numa_node: node,
        ..Default::default()
    };
    // Ring buffers carry no key/value; max_entries is the byte size.
    Ok(MapHandle::create(
        MapType::RingBuf,
        Some(name),
        0,
        0,
        RINGBUF_SIZE,
        &opts,
    )?)
}

/// Insert `ring` into the `ARRAY_OF_MAPS` `outer` at index `node`. The value of
/// a map-of-maps slot is the inner map's fd.
fn insert_ring(outer: &impl MapCore, node: u32, ring: &MapHandle) -> Result<()> {
    outer.update(
        &node.to_ne_bytes(),
        &ring.as_fd().as_raw_fd().to_ne_bytes(),
        MapFlags::ANY,
    )?;
    Ok(())
}

/// Body of a per-node draining thread: pin to the node's CPUs, then poll the
/// node's rings, decoding each feature's records into a per-source batch buffer
/// and flushing the batches down `sender`, until signalled to stop. Owns the
/// ring handles for its lifetime (the kernel keeps the rings alive via the outer
/// arrays regardless).
fn drain_node<T: 'static>(
    id: u32,
    cpus: &[usize],
    rings: Vec<NodeSource<T>>,
    sender: Sender<T>,
    stop: &CancellationToken,
) {
    pin_to_cpus(id, cpus);

    // One batch buffer per source, shared (single-threaded `Rc`) between the ring
    // callback that fills it during `consume_raw` and the flush that empties it
    // right after. Pre-sized so a full ring's worth of events never reallocates.
    let mut builder = RingBufferBuilder::new();
    let mut flushers = Vec::with_capacity(rings.len());
    for (ring, decode, dropped) in &rings {
        let buffer = Rc::new(Batch::with_capacity(BATCH_CAP));
        let decode = Arc::clone(decode);
        let cb_buffer = Rc::clone(&buffer);
        if let Err(e) = builder.add(ring, move |data: &[u8]| {
            if let Some(item) = decode(data) {
                // Safety: called only here, sequentially within `consume_raw`,
                // never overlapping this buffer's flush (which runs after).
                unsafe { cb_buffer.push(item) };
            }
            0
        }) {
            error!("node {id}: failed to register ring buffer: {e}");
            return;
        }
        flushers.push(Flusher {
            buffer,
            dropped: Arc::clone(dropped),
        });
    }
    let ring_buffer = match builder.build() {
        Ok(rb) => rb,
        Err(e) => {
            error!("node {id}: failed to build ring buffer: {e}");
            return;
        }
    };

    drain_loop(&ring_buffer, &sender, &flushers, stop);
}

/// Drain `ring_buffer` on a fixed poll interval until `stop` is cancelled.
/// `consume_raw` is a memory-only read (no syscall) that drains every event that
/// has accumulated since the last sweep into the sources' batch buffers, which
/// are then flushed down `sender` (one alloc-free `try_send` per event); sleeping [`POLL_INTERVAL`]
/// between sweeps lets a whole batch build up rather than waking per event.
/// `stop` is checked once per interval, so shutdown lands within one interval.
fn drain_loop<T>(
    ring_buffer: &RingBuffer<'_>,
    sender: &Sender<T>,
    flushers: &[Flusher<T>],
    stop: &CancellationToken,
) {
    while !stop.is_cancelled() {
        // `consume_raw` has returned before we flush, so every ring callback has
        // finished and released its buffer borrow: safe to touch the batches.
        if ring_buffer.consume_raw() > 0 {
            for flusher in flushers {
                flusher.flush(sender);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Pin the calling thread to `cpus` via `sched_setaffinity`, so it drains a ring
/// from the node that produced it. A no-op (logged) on failure or empty list.
fn pin_to_cpus(node: u32, cpus: &[usize]) {
    if cpus.is_empty() {
        return;
    }
    // Safety: cpu_set_t is a plain bitmask; we zero it, set in-range bits, and
    // pass its size to sched_setaffinity for the current thread (pid 0).
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) != 0 {
            warn!(
                "node {node}: failed to pin draining thread: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Enumerate the machine's NUMA nodes and their CPUs from
/// `/sys/devices/system/node`. Falls back to a single node 0 spanning every CPU
/// when NUMA isn't exposed (matching `bpf_get_numa_node_id()` returning 0).
fn numa_nodes() -> Vec<NumaNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_prefix("node"))
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let cpus = read_cpulist(&entry.path().join("cpulist")).unwrap_or_default();
            nodes.push(NumaNode { id, cpus });
        }
    }
    if nodes.is_empty() {
        let nproc = std::thread::available_parallelism().map_or(1, |n| n.get());
        nodes.push(NumaNode {
            id: 0,
            cpus: (0..nproc).collect(),
        });
    }
    nodes.sort_by_key(|n| n.id);
    nodes
}

fn read_cpulist(path: &Path) -> Option<Vec<usize>> {
    Some(parse_cpulist(&std::fs::read_to_string(path).ok()?))
}

/// Parse a Linux cpulist (e.g. `"0-3,8,12-15"`) into the explicit CPU ids.
fn parse_cpulist(s: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                    cpus.extend(a..=b);
                }
            }
            None => {
                if let Ok(n) = part.parse::<usize>() {
                    cpus.push(n);
                }
            }
        }
    }
    cpus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpulist_ranges_and_singletons() {
        assert_eq!(
            parse_cpulist("0-3,8,12-15\n"),
            vec![0, 1, 2, 3, 8, 12, 13, 14, 15]
        );
        assert_eq!(parse_cpulist("5"), vec![5]);
        assert_eq!(parse_cpulist(""), Vec::<usize>::new());
        assert_eq!(parse_cpulist("\n"), Vec::<usize>::new());
    }
}
