//! Per-NUMA-node ring buffer draining.
//!
//! The IO and metadata eBPF programs no longer write into a single global ring
//! buffer; each writes into the ring buffer for the CPU's local NUMA node (an
//! `ARRAY_OF_MAPS` keyed by `bpf_get_numa_node_id()`, see
//! `src/bpf/numa_ringbuf.bpf.h`). A single global ring made every NUMA domain
//! fight over one reserve spinlock + its cache line across the inter-node
//! interconnect; sharding the ring per node keeps that lock node-local.
//!
//! This module:
//!  1. enumerates the machine's NUMA nodes and their CPUs,
//!  2. creates one NUMA-placed ring buffer per node per feature and inserts it
//!     into the feature's outer array — done **before** the programs attach so
//!     the very first event finds a ring for its node, and
//!  3. spawns one OS thread per node, pinned to that node's CPUs, that drains
//!     the node's IO + metadata rings and forwards decoded events down a
//!     bounded channel to the async record loop in [`crate::app`].
//!
//! The draining thread does only the NUMA-local work (`ring_buffer__poll` +
//! decode); the actual `record()` (which needs the tokio runtime for its slow
//! `/proc` resolution path) runs on a tokio task draining the channel. Keeping
//! the thread pinned to the producing node is the whole point — it ensures the
//! ring's reserve/commit atomics and backing pages stay node-local.

use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, RingBufferBuilder};
use log::{error, info, warn};
use tokio::sync::mpsc;

use crate::bindings::{IOEvent, MetadataEvent};

/// Byte size of each per-node ring buffer. MUST stay in sync with
/// `NUMA_RINGBUF_SIZE` in `src/bpf/numa_ringbuf.bpf.h`: the inner-map prototype
/// is created at that size and the kernel's map-in-map compatibility check
/// requires every inserted ring to match the prototype's metadata exactly.
const RINGBUF_SIZE: u32 = 1 << 22; // 4 MiB

/// `BPF_F_NUMA_NODE` (uapi/linux/bpf.h): place the ring's pages on a specific
/// NUMA node. Also the only flag `BPF_MAP_TYPE_RINGBUF` permits, so the per-node
/// rings carry exactly this flag to match the prototype's `map_flags`.
const BPF_F_NUMA_NODE: u32 = 1 << 2;

/// Bound on the channel buffering decoded events between the per-node draining
/// threads and the async record task. On overflow events are dropped (and
/// counted) rather than blocking the draining thread — the same drop-on-full
/// behaviour the kernel ring buffer already has.
const CHANNEL_CAPACITY: usize = 1 << 16;

/// How long each draining thread blocks in `poll` before re-checking the stop
/// flag. Only affects shutdown latency; events wake the poll immediately.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// A decoded event forwarded from a draining thread to the async record task.
pub enum RawEvent {
    Io(IOEvent),
    Meta(MetadataEvent),
}

/// A NUMA node and the CPUs that belong to it.
struct NumaNode {
    id: u32,
    cpus: Vec<usize>,
}

/// Handle to the spawned per-node draining threads; [`shutdown`](Self::shutdown)
/// stops and joins them.
pub struct Drainers {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Drainers {
    /// Signal the draining threads to stop and join them. Their channel senders
    /// drop as they exit, closing the channel so the record task ends too.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Create one NUMA-placed ring buffer per online node for both features, insert
/// each into the matching outer `ARRAY_OF_MAPS`, and spawn a pinned draining
/// thread per node. Returns the receiving end of the event channel plus a
/// [`Drainers`] handle for shutdown.
///
/// Must be called **before** the eBPF programs are attached, so events always
/// find a populated ring for their node.
pub fn setup(
    io_outer: &impl MapCore,
    meta_outer: &impl MapCore,
    dropped: Arc<AtomicU64>,
) -> Result<(mpsc::Receiver<RawEvent>, Drainers)> {
    let nodes = numa_nodes();
    info!(
        "draining {} NUMA node ring buffer(s) ({} total)",
        nodes.len(),
        nodes.iter().map(|n| n.id).max().map_or(0, |m| m + 1)
    );

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(nodes.len());

    for node in nodes {
        // Create and insert this node's rings while the outer maps are in hand;
        // the rings' pages are placed on the node so its CPUs reserve locally.
        let io_ring = create_node_ringbuf("io_events_node", node.id)?;
        let meta_ring = create_node_ringbuf("meta_events_node", node.id)?;
        insert_ring(io_outer, node.id, &io_ring)?;
        insert_ring(meta_outer, node.id, &meta_ring)?;

        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let dropped = Arc::clone(&dropped);
        let cpus = node.cpus;
        let id = node.id;
        let thread = std::thread::Builder::new()
            .name(format!("drain-node{id}"))
            .spawn(move || drain_node(id, &cpus, io_ring, meta_ring, tx, &stop, &dropped))?;
        threads.push(thread);
    }

    Ok((rx, Drainers { stop, threads }))
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
/// node's two rings forwarding decoded events until signalled to stop. Owns the
/// ring handles for its lifetime (the kernel keeps the rings alive via the outer
/// array regardless).
fn drain_node(
    id: u32,
    cpus: &[usize],
    io_ring: MapHandle,
    meta_ring: MapHandle,
    tx: mpsc::Sender<RawEvent>,
    stop: &AtomicBool,
    dropped: &AtomicU64,
) {
    pin_to_cpus(id, cpus);

    let mut builder = RingBufferBuilder::new();
    let io_cb = {
        let tx = tx.clone();
        move |data: &[u8]| {
            if data.len() >= size_of::<IOEvent>() {
                // Safety: the BPF program wrote an IOEvent here; the length
                // check guards the read and we read unaligned (the slice has no
                // alignment guarantee).
                let event = unsafe { (data.as_ptr() as *const IOEvent).read_unaligned() };
                if tx.try_send(RawEvent::Io(event)).is_err() {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            0
        }
    };
    let meta_cb = move |data: &[u8]| {
        if data.len() >= size_of::<MetadataEvent>() {
            // Safety: as above, for a MetadataEvent.
            let event = unsafe { (data.as_ptr() as *const MetadataEvent).read_unaligned() };
            if tx.try_send(RawEvent::Meta(event)).is_err() {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        0
    };

    if let Err(e) = builder
        .add(&io_ring, io_cb)
        .and_then(|b| b.add(&meta_ring, meta_cb))
    {
        error!("node {id}: failed to register ring buffers: {e}");
        return;
    }
    let ring_buffer = match builder.build() {
        Ok(rb) => rb,
        Err(e) => {
            error!("node {id}: failed to build ring buffer: {e}");
            return;
        }
    };

    while !stop.load(Ordering::Relaxed) {
        // Negative return is an error (e.g. EINTR); keep polling. A closed
        // channel is handled by try_send above, not here.
        let _ = ring_buffer.poll_raw(POLL_TIMEOUT);
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
