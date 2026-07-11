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
//! The draining thread does only the NUMA-local work (`ring_buffer__poll` +
//! the feature's decode callback, which typically forwards down a bounded
//! channel); anything slow (e.g. `/proc` resolution) belongs on the feature's
//! own task consuming that channel. Keeping the thread pinned to the producing
//! node is the whole point — it ensures the ring's reserve/commit atomics and
//! backing pages stay node-local.
//!
//! [`register`]: DrainerBuilder::register

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, RingBuffer, RingBufferBuilder};
use log::{error, info, warn};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

/// Byte size of each per-node ring buffer. MUST stay in sync with
/// `NUMA_RINGBUF_SIZE` in `src/bpf/numa_ringbuf.bpf.h`: the inner-map prototype
/// is created at that size and the kernel's map-in-map compatibility check
/// requires every inserted ring to match the prototype's metadata exactly.
const RINGBUF_SIZE: u32 = 1 << 18; // 256KiB

/// `BPF_F_NUMA_NODE` (uapi/linux/bpf.h): place the ring's pages on a specific
/// NUMA node. Also the only flag `BPF_MAP_TYPE_RINGBUF` permits, so the per-node
/// rings carry exactly this flag to match the prototype's `map_flags`.
const BPF_F_NUMA_NODE: u32 = 1 << 2;

/// A feature's decode callback, run on the draining thread for every raw ring
/// payload. Shared behind an `Arc` because the same callback drains every
/// node's ring for that feature. Must stay cheap and non-blocking (decode +
/// `try_send`); drop-on-full is the callback's business, matching the
/// drop-on-full behaviour the kernel ring buffer already has.
pub type RingCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Decode a POD event `T` from a raw ring payload, or `None` when the payload
/// is too short. Reads unaligned: ring slices carry no alignment guarantee.
pub fn decode_event<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < size_of::<T>() {
        return None;
    }
    // Safety: length checked above, and the BPF side only ever submits a `T`
    // into the ring this callback was registered for.
    Some(unsafe { (data.as_ptr() as *const T).read_unaligned() })
}

/// A NUMA node and the CPUs that belong to it.
struct NumaNode {
    id: u32,
    cpus: Vec<usize>,
}

/// One registered feature: its per-node rings (index-aligned with the builder's
/// node list) and the callback that decodes its payloads.
struct Source {
    rings: Vec<MapHandle>,
    cb: RingCallback,
}

/// Builder collecting every feature's per-node rings before the draining
/// threads start. Features [`register`](Self::register) while wiring up (after
/// their maps are loaded, before their programs attach); [`start`](Self::start)
/// then spawns one pinned draining thread per node covering all of them.
pub struct DrainerBuilder {
    nodes: Vec<NumaNode>,
    sources: Vec<Source>,
}

impl DrainerBuilder {
    /// Enumerate the machine's NUMA topology; no rings exist yet.
    pub fn new() -> Self {
        let nodes = numa_nodes();
        info!(
            "draining {} NUMA node ring buffer(s) ({} total)",
            nodes.len(),
            nodes.iter().map(|n| n.id).max().map_or(0, |m| m + 1)
        );
        Self {
            nodes,
            sources: Vec::new(),
        }
    }

    /// Create one NUMA-placed ring buffer per online node for a feature, insert
    /// each into the feature's outer `ARRAY_OF_MAPS`, and record `cb` as the
    /// decode callback for those rings. `name` names the inner rings (visible in
    /// `bpftool map list`).
    ///
    /// Must be called **before** the feature's eBPF programs are attached, so
    /// events always find a populated ring for their node.
    pub fn register(&mut self, name: &str, outer: &impl MapCore, cb: RingCallback) -> Result<()> {
        let mut rings = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            // The rings' pages are placed on the node so its CPUs reserve locally.
            let ring = create_node_ringbuf(name, node.id)?;
            insert_ring(outer, node.id, &ring)?;
            rings.push(ring);
        }
        self.sources.push(Source { rings, cb });
        Ok(())
    }

    /// Spawn one pinned draining thread per node, each polling every registered
    /// feature's ring for that node. With nothing registered (no event-driven
    /// feature enabled) no threads are spawned.
    pub fn start(self) -> Result<Drainers> {
        let stop = CancellationToken::new();
        let mut threads = Vec::with_capacity(self.nodes.len());

        // Regroup the per-source ring columns into one row per node.
        let mut per_node: Vec<Vec<(MapHandle, RingCallback)>> =
            self.nodes.iter().map(|_| Vec::new()).collect();
        for source in self.sources {
            for (slot, ring) in per_node.iter_mut().zip(source.rings) {
                slot.push((ring, Arc::clone(&source.cb)));
            }
        }

        for (node, rings) in self.nodes.into_iter().zip(per_node) {
            if rings.is_empty() {
                continue;
            }
            let stop = stop.clone();
            let id = node.id;
            let thread = std::thread::Builder::new()
                .name(format!("drain-node{id}"))
                .spawn(move || drain_node(id, &node.cpus, rings, &stop))?;
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
/// node's rings, running each feature's decode callback, until signalled to
/// stop. Owns the ring handles for its lifetime (the kernel keeps the rings
/// alive via the outer arrays regardless).
fn drain_node(
    id: u32,
    cpus: &[usize],
    rings: Vec<(MapHandle, RingCallback)>,
    stop: &CancellationToken,
) {
    pin_to_cpus(id, cpus);

    let mut builder = RingBufferBuilder::new();
    for (ring, cb) in &rings {
        let cb = Arc::clone(cb);
        if let Err(e) = builder.add(ring, move |data: &[u8]| {
            cb(data);
            0
        }) {
            error!("node {id}: failed to register ring buffer: {e}");
            return;
        }
    }
    let ring_buffer = match builder.build() {
        Ok(rb) => rb,
        Err(e) => {
            error!("node {id}: failed to build ring buffer: {e}");
            return;
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("node {id}: failed to build tokio runtime: {e}");
            return;
        }
    };
    runtime.block_on(drain_loop(id, &ring_buffer, stop));
}

/// Drain `ring_buffer` on the current-thread runtime: sleep in epoll on the
/// ring's fd, and greedily `consume` whenever it becomes readable, until `stop`
/// is cancelled. `consume` drains every pending event (the fd is edge-triggered,
/// so a partial drain would leave events unwoken), then `clear_ready` re-arms
/// the wait for the next batch.
async fn drain_loop(id: u32, ring_buffer: &RingBuffer<'_>, stop: &CancellationToken) {
    let epoll_fd = ring_buffer.epoll_fd();
    let async_fd = match AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(epoll_fd) },
        Interest::READABLE,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            error!("node {id}: failed to register ring buffer epoll fd: {e}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = async_fd.async_io(Interest::READABLE, |_| {
                let consumed = ring_buffer.consume_raw();
                match consumed {
                    n if n > 0 => Ok(n),
                    0 => Err(std::io::ErrorKind::WouldBlock.into()),
                    n => Err(std::io::Error::from_raw_os_error(-n)),
                }
            }) => {}
        };
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
