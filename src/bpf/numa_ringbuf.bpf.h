#pragma once

// Per-NUMA-node event ring buffers.
//
// A single global BPF_MAP_TYPE_RINGBUF serializes every CPU's
// bpf_ringbuf_reserve on one spinlock; on a multi-socket box that lock and its
// cache line bounce across the inter-node interconnect, so every NUMA domain
// fights over it. Instead each feature keeps an ARRAY_OF_MAPS keyed by NUMA
// node id (bpf_get_numa_node_id()) whose values are one ring buffer per node,
// so the reserve spinlock is sharded per node and stays node-local. Userspace
// creates the real inner rings (NUMA-placed) and inserts them before the
// programs attach, then drains each node's ring from a thread pinned to that
// node (see src/numa.rs).

#include <vmlinux.h>
//
#include <bpf/bpf_helpers.h>

// Byte size of each per-node ring buffer. MUST stay in sync with
// `RINGBUF_SIZE` in src/numa.rs: the inner-map prototype below is created at
// this size and the kernel's map-in-map compatibility check requires every
// inserted ring to match the prototype's metadata exactly.
#define NUMA_RINGBUF_SIZE (1 << 16) // 64 KiB

// Ceiling on the NUMA node id used as the ARRAY_OF_MAPS key. Real hardware has
// far fewer nodes; userspace only populates the slots for online nodes. An out
// of range / unpopulated key falls back to node 0 (see numa_ringbuf_reserve).
#define MAX_NUMA_NODES 256

// Inner-map prototype: supplies the inner ring's type/size/flags so the outer
// ARRAY_OF_MAPS can validate the rings userspace inserts. libbpf creates one
// real ring from this template (NUMA node 0); it is never written to. The
// BPF_F_NUMA_NODE flag must be present so its map_flags match the per-node
// rings userspace creates with BPF_F_NUMA_NODE | numa_node=<n>.
struct numa_ringbuf_inner {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, NUMA_RINGBUF_SIZE);
    __uint(map_flags, BPF_F_NUMA_NODE);
} numa_ringbuf_inner SEC(".maps");

// Declares a per-NUMA-node ring buffer array named NAME.
#define DEFINE_NUMA_RINGBUF(NAME)                                              \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);                              \
        __uint(max_entries, MAX_NUMA_NODES);                                   \
        __type(key, u32);                                                      \
        __array(values, struct numa_ringbuf_inner);                            \
    } NAME SEC(".maps")

// Reserve `size` bytes in the calling CPU's local NUMA node ring of `outer`
// (an ARRAY_OF_MAPS declared with DEFINE_NUMA_RINGBUF). Returns NULL if no ring
// is mapped for this node, in which case the caller drops the event. The
// reserved sample is submitted/discarded with the usual bpf_ringbuf_submit /
// bpf_ringbuf_discard, which locate their ring from the sample itself.
static __always_inline void *numa_ringbuf_reserve(void *outer, u64 size) {
    const u32 node = bpf_get_numa_node_id();
    void *rb = bpf_map_lookup_elem(outer, &node);
    if (rb == NULL) {
        // Out of range or not populated (should not happen: userspace
        // populates every online node, and the helper only returns online
        // nodes). Fall back to node 0, which is always populated.
        u32 zero = 0;
        rb = bpf_map_lookup_elem(outer, &zero);
        if (rb == NULL) {
            return NULL;
        }
    }
    return bpf_ringbuf_reserve(rb, size, 0);
}
