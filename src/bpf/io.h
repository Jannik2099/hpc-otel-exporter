#pragma once

#include "vfs_types.h"

// Types shared between the IO-tracing BPF program (src/bpf/io.bpf.c) and the
// userspace IO metrics (src/metrics/io.rs, via bindgen -> crate::bindings).
// The cross-feature FsMagic / TimeInfo types live in vfs_types.h.

struct IOEvent {
    struct TimeInfo time_info;
    enum FsMagic fs_magic;
    uint64_t inode;
    uint64_t cgroup_id;
    // MSB stores READ = 0, WRITE = 1
    // linux caps at 2 GiB, so we get a free bit
    uint32_t num_bytes_transferred;
    int32_t mount_id;
    uint32_t pid;
    uint32_t tgid;
};

// Ring buffer entries have a 8 byte header followed by payload,
// thus ensure 56 byte size so that each event fills a cacheline
// If we need more space in the future, there's a few things we can drop:
// - pid can be reconstructed from tgid
// - cgroup_id can be reconstructed from pid
// - FsMagic could be compressed to one byte (realistically even less),
//     discarding unknown magic values
// - In case of dire need, we can omit some bits from the timestamps
//     56 bits for 2 years uptime start_time, 36 bits for ~68 seconds duration
//     even less if we approximate start_time in microseconds ( / 1024 )
_Static_assert(sizeof(struct IOEvent) == 56);
