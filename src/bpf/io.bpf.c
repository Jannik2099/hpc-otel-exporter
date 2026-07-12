// IO tracing: records the size and duration of synchronous vfs_read/vfs_write,
// grouped by cgroup, into the EVENTS ring buffer.
//
// A standalone BPF object (one per signal): loaded, verified and its maps
// created only when the io_requests signal is enabled.

#include "io.h"

#include "cgroup_id.bpf.h"
#include "numa_ringbuf.bpf.h"
#include "vfs_common.bpf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct IOStarts {
    u64 read;
    u64 write;
};

// Per-task start timestamp of the in-flight read/write, stashed at entry and
// consumed at exit to compute the operation's duration.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct IOStarts);
} TASK_STORAGE SEC(".maps");

// Completed IO operations (struct IOEvent), drained by userspace IO metrics.
// One ring buffer per NUMA node (see numa_ringbuf.bpf.h); the recording CPU
// reserves in its local node's ring.
DEFINE_NUMA_RINGBUF(IO_EVENTS);

static __always_inline s32 file_to_mount_id(const struct file *file) {
    const struct vfsmount *vfsmount = file->f_path.mnt;

    const ptrdiff_t offset_mnt = bpf_core_field_offset(struct mount, mnt);
    const struct mount *mnt = (void *)vfsmount - offset_mnt;

    // this still requires a CO_RE call because the mnt pointer is "laundered"
    return BPF_CORE_READ(mnt, mnt_id);
}

static __always_inline void record_start(const struct file *file,
                                         bool is_write) {
    const enum FsMagic magic = file_fs_magic(file);
    // Skip ephemeral filesystems
    if (is_ephemeral_fs_cheap(magic)) {
        return;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    struct IOStarts *start_times = bpf_task_storage_get(
        &TASK_STORAGE, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (start_times == NULL) {
        return;
    }
    u64 *start_time = is_write ? &start_times->write : &start_times->read;
    // set-if-zero: under same-op re-entrancy the outermost call wins.
    if (*start_time == 0) {
        *start_time = bpf_ktime_get_ns();
    }
}

static __always_inline void record_end(const struct file *file, const s64 bytes,
                                       const bool is_write) {
    const u64 end_time = bpf_ktime_get_ns();

    struct task_struct *task = bpf_get_current_task_btf();
    struct IOStarts *start_times =
        bpf_task_storage_get(&TASK_STORAGE, task, NULL, 0);

    // Always consume + clear the slot, even if we drop this event below, so a
    // filtered exit (bytes <= 0, ephemeral fs) can't orphan the timestamp. The
    // set-if-zero in record_start would otherwise refuse to refresh the stale
    // value, making the next successful op compute a bogus duration from an
    // ancient start time.
    u64 start_time_ns = 0;
    if (start_times != NULL) {
        if (is_write) {
            start_time_ns = start_times->write;
            start_times->write = 0;
        } else {
            start_time_ns = start_times->read;
            start_times->read = 0;
        }
    }
    // No matching start: entry was filtered (ephemeral fs) or already consumed
    // by an inner re-entry. Either way, don't emit a bogus duration.
    if (start_time_ns == 0) {
        return;
    }

    if (bytes <= 0) {
        // No bytes transferred, skip
        return;
    }

    const enum FsMagic magic = file_fs_magic(file);
    if (is_ephemeral_fs_cheap(magic)) {
        return;
    }

    struct IOEvent *const event =
        numa_ringbuf_reserve(&IO_EVENTS, sizeof(struct IOEvent));
    if (event == NULL) {
        return;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    const u32 MSB = 0b10000000000000000000000000000000;
    u32 num_bytes_transferred = (u32)bytes;
    if (is_write) {
        num_bytes_transferred |= MSB;
    } else {
        num_bytes_transferred &= ~MSB;
    }

    event->time_info.start_time = start_time_ns;
    event->time_info.end_time = end_time;
    event->fs_magic = magic;
    event->inode = file->f_inode->i_ino;
    event->cgroup_id = current_cgroup_id();
    event->num_bytes_transferred = num_bytes_transferred;
    event->mount_id = file_to_mount_id(file);
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;

    // NO_WAKEUP: userspace drains the ring on a timer (see src/numa.rs)
    bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);

    return;
}

SEC("fentry/vfs_read")
int BPF_PROG(record_vfs_read_entry, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/) {
    record_start(file, false);
    return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(record_vfs_write_entry, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/) {
    record_start(file, true);
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(record_vfs_read_exit, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/, const s64 ret) {
    record_end(file, ret, false);
    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(record_vfs_write_exit, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/, const s64 ret) {
    record_end(file, ret, true);
    return 0;
}
