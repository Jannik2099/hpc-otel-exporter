#include "common_bpf.h"
#include "common_shared.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u64);
} TASK_STORAGE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} EVENTS SEC(".maps");

static __always_inline enum FsMagic get_fs_magic(const struct file *file) {
    return file->f_path.mnt->mnt_sb->s_magic;
}

static __always_inline s32 file_to_mount_id(const struct file *file) {
    const struct vfsmount *vfsmount = file->f_path.mnt;

    const ptrdiff_t offset_mnt = bpf_core_field_offset(struct mount, mnt);
    const struct mount *mnt = (void *)vfsmount - offset_mnt;

    // this still requires a CO_RE call because the mnt pointer is "laundered"
    return BPF_CORE_READ(mnt, mnt_id);
}

static __always_inline void record_start(const struct file *file) {
    const enum FsMagic magic = get_fs_magic(file);
    // Skip ephemeral filesystems
    if (is_ephemeral_fs_cheap(magic)) {
        return;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    u64 *start_time = bpf_task_storage_get(&TASK_STORAGE, task, NULL,
                                           BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (start_time == NULL) {
        return;
    }
    *start_time = bpf_ktime_get_ns();
}

static __always_inline void record_end(const struct file *file, const s64 ret,
                                       const bool is_write) {
    const u64 end_time = bpf_ktime_get_ns();

    if (ret <= 0) {
        // No bytes transferred, skip
        return;
    }

    const enum FsMagic magic = get_fs_magic(file);
    if (is_ephemeral_fs_cheap(magic)) {
        return;
    }

    struct IOEvent *const event =
        bpf_ringbuf_reserve(&EVENTS, sizeof(struct IOEvent), 0);
    if (event == NULL) {
        return;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    struct task_struct *task = bpf_get_current_task_btf();
    u64 *start_time = bpf_task_storage_get(&TASK_STORAGE, task, NULL, 0);

    u64 start_time_ns = 0;
    if (start_time != NULL) {
        start_time_ns = *start_time;
        *start_time = 0;
    }

    const u32 MSB = 0b10000000000000000000000000000000;
    u32 num_bytes_transferred = (u32)ret;
    if (is_write) {
        num_bytes_transferred |= MSB;
    } else {
        num_bytes_transferred &= ~MSB;
    }

    event->time_info.start_time = start_time_ns;
    event->time_info.end_time = end_time;
    event->fs_magic = magic;
    event->inode = file->f_inode->i_ino;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->num_bytes_transferred = num_bytes_transferred;
    event->mount_id = file_to_mount_id(file);
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;

    bpf_ringbuf_submit(event, 0);

    return;
}

SEC("fentry/vfs_read")
int BPF_PROG(record_vfs_read_entry, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/) {
    record_start(file);
    return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(record_vfs_write_entry, const struct file *file, char * /*buf*/,
             const u64 /*count*/, loff_t * /*pos*/) {
    record_start(file);
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
