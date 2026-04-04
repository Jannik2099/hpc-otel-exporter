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

static enum FsMagic get_fs_magic(const struct file *file) { return file->f_path.mnt->mnt_sb->s_magic; }

static s32 file_to_mount_id(const struct file *file) {
    const struct vfsmount *vfsmount = file->f_path.mnt;

    const ptrdiff_t offset_mnt = bpf_core_field_offset(struct mount, mnt);
    const struct mount *mnt = (void *)vfsmount - offset_mnt;

    // this still requires a CO_RE call because the mnt pointer is "laundered"
    return BPF_CORE_READ(mnt, mnt_id);
}

SEC("fentry/vfs_read")
int BPF_PROG(bpf_fentry_test, const struct file *file) {
    const enum FsMagic magic = get_fs_magic(file);
    // Skip ephemeral filesystems
    if (is_ephemeral_fs_cheap(magic)) {
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    u64 *start_time = bpf_task_storage_get(&TASK_STORAGE, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (start_time == NULL) {
        return 0;
    }
    *start_time = bpf_ktime_get_ns();

    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(bpf_fexit_test, const struct file *file, char *, const u64 count, loff_t *, const s64 ret) {
    const u64 end_time = bpf_ktime_get_ns();

    if (ret <= 0) {
        // No bytes transferred, skip
        return 0;
    }

    const enum FsMagic magic = get_fs_magic(file);
    if (is_ephemeral_fs_cheap(magic)) {
        return 0;
    }

    struct IOEvent *const event = bpf_ringbuf_reserve(&EVENTS, sizeof(struct IOEvent), 0);
    if (event == NULL) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    struct task_struct *task = bpf_get_current_task_btf();
    u64 *start_time = bpf_task_storage_get(&TASK_STORAGE, task, NULL, 0);

    u64 start_time_ns = 0;
    if (start_time != NULL) {
        start_time_ns = *start_time;
        *start_time = 0;
    }

    event->time_info.start_time = start_time_ns;
    event->time_info.end_time = end_time;
    event->fs_magic = magic;
    event->inode = file->f_inode->i_ino;
    event->num_bytes_requested = count;
    event->num_bytes_transferred = ((u32)ret) & 0b01111111111111111111111111111111;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->mount_id = file_to_mount_id(file);
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;

    bpf_ringbuf_submit(event, 0);

    return 0;
}
