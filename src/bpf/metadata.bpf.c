// VFS metadata tracing: records the duration of the namespace/attribute VFS
// operations (open, close, create, stat, ...), grouped by cgroup, into the
// METADATA_EVENTS ring buffer. Unlike io.bpf.c these entry points are mostly
// inode/dentry-based and carry no byte count or mount id; see metadata.h.
//
// Kernel portability: these VFS helpers' argument lists differ across versions.
// Older kernels carry an extra `struct inode *dir` and lack the trailing
// delegated-inode arg, and vfs_mkdir even changed its return type. We stay
// CO-RE-portable by:
//   1. reading only the leading argument *prefix* up to the dentry at fentry,
//      so trailing-argument differences never matter there;
//   2. capturing fs_magic + the start timestamp at fentry, so fexit needs no
//      input arguments; and
//   3. reading the return value at fexit via bpf_get_func_ret(), which is
//      argument-signature- and return-type-agnostic, so the argument-count /
//      return-type changes never matter at exit either.
// The one position that still has to be resolved is vfs_create's dentry, whose
// *argument slot* moved (the parent dir inode used to precede it); we pick it
// at load time with a CO-RE field probe (see vfs_layout_is_modern), so libbpf
// prunes the wrong branch before verification.

#include "metadata.h"

#include "cgroup_id.bpf.h"
#include "numa_ringbuf.bpf.h"
#include "vfs_common.bpf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// A return value in [-MAX_ERRNO, -1], reinterpreted as an unsigned long, marks
// an error (the kernel's IS_ERR_VALUE). Holds across int, ssize_t and
// ERR_PTR/pointer-returning helpers (e.g. vfs_mkdir returns struct dentry *).
#define META_MAX_ERRNO 4095

// Detects the modern VFS argument layout (the parent dir inode dropped in
// favour of the parent dentry). We can't CO-RE-probe a function prototype, so
// we key off the matching `struct renamedata` change (`old_dir` ->
// `old_parent`) from the same VFS conversion.
struct renamedata___new {
    struct dentry *old_parent;
} __attribute__((preserve_access_index));

static __always_inline bool vfs_layout_is_modern(void) {
    return bpf_core_field_exists(struct renamedata___new, old_parent);
}

// Per-op in-flight state: the start timestamp plus the filesystem magic
// captured at fentry, so the matching fexit program needs no input arguments.
// One slot per op so a nested re-entry of the SAME op (e.g. overlayfs vfs_mkdir
// -> vfs_mkdir on the upper layer) collapses to a single event for the
// outermost call rather than corrupting its duration.
struct MetaSlot {
    u64 start;
    enum FsMagic magic;
};

struct MetaStarts {
    struct MetaSlot slots[METADATA_OP_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct MetaStarts);
} META_STORAGE SEC(".maps");

// Completed VFS metadata operations (struct MetadataEvent), drained by
// userspace metadata metrics. One ring buffer per NUMA node (see
// numa_ringbuf.bpf.h); the recording CPU reserves in its local node's ring.
DEFINE_NUMA_RINGBUF(METADATA_EVENTS);

static __always_inline void meta_start(const enum MetadataOp op,
                                       const struct dentry *dentry) {
    if (op >= METADATA_OP_MAX) {
        return;
    }
    const enum FsMagic magic = dentry_fs_magic(dentry);
    // Skip ephemeral filesystems (proc/sys/pipes/...).
    if (is_ephemeral_fs_cheap(magic)) {
        return;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    struct MetaStarts *starts = bpf_task_storage_get(
        &META_STORAGE, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (starts == NULL) {
        return;
    }
    // set-if-zero: under same-op re-entrancy the outermost call wins.
    if (starts->slots[op].start == 0) {
        starts->slots[op].start = bpf_ktime_get_ns();
        starts->slots[op].magic = magic;
    }
}

// Called from every fexit. The return value comes from bpf_get_func_ret(),
// which works regardless of the traced function's signature.
static __always_inline void meta_end(const enum MetadataOp op, void *ctx) {
    const u64 end_time = bpf_ktime_get_ns();
    if (op >= METADATA_OP_MAX) {
        return;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    struct MetaStarts *starts =
        bpf_task_storage_get(&META_STORAGE, task, NULL, 0);
    if (starts == NULL) {
        return;
    }
    const u64 start_time = starts->slots[op].start;
    const enum FsMagic magic = starts->slots[op].magic;
    starts->slots[op].start = 0;
    // No matching start: entry was filtered (ephemeral fs) or already consumed
    // by an inner re-entry. Either way, don't emit a bogus duration.
    if (start_time == 0) {
        return;
    }

    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);

    struct MetadataEvent *const event =
        numa_ringbuf_reserve(&METADATA_EVENTS, sizeof(struct MetadataEvent));
    if (event == NULL) {
        return;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    event->time_info.start_time = start_time;
    event->time_info.end_time = end_time;
    event->fs_magic = magic;
    event->cgroup_id = current_cgroup_id();
    event->op = op;
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
    event->error = (unsigned long)ret >= (unsigned long)-META_MAX_ERRNO ? 1 : 0;
    event->_pad[0] = 0;
    event->_pad[1] = 0;
    event->_pad[2] = 0;

    bpf_ringbuf_submit(event, 0);
}

// open: vfs_open(const struct path *path, struct file *file).
SEC("fentry/vfs_open")
int BPF_PROG(meta_vfs_open_entry, const struct path *path) {
    meta_start(METADATA_OP_OPEN, path->dentry);
    return 0;
}
SEC("fexit/vfs_open")
int BPF_PROG(meta_vfs_open_exit) {
    meta_end(METADATA_OP_OPEN, ctx);
    return 0;
}

// close: filp_close(struct file *filp, fl_owner_t id). The VFS-level close path
// for explicit close(2)/dup/exec; the final __fput is a separate teardown.
SEC("fentry/filp_close")
int BPF_PROG(meta_filp_close_entry, struct file *filp) {
    meta_start(METADATA_OP_CLOSE, filp->f_path.dentry);
    return 0;
}
SEC("fexit/filp_close")
int BPF_PROG(meta_filp_close_exit) {
    meta_end(METADATA_OP_CLOSE, ctx);
    return 0;
}

// create: the dentry sits at arg1 on modern kernels
//   vfs_create(idmap, dentry, mode, delegated_inode *)
// but at arg2 on older ones
//   vfs_create(userns, struct inode *dir, dentry, umode_t, bool)
// — the parent dir inode used to precede it. Both arg1 and arg2 are in-bounds
// on either layout, so reading the raw ctx slot always verifies; the CO-RE
// branch selects the BTF-typed dentry.
static const __always_inline struct dentry *
vfs_create_dentry(unsigned long long *ctx) {
    // Read both candidate slots with constant offsets, then select on the
    // loaded *values*. The verifier only permits dereferencing a ctx pointer at
    // an instruction-immediate offset; it rejects any deref reached via ctx
    // register arithmetic ("dereference of modified ctx ptr disallowed").
    //
    // Materializing the two loads into locals is not enough on its own: since
    // each local feeds only one arm of the ?:, clang's sinking pass pushes each
    // load down into its branch, reconstructing `ctx + reg; load`. barrier_var
    // pins both loaded values into registers before the branch, forcing the two
    // immediate-offset ctx loads to stay put. (This is morally what BPF_PROG's
    // wrapper does: it reads every ctx[N] eagerly up front and hands the body
    // already-loaded scalars.)
    const struct dentry *arg1 = (const struct dentry *)ctx[1];
    const struct dentry *arg2 = (const struct dentry *)ctx[2];
    barrier_var(arg1);
    barrier_var(arg2);
    return vfs_layout_is_modern() ? arg1 : arg2;
}

SEC("fentry/vfs_create")
int BPF_PROG(meta_vfs_create_entry) {
    meta_start(METADATA_OP_CREATE, vfs_create_dentry(ctx));
    return 0;
}
SEC("fexit/vfs_create")
int BPF_PROG(meta_vfs_create_exit) {
    meta_end(METADATA_OP_CREATE, ctx);
    return 0;
}

// mkdir: vfs_mkdir(idmap/userns, struct inode *dir, struct dentry *dentry,
// ...). dentry is arg2 on every kernel.
SEC("fentry/vfs_mkdir")
int BPF_PROG(meta_vfs_mkdir_entry, void * /*idmap*/, void * /*dir*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_MKDIR, dentry);
    return 0;
}
SEC("fexit/vfs_mkdir")
int BPF_PROG(meta_vfs_mkdir_exit) {
    meta_end(METADATA_OP_MKDIR, ctx);
    return 0;
}

// rmdir: vfs_rmdir(idmap/userns, struct inode *dir, struct dentry *dentry,
// ...).
SEC("fentry/vfs_rmdir")
int BPF_PROG(meta_vfs_rmdir_entry, void * /*idmap*/, void * /*dir*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_RMDIR, dentry);
    return 0;
}
SEC("fexit/vfs_rmdir")
int BPF_PROG(meta_vfs_rmdir_exit) {
    meta_end(METADATA_OP_RMDIR, ctx);
    return 0;
}

// unlink: vfs_unlink(idmap/userns, struct inode *dir, struct dentry *dentry,
// ...).
SEC("fentry/vfs_unlink")
int BPF_PROG(meta_vfs_unlink_entry, void * /*idmap*/, void * /*dir*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_UNLINK, dentry);
    return 0;
}
SEC("fexit/vfs_unlink")
int BPF_PROG(meta_vfs_unlink_exit) {
    meta_end(METADATA_OP_UNLINK, ctx);
    return 0;
}

// rename: vfs_rename(struct renamedata *rd). Keyed on the source dentry; the
// `old_dentry` field exists on both layouts and CO-RE relocates its offset.
SEC("fentry/vfs_rename")
int BPF_PROG(meta_vfs_rename_entry, const struct renamedata *rd) {
    meta_start(METADATA_OP_RENAME, rd->old_dentry);
    return 0;
}
SEC("fexit/vfs_rename")
int BPF_PROG(meta_vfs_rename_exit) {
    meta_end(METADATA_OP_RENAME, ctx);
    return 0;
}

// link: vfs_link(struct dentry *old_dentry, ...). old_dentry is arg0 on every
// kernel.
SEC("fentry/vfs_link")
int BPF_PROG(meta_vfs_link_entry, struct dentry *old_dentry) {
    meta_start(METADATA_OP_LINK, old_dentry);
    return 0;
}
SEC("fexit/vfs_link")
int BPF_PROG(meta_vfs_link_exit) {
    meta_end(METADATA_OP_LINK, ctx);
    return 0;
}

// symlink: vfs_symlink(idmap/userns, struct inode *dir, struct dentry *dentry,
// ...).
SEC("fentry/vfs_symlink")
int BPF_PROG(meta_vfs_symlink_entry, void * /*idmap*/, void * /*dir*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_SYMLINK, dentry);
    return 0;
}
SEC("fexit/vfs_symlink")
int BPF_PROG(meta_vfs_symlink_exit) {
    meta_end(METADATA_OP_SYMLINK, ctx);
    return 0;
}

// mknod: vfs_mknod(idmap/userns, struct inode *dir, struct dentry *dentry,
// ...).
SEC("fentry/vfs_mknod")
int BPF_PROG(meta_vfs_mknod_entry, void * /*idmap*/, void * /*dir*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_MKNOD, dentry);
    return 0;
}
SEC("fexit/vfs_mknod")
int BPF_PROG(meta_vfs_mknod_exit) {
    meta_end(METADATA_OP_MKNOD, ctx);
    return 0;
}

// stat: vfs_getattr(const struct path *path, ...).
SEC("fentry/vfs_getattr")
int BPF_PROG(meta_vfs_getattr_entry, const struct path *path) {
    meta_start(METADATA_OP_GETATTR, path->dentry);
    return 0;
}
SEC("fexit/vfs_getattr")
int BPF_PROG(meta_vfs_getattr_exit) {
    meta_end(METADATA_OP_GETATTR, ctx);
    return 0;
}

// setattr (chmod/chown/truncate/utimes): notify_change(idmap/userns, dentry,
// ...).
SEC("fentry/notify_change")
int BPF_PROG(meta_notify_change_entry, void * /*idmap*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_SETATTR, dentry);
    return 0;
}
SEC("fexit/notify_change")
int BPF_PROG(meta_notify_change_exit) {
    meta_end(METADATA_OP_SETATTR, ctx);
    return 0;
}

// readdir (getdents): iterate_dir(struct file *file, ...).
SEC("fentry/iterate_dir")
int BPF_PROG(meta_iterate_dir_entry, struct file *file) {
    meta_start(METADATA_OP_READDIR, file->f_path.dentry);
    return 0;
}
SEC("fexit/iterate_dir")
int BPF_PROG(meta_iterate_dir_exit) {
    meta_end(METADATA_OP_READDIR, ctx);
    return 0;
}

// fsync: vfs_fsync(struct file *file, int datasync).
SEC("fentry/vfs_fsync")
int BPF_PROG(meta_vfs_fsync_entry, struct file *file) {
    meta_start(METADATA_OP_FSYNC, file->f_path.dentry);
    return 0;
}
SEC("fexit/vfs_fsync")
int BPF_PROG(meta_vfs_fsync_exit) {
    meta_end(METADATA_OP_FSYNC, ctx);
    return 0;
}

// getxattr: vfs_getxattr(idmap/userns, struct dentry *dentry, ...).
SEC("fentry/vfs_getxattr")
int BPF_PROG(meta_vfs_getxattr_entry, void * /*idmap*/, struct dentry *dentry) {
    meta_start(METADATA_OP_GETXATTR, dentry);
    return 0;
}
SEC("fexit/vfs_getxattr")
int BPF_PROG(meta_vfs_getxattr_exit) {
    meta_end(METADATA_OP_GETXATTR, ctx);
    return 0;
}

// setxattr: vfs_setxattr(idmap/userns, struct dentry *dentry, ...).
SEC("fentry/vfs_setxattr")
int BPF_PROG(meta_vfs_setxattr_entry, void * /*idmap*/, struct dentry *dentry) {
    meta_start(METADATA_OP_SETXATTR, dentry);
    return 0;
}
SEC("fexit/vfs_setxattr")
int BPF_PROG(meta_vfs_setxattr_exit) {
    meta_end(METADATA_OP_SETXATTR, ctx);
    return 0;
}

// listxattr: vfs_listxattr(struct dentry *dentry, ...). dentry is arg0.
SEC("fentry/vfs_listxattr")
int BPF_PROG(meta_vfs_listxattr_entry, struct dentry *dentry) {
    meta_start(METADATA_OP_LISTXATTR, dentry);
    return 0;
}
SEC("fexit/vfs_listxattr")
int BPF_PROG(meta_vfs_listxattr_exit) {
    meta_end(METADATA_OP_LISTXATTR, ctx);
    return 0;
}

// removexattr: vfs_removexattr(idmap/userns, struct dentry *dentry, ...).
SEC("fentry/vfs_removexattr")
int BPF_PROG(meta_vfs_removexattr_entry, void * /*idmap*/,
             struct dentry *dentry) {
    meta_start(METADATA_OP_REMOVEXATTR, dentry);
    return 0;
}
SEC("fexit/vfs_removexattr")
int BPF_PROG(meta_vfs_removexattr_exit) {
    meta_end(METADATA_OP_REMOVEXATTR, ctx);
    return 0;
}
