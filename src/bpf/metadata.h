#pragma once

#include "vfs_types.h"

// Types shared between the VFS metadata-tracing BPF program
// (src/bpf/metadata.bpf.c) and the userspace metadata metrics
// (src/metrics/metadata.rs, via bindgen -> crate::bindings).
//
// Where IO tracing records the size+duration of vfs_read/vfs_write, this
// records the duration of the namespace/attribute VFS operations (open, close,
// create, stat, ...). They share FsMagic + TimeInfo (vfs_types.h) but, being
// mostly inode/dentry-based rather than file-based, carry no byte count or
// mount id.

// The VFS operation an event describes; recorded as the `vfs.op` metric
// attribute. One value per generic VFS entry point we hook, so a single value
// covers every syscall variant (e.g. OPEN is open/openat/openat2/creat alike).
enum MetadataOp : uint32_t {
    METADATA_OP_OPEN = 0,    // vfs_open
    METADATA_OP_CLOSE,       // filp_close
    METADATA_OP_CREATE,      // vfs_create
    METADATA_OP_MKDIR,       // vfs_mkdir
    METADATA_OP_RMDIR,       // vfs_rmdir
    METADATA_OP_UNLINK,      // vfs_unlink
    METADATA_OP_RENAME,      // vfs_rename
    METADATA_OP_LINK,        // vfs_link
    METADATA_OP_SYMLINK,     // vfs_symlink
    METADATA_OP_MKNOD,       // vfs_mknod
    METADATA_OP_GETATTR,     // vfs_getattr (stat family)
    METADATA_OP_SETATTR,     // notify_change (chmod/chown/truncate/utimes)
    METADATA_OP_READDIR,     // iterate_dir (getdents family)
    METADATA_OP_FSYNC,       // vfs_fsync
    METADATA_OP_GETXATTR,    // vfs_getxattr
    METADATA_OP_SETXATTR,    // vfs_setxattr
    METADATA_OP_LISTXATTR,   // vfs_listxattr
    METADATA_OP_REMOVEXATTR, // vfs_removexattr
    METADATA_OP_MAX, // sentinel; also the per-task start-timestamp count
};

// A completed VFS metadata operation, drained by userspace metadata metrics.
struct MetadataEvent {
    struct TimeInfo time_info;
    enum FsMagic fs_magic;
    uint64_t cgroup_id;
    enum MetadataOp op;
    uint32_t pid;
    uint32_t tgid;
    // 0 on success, 1 when the call returned an error (IS_ERR_VALUE on the
    // raw return register, so it holds across int / ssize_t / pointer returns).
    uint8_t error;
    uint8_t _pad[11];
};

// Ring buffer entries have a 8 byte header followed by payload,
// thus ensure 56 byte size so that each event fills a cacheline
_Static_assert(sizeof(struct MetadataEvent) == 56);
