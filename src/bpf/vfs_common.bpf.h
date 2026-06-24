#pragma once

// BPF-side VFS helpers shared between the IO (io.bpf.c) and metadata
// (metadata.bpf.c) programs: the cheap ephemeral-filesystem filter and the
// fs-magic accessors. These do direct (CO-RE-relocated) field loads on
// PTR_TO_BTF_ID arguments, which the verifier turns into fault-safe probe
// reads, so callers don't need to null-check the pointers.

#include "vfs_types.h"

#include <bpf/bpf_core_read.h>

// Filesystems whose IO/metadata we never want to record: pseudo/virtual ones
// with no real backing store. A subset of FsMagic::is_ephemeral_fs (the Rust
// side, src/metrics/io.rs) cheap enough to evaluate in the hot path.
static __always_inline bool is_ephemeral_fs_cheap(enum FsMagic magic) {
    return magic == ANON_INODE_FS_MAGIC || magic == TMPFS_MAGIC ||
           magic == PIPEFS_MAGIC || magic == SYSFS_MAGIC ||
           magic == PROC_SUPER_MAGIC || magic == SOCKFS_MAGIC ||
           magic == CGROUP2_SUPER_MAGIC;
}

static __always_inline enum FsMagic file_fs_magic(const struct file *file) {
    return file->f_path.mnt->mnt_sb->s_magic;
}

// The superblock magic reachable from any dentry (positive or negative): the
// inode-based metadata ops (vfs_create/unlink/mkdir/...) carry no vfsmount, so
// dentry->d_sb is the common source of the filesystem type.
static __always_inline enum FsMagic
dentry_fs_magic(const struct dentry *dentry) {
    return dentry->d_sb->s_magic;
}
