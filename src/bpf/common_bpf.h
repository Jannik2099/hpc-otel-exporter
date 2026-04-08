#pragma once

#include "common_shared.h"

static inline _Bool is_ephemeral_fs_cheap(enum FsMagic magic) {
    return magic == ANON_INODE_FS_MAGIC || magic == TMPFS_MAGIC ||
           magic == PIPEFS_MAGIC || magic == SYSFS_MAGIC ||
           magic == PROC_SUPER_MAGIC || magic == SOCKFS_MAGIC ||
           magic == CGROUP2_SUPER_MAGIC;
}
