#pragma once

// Selects which cgroup id every feature records on its events: the v2 (unified)
// id from bpf_get_current_cgroup_id(), or the v1 id of the cpu,cpuacct
// hierarchy. Userspace sets the two rodata knobs below before load (see
// src/app.rs) from the --use-cgroups-v1 flag; the branch is then
// constant-folded and the unused side dead-code-eliminated, so a v2 run pays
// nothing.
//
// SLURM with cgroupsv1 only creates v1 cgroups (every job lands in one
// slurmd.service v2 cgroup), so v1 ids are what lets userspace attribute
// events to a job. The id is the cgroup directory's kernfs inode, matching the
// stat inode userspace resolves against.

#include <vmlinux.h>
//
#include "prelude.h" // IWYU pragma: keep

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// Record the v1 (cpu,cpuacct) cgroup id instead of the v2 id.
const volatile bool USE_CGROUPS_V1 = false;
// The cpu,cpuacct v1 hierarchy id (the leading field of the matching
// /proc/self/cgroup line), detected by userspace and passed to
// bpf_task_get_cgroup1.
const volatile int CGROUP_V1_HID = 0;

// The cgroup id to stamp on an event for the current task, honouring the v1/v2
// mode selected at load time. Returns 0 if the v1 cgroup can't be fetched (the
// event is then attributed to the root/unresolved bucket and dropped
// userspace).
static __always_inline u64 current_cgroup_id(void) {
    if (!USE_CGROUPS_V1) {
        return bpf_get_current_cgroup_id();
    }
    struct task_struct *task = bpf_get_current_task_btf();
    struct cgroup *cgrp = bpf_task_get_cgroup1(task, CGROUP_V1_HID);
    if (cgrp == NULL) {
        return 0;
    }
    const u64 id = BPF_CORE_READ(cgrp, kn, id);
    bpf_cgroup_release(cgrp);
    return id;
}
