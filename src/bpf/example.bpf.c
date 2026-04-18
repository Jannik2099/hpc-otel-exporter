#include <vmlinux.h>
//
#include "common_bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
