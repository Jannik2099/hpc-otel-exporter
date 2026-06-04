// Entry translation unit for the exporter's eBPF object.

#include <vmlinux.h>
//
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#include "io.bpf.c"
#include "profiling.bpf.c"
