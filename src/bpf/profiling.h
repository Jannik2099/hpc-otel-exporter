#pragma once

#include "prelude.h"

// Types and constants shared between the CPU sampling/unwinding BPF program
// (src/bpf/profiling.bpf.c) and the userspace profiler (src/profiling/*, via
// bindgen -> crate::bindings).

// Key for the STACK_COUNTS hash map: one entry per distinct on-CPU user stack
// observed for a given (cgroup, thread). The kernel accumulates a sample count
// per key; userspace drains and symbolizes them into pprof profiles.
struct StackKey {
    uint64_t cgroup_id;
    uint32_t tgid;
    uint32_t pid;
    // Hash of the unwound instruction-pointer chain; our own stack id (we no
    // longer use bpf_get_stackid). Indexes the STACKS map. 0 = empty stack.
    uint64_t stack_id;
};

// One entry of the UNWIND_MISSES ring buffer: a sample the in-kernel walker
// couldn't fully unwind because the thread group's tables aren't loaded yet.
// Carries the cgroup it was running in alongside the tgid so userspace can
// attribute the on-demand load work (span/metric/log) to the workload that
// triggered it, exactly as it would resolve the cgroup for a stack sample.
struct UnwindMiss {
    uint32_t tgid;
    uint32_t _pad;
    uint64_t cgroup_id;
};

// ---------------------------------------------------------------------------
// Native (.eh_frame DWARF) CPU stack unwinder
//
// We no longer rely on bpf_get_stackid()'s frame-pointer walk (release builds
// omit frame pointers, collapsing every stack to its leaf). Instead userspace
// parses each executable's .eh_frame into BPF maps and the perf_event program
// walks the user stack in-kernel.
//
// Each executable's evaluated CFI is flattened into a single array of UnwindRow,
// sorted ascending by module address and binary-searched directly: the row with
// the greatest pc <= the target address gives the rule in effect. Function ends
// are marked with "stopper" rows (CFA_UNSUPPORTED) wherever a gap follows, so a
// PC with no unwind info stops the walk instead of inheriting the previous
// function's rule. (We require .eh_frame_hdr for the linker's sorted function
// order; executables that have .eh_frame without it simply unwind to a single
// frame.)
// ---------------------------------------------------------------------------

// Maximum frames captured per user stack (matches perf's default stack depth).
#define MAX_STACK_DEPTH 127

// Each executable's flat unwind table lives in its own inner BPF array map
// (UNWIND_ROWS, keyed by exec_id), sized to that file's row count. This keeps
// total memory proportional to what is actually mapped (no fixed arena) and lets
// the table be freed the moment no live process references the file.

// Outer HASH_OF_MAPS capacity: distinct executables tracked at once. Inner maps
// are created on demand and reclaimed (deleted) as referencing processes exit.
#define MAX_EXECUTABLES 16384

// Per-executable sanity cap on rows (inner map size). A file whose .eh_frame is
// larger than this unwinds to a single frame rather than allocating absurdly.
#define MAX_ROWS_PER_EXEC (4 * 1024 * 1024)

// Per-process cap on distinct file-backed executable mappings we track. Beyond
// this, a process' remaining libraries simply go unwound (partial stacks).
#define MAX_MAPPINGS_PER_PROC 192

// How a row's canonical frame address (CFA, the caller's stack pointer at the
// call site) is computed.
enum CfaType : uint8_t {
    CFA_UNSUPPORTED = 0, // no flattenable rule (DWARF expr/PLT/sentinel) -> stop
    CFA_RSP = 1,         // CFA = rsp + cfa_offset
    CFA_RBP = 2,         // CFA = rbp + cfa_offset
};

// How a row recovers the caller's RBP.
enum RbpRule : uint8_t {
    RBP_UNSUPPORTED = 0, // unknown rule -> stop unwinding
    RBP_UNCHANGED = 1,   // caller rbp == current rbp (CFI leaves it untouched)
    RBP_CFA_OFFSET = 2,  // caller rbp = *(CFA + rbp_offset)
    RBP_UNDEFINED = 3,   // rbp is dead in the caller; keep the current value
};

// One unwind-table row: the rule set effective from `pc` up to the next row's
// `pc`. The return address is read at *(CFA - 8) (x86_64 SysV); any FDE row
// specifying a different RA rule is emitted as CFA_UNSUPPORTED. All of an
// executable's rows form a single array (UNWIND_ROWS) sorted ascending by `pc`
// and binary-searched directly; the end of a function is marked with a stopper
// row (CFA_UNSUPPORTED) wherever a gap follows it, so a PC with no unwind info
// stops the walk rather than inheriting the previous function's rule. 16 bytes.
struct UnwindRow {
    uint64_t pc;        // module-relative virtual address
    int16_t cfa_offset; // signed displacement from the CFA base register
    int16_t rbp_offset; // CFA-relative offset of the saved rbp (RBP_CFA_OFFSET)
    uint8_t cfa_type;   // enum CfaType
    uint8_t rbp_type;   // enum RbpRule
    uint16_t _pad;
};

// One file-backed executable mapping inside a process. A runtime PC is
// translated into the FDE address space via `mva = runtime_pc - load_offset`
// before the unwinder searches that executable's rows.
struct MappingEntry {
    uint64_t begin;       // [begin, end) runtime virtual address range
    uint64_t end;
    uint64_t load_offset; // mva = runtime_pc - load_offset
    uint64_t exec_id;     // key into the EXECUTABLES map
};

// All file-backed executable mappings of one process, sorted ascending by
// `begin` so the unwinder can binary-search them by PC.
struct ProcessMappings {
    uint32_t len;
    struct MappingEntry entries[MAX_MAPPINGS_PER_PROC];
};

// Metadata for one executable's unwind table. The flat, PC-sorted rows live in a
// per-executable inner map (UNWIND_ROWS, keyed by exec_id); this carries their
// count, which is the upper bound for the in-kernel binary search. row_count == 0
// means the file had no usable .eh_frame_hdr (it unwinds to one frame, with no
// inner map).
struct ExecInfo {
    uint32_t row_count;
};

// One captured user call stack: leaf-first instruction pointers, zero-padded.
// A zero entry marks the end when the stack is shorter than MAX_STACK_DEPTH.
struct Stack {
    uint64_t addrs[MAX_STACK_DEPTH];
};
