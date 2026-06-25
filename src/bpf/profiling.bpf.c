// CPU profiling: a perf_event sampler that DWARF-unwinds the on-CPU user stack
// in-kernel (using per-executable .eh_frame tables userspace loads into the
// maps below) and aggregates per-(cgroup, thread, stack) sample counts.

#include "profiling.h"

#include "cgroup_id.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Template for one executable's inner rows map (its flat, PC-sorted unwind
// table). max_entries is a placeholder; the real per-executable maps are
// created at runtime sized to the file's row count and inserted into
// UNWIND_ROWS.
struct unwind_rows_inner {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_INNER_MAP);
    __type(key, u32);
    __type(value, struct UnwindRow);
} unwind_rows_inner SEC(".maps");

// exec_id -> that executable's inner rows map (its complete flat unwind table).
// Total memory is proportional to the executables actually mapped; the entry is
// deleted, freeing the inner map, once no live process references the file.
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_EXECUTABLES);
    __type(key, u64);
    __array(values, struct unwind_rows_inner);
} UNWIND_ROWS SEC(".maps");

// exec_id -> its flat unwind table's row count (the binary-search bound).
// row_count == 0 means the file has no usable unwind info (one frame only).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EXECUTABLES);
    __type(key, u64);
    __type(value, struct ExecInfo);
} EXECUTABLES SEC(".maps");

// tgid -> its file-backed executable mappings, sorted by start address.
// BPF_F_NO_PREALLOC: struct ProcessMappings is ~6 KiB (MAX_MAPPINGS_PER_PROC
// entries inline), so preallocating all max_entries would reserve ~50 MiB up
// front regardless of load. Elements are only ever inserted/updated from
// userspace and the sampler merely looks them up (lookups never allocate), so
// on-demand allocation is safe and total memory tracks the processes actually
// sampled.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct ProcessMappings);
} PROC_MAPPINGS SEC(".maps");

// stack_id (hash) -> the unwound instruction-pointer chain. Multiple
// STACK_COUNTS entries may reference one stack id; userspace frees ids after a
// full drain.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct Stack);
} STACKS SEC(".maps");

// Per-CPU scratch for building one stack before it is hashed and stored. Kept
// off the (512 B) BPF stack because struct Stack is ~1 KiB.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct Stack);
} SCRATCH SEC(".maps");

// One binary search's mutable bounds (lo/hi/found). Held in a per-CPU map, not
// on the BPF stack or in registers, on purpose: the open-coded iterator
// searches below re-read these from map memory each step. The verifier doesn't
// track map-value contents, so each read is an unknown-but-bounded scalar
// rather than a per-path precise constant. That keeps the loop body's register
// state identical across iterations so the verifier's state-pruning converges;
// carrying the induction variables precisely (in registers/stack) instead makes
// the verifier explore every path of the search and blow past its
// 1M-instruction limit (E2BIG). find_mapping and find_row never run
// concurrently, so they share the single slot.
struct SearchState {
    u32 lo;
    u32 hi;
    u32 found;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct SearchState);
} SEARCH_SCRATCH SEC(".maps");

// In-kernel aggregation of CPU samples: StackKey -> sample count. This keeps
// per-sample overhead to a single hash update and avoids any ringbuf traffic
// for profiling.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct StackKey);
    __type(value, u64);
} STACK_COUNTS SEC(".maps");

// Notifies userspace that a sampled tgid has no (or stale) unwind info loaded,
// so it can read /proc/<pid>/maps and populate the maps above. Payload:
// struct UnwindMiss (tgid + the cgroup the sample ran in).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KiB
} UNWIND_MISSES SEC(".maps");

// ---------------------------------------------------------------------------
// Native (.eh_frame DWARF) CPU stack unwinder
//
// bpf_get_stackid() only frame-pointer-unwinds, which collapses every stack to
// its leaf on frame-pointer-less release builds. Instead we walk the user stack
// here using the per-executable unwind table userspace parsed from .eh_frame /
// .eh_frame_hdr and loaded into the maps above: a single flat, PC-sorted array
// of CFI rows per executable (UNWIND_ROWS) the kernel binary-searches directly.
// ---------------------------------------------------------------------------

// Binary-search iteration caps (>= log2 of the searched range, with margin).
// The searches run as open-coded iterator (bpf_for) loops. An open-coded
// iterator terminates verification by state convergence, not by its [0, cap)
// range, so the loop-carried bounds must reach a stable abstract state or the
// verifier explores the search path-by-path to the 1M-instruction limit
// (E2BIG). We get that convergence by holding lo/hi/found in SEARCH_SCRATCH and
// re-reading them each step (see that map's comment): map reads are opaque to
// the verifier, so the loop body's register state is identical every iteration
// and pruning kicks in. The cap then only bounds the runtime trip count, and
// each search still terminates early once its range is empty. The row search
// covers the whole table (at most MAX_ROWS_PER_EXEC entries), so 32 (>=
// log2(4Mi) = 22, with margin) fits.
#define UNWIND_SEARCH_ITERS 32
#define MAPPING_SEARCH_ITERS 12 // covers MAX_MAPPINGS_PER_PROC, with margin

// 64-bit FNV-1a constants, used to fold a stack into a stack id.
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

// --- mapping search: binary search over a process' sorted mappings ----------

// Copy the mapping of `tgid` that contains `pc` into `out`; returns false if
// the process has no loaded mappings or `pc` falls in none of them. The
// mappings pointer is looked up once and held across the loop; the search
// bounds live in SEARCH_SCRATCH and are re-read each step so the verifier sees
// them as opaque (see that map's comment for why this is required to converge).
static __always_inline bool find_mapping(u32 tgid, u64 pc,
                                         struct MappingEntry *out) {
    struct ProcessMappings *pm = bpf_map_lookup_elem(&PROC_MAPPINGS, &tgid);
    if (!pm) {
        return false;
    }
    u32 hi = pm->len;
    if (hi > MAX_MAPPINGS_PER_PROC) {
        hi = MAX_MAPPINGS_PER_PROC;
    }
    const u32 zero = 0;
    struct SearchState *s = bpf_map_lookup_elem(&SEARCH_SCRATCH, &zero);
    if (!s) {
        return false;
    }
    s->lo = 0;
    s->hi = hi;
    s->found = MAX_MAPPINGS_PER_PROC; // greatest index with begin <= pc

    int i;
    bpf_for(i, 0, MAPPING_SEARCH_ITERS) {
        u32 lo = s->lo;
        u32 hi_ = s->hi;
        if (lo >= hi_) {
            break;
        }
        u32 mid = lo + (hi_ - lo) / 2;
        if (mid >= MAX_MAPPINGS_PER_PROC) {
            break; // bounds the array index for the verifier
        }
        if (pm->entries[mid].begin <= pc) {
            s->found = mid;
            s->lo = mid + 1;
        } else {
            s->hi = mid;
        }
    }

    u32 found = s->found;
    if (found >= MAX_MAPPINGS_PER_PROC) {
        return false;
    }
    struct MappingEntry *e = &pm->entries[found];
    if (pc >= e->begin && pc < e->end) {
        *out = *e;
        return true;
    }
    return false; // pc falls in a gap between mappings
}

// --- row search: binary search over an executable's flat unwind table --------

// Copy the unwind row covering module address `mva` within executable
// `exec_id`'s `row_count`-entry flat table into `out`; returns false if `mva`
// precedes the first row (no covering rule -> stop the walk). The matched row's
// rule applies from its `pc` up to the next row's `pc`; an end-of-function
// stopper row terminates each function followed by a gap, so a `mva` past all
// code resolves to a stopper rather than inheriting the last function's rule.
//
// The inner rows map is looked up once and held across the loop; the search
// bounds live in SEARCH_SCRATCH and are re-read each step so the verifier sees
// them as opaque (see that map's comment for why this is required to converge).
static __always_inline bool find_row(u64 exec_id, u32 row_count, u64 mva,
                                     struct UnwindRow *out) {
    void *inner = bpf_map_lookup_elem(&UNWIND_ROWS, &exec_id);
    if (!inner) {
        return false;
    }
    const u32 zero = 0;
    struct SearchState *s = bpf_map_lookup_elem(&SEARCH_SCRATCH, &zero);
    if (!s) {
        return false;
    }
    s->lo = 0;
    s->hi = row_count;
    s->found = row_count; // greatest index with pc <= mva, else == row_count

    int i;
    bpf_for(i, 0, UNWIND_SEARCH_ITERS) {
        u32 lo = s->lo;
        u32 hi = s->hi;
        if (lo >= hi) {
            break;
        }
        u32 mid = lo + (hi - lo) / 2;
        struct UnwindRow *row = bpf_map_lookup_elem(inner, &mid);
        if (!row) {
            break;
        }
        if (row->pc <= mva) {
            s->found = mid;
            s->lo = mid + 1;
        } else {
            s->hi = mid;
        }
    }

    u32 found = s->found;
    if (found >= row_count) {
        return false;
    }
    struct UnwindRow *row = bpf_map_lookup_elem(inner, &found);
    if (!row) {
        return false;
    }
    *out = *row;
    return true;
}

// Periodic CPU sampler. Attached to a per-CPU perf event (HW cycles) from
// userspace. On each sample we DWARF-unwind the on-CPU thread's user stack and
// bump an in-kernel counter keyed by (cgroup, tgid, pid, stack id).
SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 tgid = pid_tgid >> 32;
    const u32 pid = pid_tgid & 0xFFFFFFFF;

    if (tgid == 0) {
        return 0; // idle / kernel threads have no user stack
    }

    const u32 zero = 0;
    struct Stack *stack = bpf_map_lookup_elem(&SCRATCH, &zero);
    if (!stack) {
        return 0;
    }
    // Clear stale entries: the hash and the zero terminator both rely on the
    // unused tail being zero.
    __builtin_memset(stack, 0, sizeof(*stack));

    struct pt_regs *regs = (struct pt_regs *)&ctx->regs;
    u64 rip = PT_REGS_IP(regs);
    u64 rsp = PT_REGS_SP(regs);
    u64 rbp = PT_REGS_FP(regs);

    bool miss = false;
    u32 depth = 0;
    // Outer frame walk. Deliberately a plain rolled loop, not an open-coded
    // iterator: its only precise loop-carried value is `frame`, and every
    // per-frame branch re-converges (rip/rsp/rbp are opaque scalars) before the
    // next iteration, so verifier state stays linear in depth. The binary
    // searches it calls are each their own bpf_for iterator, verified
    // independently.
#pragma clang loop unroll(disable)
    for (int frame = 0; frame < MAX_STACK_DEPTH; frame++) {
        stack->addrs[frame] = rip;
        depth = frame + 1;

        struct MappingEntry m;
        if (!find_mapping(tgid, rip, &m)) {
            // PC is in no known mapping: either the process isn't loaded yet,
            // or it mapped new code (e.g. dlopen) since we last read its maps.
            // Ask userspace to (re)read /proc/<pid>/maps; it rebuilds only if
            // they actually changed, so a permanent gap (vDSO/JIT) just no-ops.
            miss = true;
            break;
        }
        struct ExecInfo *exec = bpf_map_lookup_elem(&EXECUTABLES, &m.exec_id);
        if (!exec) {
            miss = true; // mapping known but its table isn't loaded yet
            break;
        }
        if (exec->row_count == 0) {
            break; // file has no usable unwind info: leaf frame only
        }
        // Single-level lookup: binary-search the executable's flat, PC-sorted
        // row table for the rule set covering this PC.
        u64 mva = rip - m.load_offset;
        struct UnwindRow row;
        if (!find_row(m.exec_id, exec->row_count, mva, &row) ||
            row.cfa_type == CFA_UNSUPPORTED) {
            break;
        }

        u64 cfa = (row.cfa_type == CFA_RBP ? rbp : rsp) + (s64)row.cfa_offset;

        // The return address sits at CFA - 8 on x86_64.
        u64 ra = 0;
        if (bpf_probe_read_user(&ra, sizeof(ra), (void *)(cfa - 8)) != 0 ||
            ra == 0) {
            break; // unreadable or top of stack
        }

        // Recover the caller's frame base for any deeper rbp-relative CFA
        // rules.
        u64 next_rbp = rbp;
        if (row.rbp_type == RBP_CFA_OFFSET) {
            bpf_probe_read_user(&next_rbp, sizeof(next_rbp),
                                (void *)(cfa + (s64)row.rbp_offset));
        }
        rip = ra;
        rsp = cfa;
        rbp = next_rbp;
    }

    if (miss) {
        struct UnwindMiss *slot =
            bpf_ringbuf_reserve(&UNWIND_MISSES, sizeof(*slot), 0);
        if (slot) {
            slot->tgid = tgid;
            slot->_pad = 0;
            slot->cgroup_id = current_cgroup_id();
            bpf_ringbuf_submit(slot, 0);
        }
    }

    if (depth == 0) {
        return 0;
    }

    // Fold the chain into a stack id and store the chain once per distinct id.
    u64 stack_id = FNV_OFFSET;
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        stack_id ^= stack->addrs[i];
        stack_id *= FNV_PRIME;
    }
    bpf_map_update_elem(&STACKS, &stack_id, stack, BPF_ANY);

    struct StackKey key = {
        .cgroup_id = current_cgroup_id(),
        .tgid = tgid,
        .pid = pid,
        .stack_id = stack_id,
    };
    u64 *count = bpf_map_lookup_elem(&STACK_COUNTS, &key);
    if (count != NULL) {
        __sync_fetch_and_add(count, 1);
    } else {
        const u64 one = 1;
        bpf_map_update_elem(&STACK_COUNTS, &key, &one, BPF_NOEXIST);
    }

    return 0;
}
