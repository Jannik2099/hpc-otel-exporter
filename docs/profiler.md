# The eBPF CPU Profiler

This document describes how the CPU sampling profiler in this exporter works: how
stacks are captured and unwound **in the kernel** using DWARF `.eh_frame` tables
that userspace parses and feeds in, how those frames are symbolized and cached,
and how every piece of state is scoped per cgroup and reclaimed when a cgroup or
process exits.

The audience is both humans and AI agents working on this code. File and symbol
references point at the implementation so it can be cross-checked against the
source.

## Table of contents

- [Why in-kernel DWARF unwinding](#why-in-kernel-dwarf-unwinding)
- [Component map](#component-map)
- [End-to-end data flow](#end-to-end-data-flow)
- [Sampling: `perf_event_open`](#sampling-perf_event_open)
- [In-kernel unwinding](#in-kernel-unwinding)
- [The unwind tables and their BPF maps](#the-unwind-tables-and-their-bpf-maps)
- [Userspace ⇄ kernel: the UnwindMiss loop](#userspace--kernel-the-unwindmiss-loop)
- [Building the unwind tables from `.eh_frame`](#building-the-unwind-tables-from-eh_frame)
- [Draining samples and symbolization](#draining-samples-and-symbolization)
  - [The negative range cache (non-ELF / JIT regions)](#the-negative-range-cache-non-elf--jit-regions)
- [pprof construction and the push to Pyroscope](#pprof-construction-and-the-push-to-pyroscope)
- [Per-cgroup scoping](#per-cgroup-scoping)
- [Resource lifecycle and cleanup](#resource-lifecycle-and-cleanup)
- [Tunables and caps](#tunables-and-caps)
- [Security boundary](#security-boundary)

## Why in-kernel DWARF unwinding

`bpf_get_stackid()` only walks frame pointers. Release builds (and most of glibc,
libstdc++, etc.) are compiled with `-fomit-frame-pointer`, so a frame-pointer walk
collapses essentially every stack to its leaf frame - useless for a flamegraph.

The alternative is to unwind using the DWARF call-frame information that compilers
already emit in `.eh_frame` (for exception handling / `backtrace()`), indexed by
the linker-built `.eh_frame_hdr` search table. Evaluating full DWARF CFI in the
kernel is impossible (it is a Turing-ish bytecode and the verifier would reject
it), so the work is **split**:

- **Userspace** parses each executable's `.eh_frame` / `.eh_frame_hdr` _once_,
  evaluates the CFI programs ahead of time, and flattens the result into a compact,
  fixed-size table of rows ([`src/profiling/unwind.rs`](../src/profiling/unwind.rs)).
- **The kernel** does only a pair of binary searches and a couple of arithmetic
  steps + user-memory reads per frame - no DWARF interpretation at sample time
  ([`src/bpf/profiling.bpf.c`](../src/bpf/profiling.bpf.c), `do_sample`).

This mirrors the design of production profilers like Parca/OpenTelemetry eBPF
profiler.

## Component map

| File                                                                  | Role                                                                                         |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [`src/bpf/exporter.bpf.c`](../src/bpf/exporter.bpf.c)                 | Entry BPF translation unit: `#include`s the per-feature fragments into one object.           |
| [`src/bpf/profiling.bpf.c`](../src/bpf/profiling.bpf.c)               | The `perf_event` program `do_sample` + the unwinder helpers and all profiling/unwind maps.   |
| [`src/bpf/profiling.h`](../src/bpf/profiling.h)                       | Profiling structs/constants shared between BPF C and Rust (via bindgen → `crate::bindings`). |
| [`src/profiling/mod.rs`](../src/profiling/mod.rs)                     | The `Profiler` facade: attach, drain, orchestrate symbolization, build pprof, push.          |
| [`src/profiling/perf_event.rs`](../src/profiling/perf_event.rs)       | `perf_event_open` + per-CPU sampler attach (`attach_perf_samplers`).                         |
| [`src/profiling/symbolize.rs`](../src/profiling/symbolize.rs)         | Address→frame resolution (blazesym workers), the per-cgroup caches, and the string interner. |
| [`src/profiling/pprof.rs`](../src/profiling/pprof.rs)                 | `ProfileBuilder`: encodes resolved frames into a `google.v1.Profile`.                        |
| [`src/profiling/push.rs`](../src/profiling/push.rs)                   | `Pusher`: uploads per-cgroup pprof to Pyroscope.                                             |
| [`src/profiling/unwind.rs`](../src/profiling/unwind.rs)               | Parses an ELF's `.eh_frame`/`.eh_frame_hdr` into the flat, PC-sorted unwind row table.       |
| [`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs) | Keeps the BPF unwind maps populated; demand-driven loading + refcounted eviction.            |
| [`src/profiling/proc_maps.rs`](../src/profiling/proc_maps.rs)         | Parses `/proc/<pid>/maps`; computes `exec_id` and the runtime-PC → module-VA `load_offset`.  |
| [`src/cgroup.rs`](../src/cgroup.rs)                                   | `CgroupRegistry` + `PerCgroup<T>`: per-cgroup meter providers and the live-cgroup snapshot.  |
| [`src/app.rs`](../src/app.rs)                                         | Wires it all together; runs the event loop.                                                  |

## End-to-end data flow

```
                         ┌──────────────────────── kernel ─────────────────────────┐
 perf event (per-CPU) ──▶│ do_sample:                                              │
   N Hz CPU-clock        │   walk user stack via PROC_MAPPINGS + UNWIND_ROWS      │
                         │   ├─ success ─▶ STACKS[stack_id], STACK_COUNTS[key]++   │
                         │   └─ miss ────▶ UNWIND_MISSES ringbuf {tgid, cgroup_id} │
                         └───────┬───────────────────────────────┬────────────────-┘
                                 │ (ring buffer)                  │ (maps, polled)
                                 ▼                                ▼
       ┌──────────── userspace event loop (src/app.rs) ────────────────────┐
       │  UNWIND_MISSES cb ─▶ pending_misses{tgid→cgroup}                    │
       │  cleanup tick (5s):                                                 │
       │     registry.cleanup_dead_cgroups() ─▶ live set                     │
       │     UnwindLoader.ensure_pid(pid) ─▶ read /proc/pid/maps,            │
       │         parse .eh_frame, publish inner maps, PROC_MAPPINGS          │
       │     UnwindLoader.evict_dead() ─▶ release refs, free inner maps      │
       │  profile tick (5s):                                                 │
       │     Profiler.collect() ─▶ drain STACK_COUNTS/STACKS, symbolize,     │
       │         build one pprof per cgroup ─▶ Pusher.push() ─▶ Pyroscope    │
       └────────────────────────────────────────────────────────────────────┘
```

Two independent timers drive the userspace side, both in the `tokio::select!`
loop in [`src/app.rs`](../src/app.rs):

- the **cleanup tick** (default 5 s) services unwind misses and reclaims dead
  state, and
- the **profile tick** (`--profile-interval-secs`, default 5 s) drains, symbolizes
  and pushes profiles.

The `UNWIND_MISSES` ring buffer is drained continuously (it shares the same epoll
fd as the IO `EVENTS` ring buffer), but the misses are only _acted on_ on the
cleanup tick.

## Sampling: `perf_event_open`

`attach_perf_samplers` in [`src/profiling/perf_event.rs`](../src/profiling/perf_event.rs) opens one
`PERF_COUNT_SW_CPU_CLOCK` software event **per online CPU**, sampling at a target
frequency (`--profile-frequency`, default 97 Hz - chosen as a prime to avoid
beating with periodic workloads), and attaches the `do_sample` BPF program to each
via `prog.attach_perf_event(fd)`.

Key attribute choices (`PerfEventAttr`):

- **`freq` mode** (`PERF_ATTR_FLAG_FREQ`): sample at ~N Hz per CPU rather than at a
  fixed event period.
- **`exclude_kernel`** (`PERF_ATTR_FLAG_EXCLUDE_KERNEL`): only sample while the CPU
  is in user mode. Without it the sampled leaf `rip` could be a kernel address the
  user-space symbolizer cannot resolve. The result is a user-stack profile.
- `pid = -1, cpu = N`: sample every process on that CPU.

The `PerfSampler` returned holds the perf fds and BPF `Link`s; dropping it detaches
the sampler. Offline CPUs (ENODEV/EINVAL) are skipped.

Each sample period represents `period_ns = 1e9 / freq` of wall-clock CPU time; this
is later recorded as the pprof period so a sample count converts to a CPU-time
estimate.

## In-kernel unwinding

`do_sample` ([`src/bpf/profiling.bpf.c`](../src/bpf/profiling.bpf.c)) runs on every
perf sample. Outline:

1. **Identify the thread.** `bpf_get_current_pid_tgid()` gives `tgid` (process) and
   `pid` (thread). Idle/kernel threads (`tgid == 0`) are dropped.
2. **Grab scratch.** A `struct Stack` (`MAX_STACK_DEPTH = 127` × `u64`, ~1 KiB) is
   too big for the 512 B BPF stack, so it lives in a per-CPU `SCRATCH` array map and
   is `memset` to zero (the trailing zeros act as the stack terminator and feed the
   hash).
3. **Seed registers** from the sampled `pt_regs`: `rip`, `rsp`, `rbp`.
4. **Walk frames** up to `MAX_STACK_DEPTH`. For each frame:
   - Record `rip` into `stack->addrs[frame]`.
   - **Find the mapping:** `find_mapping(tgid, rip)` binary-searches this process'
     sorted `PROC_MAPPINGS` for the executable mapping containing `rip`. A miss here
     means the process isn't loaded yet or `dlopen`'d new code → set `miss = true`,
     stop.
   - **Find the executable's table metadata:** `EXECUTABLES[exec_id]` gives
     `row_count`. Absent → `miss = true`, stop. `row_count == 0` (file has no
     usable unwind info) → stop with the leaf frame only (no miss; it's loaded).
   - **Translate to module space:** `mva = rip - m.load_offset`. The unwind table
     is keyed by module virtual address (the address space `.eh_frame` uses), not
     the runtime address, so the same on-disk file shares one table regardless of
     ASLR/PIE load base.
   - **Single-level table lookup:** `find_row(exec_id, row_count, mva)`
     binary-searches the executable's whole flat, PC-sorted row table
     (`UNWIND_ROWS[exec_id]`) for the row with the greatest `pc ≤ mva` - the rule
     set in effect at `mva`. A `mva` before the first row stops the walk.
   - A row with `cfa_type == CFA_UNSUPPORTED` (a "stopper") ends the walk - we
     produce a partial stack rather than a wrong one. Stoppers also mark each
     function's end where a gap follows, so a `mva` with no unwind info (an
     inter-function gap, or past all code) resolves to a stopper and stops cleanly
     instead of inheriting the previous function's rule.
   - **Apply the rule** to step to the caller:
     - `cfa = (cfa_type == CFA_RBP ? rbp : rsp) + cfa_offset` - the Canonical Frame
       Address (the caller's `rsp` at the call site).
     - `ra = *(cfa - 8)` via `bpf_probe_read_user` - the return address on x86-64
       SysV. Unreadable or zero → top of stack, stop.
     - Recover the caller's `rbp`: if `rbp_type == RBP_CFA_OFFSET`, read
       `*(cfa + rbp_offset)`; otherwise keep the current `rbp` (callee-saved,
       untouched by this frame).
     - Advance: `rip = ra; rsp = cfa; rbp = next_rbp`.

The two binary searches (in `find_mapping` and `find_row`) each run as an
**open-coded iterator loop** (`bpf_for`, backed by the `bpf_iter_num_new` /
`bpf_iter_num_next` / `bpf_iter_num_destroy` kfuncs). Unlike `bpf_loop` - whose
callback the verifier analyzes exactly once - an open-coded iterator terminates
verification by **state convergence**: the verifier simulates iterations until a
loop-head state matches a previously-seen one. The `[0, cap)` range is only a
runtime bound, not a verification one.

Binary search defeats naive convergence: `mid` is used as an array index, which
forces the verifier to track it - and, by backtracking, its source bounds - as
_precise_ constants, so every iteration is a distinct state and it never
converges (it explores the search path-by-path until it hits the 1M-instruction
limit and is rejected with `E2BIG`). The fix is to make those bounds **opaque to
the verifier**: `lo`/`hi`/`found` live in the per-CPU `SEARCH_SCRATCH` map and
are re-read from map memory each step. The verifier doesn't track map-value
contents, so each read is an unknown-but-bounded scalar; the loop body's register
state is then identical every iteration (only the iterator and the stable map
pointers are carried), and pruning converges. The BPF _stack_ would not work here

- the verifier tracks spill slots precisely - so the state has to sit in a map.
  The two searches never run concurrently and share the one scratch slot.

Iteration caps (`UNWIND_SEARCH_ITERS = 32`, `MAPPING_SEARCH_ITERS = 12`) bound the
runtime trip count and are ≥ log2 of the searched range - the row search now
covers the whole table (≤ `MAX_ROWS_PER_EXEC`, so log2 ≤ 22 < 32); the searches
also terminate early at runtime when their range empties.

The **outer frame walk** is intentionally _not_ an open-coded iterator: its only
loop-carried precise value is the frame counter, and the per-frame branches all
re-converge (`rip`/`rsp`/`rbp` become opaque scalars), so verifier state stays
linear in depth.

After the walk:

- If `miss`, push a `struct UnwindMiss { tgid, cgroup_id }` onto the
  `UNWIND_MISSES` ring buffer.
- Fold the captured chain into a 64-bit FNV-1a **stack id** over the whole
  fixed-size `addrs` array (the zero tail makes equal stacks hash equally).
- Store the chain once at `STACKS[stack_id]` and bump
  `STACK_COUNTS[{cgroup_id, tgid, pid, stack_id}]`. This is the only per-sample
  write to the aggregation maps; no per-sample ringbuffer traffic for profiling.

## The unwind tables and their BPF maps

Defined in [`src/bpf/profiling.bpf.c`](../src/bpf/profiling.bpf.c) and
[`src/bpf/profiling.h`](../src/bpf/profiling.h):

| Map              | Type               | Key → Value                                   | Purpose                                                                                                                                                                                                             |
| ---------------- | ------------------ | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PROC_MAPPINGS`  | HASH (no-prealloc) | `tgid` → `struct ProcessMappings`             | Per-process sorted list of file-backed executable mappings (`begin/end/load_offset/exec_id`). Up to `MAX_MAPPINGS_PER_PROC = 192`. `BPF_F_NO_PREALLOC` - the ~6 KiB value would otherwise reserve ~50 MiB up front. |
| `EXECUTABLES`    | HASH               | `exec_id` → `struct ExecInfo`                 | Per-file `row_count` - the flat-table binary-search bound; `0` means "no usable unwind info, one frame only".                                                                                                       |
| `UNWIND_ROWS`    | HASH_OF_MAPS       | `exec_id` → inner ARRAY of `struct UnwindRow` | Per-file flat, PC-sorted unwind table the kernel binary-searches directly.                                                                                                                                          |
| `STACKS`         | HASH               | `stack_id` → `struct Stack`                   | The captured IP chain for each distinct stack id.                                                                                                                                                                   |
| `STACK_COUNTS`   | HASH               | `struct StackKey` → `u64`                     | Aggregated sample counts per `(cgroup_id, tgid, pid, stack_id)`.                                                                                                                                                    |
| `SCRATCH`        | PERCPU_ARRAY       | `0` → `struct Stack`                          | Per-CPU scratch for building a stack off the BPF stack.                                                                                                                                                             |
| `SEARCH_SCRATCH` | PERCPU_ARRAY       | `0` → `struct SearchState`                    | Per-CPU `lo`/`hi`/`found` for one binary search. Held in a map (not registers) so the open-coded iterator loops converge for the verifier - see the unwinder section.                                               |
| `UNWIND_MISSES`  | RINGBUF            | -                                             | Notifies userspace of a tgid whose tables aren't loaded.                                                                                                                                                            |

### Why hash-of-maps (map-in-map)

`UNWIND_ROWS` is a `BPF_MAP_TYPE_HASH_OF_MAPS`. Each executable's flat row table
lives in its **own inner array map**, sized exactly to that file's row count, and
the inner map is inserted under the file's `exec_id`. This is the key
memory-management decision:

- **No fixed arena.** Total kernel memory tracks what is actually mapped by live
  processes, not a worst-case pre-allocation.
- **Per-file dedup.** `exec_id = hash(dev, inode)` ([`src/profiling/proc_maps.rs`](../src/profiling/proc_maps.rs),
  `exec_id`), so libc mapped by 500 processes is parsed and stored **once**.
- **Precise reclamation.** Deleting the `exec_id` key from the outer map drops the
  kernel's last reference to the inner map, which the kernel then frees. This is how
  table memory is returned when the last referencing process exits (see
  [Resource lifecycle](#resource-lifecycle-and-cleanup)).

The inner maps are created at runtime with `BPF_F_INNER_MAP`
([`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs), `create_inner_array`), which
lets each inner map have a different `max_entries` than the placeholder template
(`unwind_rows_inner`) declared in the BPF object.

### The compact row format and the flat table

`struct UnwindRow` is **16 bytes** ([`profiling.h`](../src/bpf/profiling.h)):

```c
struct UnwindRow {
    uint64_t pc;        // module-relative VA where this rule set starts
    int16_t cfa_offset; // CFA = (rsp|rbp) + cfa_offset
    int16_t rbp_offset; // saved caller rbp at *(CFA + rbp_offset)
    uint8_t cfa_type;   // CFA_RSP | CFA_RBP | CFA_UNSUPPORTED
    uint8_t rbp_type;   // RBP_UNCHANGED | RBP_CFA_OFFSET | RBP_UNDEFINED | RBP_UNSUPPORTED
    uint16_t _pad;
};
```

The return address is hard-assumed at `*(CFA - 8)` (x86-64 SysV); any FDE
specifying a different RA rule is flattened to a stopper.

There is **no separate FDE index**. All of an executable's functions' rows are
concatenated in the linker's ascending-PC order into one flat array, kept strictly
ascending by `pc` (function ranges don't overlap), and the kernel binary-searches
it directly - the row with the greatest `pc ≤ mva` gives the rule. Function
boundaries matter only where code is _not_ contiguous: wherever a function is
followed by a gap (or is the last function), the builder appends an
**end-of-function stopper** at the function's end address, so a PC landing in a gap
resolves to a stopper and the walk stops cleanly. Because `.text` is densely
packed, gaps are rare, so stoppers add far fewer rows than the eliminated FDE index
(24 B/function) saved - a net ~⅓ reduction in unwind-table memory, one fewer BPF
map, and a single binary search per frame instead of two.

## Userspace ⇄ kernel: the UnwindMiss loop

The kernel cannot read `/proc/<pid>/maps` or parse ELF, so table loading is
**demand-driven** from userspace and triggered by the kernel:

1. **Kernel detects a gap.** During `do_sample`, if `rip` is in no known mapping
   for `tgid`, or the mapping's `exec_id` has no `EXECUTABLES` entry, it sets
   `miss` and submits `{tgid, cgroup_id}` to `UNWIND_MISSES`.
2. **Userspace records the miss.** The ringbuffer callback in
   [`src/app.rs`](../src/app.rs) inserts `tgid → cgroup_id` into `pending_misses`
   (a `Mutex<FxHashMap>`). A tgid maps to one cgroup; a re-miss before draining just
   keeps the latest.
3. **Cleanup tick services misses.** Every cleanup tick, the loop drains
   `pending_misses` and calls `UnwindLoader::ensure_pid(pid, cgroup_id, …)` for each.
4. **`ensure_pid` loads (or reloads) the process** ([`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs)):
   - Read `/proc/<pid>/maps`. If the read fails the process exited → `evict` it
     (release refs, delete `PROC_MAPPINGS`).
   - Compute a `maps_signature` (a digest over begin/end/offset/inode of the
     executable mappings). **If unchanged from the last load, return early.** This
     makes a _stable_ gap - the vDSO, or a non-ELF mapping at a fixed address - a
     cheap no-op: the kernel keeps re-missing on that PC every sample, but userspace
     recognizes the signature and does nothing. Note this only suppresses reloads
     while the maps are stable: a churning JIT that mmaps _fresh_ executable regions
     changes the signature and does trigger a reload each time (those regions are
     then classified `Failed`/unmapped, so they unwind to one frame). The
     symbolization side of the same workload is handled separately by a negative
     range cache (see [Draining samples and symbolization](#draining-samples-and-symbolization)).
   - For each executable mapping, `ensure_exec` parses the backing file's unwind
     info **once** (keyed by `exec_id`) and publishes its inner maps. New code from a
     `dlopen` changes the signature, so the reload picks it up.
   - Build the sorted `ProcessMappings` and write it to `PROC_MAPPINGS[tgid]`. This
     is written **even when empty**, so a process with no unwindable code stops being
     re-reported as a miss on every sample.
   - Update reference counts (`commit_refs`).

The crucial property: the kernel's only job is to _notice_ it lacks data and name
the culprit; it never blocks. Userspace reconciles lazily and idempotently. A
process is typically fully loaded within one cleanup tick of its first sample, and
its subsequent samples unwind in-kernel with no userspace involvement.

### Reading the backing file

`ensure_pid` opens each library through `/proc/<pid>/map_files/<begin>-<end>`
rather than the path string from `maps`. That symlink resolves to the exact mapped
inode **inside the target's mount namespace** (so containerized / SLURM-jobstep
workloads resolve correctly) and survives the file being unlinked or replaced on
disk.

### Mapping a runtime PC to a module VA

For each executable mapping, the loader must compute the `load_offset` that turns a
runtime PC into the module virtual address the unwind table is keyed by
(`mva = pc - load_offset`). That requires picking the ELF `PT_LOAD` segment the
`/proc/<pid>/maps` line belongs to, via `proc_maps::segment_for_mapping`.

There is a subtle, easy-to-get-wrong detail here. The kernel rounds a segment's
`p_offset` **down to a page boundary** when it `mmap`s a `PT_LOAD`, and that rounded
value is the `offset` column in `/proc/<pid>/maps`. A `PT_LOAD`'s `p_offset` is only
page-aligned in the file when the binary is linked with `-z separate-code` usually the default,
but **not** guaranteed. Some linker configurations pack segments so the
executable `PT_LOAD` starts mid-page; then the `file_offset` reported in `maps` is
the page _below_ `p_offset`.

So the segment is selected by testing whether the mapping's file range
`[file_offset, file_offset + (end - begin))` **overlaps** the segment's file range
`[p_offset, p_offset + p_filesz)` - _not_ whether the segment contains
`file_offset`. A containment test fails on a non-page-aligned executable segment and
the mapping is dropped from `PROC_MAPPINGS` entirely, which silently collapses every
stack with a PC in that file to its leaf frame (no parent) while correctly
page-aligned libraries keep unwinding - and since symbolization does its own segment
math (blazesym), the symptom looks like a pure unwinder bug confined to one binary.
This regressed exactly once (a non-`separate-code` main binary on Rocky Linux 9);
`compute_load_offset` itself was always correct once the right segment is chosen,
because no executed instruction lives in the sub-page of rounding slack before
`p_offset`.

## Building the unwind tables from `.eh_frame`

[`src/profiling/unwind.rs`](../src/profiling/unwind.rs) (`parse_executable` → `build_from_object`) turns
one ELF into `(fde_count, Vec<UnwindRow>)` plus its executable `PT_LOAD` segments
(`fde_count` is informational - the number of functions with unwind info - surfaced
as the `unwind.fdes` metric; the kernel keeps no FDE index):

1. **Require both sections.** `.eh_frame` and `.eh_frame_hdr` must be present. If
   either is missing (or the hdr search table is empty), the file yields an empty
   table → it unwinds to a single frame. We deliberately do _not_ rebuild the search
   table ourselves.
2. **Walk the linker's sorted index.** `.eh_frame_hdr` already contains a
   sorted-by-PC, one-entry-per-function table mapping a PC to its FDE. Iterating it
   (via `gimli`) yields FDEs in ascending-PC order **for free** - no sorting on our
   side, which is exactly the order the kernel binary-search needs.
3. **Evaluate each FDE's CFI program** into rows (one row per address range where
   the rule set is constant) with `gimli`'s `UnwindContext`, appending them to the
   single growing flat table.
4. **Classify each row** (`classify_row`) into the compact 16-byte form. Only the
   handful of rules expressible in that form are kept:
   - CFA = `rsp`/`rbp` + offset (offset must fit `i16`),
   - return address at `*(CFA - 8)`,
   - caller `rbp` saved at a CFA-relative offset, or left unchanged.
   - **Anything else** - DWARF expressions, PLT trampolines, frames larger than an
     `i16` CFA offset, signal frames, non-standard RA rules - becomes a **stopper
     row** (`CFA_UNSUPPORTED`). The walk ends there, yielding a partial-but-correct
     stack rather than a guessed one.
5. **Collapse adjacent identical rules** (`same_rules`) _within_ a function, keeping
   the table small; adjacent functions are never collapsed across the boundary so
   their ranges stay distinguishable.
6. **Bridge gaps with stoppers.** When a function doesn't start exactly where the
   previous one ended (a gap, or a skipped no-row function), append a stopper at the
   previous function's end; likewise terminate the final function. This is what lets
   the single flat array replace the old FDE-index bound check.

The result is published by `publish_exec` → `publish_inner_maps`
([`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs)): one inner array map (the flat
row table) is created and inserted into `UNWIND_ROWS`. A file whose rows exceed
`MAX_ROWS_PER_EXEC` (4 Mi) is rejected (one frame only) rather than allocating
absurdly. Either way an `EXECUTABLES` entry is written - even for an unparseable
file - so the kernel sees a definitive "one frame" answer and stops re-missing.

## Draining samples and symbolization

On each profile tick, `Profiler::collect` ([`src/profiling/mod.rs`](../src/profiling/mod.rs))
runs synchronously against the maps:

1. **`drain_maps`** snapshots the `STACK_COUNTS` keys up front (deleting
   mid-iteration would reset the kernel's key cursor), then `lookup_and_delete`s each
   entry. For each key it resolves the stack id against `STACKS` (cached so each id is
   read once), and groups the samples by `cgroup_id` then by `tgid`. Addresses are
   only meaningful within a process' address space, hence the `tgid` grouping.
2. **Free stack slots.** After draining, every referenced `stack_id` is deleted from
   `STACKS` (multiple count entries can share an id, so this is done once per id).
3. **Ensure caches.** For each cgroup, ensure a `CgroupCache` exists (resolving the
   cgroup's name/meter via the registry; `None` → root or vanished cgroup, which
   Pyroscope rejects anyway, so it is dropped from the batch).
4. **Symbolize in parallel** (below), then `build_profile` encodes each cgroup's
   samples from the now-warm caches.

### Parallel symbolization

blazesym's `Symbolizer` holds a `RefCell` and (via its default `dwarf` feature) an
`Rc`, so it is **neither `Send` nor `Sync`** - it can be neither shared across
threads nor moved into one. Symbolization is therefore parallelized by giving each
worker its **own** short-lived `Symbolizer`, and `collect` is staged so the shared
per-cgroup caches are only ever touched on the `collect` thread - no cache locking:

1. **Build the request queue** (`Profiler::build_requests`, serial, reads caches).
   For each `(cgroup, tgid)` it unions the _query_ addresses across all that
   process' stacks, dropping any already in the frame LRU or in a known-bad range
   (below), and emits one `SymRequest { cgroup_id, tgid, cgroup_name, addrs }` per
   process with work to do. Batching per process (not per stack) means one blazesym
   call per process and a clean unit of parallelism.
2. **Dispatch** (`resolve_parallel`, parallel, touches no shared state). Each request
   is run on a `tokio::task::spawn_blocking` worker, bounded to
   `symbolize_parallelism()` (= CPU count) concurrent parses via a `Semaphore` so
   blazesym doesn't spin up a parse per process. `resolve_request` builds a private
   `Symbolizer`, symbolizes, converts results to owned `Frame`s (blazesym's
   `Symbolized<'src>` borrows the symbolizer, so this must happen before the worker
   returns), and drops the symbolizer - releasing its open fds - when done.
3. **Fold results back** (`CgroupCache::apply`, serial, writes caches). Inserts the
   resolved frames into the LRU and records discovered bad ranges.
4. **`build_profile`** then resolves each stack's frames with `lookup_frames`, a pure
   cache read (every miss was just filled, so it never symbolizes; a still-missing
   address - a worker that hit `NotFound`, or panicked - renders as `[unknown]`).

Because each worker's symbolizer is dropped at the end of the drain, blazesym's
fds never accumulate across drains, so there is **no shared symbolizer and no TTL
rebuild** (the previous design's mechanism for bounding fd growth). The cost is that
two processes mapping the same library in the same drain each parse it in their own
worker; this is rare in steady state because the frame LRU means a hot address only
misses (and thus only symbolizes) the first time it is seen per process.

Address handling within a worker (`resolve_request` / `resolve_each`):

- The **leaf** (`addrs[0]`) is the sampled PC, symbolized at its exact address; every
  **other frame** is a return address symbolized at `addr - 1` (see `query_addr`) so
  it lands inside the calling instruction rather than the next function.
- Inline frames are expanded into a leaf-first `Vec<FrameLine>` per address
  (`Frame::from_symbolized`), reordering blazesym's outermost-first inline reporting
  to pprof's innermost-first convention.
- A whole-batch failure (process gone = `NotFound`, permission denied) resolves
  **nothing**, so it's retried next interval. `NotFound` is silent (exited processes
  are normal); others are logged.
- `InvalidData` means an address points at bytes blazesym can't parse as ELF -
  almost always a `memfd`/JIT region or a non-ELF mapping (e.g. a Wine PE/DLL). In a
  _batch_ it fails the _entire_ batch even if only one address is bad, so
  `resolve_each` retries address-by-address to isolate the offender; a _single_-frame
  request hits the same error directly. Either way the offender is fed to the
  **negative range cache** below rather than cached as a lone address.
- A per-address `Unknown` (stripped/anonymous, but still ELF-backed) **is** cached
  as `Frame::unknown`, to avoid re-querying that stable address every interval.

### The negative range cache (non-ELF / JIT regions)

Per-address caching cannot help a region whose **addresses churn**: a JIT engine or
a Wine module continuously emits code at fresh addresses, so each drain brings a
brand-new `(pid, address)` that misses the frame cache and re-hits blazesym (which
re-reads `/proc/<pid>/maps`, finds no on-disk ELF, and fails with `InvalidData`).
The fix is to negative-cache the **enclosing mapping**, not the address.

`CgroupCache::bad_ranges` is a per-pid list of `[begin, end)` ranges known to be
un-symbolizable. When a worker (`resolve_request` single, or `resolve_each` batch
isolation) sees an `InvalidData` address, `mark_bad_range` reads `/proc/<tgid>/maps`
once ([`proc_maps::range_containing`](../src/profiling/proc_maps.rs) - which considers _all_
mappings, not just executable ELF) and records the enclosing range into the
worker's `SymResult`; `apply` then folds it into the cgroup's `bad_ranges`.
Thereafter `build_requests` filters any query address inside a bad range _before_
dispatch (and `lookup_frames` renders it `[unknown]`), so it never reaches blazesym.
A churning region thus costs **one** discovery (a single failed `symbolize_single`
plus one maps read) and is silent afterward, instead of one failed symbolization per
sample per drain.

Entries are added only for pids that actually run such code, so the structure stays
small (a process' handful of JIT regions). They are dropped when the `CgroupCache`
is evicted, and additionally **every `BAD_RANGE_TTL` (60 s)** all cgroups'
`bad_ranges` are cleared (in `Profiler::retain_live`) and re-evaluated, so a JIT
region that was unmapped and replaced by real ELF code isn't suppressed forever.
The same `(pid, address)` reuse caveat as the frame cache otherwise applies.

### The frame cache

`CgroupCache::frames` is a bounded **LRU** keyed by `(tgid, address)`, capacity
`SYMBOL_CACHE_CAPACITY = 32_768`, persisted across drains so recurring hot stacks
are not re-symbolized every interval - only genuinely new addresses ever pay for a
symbolize/parse, in the parallel phase above.

Two deliberate staleness properties:

- The workers **never** ask blazesym to freeze VMAs (`Symbolizer::cache()` is never
  called), so `/proc/<pid>/maps` is re-read on every call and code mapped later
  (`dlopen`) resolves fine.
- But cached frames are keyed by `(pid, address)`, so a **PID reused** by a
  different process within a still-live cgroup - or the rare same-address remap -
  can be misattributed until the cgroup is evicted. Accepted trade-off.

There is no long-lived symbolizer to bound: each drain's workers build and drop
their own, so blazesym's per-file open fds never outlive a single `collect`.

### String interning

A cached `Frame` is a `Vec<FrameLine>` (one per inline level), each `FrameLine`
holding a function name and a source-file path. The same name/path otherwise
repeats once per inline line, per process, and per cgroup - so across many cgroups
the frame caches hold huge numbers of duplicate strings. `FrameLine.name`/`.file`
are therefore `Arc<str>` deduplicated through a process-wide `StringInterner`
([`src/profiling/symbolize.rs`](../src/profiling/symbolize.rs)), shared with the symbolization workers
(behind an `Arc`) so they intern as they build frames. A side benefit: cloning a
cached `Frame` (which `lookup_frames` does per stack) is now a handful of refcount
bumps instead of deep string copies.

The interner is a `DashMap<u64 content-hash, Vec<Weak<str>>>`. The **`Weak`**
values are the key design point: a strong interner would pin every string it ever
saw (the union of all binaries' symbol names - unbounded growth), whereas a string
here is freed once the last `Frame` referencing it is evicted. It is keyed by hash
rather than by the `Arc<str>` itself precisely because an owning key would pin the
string; hash collisions share a bucket and are disambiguated by content. Dead weak
entries are pruned opportunistically when a bucket is touched and swept wholesale
in `Profiler::retain_live` (each cleanup tick, right after dead cgroups' caches are
dropped). The ubiquitous `[unknown]` name and the empty path are shared via a
`OnceLock` rather than the interner, since they recur in nearly every unresolved
frame and have no `CodeInfo` to key on.

## pprof construction and the push to Pyroscope

`build_profile` feeds resolved frames into a `ProfileBuilder` that emits a
`google.v1.Profile` (standard pprof). It interns strings, functions (`(name,
file)`), and locations (`(tgid, address)` - addresses are only unique within a
process). Each sample carries two values: `samples/count` and `cpu/nanoseconds`
(`count * period_ns`), with the period derived from the sampling frequency.

`Pusher::push` sends one `push.v1.RawProfileSeries` **per cgroup** to Pyroscope's
`push.v1.PusherService/Push` RPC (Connect protocol, protobuf body). The pprof bytes
are gzipped (`raw_profile`). Labels:

- `__name__ = process_cpu`
- `service_name = <cgroup name>` - so Grafana groups profiles by the SLURM job /
  workload,
- `exporter = hpc-otel-exporter`,
- `hostname = <node>`.

The push is spawned onto a separate tokio task (`Pusher` is cheap to clone and holds
no symbolization state), so the event loop never blocks on network IO.

## Per-cgroup scoping

A **cgroup is the unit of a workload** here (a SLURM job / job step). Profiles,
metrics, caches, and miss attribution are all scoped per cgroup id
(`bpf_get_current_cgroup_id()`), so per-job flamegraphs are produced without a
per-job agent.

The scoping is threaded through every layer:

- **Kernel:** `StackKey` and `UnwindMiss` both carry `cgroup_id`. Aggregation in
  `STACK_COUNTS` is already per-cgroup.
- **Cgroup identity:** `CgroupRegistry` ([`src/cgroup.rs`](../src/cgroup.rs))
  is the single source of truth. `get_or_create(cgroup_id)` resolves the id (a cgroup
  directory inode) to a human name by walking `/sys/fs/cgroup` (`resolve_cgroup_name`)
  and lazily creates one `SdkMeterProvider` per cgroup, shared by IO metrics, the
  profiler, and the unwind loader. The root cgroup (empty name) returns `None` and is
  skipped everywhere.
- **Symbolization:** one `CgroupCache` per cgroup - its own LRU frame cache and its
  own `ProfilingMetrics` bound to a constant `cgroup.name` attribute. (The blazesym
  symbolizer itself is shared; only the frame cache is per-cgroup. Correctness is
  unaffected since blazesym keys its own state by file/pid.)
- **Unwind loader metrics:** `UnwindLoader::cgroup_metrics` holds one
  `UnwindMetrics` per cgroup, created on first load. Note that the unwind _tables_
  (`PROC_MAPPINGS`, `EXECUTABLES`, `UNWIND_ROWS`) are keyed by `tgid`/`exec_id`,
  **not** by cgroup - a file shared across cgroups is stored once - but the _load
  work_ is attributed to the cgroup whose sample triggered the miss, via the
  `cgroup_id` carried on the `UnwindMiss`. Alongside the cumulative load counters
  (`unwind.process_loads`/`libraries_read`/`libraries_failed`), `UnwindMetrics`
  carries resident-table **gauges** (`unwind.fdes`, `unwind.rows`,
  `unwind.table_bytes`, `unwind.executables`, `unwind.processes`) refreshed each
  cleanup tick by `UnwindLoader::record_table_gauges`. Because the tables are
  keyed by `exec_id`, these count each distinct file **once per cgroup that maps
  it**, so they measure a workload's unwind footprint, not the (smaller,
  deduplicated) total kernel allocation. `table_bytes` is `rows·sizeof(UnwindRow)`
  (the inner-map data size); `unwind.fdes` is the function count, informational
  only since the kernel no longer stores an FDE index.
- **Observability:** the demand-driven loading is traced. `ensure_pid` opens an
  `unwind.load_process` span (with child `unwind.read_library` spans per file
  parsed) and increments per-cgroup counters, all tagged `cgroup.name`. Symbolization
  opens a `profiling.symbolize` span. These reach OTel through the
  tracing-opentelemetry layer.

## Resource lifecycle and cleanup

Three classes of state are reclaimed, all driven from the single **cleanup tick** so
every feature prunes against one consistent liveness snapshot
(`registry.cleanup_dead_cgroups()` returns the `live: FxHashSet<u64>` of cgroup
ids).

### 1. When a cgroup exits

`cleanup_dead_cgroups` walks `/sys/fs/cgroup`, and for any tracked cgroup id no
longer present, shuts down and drops its `SdkMeterProvider` (stopping its metric
export). The returned `live` set is then handed to each feature's `retain_live`:

- `IoMetrics::retain_live` - drops IO instruments for dead cgroups.
- `Profiler::retain_live` - `self.cgroups.retain(live)` drops the dead cgroups'
  `CgroupCache` (frame LRU + bad-range negative cache + metrics), and every
  `BAD_RANGE_TTL` clears all surviving cgroups' negative-cache ranges.
- `UnwindLoader::retain_live` - drops dead cgroups' `UnwindMetrics`.

So a cgroup's **symbolization caches and metrics** are freed promptly when the
workload exits. (The kernel unwind tables are reclaimed per-process, below, not
per-cgroup.)

### 2. When a process exits

This is what frees the **map-in-map kernel memory**. Two paths, both in
[`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs):

- **Reactive:** if `ensure_pid` reads `/proc/<pid>/maps` and gets an error
  (process gone), it `evict`s immediately.
- **Proactive:** `evict_dead` runs every cleanup tick. It `stat`s `/proc/<pid>` for
  each tracked pid (cheap - no maps re-parse) and `evict`s the ones that vanished.

`evict(pid)`:

- deletes `PROC_MAPPINGS[tgid]` (so a reused PID re-loads fresh), and
- calls `release_exec` for each `exec_id` the process referenced.

**Reference counting** is the core mechanism. Each `ExecEntry::Mapped` carries a
`refs` count of live processes mapping that file. `commit_refs` bumps refs for newly
referenced files and releases refs for ones a process no longer maps (e.g. after a
`dlclose`-induced signature change). `release_exec` decrements; **when refs reach
zero** it:

- removes the `execs` bookkeeping entry,
- deletes `EXECUTABLES[exec_id]`, and
- if the file was published, deletes `UNWIND_ROWS[exec_id]` - which drops the
  kernel's last reference to that inner map, letting the kernel free it.

So shared libraries stay resident as long as _any_ live sampled process maps them,
and are freed the moment the last one exits - total kernel memory tracks the live
working set, with no arena and no leak on process churn.

### 3. PID reuse

Because `PROC_MAPPINGS` and the frame cache are keyed by tgid/pid, a recycled PID is
handled by: maps-signature change → `ensure_pid` reload on the next miss, and
`evict` on death deleting the stale `PROC_MAPPINGS`. The symbolization frame cache's
`(pid, address)` keying is the one place a brief misattribution window can exist for
a reused PID within a still-live cgroup (documented above).

## Tunables and caps

| Name                      | Where                                           | Value | Meaning                                                    |
| ------------------------- | ----------------------------------------------- | ----- | ---------------------------------------------------------- |
| `--profile-frequency`     | CLI                                             | 97 Hz | Per-CPU sampling frequency.                                |
| `--profile-interval-secs` | CLI                                             | 5 s   | Drain/symbolize/push period.                               |
| `--no-profiling`          | CLI                                             | off   | Disable the profiler entirely.                             |
| cleanup tick              | [`app.rs`](../src/app.rs)                       | 5 s   | Services misses, evicts dead state.                        |
| `MAX_STACK_DEPTH`         | shared                                          | 127   | Max frames per stack.                                      |
| `MAX_EXECUTABLES`         | shared                                          | 16384 | Distinct executables tracked (outer map cap).              |
| `MAX_ROWS_PER_EXEC`       | shared                                          | 4 Mi  | Per-file row cap; larger files → one frame.                |
| `MAX_MAPPINGS_PER_PROC`   | shared                                          | 192   | Per-process executable mappings tracked.                   |
| `SYMBOL_CACHE_CAPACITY`   | [`symbolize.rs`](../src/profiling/symbolize.rs) | 32768 | Per-cgroup LRU frame cache size.                           |
| `BAD_RANGE_TTL`           | [`symbolize.rs`](../src/profiling/symbolize.rs) | 60 s  | Negative-cache (JIT/non-ELF range) re-evaluation interval. |
| `symbolize_parallelism()` | [`symbolize.rs`](../src/profiling/symbolize.rs) | CPUs  | Max concurrent symbolization workers per drain.            |
| `UNWIND_SEARCH_ITERS`     | [`profiling.bpf.c`](../src/bpf/profiling.bpf.c) | 32    | `bpf_for` iterator cap for the flat row search.            |
| `MAPPING_SEARCH_ITERS`    | [`profiling.bpf.c`](../src/bpf/profiling.bpf.c) | 12    | `bpf_for` iterator cap for mapping search.                 |
| `STACKS` / `STACK_COUNTS` | [`profiling.bpf.c`](../src/bpf/profiling.bpf.c) | 16384 | Aggregation map capacities.                                |

## Security boundary

The profiler samples **untrusted** target processes, so symbolization is hardened
(see also the `security-boundary-untrusted-symbolization` memory):

- `process.perf_map = false` - ignore attacker-writable JIT `perf-<pid>.map` files.
- Symbol names are treated as **opaque strings only** - never interpreted, executed,
  or used in a path.
- Backing files are opened via `/proc/<pid>/map_files/...` (the kernel's view of the
  mapped inode), not via attacker-controllable path strings from `maps`.
- The in-kernel walker only ever issues `bpf_probe_read_user` (faulting reads of the
  target's own memory) and bounded map lookups; a malformed stack yields a partial or
  empty trace, never a kernel fault or out-of-bounds access (the verifier guarantees
  the latter).

---

_Implementation entry points:_ `do_sample`
([`src/bpf/profiling.bpf.c`](../src/bpf/profiling.bpf.c)),
`Profiler::collect` ([`src/profiling/mod.rs`](../src/profiling/mod.rs)),
`UnwindLoader::ensure_pid` ([`src/profiling/unwind_loader.rs`](../src/profiling/unwind_loader.rs)),
`parse_executable` ([`src/profiling/unwind.rs`](../src/profiling/unwind.rs)).
