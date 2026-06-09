//! Symbolization: turning the raw instruction addresses drained from the kernel
//! into named, source-located frames, with per-cgroup caching.
//!
//! The blazesym [`Symbolizer`] is neither `Send` nor `Sync`, so symbolization is
//! parallelized by giving each worker its own short-lived symbolizer
//! ([`resolve_parallel`]); the per-cgroup [`CgroupCache`]s (frame LRU + negative
//! range cache) are only ever touched on the orchestrating thread. Resolved frame
//! strings are deduplicated process-wide through a [`StringInterner`].
//!
//! Security note: the profiler symbolizes **untrusted** target processes, so
//! symbol names are treated as opaque strings only (never interpreted, executed,
//! or used in a path) and attacker-writable JIT maps are ignored — see the
//! `security-boundary-untrusted-symbolization` memory and docs/profiler.md.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use blazesym::Pid;
use blazesym::helper::{ElfResolver, read_elf_build_id};
use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{
    CodeInfo, Input, ProcessMemberInfo, ProcessMemberType, Resolve, Symbolized, Symbolizer,
};
use dashmap::DashMap;
use log::debug;
use lru::LruCache;
use opentelemetry::KeyValue;
use opentelemetry::metrics::BoundCounter;
use rustc_hash::FxBuildHasher;

use crate::cgroup::CgroupMeter;
use crate::telemetry::record_span_error;

use super::debuginfod::DebuginfodClient;
use super::perf_event::num_configured_cpus;
use super::proc_maps;

/// Per-cgroup symbol cache capacity (number of distinct (pid, address) frames).
/// Bounds memory for long-lived workloads; a CPU flamegraph rarely has more than
/// a few thousand distinct frames, so this comfortably holds the hot set.
const SYMBOL_CACHE_CAPACITY: usize = 32_768;

/// How long a negative-cache range (a `memfd`/JIT mapping found un-symbolizable)
/// is trusted before every cgroup's [`bad_ranges`](CgroupCache::bad_ranges) are
/// cleared and re-evaluated. A JIT region can be unmapped and a different mapping
/// placed at the same address, so we periodically forget these so a re-used range
/// is given another chance rather than resolving to `[unknown]` forever.
pub(crate) const BAD_RANGE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on backing-file parses happening at once during a drain. Each
/// parallel symbolization worker builds its own blazesym [`Symbolizer`] (the type
/// is neither `Send` nor `Sync`, so it can't be shared) and parsing ELF/DWARF is
/// CPU-bound, so we cap concurrency at the CPU count rather than letting tokio's
/// blocking pool spin up a worker per process.
fn symbolize_parallelism() -> usize {
    num_configured_cpus().max(1) as usize
}

/// Per-cgroup symbol cache, persisted across drains so that recurring hot stacks
/// are not re-symbolized every interval.
///
/// The blazesym [`Symbolizer`] itself is *shared* across all cgroups (its
/// per-instance memory footprint is too high to keep one per cgroup); only this
/// bounded frame cache is per-cgroup. Symbolization correctness is unaffected —
/// blazesym keys its internal state by file/pid — and symbol names are still
/// treated as opaque strings (see the module-level security note).
///
/// # Cache staleness
///
/// `symbolize()` re-reads `/proc/<pid>/maps` on every call (we never call
/// [`Symbolizer::cache`], so VMAs are never frozen), so newly mapped code (e.g.
/// `dlopen`) resolves fine. We do cache resolved frames per `(pid, address)`,
/// so a pid reused by a different process — or the rare case of the same address
/// being re-mapped to different code — within a still-live cgroup may be
/// misattributed until the cgroup is evicted.
pub(crate) struct CgroupCache {
    /// Shared per-cgroup meter; also the source of the cgroup's resolved
    /// `service_name` (cached here to avoid re-walking `/sys/fs/cgroup`).
    pub(crate) meter: Arc<CgroupMeter>,
    pub(crate) metrics: ProfilingMetrics,
    /// (pid, instruction address) -> resolved frame. Bounded LRU so a
    /// long-running workload can't grow the cache without limit.
    pub(crate) frames: LruCache<(u32, u64), Frame>,
    /// Per-pid address ranges known to be un-symbolizable: `memfd`/JIT regions
    /// and non-ELF mappings (e.g. Wine PE/DLLs) that blazesym fails with
    /// `InvalidData`. Such regions churn through fresh addresses, so the
    /// per-`(pid, address)` [`frames`](Self::frames) cache never hits and every
    /// drain would re-hammer blazesym. We negative-cache the whole *mapping*
    /// instead: any query address inside one resolves straight to `[unknown]`
    /// without touching the symbolizer. Entries persist for the cgroup's
    /// lifetime (freed when its `CgroupCache` is dropped on eviction) and are
    /// only ever added for pids that actually run such code, so this stays
    /// small. The per-pid range list mirrors a process' few JIT regions.
    pub(crate) bad_ranges: HashMap<u32, Vec<(u64, u64)>>,
}

/// Per-cgroup profiler metrics, reported through the cgroup's shared
/// [`CgroupMeter`]. All counters are monotonic sums bound to a constant
/// `cgroup.name` attribute (mirroring the IO metrics), so series can be grouped
/// by cgroup even though each cgroup already has its own provider. Binding once
/// avoids the per-recording attribute lookup, just like the IO histograms.
pub(crate) struct ProfilingMetrics {
    pub(crate) profiles_collected: BoundCounter<u64>,
    pub(crate) samples_collected: BoundCounter<u64>,
    pub(crate) symbolize_invocations: BoundCounter<u64>,
    pub(crate) frames_resolved: BoundCounter<u64>,
    pub(crate) frame_cache_hits: BoundCounter<u64>,
    pub(crate) lru_insertions: BoundCounter<u64>,
    pub(crate) lru_evictions: BoundCounter<u64>,
}

impl ProfilingMetrics {
    fn new(cgroup: &CgroupMeter) -> Self {
        let meter = &cgroup.meter;
        let attrs = [KeyValue::new("cgroup.name", cgroup.name.clone())];
        ProfilingMetrics {
            profiles_collected: meter
                .u64_counter("profiling.profiles.collected")
                .with_description("CPU profiles built and queued for push")
                .build()
                .bind(&attrs),
            samples_collected: meter
                .u64_counter("profiling.samples.collected")
                .with_description("CPU stack samples drained from the kernel")
                .build()
                .bind(&attrs),
            symbolize_invocations: meter
                .u64_counter("profiling.symbolize.invocations")
                .with_description("Calls into blazesym to symbolize a batch of addresses")
                .build()
                .bind(&attrs),
            frames_resolved: meter
                .u64_counter("profiling.symbolize.frames_resolved")
                .with_description("Addresses symbolized (frame cache misses)")
                .build()
                .bind(&attrs),
            frame_cache_hits: meter
                .u64_counter("profiling.symbolize.cache_hits")
                .with_description("Address lookups served from the frame cache")
                .build()
                .bind(&attrs),
            lru_insertions: meter
                .u64_counter("profiling.symbolize.lru_insertions")
                .with_description("New frames inserted into the LRU cache")
                .build()
                .bind(&attrs),
            lru_evictions: meter
                .u64_counter("profiling.symbolize.lru_evictions")
                .with_description("Cached frames evicted from LRU")
                .build()
                .bind(&attrs),
        }
    }
}

/// Build a fresh blazesym symbolizer configured for code-info + inline frames.
/// One is built per symbolization worker per drain (the type is neither `Send`
/// nor `Sync`, so it can't be cached or shared) and dropped when the worker
/// finishes, so its open fds never outlive a single drain.
///
/// When a [`DebuginfodClient`] is configured, a process-member dispatcher is
/// installed so each file-backed mapping is symbolized against debuginfod-fetched
/// debug info where available, falling back to blazesym's default resolver (local
/// debug info, then symtab) otherwise — see [`dispatch_debuginfod`].
fn build_symbolizer(debuginfod: Option<Arc<DebuginfodClient>>) -> Symbolizer {
    let builder = Symbolizer::builder()
        .enable_auto_reload(true)
        .enable_code_info(true)
        .enable_demangling(true)
        .enable_inlined_fns(true);
    let builder = match debuginfod {
        Some(client) => {
            // blazesym calls the dispatcher synchronously while symbolizing, so
            // the async fetch is bridged with `Handle::block_on`. This is sound
            // because `resolve_request` runs the symbolizer on a `spawn_blocking`
            // thread (not inside an async task), where blocking on the runtime is
            // allowed. Captured once here so every dispatch reuses it.
            let handle = tokio::runtime::Handle::current();
            builder.set_process_dispatcher(move |info| dispatch_debuginfod(info, &client, &handle))
        }
        None => builder,
    };
    builder.build()
}

/// blazesym process-member dispatcher: for each file-backed mapping, fetch its
/// split debug info from a debuginfod server (by GNU build ID) and symbolize
/// against that. Returning `Ok(None)` falls back to blazesym's default resolver,
/// so a mapping with no build ID, a build ID no server knows, or any single
/// fetch failure degrades to the existing local-debug-info behavior rather than
/// failing the whole process' symbolization.
///
/// Runs on the worker's `spawn_blocking` thread; the network fetch is driven on
/// the current tokio runtime via `handle.block_on`.
fn dispatch_debuginfod(
    info: ProcessMemberInfo<'_>,
    client: &DebuginfodClient,
    handle: &tokio::runtime::Handle,
) -> Result<Option<Box<dyn Resolve>>, blazesym::Error> {
    // Only file-backed mappings have an on-disk ELF carrying a build ID; [vdso],
    // JIT, and other anonymous members have nothing to fetch.
    let ProcessMemberType::Path(entry) = info.member_entry else {
        return Ok(None);
    };

    // Read the build ID from the target's *own* copy of the binary (maps_file is
    // a `/proc/<pid>/map_files/` path, so it resolves inside the target's mount
    // namespace and survives unlinked files).
    let Some(build_id) = read_elf_build_id(&entry.maps_file)? else {
        // No GNU build ID (e.g. Rust/Go binaries): nothing to look up.
        return Ok(None);
    };

    let path = match handle.block_on(client.fetch_debug_info(&build_id)) {
        Ok(Some(path)) => path,
        // No server had it: let the default resolver try local debug info.
        Ok(None) => return Ok(None),
        // A fetch error must not abort symbolization of the whole process.
        Err(e) => {
            debug!("debuginfod fetch failed: {e:#}");
            return Ok(None);
        }
    };

    // A corrupt/unreadable fetched file likewise degrades to the default
    // resolver rather than failing the mapping.
    match ElfResolver::open(&path) {
        Ok(resolver) => Ok(Some(Box::new(resolver))),
        Err(e) => {
            debug!("failed to open fetched debug info {}: {e}", path.display());
            Ok(None)
        }
    }
}

/// The address blazesym is queried at for stack slot `i`. The leaf (`i == 0`) is
/// the sampled PC and is queried exactly; every caller frame is a *return*
/// address pointing just past a `call`, so it is queried at `addr - 1` to land
/// inside the calling instruction rather than the next function or padding.
pub(crate) fn query_addr(i: usize, a: u64) -> u64 {
    if i == 0 { a } else { a.wrapping_sub(1) }
}

impl CgroupCache {
    pub(crate) fn new(meter: Arc<CgroupMeter>) -> Self {
        let capacity = NonZeroUsize::new(SYMBOL_CACHE_CAPACITY).expect("capacity is non-zero");
        let metrics = ProfilingMetrics::new(&meter);
        CgroupCache {
            meter,
            metrics,
            frames: LruCache::new(capacity),
            bad_ranges: HashMap::new(),
        }
    }

    /// Whether `addr` falls in a mapping previously found un-symbolizable for
    /// `tgid` (a `memfd`/JIT or non-ELF region). Such addresses are resolved to
    /// `[unknown]` without ever reaching blazesym.
    pub(crate) fn in_bad_range(&self, tgid: u32, addr: u64) -> bool {
        self.bad_ranges
            .get(&tgid)
            .is_some_and(|ranges| ranges.iter().any(|&(b, e)| addr >= b && addr < e))
    }

    /// Resolve one stack's addresses to leaf-first frames from the cache only.
    /// By the time [`build_profile`](super::Profiler::build_profile) calls this
    /// the cache misses have already been resolved in parallel and folded in by
    /// [`collect`](super::Profiler::collect), so this never touches a symbolizer:
    /// a hit returns the cached frame; anything still missing (a known-bad range,
    /// or an address a failed/panicked worker left unresolved) becomes a single
    /// `[unknown]` frame. An empty stack (the kernel couldn't walk it) is
    /// likewise one unknown frame.
    pub(crate) fn lookup_frames(&mut self, tgid: u32, addrs: &[u64]) -> Vec<Frame> {
        if addrs.is_empty() {
            return vec![Frame::unknown()];
        }
        let mut hits = 0u64;
        let frames = addrs
            .iter()
            .enumerate()
            .map(|(i, &a)| {
                let qa = query_addr(i, a);
                if let Some(frame) = self.frames.get(&(tgid, qa)) {
                    hits += 1;
                    frame.clone()
                } else {
                    // A bad-range address was intentionally never resolved; count
                    // it as a hit (it needed no symbolization), like the old
                    // single-pass path did, but still render it unknown.
                    if self.in_bad_range(tgid, qa) {
                        hits += 1;
                    }
                    Frame::unknown()
                }
            })
            .collect();
        self.metrics.frame_cache_hits.add(hits);
        frames
    }

    /// Fold one worker's [`SymResult`] back into this cgroup's caches: insert the
    /// resolved frames into the LRU and record any negative-cache ranges the
    /// worker discovered. Runs serially in [`collect`](super::Profiler::collect),
    /// so it needs no locking. A whole-batch failure (process gone) resolved
    /// nothing and is retried next drain; a per-address `Unknown` (stripped) is
    /// cached as unknown so it isn't re-queried. Symbol names are treated as
    /// opaque strings only — see the module-level security note.
    pub(crate) fn apply(&mut self, res: SymResult) {
        let tgid = res.tgid;
        self.metrics
            .symbolize_invocations
            .add(res.symbolize_invocations);
        for (begin, end) in res.bad_ranges {
            // One request per pid, so no worker raced this one; but a previous
            // drain may already know the region.
            if !self.in_bad_range(tgid, begin) {
                self.bad_ranges.entry(tgid).or_default().push((begin, end));
            }
        }
        for (addr, frame) in res.resolved {
            let key = (tgid, addr);
            let mut inserted_new_key = true;
            if let Some(prev) = self.frames.push(key, frame) {
                if prev.0 != key {
                    self.metrics.lru_evictions.add(1);
                } else {
                    inserted_new_key = false;
                }
            }
            if inserted_new_key {
                self.metrics.lru_insertions.add(1);
            }
        }
    }
}

/// One process' worth of cache-miss addresses to symbolize, dispatched to a
/// blocking worker. `addrs` are *query* addresses (see [`query_addr`]), already
/// deduplicated and known to miss the cgroup's caches at dispatch time.
pub(crate) struct SymRequest {
    pub(crate) cgroup_id: u64,
    pub(crate) tgid: u32,
    /// The cgroup's resolved name, for the worker's `profiling.symbolize` span.
    pub(crate) cgroup_name: String,
    pub(crate) addrs: Vec<u64>,
}

/// The result of one [`SymRequest`], folded back into the cgroup's caches by
/// [`CgroupCache::apply`]. Fully owned so it can cross the worker's thread
/// boundary (blazesym's borrowed `Symbolized` is converted to [`Frame`] first).
pub(crate) struct SymResult {
    pub(crate) cgroup_id: u64,
    tgid: u32,
    /// `(query address -> resolved frame)` to insert into the LRU. Includes
    /// `[unknown]` frames for stripped-but-stable addresses.
    resolved: Vec<(u64, Frame)>,
    /// Mappings found un-symbolizable (`memfd`/JIT) to negative-cache.
    bad_ranges: Vec<(u64, u64)>,
    /// blazesym calls made, for the `symbolize_invocations` metric.
    symbolize_invocations: u64,
}

/// Resolve every [`SymRequest`] in parallel on blocking threads — bounded to
/// [`symbolize_parallelism`] concurrent parses — and collect the [`SymResult`]s.
///
/// Each worker builds its **own** blazesym [`Symbolizer`]: the type is neither
/// `Send` nor `Sync`, so it can be neither shared across nor moved between
/// threads. It is dropped when the worker finishes, releasing its open fds, so
/// nothing accumulates across drains. No locking is needed: workers touch no
/// shared cache — the per-cgroup caches are read before dispatch (to build the
/// requests) and written after join (to fold results in). Per the module note,
/// repeated parsing of the same file by concurrent workers is rare because the
/// frame LRU keeps a hot address from missing in two processes at once.
pub(crate) async fn resolve_parallel(
    requests: Vec<SymRequest>,
    interner: &Arc<StringInterner>,
    debuginfod: Option<&Arc<DebuginfodClient>>,
) -> Vec<SymResult> {
    if requests.is_empty() {
        return Vec::new();
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(symbolize_parallelism()));
    let mut handles = Vec::with_capacity(requests.len());
    for req in requests {
        // Acquire before spawning so at most `parallelism` symbolizers parse at
        // once; the permit rides into the task and frees its slot on completion.
        // A debuginfod fetch blocks its worker (and so holds a permit) only until
        // the file is cached the first time; later drains hit the on-disk cache.
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let interner = Arc::clone(interner);
        let debuginfod = debuginfod.cloned();
        handles.push(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolve_request(req, &interner, debuginfod)
        }));
    }
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(res) => results.push(res),
            // A panicked worker loses just its process' frames this drain; they
            // stay cache-missing and are retried next interval.
            Err(e) => debug!("symbolization worker failed: {e}"),
        }
    }
    results
}

/// Symbolize one process' addresses on a blocking thread with a fresh, private
/// [`Symbolizer`]. Pure with respect to shared state: it returns the frames to
/// cache plus any negative-cache ranges it found, for [`CgroupCache::apply`] to
/// fold in. Mirrors the old in-place resolver's batch/`InvalidData`/`NotFound`
/// handling, writing into the owned [`SymResult`] instead of a borrowed cache.
fn resolve_request(
    req: SymRequest,
    interner: &StringInterner,
    debuginfod: Option<Arc<DebuginfodClient>>,
) -> SymResult {
    let SymRequest {
        cgroup_id,
        tgid,
        cgroup_name,
        addrs,
    } = req;

    let mut out = SymResult {
        cgroup_id,
        tgid,
        resolved: Vec::new(),
        bad_ranges: Vec::new(),
        symbolize_invocations: 0,
    };

    let symbolizer = build_symbolizer(debuginfod);
    let mut process = Process::new(Pid::from(tgid));
    // Harden against untrusted targets: ignore attacker-writable JIT maps.
    process.perf_map = false;
    process.debug_syms = true;
    process.map_files = true;

    // Span the blazesym work: it parses user binaries (expensive) and fails in
    // ways worth seeing (process gone, permission denied, stripped files).
    // blazesym's own `tracing` spans nest under this via the per-thread span
    // stack; since this runs on a dedicated blocking thread there is no `.await`
    // while the guard is held, so entering it here is sound. (spawn_blocking does
    // not inherit the caller's span, so this is a root span — as before, since
    // `collect` was uninstrumented.)
    let span = tracing::info_span!(
        "profiling.symbolize",
        "cgroup.name" = cgroup_name.as_str(),
        "process.pid" = tgid,
        "symbolize.addresses" = addrs.len(),
        "otel.status_code" = tracing::field::Empty,
        "otel.status_description" = tracing::field::Empty,
    );
    let _entered = span.enter();

    // NB: do not call `Symbolizer::cache()` — that would freeze this pid's VMA
    // map and stop `/proc/<pid>/maps` from being re-read, breaking resolution of
    // code mapped later (e.g. `dlopen`). Plain `symbolize()` re-reads every call.
    out.symbolize_invocations += 1;
    let symbolized = match addrs.len() {
        1 => match symbolizer
            .symbolize_single(&Source::Process(process.clone()), Input::AbsAddr(addrs[0]))
        {
            Ok(s) => vec![s],
            Err(e) => {
                match e.kind() {
                    blazesym::ErrorKind::NotFound => (),
                    // A lone address in a non-ELF / memfd-backed (JIT) region.
                    // These churn through fresh addresses, so the per-address
                    // frame cache never helps; negative-cache the whole mapping.
                    blazesym::ErrorKind::InvalidData => {
                        debug!("symbolization failed for pid {tgid}: {e}");
                        mark_bad_range(&mut out.bad_ranges, tgid, addrs[0]);
                    }
                    _ => debug!("symbolization failed for pid {tgid}: {e}"),
                }
                record_span_error(&span, &e);
                return out;
            }
        },
        _ => {
            match symbolizer.symbolize(&Source::Process(process.clone()), Input::AbsAddr(&addrs)) {
                Ok(s) => s,
                Err(e) => {
                    match e.kind() {
                        // Don't log on processes that disappeared, it's just noise.
                        blazesym::ErrorKind::NotFound => (),
                        // A single address pointing at data blazesym can't parse fails
                        // the *entire* batch. The usual culprit is JIT code in a
                        // memfd-backed region (no on-disk ELF); isolate it below.
                        blazesym::ErrorKind::InvalidData => {
                            debug!(
                                "batch symbolization failed, retrying individually: pid {tgid}: {e}"
                            );
                            record_span_error(&span, &e);
                            resolve_each(&mut out, &symbolizer, &process, tgid, &addrs, interner);
                            return out;
                        }
                        _ => {
                            debug!("symbolization failed for pid {tgid}: {e}");
                            record_span_error(&span, &e);
                        }
                    }
                    return out;
                }
            }
        }
    };

    for (&addr, sym) in addrs.iter().zip(symbolized) {
        out.resolved
            .push((addr, Frame::from_symbolized(addr, &sym, interner)));
    }
    out
}

/// Per-address fallback for a batch that failed with [`InvalidData`]: one address
/// points at data blazesym can't parse, but it doesn't say which. Symbolizing one
/// at a time isolates the offender, whose whole mapping is negative-cached (a
/// JIT/non-ELF region churns through fresh addresses, so caching the single
/// address is futile) while every other address resolves normally.
///
/// [`InvalidData`]: blazesym::ErrorKind::InvalidData
fn resolve_each(
    out: &mut SymResult,
    symbolizer: &Symbolizer,
    process: &Process,
    tgid: u32,
    addrs: &[u64],
    interner: &StringInterner,
) {
    for &addr in addrs {
        // An earlier address in this batch may have already negative-cached the
        // region this one lives in; don't re-query it.
        if out.bad_ranges.iter().any(|&(b, e)| addr >= b && addr < e) {
            continue;
        }
        out.symbolize_invocations += 1;
        // `symbolize_single` reports failures as `Err` rather than folding them
        // into `Symbolized::Unknown`, so we can tell the offending address apart
        // from a legitimately unresolvable one.
        let frame = match symbolizer
            .symbolize_single(&Source::Process(process.clone()), Input::AbsAddr(addr))
        {
            Ok(sym) => Frame::from_symbolized(addr, &sym, interner),
            // The process vanished mid-fallback: stop rather than caching stale
            // unknowns we'd never refresh.
            Err(e) if e.kind() == blazesym::ErrorKind::NotFound => return,
            // The offending address: a non-ELF / memfd (JIT) region. Negative-
            // cache the whole mapping rather than this lone churning address.
            Err(e) if e.kind() == blazesym::ErrorKind::InvalidData => {
                debug!(
                    "symbolization failed for pid {tgid} address 0x{addr:x}, \
                     negative-caching its region"
                );
                mark_bad_range(&mut out.bad_ranges, tgid, addr);
                continue;
            }
            // Otherwise unresolvable (e.g. stripped): cache as unknown so we don't
            // re-query this stable address every interval.
            Err(_) => {
                debug!(
                    "symbolization failed for pid {tgid} address 0x{addr:x}, caching as unknown"
                );
                Frame::unknown()
            }
        };
        out.resolved.push((addr, frame));
    }
}

/// Append the whole mapping containing `addr` (read from `/proc/<tgid>/maps`) to
/// `ranges` as un-symbolizable, so the region's churning addresses stop hitting
/// blazesym on every drain. Falls back to the single address if the enclosing
/// mapping can't be determined (process gone, address in no mapping). A no-op if
/// `addr` is already covered. The blocking `/proc` read is fine: this only runs
/// inside a [`spawn_blocking`](tokio::task::spawn_blocking) worker.
fn mark_bad_range(ranges: &mut Vec<(u64, u64)>, tgid: u32, addr: u64) {
    if ranges.iter().any(|&(b, e)| addr >= b && addr < e) {
        return;
    }
    let range = std::fs::read_to_string(format!("/proc/{tgid}/maps"))
        .ok()
        .and_then(|maps| proc_maps::range_containing(&maps, addr))
        .unwrap_or((addr, addr.saturating_add(1)));
    debug!("pid {tgid}: negative-caching un-symbolizable region {range:x?}");
    ranges.push(range);
}

/// Process-wide interner that deduplicates the symbol-name and source-file
/// strings held across every cgroup's frame cache. The same function name or file
/// path otherwise appears once per inline line, per process, and per cgroup;
/// interning collapses them to a single allocation shared by reference (and makes
/// [`Frame`] cheap to clone — a refcount bump instead of a deep string copy).
///
/// Values are [`Weak`], so an interned string is freed once the last [`Frame`]
/// referencing it is evicted from the caches: the interner never pins a string
/// nothing uses, unlike a strong interner that would grow without bound with the
/// union of every binary's symbol names. Keyed by content hash because a `Weak`
/// can't double as its own key (an `Arc<str>` key would pin the string);
/// collisions share a bucket and are disambiguated by content. Dead weak entries
/// in a bucket are dropped whenever that bucket is touched, and [`sweep`] drops
/// fully-emptied buckets, so the map tracks the live string set plus brief slack.
///
/// [`sweep`]: Self::sweep
#[derive(Default)]
pub(crate) struct StringInterner {
    buckets: DashMap<u64, Vec<Weak<str>>, FxBuildHasher>,
}

impl StringInterner {
    /// Return the shared `Arc<str>` for `s`, creating it if no live copy exists.
    fn intern(&self, s: &str) -> Arc<str> {
        let mut bucket = self.buckets.entry(str_hash(s)).or_default();
        let mut canonical = None;
        // Reuse the live copy whose content matches; drop dead weaks in passing.
        bucket.retain(|weak| match weak.upgrade() {
            Some(arc) => {
                if canonical.is_none() && arc.as_ref() == s {
                    canonical = Some(arc);
                }
                true
            }
            None => false,
        });
        if let Some(arc) = canonical {
            return arc;
        }
        let arc: Arc<str> = Arc::from(s);
        bucket.push(Arc::downgrade(&arc));
        arc
    }

    /// Drop buckets whose strings have all been freed, so the map doesn't keep
    /// tombstones for strings interned once and never seen again. Cheap; called on
    /// the periodic cleanup tick.
    pub(crate) fn sweep(&self) {
        self.buckets.retain(|_, weaks| {
            weaks.retain(|w| w.strong_count() > 0);
            !weaks.is_empty()
        });
    }
}

fn str_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

/// The shared `Arc<str>` for the ubiquitous `[unknown]` name and the empty source
/// path, deduped process-wide without going through the interner (they have no
/// `CodeInfo` to key on and recur in nearly every unresolved frame).
fn unknown_name() -> Arc<str> {
    static UNKNOWN: OnceLock<Arc<str>> = OnceLock::new();
    UNKNOWN.get_or_init(|| Arc::from("[unknown]")).clone()
}

fn empty_path() -> Arc<str> {
    static EMPTY: OnceLock<Arc<str>> = OnceLock::new();
    EMPTY.get_or_init(|| Arc::from("")).clone()
}

/// One source line of a resolved location: a function plus, when DWARF info is
/// available, the source file and line of the instruction (or, for an outer
/// inline frame, the call site of the next-inner one).
#[derive(Clone)]
pub(crate) struct FrameLine {
    pub(crate) name: Arc<str>,
    /// `dir`-joined source path; empty when unknown (no debug info).
    pub(crate) file: Arc<str>,
    /// Source line, 0 when unknown.
    pub(crate) line: i64,
}

impl FrameLine {
    fn new(name: &str, code_info: Option<&CodeInfo>, interner: &StringInterner) -> Self {
        let (file, line) = match code_info {
            Some(ci) => (
                interner.intern(&code_info_path(ci)),
                ci.line.unwrap_or(0) as i64,
            ),
            None => (empty_path(), 0),
        };
        FrameLine {
            name: interner.intern(name),
            file,
            line,
        }
    }

    fn unknown(name: Arc<str>) -> Self {
        FrameLine {
            name,
            file: empty_path(),
            line: 0,
        }
    }
}

/// One resolved location: an instruction address plus its inline chain, ordered
/// innermost (leaf) first to match pprof's `Line` ordering. A single
/// `[unknown]` line means the address could not be symbolized.
#[derive(Clone)]
pub(crate) struct Frame {
    pub(crate) address: u64,
    pub(crate) lines: Vec<FrameLine>,
}

impl Frame {
    pub(crate) fn unknown() -> Self {
        Frame {
            address: 0,
            lines: vec![FrameLine::unknown(unknown_name())],
        }
    }

    fn from_symbolized(addr: u64, sym: &Symbolized, interner: &StringInterner) -> Self {
        let Some(s) = sym.as_sym() else {
            return Frame {
                address: addr,
                // A unique per-address name, so interning wouldn't help; allocate
                // it directly (it's stored once in the LRU).
                lines: vec![FrameLine::unknown(Arc::from(format!(
                    "[unknown 0x{addr:x}]"
                )))],
            };
        };

        // blazesym reports inlined functions outermost-first (`f, g, h`) with
        // `s.name` the real (outermost) function; pprof wants innermost-first.
        // Line attribution: the innermost frame uses the instruction's location
        // (`s.code_info`); each outer frame uses the *call site* of the
        // next-inner inlined function (`inlined[..].code_info`).
        let n = s.inlined.len();
        let mut lines = Vec::with_capacity(n + 1);
        for p in 0..=n {
            let name: &str = if p < n {
                &s.inlined[n - 1 - p].name
            } else {
                &s.name
            };
            let code_info = if p == 0 {
                s.code_info.as_deref()
            } else {
                s.inlined[n - p].code_info.as_ref()
            };
            lines.push(FrameLine::new(name, code_info, interner));
        }
        Frame {
            address: addr,
            lines,
        }
    }
}

/// Join a [`CodeInfo`]'s directory and file into a single source path string.
fn code_info_path(ci: &CodeInfo) -> String {
    let file: &std::ffi::OsStr = &ci.file;
    match &ci.dir {
        Some(dir) => dir.join(file).to_string_lossy().into_owned(),
        None => std::path::Path::new(file).to_string_lossy().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(name: &str, file: &str, line: i64) -> FrameLine {
        FrameLine {
            name: Arc::from(name),
            file: Arc::from(file),
            line,
        }
    }

    #[test]
    fn interner_dedups_live_strings_and_reclaims_dropped_ones() {
        let interner = StringInterner::default();

        // Equal content returns one shared allocation while a strong ref is live.
        let a = interner.intern("do_work");
        let b = interner.intern("do_work");
        assert!(Arc::ptr_eq(&a, &b), "equal strings must share one Arc");
        // The interner holds only a Weak, so the two handles are the only strong
        // refs — it never pins a string on its own.
        assert_eq!(Arc::strong_count(&a), 2);

        // Distinct content is a distinct allocation.
        assert!(!Arc::ptr_eq(&a, &interner.intern("other")));

        // Once every strong ref is dropped the entries are reclaimable; a sweep
        // prunes the now-dead weaks (and their emptied buckets).
        drop(a);
        drop(b);
        interner.sweep();
        assert!(
            interner.buckets.is_empty(),
            "sweep must drop buckets whose strings were all freed"
        );
    }

    #[test]
    fn apply_folds_worker_results_into_cache() {
        let mut cache = CgroupCache::new(CgroupMeter::for_test("test"));
        cache.apply(SymResult {
            cgroup_id: 1,
            tgid: 7,
            resolved: vec![(
                0x1000,
                Frame {
                    address: 0x1000,
                    lines: vec![line("f", "/src/a.rs", 3)],
                },
            )],
            bad_ranges: vec![(0x7f00_0000, 0x7f10_0000)],
            symbolize_invocations: 2,
        });

        // The resolved frame is now cached and the bad range recorded.
        assert!(cache.frames.contains(&(7, 0x1000)));
        assert!(cache.in_bad_range(7, 0x7f08_0000));

        // A later lookup serves the cached frame for the resolved address and an
        // `[unknown]` for the (intentionally unresolved) bad-range address.
        let frames = cache.lookup_frames(7, &[0x1000]);
        assert_eq!(&*frames[0].lines[0].name, "f");
        let frames = cache.lookup_frames(7, &[0x7f08_0000]); // inside the bad range
        assert!(matches!(frames[0].lines.as_slice(), [l] if &*l.name == "[unknown]"));

        // Applying the same bad range again is idempotent (no duplicate entry).
        cache.apply(SymResult {
            cgroup_id: 1,
            tgid: 7,
            resolved: Vec::new(),
            bad_ranges: vec![(0x7f00_0000, 0x7f10_0000)],
            symbolize_invocations: 0,
        });
        assert_eq!(cache.bad_ranges[&7].len(), 1);
    }

    #[test]
    fn bad_range_negative_cache_excludes_addresses_from_resolution() {
        let mut cache = CgroupCache::new(CgroupMeter::for_test("test"));

        // A whole un-symbolizable region (e.g. a memfd JIT mapping) is recorded.
        cache
            .bad_ranges
            .entry(42)
            .or_default()
            .push((0x7f00_0000, 0x7f10_0000));

        // Every address inside it — including ones never seen before, as a JIT
        // region churns through — is considered bad without touching blazesym.
        assert!(cache.in_bad_range(42, 0x7f00_0000)); // inclusive lower bound
        assert!(cache.in_bad_range(42, 0x7f08_1234));
        assert!(!cache.in_bad_range(42, 0x7f10_0000)); // exclusive upper bound
        assert!(!cache.in_bad_range(42, 0x6fff_ffff));
        // Ranges are per-pid: another process' identical address is unaffected.
        assert!(!cache.in_bad_range(7, 0x7f08_1234));

        // A bad-range address is never put in a request (the dispatch filter in
        // `Profiler::build_requests` mirrors this `in_bad_range` check), and a
        // build-time `lookup_frames` renders it `[unknown]` without caching it —
        // so a churning JIT region never thrashes the LRU.
        let frames = cache.lookup_frames(42, &[0x7f08_1234]);
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0].lines.as_slice(), [l] if &*l.name == "[unknown]"));
        assert!(
            cache.frames.is_empty(),
            "bad-range addrs must not be cached"
        );
    }
}
