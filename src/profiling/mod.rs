//! CPU profiling: the [`Profiler`] facade that owns the whole sampling pipeline —
//! perf-event sampling, the in-kernel unwinder's userspace half, draining and
//! symbolizing the kernel's stack aggregation, building per-cgroup pprof, and
//! pushing it to Pyroscope.
//!
//! The event loop ([`crate::app`]) drives it through a small surface:
//! [`Profiler::attach`] (start sampling), [`Profiler::miss_sink`] (the ringbuffer
//! callback's drop point for unwind misses), [`Profiler::on_cleanup`] (per
//! cleanup-tick reconciliation), and [`Profiler::collect_and_push`] (per
//! profile-tick drain + upload). Everything else — the unwind loader, the symbol
//! caches, the perf sampler guard — is encapsulated here.
//!
//! Submodules: [`perf_event`] (sampling sources), [`unwind`]/[`unwind_loader`]/
//! [`proc_maps`] (the native unwinder's table building/loading), [`symbolize`]
//! (address → frame resolution + caching), [`pprof`]/[`push`]/[`proto`] (output).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use libbpf_rs::{MapCore, MapFlags, ProgramMut};
use prost::Message;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::bindings::StackKey;
use crate::cgroup::{CgroupRegistry, PerCgroup};

mod perf_event;
mod pprof;
mod proc_maps;
mod proto;
mod push;
mod symbolize;
mod unwind;
mod unwind_loader;

use perf_event::{PerfSampler, attach_perf_samplers};
use pprof::ProfileBuilder;
use push::Pusher;
use symbolize::{
    BAD_RANGE_TTL, CgroupCache, StringInterner, SymRequest, query_addr, resolve_parallel,
};
use unwind_loader::UnwindLoader;

/// Maximum frames per captured stack; the single source of truth lives in the
/// shared BPF header (`MAX_STACK_DEPTH`) and sizes the `Stack` value type.
const MAX_STACK_DEPTH: usize = crate::bindings::MAX_STACK_DEPTH as usize;

/// A finished pprof profile for one cgroup, ready to push to Pyroscope.
pub(crate) struct CpuProfile {
    pub(crate) cgroup_name: String,
    /// Serialized `google.v1.Profile` (uncompressed; gzipped at push time).
    pub(crate) data: Vec<u8>,
}

/// Per-cgroup raw samples gathered from the BPF maps before symbolization.
/// Keyed by tgid because instruction addresses are only meaningful within a
/// single process' address space.
#[derive(Default)]
struct CgroupSamples {
    /// tgid -> list of (leaf-first stack addresses, sample count).
    procs: HashMap<u32, Vec<(Vec<u64>, u64)>>,
}

/// The CPU profiler: drains the in-kernel stack aggregation, symbolizes, and
/// pushes per-cgroup pprof profiles to Pyroscope. Also owns the native unwinder's
/// userspace half (the [`UnwindLoader`]) and the perf sampler, so the event loop
/// only deals with the facade.
pub struct Profiler {
    pusher: Pusher,
    /// Wall-clock nanoseconds each sample represents (`1e9 / freq`).
    period_ns: i64,
    /// Length of one profiling window in nanoseconds (`interval_secs * 1e9`).
    duration_ns: i64,
    /// Per-cgroup symbol caches.
    ///
    /// Symbolization itself is *not* done here: each drain builds its blazesym
    /// `Symbolizer`s inside short-lived blocking workers (the type is neither
    /// `Send` nor `Sync`, so it can't be kept around or shared). These caches are
    /// only read to decide what needs resolving and written to fold the workers'
    /// results back in — both serially, so no locking is needed.
    cgroups: PerCgroup<CgroupCache>,
    /// When the negative-cache ranges were last cleared, for the [`BAD_RANGE_TTL`]
    /// re-evaluation sweep.
    bad_ranges_cleared: Instant,
    /// Deduplicates the symbol-name / source-file strings the per-cgroup frame
    /// caches hold. Shared (behind an `Arc`) with the parallel symbolization
    /// workers, which intern as they build frames.
    interner: Arc<StringInterner>,
    /// Userspace half of the native unwinder: keeps the kernel's per-executable
    /// `.eh_frame` tables loaded for the processes being sampled.
    loader: UnwindLoader,
    /// Tgids the in-kernel unwinder couldn't walk, each mapped to the cgroup whose
    /// sample triggered the miss. Filled from the `UNWIND_MISSES` ring buffer (via
    /// the cloneable [`miss_sink`](Self::miss_sink) handle) and drained each
    /// cleanup tick to load their unwind info. A tgid maps to one cgroup; a
    /// re-miss before draining just keeps the latest.
    pending_misses: Arc<Mutex<FxHashMap<u32, u64>>>,
    /// Holds the perf-event fds + attachments alive; dropping it detaches the
    /// sampler. `None` until [`attach`](Self::attach).
    sampler: Option<PerfSampler>,
}

/// A cloneable handle the ringbuffer callback uses to record unwind misses.
pub type MissSink = Arc<Mutex<FxHashMap<u32, u64>>>;

impl Profiler {
    pub fn new(
        base_url: String,
        hostname: String,
        freq: u64,
        interval_secs: u64,
        registry: Arc<CgroupRegistry>,
    ) -> Self {
        Self {
            pusher: Pusher::new(base_url, hostname),
            period_ns: (1_000_000_000 / freq.max(1)) as i64,
            duration_ns: (interval_secs.max(1) * 1_000_000_000) as i64,
            cgroups: PerCgroup::new(Arc::clone(&registry)),
            bad_ranges_cleared: Instant::now(),
            interner: Arc::new(StringInterner::default()),
            loader: UnwindLoader::new(registry),
            pending_misses: Arc::new(Mutex::new(FxHashMap::default())),
            sampler: None,
        }
    }

    /// Start CPU sampling: open one perf event per online CPU and attach the
    /// `do_sample` BPF program to each, keeping the attachments alive for the
    /// profiler's lifetime.
    pub fn attach(&mut self, prog: &ProgramMut, freq: u64) -> anyhow::Result<()> {
        self.sampler = Some(attach_perf_samplers(prog, freq)?);
        Ok(())
    }

    /// A cloneable handle for the `UNWIND_MISSES` ringbuffer callback to record
    /// misses into; serviced on the next [`on_cleanup`](Self::on_cleanup).
    pub fn miss_sink(&self) -> MissSink {
        Arc::clone(&self.pending_misses)
    }

    /// Per-cleanup-tick reconciliation against the registry's `live` snapshot:
    /// prune dead cgroups' symbol caches, service pending unwind misses (loading
    /// their tables from the given `UNWIND_ROWS`/`EXECUTABLES`/`PROC_MAPPINGS`
    /// maps), evict tables of exited processes, and refresh the resident-table
    /// gauges.
    pub async fn on_cleanup(
        &mut self,
        live: &FxHashSet<u64>,
        unwind_rows: &impl MapCore,
        executables: &impl MapCore,
        proc_mappings: &impl MapCore,
    ) {
        self.retain_live(live);
        self.loader.retain_live(live);

        let misses: Vec<(u32, u64)> = self.pending_misses.lock().unwrap().drain().collect();
        for (pid, cgroup_id) in misses {
            self.loader
                .ensure_pid(pid, cgroup_id, unwind_rows, executables, proc_mappings)
                .await;
        }
        self.loader
            .evict_dead(unwind_rows, executables, proc_mappings);
        // Refresh the per-cgroup resident-table gauges now that this tick's loads
        // and evictions are reflected in the loader state.
        self.loader.record_table_gauges();
    }

    /// Per-profile-tick: drain + symbolize + build per-cgroup pprof, then spawn the
    /// upload so the event loop never blocks on network IO. `counts`/`stacks` are
    /// the `STACK_COUNTS`/`STACKS` maps.
    pub async fn collect_and_push(&self, counts: &impl MapCore, stacks: &impl MapCore) {
        let profiles = self.collect(counts, stacks).await;
        if profiles.is_empty() {
            return;
        }
        let pusher = self.pusher.clone();
        tokio::spawn(async move {
            if let Err(e) = pusher.push(profiles).await {
                log::warn!("failed to push CPU profiles: {e}");
            }
        });
    }

    /// Drain the BPF aggregation maps, symbolize **in parallel**, and build one
    /// pprof profile per cgroup. Map access (drain) is synchronous; the actual
    /// upload is done separately by [`collect_and_push`](Self::collect_and_push).
    ///
    /// Staged so symbolization parallelizes without cache locking:
    /// 1. drain `STACK_COUNTS`/`STACKS` and group samples by cgroup,
    /// 2. read the per-cgroup caches to build one symbolization request per
    ///    process (the cache-miss addresses only),
    /// 3. dispatch every request to a blocking worker and await them all,
    /// 4. fold the results back into the caches, then
    /// 5. build each cgroup's profile from the now-warm caches.
    async fn collect(&self, counts: &impl MapCore, stacks: &impl MapCore) -> Vec<CpuProfile> {
        let (mut by_cgroup, stack_ids) = self.drain_maps(counts, stacks);

        // Free the stack-trace slots now that we've copied out what we need;
        // multiple count entries may share an id, hence the dedup above.
        for id in stack_ids {
            let _ = stacks.delete(&id.to_ne_bytes());
        }

        // Step 1b: ensure a cache exists for each cgroup. The shared registry
        // resolves the cgroup name (the `service_name` label) and owns its meter
        // provider; `None` means the cgroup is the root (rejected by Pyroscope
        // anyway) or vanished between sampling and draining — drop it so later
        // steps don't have to special-case it.
        let cgroup_ids: Vec<u64> = by_cgroup.keys().copied().collect();
        for cgroup_id in cgroup_ids {
            if self
                .cgroups
                .get_or_create(cgroup_id, |meter| CgroupCache::new(Arc::clone(meter)))
                .await
                .is_none()
            {
                by_cgroup.remove(&cgroup_id);
            }
        }

        // Step 2: build the symbolization queue (reads caches), step 3: resolve
        // it in parallel (touches no shared state), step 4: fold results back in.
        let requests = self.build_requests(&by_cgroup);
        let results = resolve_parallel(requests, &self.interner).await;
        for res in results {
            if let Some(mut cg) = self.cgroups.get_mut(res.cgroup_id) {
                cg.apply(res);
            }
        }

        // Step 5: build one pprof per cgroup from the warmed caches.
        let mut profiles = Vec::new();
        for (cgroup_id, samples) in by_cgroup {
            let data = self.build_profile(cgroup_id, &samples);
            if data.is_empty() {
                continue;
            }
            let Some(cg) = self.cgroups.get(cgroup_id) else {
                continue;
            };
            profiles.push(CpuProfile {
                cgroup_name: cg.meter.name.clone(),
                data,
            });
        }

        profiles
    }

    /// Build the symbolization queue for one drain: one [`SymRequest`] per
    /// process, carrying the deduplicated *query* addresses that miss this
    /// cgroup's frame cache and aren't in a known-bad range. Pure read of the
    /// caches; the returned requests are owned so they can be moved into workers.
    fn build_requests(&self, by_cgroup: &HashMap<u64, CgroupSamples>) -> Vec<SymRequest> {
        let mut requests = Vec::new();
        for (&cgroup_id, samples) in by_cgroup {
            let Some(cg) = self.cgroups.get(cgroup_id) else {
                continue; // unresolved cgroup (root/vanished): no cache, skip
            };
            for (&tgid, stacks) in &samples.procs {
                let mut seen: FxHashSet<u64> = FxHashSet::default();
                let mut missing: Vec<u64> = Vec::new();
                for (addrs, _) in stacks {
                    for (i, &a) in addrs.iter().enumerate() {
                        let qa = query_addr(i, a);
                        if cg.frames.contains(&(tgid, qa)) || cg.in_bad_range(tgid, qa) {
                            continue;
                        }
                        if seen.insert(qa) {
                            missing.push(qa);
                        }
                    }
                }
                if missing.is_empty() {
                    continue;
                }
                cg.metrics.frames_resolved.add(missing.len() as u64);
                requests.push(SymRequest {
                    cgroup_id,
                    tgid,
                    cgroup_name: cg.meter.name.clone(),
                    addrs: missing,
                });
            }
        }
        requests
    }

    /// Per-cleanup housekeeping that bounds the symbol caches:
    /// - Drop the symbol caches (frame LRU, negative-cache ranges, metric
    ///   bindings) for cgroups absent from `live`, also limiting the
    ///   stale-symbol/pid-reuse window.
    /// - Every [`BAD_RANGE_TTL`], clear all cgroups' negative-cache ranges so a
    ///   `memfd`/JIT region that was unmapped and replaced gets re-evaluated
    ///   rather than resolving to `[unknown]` forever.
    ///
    /// (There is no shared symbolizer to rebuild: each drain's workers build and
    /// drop their own, so blazesym's open fds never accumulate across drains.)
    fn retain_live(&mut self, live: &FxHashSet<u64>) {
        self.cgroups.retain_live(live);
        if self.bad_ranges_cleared.elapsed() >= BAD_RANGE_TTL {
            for mut cg in self.cgroups.iter_mut() {
                cg.bad_ranges.clear();
            }
            self.bad_ranges_cleared = Instant::now();
        }
        // Evicting dead cgroups above drops their frame caches, releasing the last
        // `Arc`s to many interned strings; sweep the now-dead `Weak` entries.
        self.interner.sweep();
    }

    /// Drain `STACK_COUNTS` (deleting as we go) and resolve referenced stacks
    /// from `STACKS`. Returns samples grouped by cgroup plus the set of stack
    /// ids that should be freed afterwards.
    fn drain_maps(
        &self,
        counts: &impl MapCore,
        stacks: &impl MapCore,
    ) -> (HashMap<u64, CgroupSamples>, Vec<u64>) {
        let mut by_cgroup: HashMap<u64, CgroupSamples> = HashMap::new();
        // Cache resolved stacks so each id is read (and later freed) once.
        let mut stack_cache: HashMap<u64, Vec<u64>> = HashMap::new();

        // Snapshot keys up front: the key iterator uses the previously returned
        // key as its cursor, so deleting entries mid-iteration would make the
        // kernel restart from the first element. Concurrent inserts after this
        // point are simply drained on the next interval.
        let keys: Vec<Vec<u8>> = counts.keys().collect();
        for key_bytes in keys {
            let count = match counts.lookup_and_delete(&key_bytes) {
                Ok(Some(v)) if v.len() >= 8 => u64::from_ne_bytes(v[..8].try_into().unwrap()),
                _ => continue,
            };
            if key_bytes.len() < std::mem::size_of::<StackKey>() {
                continue;
            }
            // Safety: keys originate from a map whose key type is StackKey, a
            // 24-byte POD; read unaligned since `keys()` yields a plain Vec<u8>.
            let key = unsafe { (key_bytes.as_ptr() as *const StackKey).read_unaligned() };

            let addrs = if key.stack_id == 0 {
                // Empty stack (nothing was unwound); render as a single unknown.
                Vec::new()
            } else {
                stack_cache
                    .entry(key.stack_id)
                    .or_insert_with(|| lookup_stack(stacks, key.stack_id))
                    .clone()
            };

            by_cgroup
                .entry(key.cgroup_id)
                .or_default()
                .procs
                .entry(key.tgid)
                .or_default()
                .push((addrs, count));
        }

        let stack_ids = stack_cache.into_keys().collect();
        (by_cgroup, stack_ids)
    }

    /// Encode one cgroup's samples into a pprof profile, resolving each stack's
    /// frames from the (already warmed by [`collect`](Self::collect)) per-cgroup
    /// cache.
    fn build_profile(&self, cgroup_id: u64, samples: &CgroupSamples) -> Vec<u8> {
        let period_ns = self.period_ns;
        let duration_ns = self.duration_ns;
        let mut cg = self
            .cgroups
            .get_mut(cgroup_id)
            .expect("cgroup cache inserted by caller");

        let mut builder = ProfileBuilder::new(period_ns, duration_ns);
        let mut total_samples = 0u64;
        for (&tgid, stacks) in &samples.procs {
            for (addrs, count) in stacks {
                total_samples += *count;
                let frames = cg.lookup_frames(tgid, addrs);
                let location_ids: Vec<u64> = frames
                    .into_iter()
                    .map(|f| builder.location(tgid, f))
                    .collect();
                builder.add_sample(location_ids, *count);
            }
        }
        cg.metrics.samples_collected.add(total_samples);

        if builder.is_empty() {
            return Vec::new();
        }
        cg.metrics.profiles_collected.add(1);
        builder.finish().encode_to_vec()
    }
}

/// Read a `STACKS` entry (a [`Stack`](crate::bindings::Stack) of leaf-first
/// addresses) and return its addresses, truncated at the first zero terminator.
fn lookup_stack(stacks: &impl MapCore, stack_id: u64) -> Vec<u64> {
    let raw = match stacks.lookup(&stack_id.to_ne_bytes(), MapFlags::ANY) {
        Ok(Some(v)) => v,
        _ => return Vec::new(),
    };
    raw.chunks_exact(8)
        .take(MAX_STACK_DEPTH)
        .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
        .take_while(|&a| a != 0)
        .collect()
}
