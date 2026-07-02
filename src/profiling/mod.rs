//! The cpu_profiles signal: perf-event sampling, the in-kernel unwinder's
//! userspace half, draining and symbolizing the kernel's stack aggregation,
//! building per-cgroup pprof, and pushing it to Pyroscope.
//!
//! [`CpuProfileCollector`] is the signal's [`Collector`] implementation: it
//! owns the profiling eBPF object (`src/bpf/profiling.bpf.c`, its own
//! skeleton), the perf sampler guard, the unwind-miss ring drain task and the
//! periodic drain+push task. The [`Profiler`] facade underneath owns the
//! pipeline state (fd-dup'd map handles, symbol caches, the unwind loader) and
//! exposes [`Profiler::on_cleanup`] (per cleanup-tick reconciliation) and
//! [`Profiler::collect_and_push`] (per profile-tick drain + upload).
//!
//! Submodules: [`perf_event`] (sampling sources), [`unwind`]/[`unwind_loader`]/
//! [`proc_maps`] (the native unwinder's table building/loading), [`symbolize`]
//! (address → frame resolution + caching), [`pprof`]/[`push`]/[`proto`] (output).

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBufferBuilder};
use prost::Message;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::io::unix::AsyncFd;

use crate::bindings::{StackKey, UnwindMiss};
use crate::bpf;
use crate::cgroup::{CgroupRegistry, PerCgroup};
use crate::collector::{BoxFuture, BuildCtx, Collector, configure_cgroup_rodata};
use crate::numa::decode_event;
use crate::telemetry;

mod debuginfod;
mod perf_event;
mod pprof;
mod proc_maps;
mod proto;
mod push;
mod symbolize;
mod unwind;
mod unwind_loader;

use debuginfod::DebuginfodClient;
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
    /// Filter-contributed attributes, attached as
    /// Pyroscope labels alongside `service_name` (see [`push`]).
    /// Empty when no filter tagged the cgroup.
    pub(crate) attrs: Vec<opentelemetry::KeyValue>,
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

impl CgroupSamples {
    /// Fold another (leaf) cgroup's samples in, merging per-tgid stack lists. Used
    /// to aggregate a SLURM job's `step_*/task_*` sub-cgroups into the job.
    fn merge(&mut self, other: CgroupSamples) {
        for (tgid, stacks) in other.procs {
            self.procs.entry(tgid).or_default().extend(stacks);
        }
    }
}

/// The CPU profiler: drains the in-kernel stack aggregation, symbolizes, and
/// pushes per-cgroup pprof profiles to Pyroscope. Also owns the native
/// unwinder's userspace half (the [`UnwindLoader`]) and the profiling map
/// handles, so [`CpuProfileCollector`] only deals with the facade (the perf
/// sampler guard lives in the collector, which starts/stops sampling).
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
    /// Optional debuginfod client for fetching split debug info the target lacks
    /// locally, shared (behind an `Arc`) with each parallel symbolization worker.
    /// `None` when `DEBUGINFOD_URLS` is unset, i.e. the operator hasn't opted in.
    debuginfod: Option<Arc<DebuginfodClient>>,
    /// Userspace half of the native unwinder: keeps the kernel's per-executable
    /// `.eh_frame` tables loaded for the processes being sampled.
    loader: UnwindLoader,
    /// Tgids the in-kernel unwinder couldn't walk, each mapped to the cgroup whose
    /// sample triggered the miss. Filled from the `UNWIND_MISSES` ring buffer (via
    /// the cloneable [`miss_sink`](Self::miss_sink) handle) and drained each
    /// cleanup tick to load their unwind info. A tgid maps to one cgroup; a
    /// re-miss before draining just keeps the latest.
    pending_misses: Arc<Mutex<FxHashMap<u32, u64>>>,
    /// Owned handles to the profiling BPF maps the periodic work touches.
    maps: ProfilerMaps,
}

/// Owned, fd-dup'd handles to the profiling maps. `MapHandle` is
/// `Send + Sync + 'static` (unlike the skel-borrowed `Map`), so the profiler
/// can live in spawned tasks without tying them to the skeleton's lifetime.
pub struct ProfilerMaps {
    /// exec_id -> inner unwind-table map (`UNWIND_ROWS`).
    unwind_rows: MapHandle,
    /// exec_id -> ExecInfo (`EXECUTABLES`).
    executables: MapHandle,
    /// tgid -> ProcessMappings (`PROC_MAPPINGS`).
    proc_mappings: MapHandle,
    /// The kernel's per-(cgroup, thread, stack) sample aggregation (`STACK_COUNTS`).
    stack_counts: MapHandle,
    /// stack_id -> captured addresses (`STACKS`).
    stacks: MapHandle,
}

/// A cloneable handle the ringbuffer callback uses to record unwind misses.
pub type MissSink = Arc<Mutex<FxHashMap<u32, u64>>>;

impl Profiler {
    fn new(
        base_url: String,
        hostname: String,
        freq: u64,
        interval_secs: u64,
        registry: Arc<CgroupRegistry>,
        maps: ProfilerMaps,
    ) -> Self {
        // Opt-in via the standard debuginfod environment; a misconfiguration is
        // logged and treated as "disabled" rather than failing profiler startup.
        let debuginfod = match DebuginfodClient::discover() {
            Ok(Some(client)) => {
                log::info!(
                    "debuginfod symbolization enabled (servers: {:?})",
                    client.urls()
                );
                Some(Arc::new(client))
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("debuginfod disabled: {e:#}");
                None
            }
        };
        Self {
            pusher: Pusher::new(base_url, hostname),
            period_ns: (1_000_000_000 / freq.max(1)) as i64,
            duration_ns: (interval_secs.max(1) * 1_000_000_000) as i64,
            cgroups: PerCgroup::new(Arc::clone(&registry)),
            bad_ranges_cleared: Instant::now(),
            interner: Arc::new(StringInterner::default()),
            debuginfod,
            loader: UnwindLoader::new(registry),
            pending_misses: Arc::new(Mutex::new(FxHashMap::default())),
            maps,
        }
    }

    /// A cloneable handle for the `UNWIND_MISSES` ringbuffer callback to record
    /// misses into; serviced on the next [`on_cleanup`](Self::on_cleanup).
    fn miss_sink(&self) -> MissSink {
        Arc::clone(&self.pending_misses)
    }

    /// Per-cleanup-tick reconciliation against the registry's `live` snapshot:
    /// prune dead cgroups' symbol caches, service pending unwind misses (loading
    /// their tables into the unwind maps), evict tables of exited processes, and
    /// refresh the resident-table gauges.
    pub async fn on_cleanup(&mut self, live: &FxHashSet<u64>) {
        self.retain_live(live);
        self.loader.retain_live(live);

        let misses: Vec<(u32, u64)> = self.pending_misses.lock().unwrap().drain().collect();
        for (pid, cgroup_id) in misses {
            self.loader
                .ensure_pid(
                    pid,
                    cgroup_id,
                    &self.maps.unwind_rows,
                    &self.maps.executables,
                    &self.maps.proc_mappings,
                )
                .await;
        }
        self.loader.evict_dead(
            &self.maps.unwind_rows,
            &self.maps.executables,
            &self.maps.proc_mappings,
        );
        // Refresh the per-cgroup resident-table gauges now that this tick's loads
        // and evictions are reflected in the loader state.
        self.loader.record_table_gauges();
    }

    /// Per-profile-tick: drain + symbolize + build per-cgroup pprof, then spawn the
    /// upload so the periodic task never blocks on network IO.
    pub async fn collect_and_push(&self) {
        let profiles = self
            .collect(&self.maps.stack_counts, &self.maps.stacks)
            .await;
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
        let (raw_by_cgroup, stack_ids) = self.drain_maps(counts, stacks);

        // Free the stack-trace slots now that we've copied out what we need;
        // multiple count entries may share an id, hence the dedup above.
        for id in stack_ids {
            let _ = stacks.delete(&id.to_ne_bytes());
        }

        // Step 1b: canonicalize. Each raw (leaf) cgroup's samples fold into its
        // canonical cgroup — the SLURM job for a job's `step_*/task_*`
        // sub-cgroups, so one profile covers the whole job — while ensuring a
        // symbol cache exists per canonical cgroup. The registry resolves the
        // cgroup name (the `service_name` label) and owns its meter provider;
        // `None` means the root cgroup (rejected by Pyroscope anyway) or one that
        // vanished between sampling and draining — drop it so later steps don't
        // have to special-case it.
        let mut by_cgroup: HashMap<u64, CgroupSamples> = HashMap::new();
        for (raw_id, samples) in raw_by_cgroup {
            let Some(cache) = self
                .cgroups
                .get_or_create(raw_id, None, |meter| CgroupCache::new(Arc::clone(meter)))
                .await
            else {
                continue;
            };
            let canonical_id = *cache.key();
            drop(cache);
            by_cgroup.entry(canonical_id).or_default().merge(samples);
        }

        // Step 2: build the symbolization queue (reads caches), step 3: resolve
        // it in parallel (touches no shared state), step 4: fold results back in.
        let requests = self.build_requests(&by_cgroup);
        let results = resolve_parallel(requests, &self.interner, self.debuginfod.as_ref()).await;
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
                attrs: cg.meter.attrs.clone(),
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

/// The cpu_profiles signal: owns the profiling eBPF object, the perf sampler
/// attachment, the unwind-miss drain task, and the periodic drain+push task
/// around the shared [`Profiler`].
pub struct CpuProfileCollector {
    skel: bpf::profiling::ProfilingSkel<'static>,
    /// Shared with the periodic profile task; an async mutex because both this
    /// collector's cleanup hook and that task hold the guard across `.await`.
    profiler: Arc<tokio::sync::Mutex<Profiler>>,
    /// Holds the perf-event fds + attachments alive; dropping it detaches the
    /// sampler. `None` until [`Collector::attach`].
    sampler: Option<perf_event::PerfSampler>,
    freq: u64,
    profile_task: tokio::task::JoinHandle<()>,
    misses_task: tokio::task::JoinHandle<()>,
}

impl CpuProfileCollector {
    /// Open + load the profiling eBPF object and spawn the unwind-miss drain
    /// and periodic profile tasks. Sampling starts at [`Collector::attach`].
    pub fn new(
        ctx: &mut BuildCtx,
        pyroscope_url: String,
        freq: u64,
        interval_secs: u64,
    ) -> anyhow::Result<Self> {
        // The skeleton borrows its open-object storage; leak that storage (one
        // small allocation per enabled signal, for the process lifetime) so the
        // collector can own the skeleton without a self-referential struct.
        let storage = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open_skel = bpf::profiling::ProfilingSkelBuilder::default().open(storage)?;
        configure_cgroup_rodata!(open_skel, ctx.v1_hierarchy_id);
        // The perf_event sampler needs a per-CPU perf fd, so it is attached
        // explicitly in `attach`; keep skel.attach() from trying to auto-attach.
        open_skel.progs.do_sample.set_autoattach(false);
        let skel = open_skel.load()?;

        let profiler = Profiler::new(
            pyroscope_url,
            telemetry::hostname(),
            freq,
            interval_secs,
            Arc::clone(&ctx.registry),
            ProfilerMaps {
                unwind_rows: MapHandle::try_from(&skel.maps.UNWIND_ROWS)?,
                executables: MapHandle::try_from(&skel.maps.EXECUTABLES)?,
                proc_mappings: MapHandle::try_from(&skel.maps.PROC_MAPPINGS)?,
                stack_counts: MapHandle::try_from(&skel.maps.STACK_COUNTS)?,
                stacks: MapHandle::try_from(&skel.maps.STACKS)?,
            },
        );
        let miss_sink = profiler.miss_sink();
        let profiler = Arc::new(tokio::sync::Mutex::new(profiler));

        // Unwind-miss ring buffer: a single global ring (low volume), drained
        // on the tokio runtime via its epoll fd into the profiler's miss sink.
        let misses_map = MapHandle::try_from(&skel.maps.UNWIND_MISSES)?;
        let misses_task = tokio::spawn(drain_misses(misses_map, miss_sink));

        // Periodic drain + symbolize + push. Ticks before attach are no-ops on
        // empty maps.
        let profile_task = tokio::spawn({
            let profiler = Arc::clone(&profiler);
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
            async move {
                loop {
                    interval.tick().await;
                    profiler.lock().await.collect_and_push().await;
                }
            }
        });

        Ok(Self {
            skel,
            profiler,
            sampler: None,
            freq,
            profile_task,
            misses_task,
        })
    }
}

impl Collector for CpuProfileCollector {
    fn attach(&mut self) -> anyhow::Result<()> {
        self.skel.attach()?;
        // Start CPU sampling: one perf event per online CPU, each with the
        // do_sample program, kept alive for the collector's lifetime.
        self.sampler = Some(perf_event::attach_perf_samplers(
            &self.skel.progs.do_sample,
            self.freq,
        )?);
        Ok(())
    }

    fn on_cleanup<'a>(&'a self, live: &'a FxHashSet<u64>) -> BoxFuture<'a> {
        Box::pin(async move {
            self.profiler.lock().await.on_cleanup(live).await;
        })
    }

    fn shutdown(&self) {
        self.profile_task.abort();
        self.misses_task.abort();
    }
}

/// Drain the `UNWIND_MISSES` ring into the profiler's miss sink on the tokio
/// runtime: register the ring's epoll fd with the reactor and consume whenever
/// it turns readable. Readiness is cleared *before* consuming so a submit
/// racing the drain re-arms the fd rather than being lost.
async fn drain_misses(map: MapHandle, sink: MissSink) {
    // Scoped so the (non-Send) builder is provably dead before the first
    // await; only the Send `RingBuffer` crosses it.
    let ringbuf = {
        let mut builder = RingBufferBuilder::new();
        let added = builder
            .add(&map, move |data: &[u8]| {
                if let Some(miss) = decode_event::<UnwindMiss>(data) {
                    sink.lock().unwrap().insert(miss.tgid, miss.cgroup_id);
                }
                0
            })
            .map(|_| ());
        added.and_then(|()| builder.build())
    };
    let ringbuf = match ringbuf {
        Ok(rb) => rb,
        Err(e) => {
            log::error!("failed to build the unwind-miss ring buffer: {e}");
            return;
        }
    };

    // Safety: the raw epoll fd belongs to `ringbuf`, which lives (owned by this
    // future) for as long as the AsyncFd does.
    let async_fd = match AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(ringbuf.epoll_fd()) },
        tokio::io::Interest::READABLE,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("failed to register the unwind-miss ring with the runtime: {e}");
            return;
        }
    };

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(guard) => guard,
            Err(e) => {
                log::error!("unwind-miss ring poll failed: {e}");
                return;
            }
        };
        guard.clear_ready();
        let consumed = ringbuf.consume_raw();
        if consumed < 0 {
            log::warn!(
                "unwind-miss ring consume failed: {}",
                std::io::Error::from_raw_os_error(-consumed as i32)
            );
        }
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
