//! Unified target-cgroup tracking.
//!
//! A **cgroup is the unit of a workload** here (a SLURM job / job step), so every
//! telemetry feature scopes its state per cgroup id ([`bpf_get_current_cgroup_id`]).
//! This module is the single source of truth for which cgroups are alive and the
//! owner of every per-cgroup [`SdkMeterProvider`], so the OTel quirk of needing one
//! provider per cgroup is paid exactly once and shared across IO metrics, CPU
//! profiling, and any feature added later.
//!
//! Two pieces make it extensible:
//! - [`CgroupRegistry`] resolves a cgroup id to a human name and lazily creates its
//!   shared meter; its per-provider histogram [views] are *contributed by features*
//!   (see [`CgroupRegistry::new`]) rather than hardcoded here.
//! - [`PerCgroup<T>`] is the per-feature state container: a feature holds one,
//!   builds its instruments/caches from the cgroup's [`CgroupMeter`] via
//!   [`PerCgroup::get_or_create`], and lets [`PerCgroup::retain_live`] prune dead
//!   cgroups — so the get-or-create + prune pattern lives in exactly one place.
//!
//! [`bpf_get_current_cgroup_id`]: https://docs.kernel.org/bpf/helpers.html
//! [views]: opentelemetry_sdk::metrics::View

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::one::{Ref, RefMut};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_otlp::{
    Compression, MetricExporter, Protocol, WithExportConfig, WithTonicConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{
    Instrument, InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Stream, Temporality,
};
use rustc_hash::{FxBuildHasher, FxHashSet};

use crate::telemetry::build_resource;

/// An export taking at least this long is logged as slow. The per-cgroup payloads
/// here are kilobytes, so a healthy export is milliseconds; crossing this points at
/// the shared OTLP channel stalling (reconnect, retry/backoff, server backpressure).
const SLOW_EXPORT_THRESHOLD: Duration = Duration::from_secs(2);

/// A metric [view] a feature contributes to every per-cgroup meter provider: given
/// an [`Instrument`], it optionally returns the [`Stream`] (aggregation) to use for
/// it. Shared behind an `Arc` because the same view is applied to each cgroup's
/// provider as it is created.
///
/// [view]: opentelemetry_sdk::metrics::View
pub type CgroupView = Arc<dyn Fn(&Instrument) -> Option<Stream> + Send + Sync>;

/// Which cgroup hierarchy the exporter tracks, selected at startup by
/// `--use-cgroups-v1` and kept in lockstep with the eBPF side (see
/// `src/bpf/cgroup_id.bpf.h`): the BPF programs stamp events with the matching
/// id, and the registry resolves/walks the matching mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupMode {
    /// The v2 (unified) hierarchy: `bpf_get_current_cgroup_id`, anchored under the
    /// cgroup2 mount.
    V2,
    /// The v1 `cpu,cpuacct` hierarchy: `bpf_task_get_cgroup1`, anchored under the
    /// cpu v1 mount.
    V1,
}

/// The SLURM identity of a tracked job cgroup, attached to its [`CgroupMeter`] so
/// every feature can stamp its metrics/profiles with the same `uid` /
/// `slurm.job_id` labels. Present only for cgroups whose path is a SLURM job (see
/// [`parse_slurm`]); `None` for ordinary system/user cgroups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlurmJob {
    pub job_id: u64,
    /// The owning user, from the `uid_<N>` path segment when present (v1 layout);
    /// `None` when the layout carries no uid segment (some v2 layouts).
    pub uid: Option<u32>,
}

/// Wraps the OTLP [`MetricExporter`] in an `Arc` so every per-cgroup provider's
/// [`PeriodicReader`] can share one exporter. A reader shutting down (when its
/// cgroup dies) must not shut the shared exporter down, hence the no-op `shutdown`.
#[derive(Clone)]
struct SharedExporter(Arc<MetricExporter>);

impl PushMetricExporter for SharedExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        self.0.export(metrics).await
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown(&self) -> OTelSdkResult {
        // Do not shutdown the shared exporter when a single reader shuts down.
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        self.0.temporality()
    }
}

/// Wraps a [`ManualReader`] in an `Arc` so the per-cgroup provider and the
/// registry share one reader: the provider drives collection into it, and
/// [`CgroupRegistry::collect_and_export_all`] reads it out on a single shared
/// timer.
///
/// [`PeriodicReader`]: opentelemetry_sdk::metrics::PeriodicReader
#[derive(Clone, Debug)]
struct SharedManualReader(Arc<ManualReader>);

impl MetricReader for SharedManualReader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }

    fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(rm)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

/// One cgroup's [`SdkMeterProvider`], shared by every feature that emits metrics
/// for that cgroup (IO tracing, CPU profiling, …).
///
/// Each provider carries hostname as a *resource* attribute; per-event attributes
/// are recorded on the instruments instead. A provider is created the first time
/// any feature touches a cgroup and is shut down + dropped by
/// [`CgroupRegistry::cleanup_dead_cgroups`] once the cgroup disappears, so stale
/// series stop being exported (the OTel SDK has no API to drop an individual
/// series, so dropping the whole provider is how a dead cgroup's series are
/// retired). Features build their own instruments from [`meter`](Self::meter) and
/// hold an `Arc<CgroupMeter>` so the provider stays alive — and exportable by
/// [`collect_and_export_all`](CgroupRegistry::collect_and_export_all) — as long as
/// anyone references it.
pub struct CgroupMeter {
    /// The **canonical** tracked cgroup id this meter is keyed by: the SLURM job
    /// cgroup's inode for a SLURM workload (so its many `step_*/task_*`
    /// sub-cgroups share one provider), or the raw event id otherwise. Features
    /// key their own [`PerCgroup`] state by this, not by the raw event id.
    pub id: u64,
    pub name: String,
    /// SLURM identity, when this cgroup is a job (see [`SlurmJob`]); `None`
    /// otherwise. Read by features to add `uid` / `slurm.job_id` attributes.
    pub slurm: Option<SlurmJob>,
    pub meter: Meter,
    provider: SdkMeterProvider,
    /// The provider's reader, shared so [`CgroupRegistry::collect_and_export_all`]
    /// can pull this cgroup's metrics on the registry's single export timer.
    reader: SharedManualReader,
}

impl CgroupMeter {
    /// Append this cgroup's SLURM identity to `attrs` — `slurm.job_id`, plus `uid`
    /// when the layout carried one. A no-op for non-SLURM cgroups. Shared by the IO
    /// and metadata metrics so every series for a job carries the same labels (the
    /// CPU profiles attach the equivalent Pyroscope labels in `profiling::push`).
    pub fn push_slurm_attrs(&self, attrs: &mut Vec<KeyValue>) {
        if let Some(slurm) = &self.slurm {
            attrs.push(KeyValue::new("slurm.job_id", slurm.job_id as i64));
            if let Some(uid) = slurm.uid {
                attrs.push(KeyValue::new("uid", i64::from(uid)));
            }
        }
    }

    /// Build a standalone meter backed by an unread [`ManualReader`], for tests
    /// in other modules that need a [`CgroupMeter`] without OTLP plumbing.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str) -> Arc<Self> {
        let reader = SharedManualReader(Arc::new(ManualReader::builder().build()));
        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .build();
        let meter = provider.meter("test");
        Arc::new(CgroupMeter {
            id: 1,
            name: name.to_owned(),
            slurm: None,
            meter,
            provider,
            reader,
        })
    }
}

/// The single source of truth for which cgroups are alive and the owner of every
/// per-cgroup [`SdkMeterProvider`].
///
/// Features ask the registry for a cgroup's [`CgroupMeter`] (via
/// [`get_or_create`](Self::get_or_create), usually indirectly through
/// [`PerCgroup`]) and attach their instruments to it, so one provider per cgroup is
/// created and shared. A single call to [`cleanup_dead_cgroups`] walks
/// `/sys/fs/cgroup`, tears down providers for exited cgroups, and hands the live
/// snapshot back so every feature prunes its per-cgroup state against the same view.
///
/// [`cleanup_dead_cgroups`]: Self::cleanup_dead_cgroups
pub struct CgroupRegistry {
    /// Tracked cgroups keyed by their **canonical** id (see [`CgroupMeter::id`]):
    /// a SLURM job's many sub-cgroups collapse to one entry here.
    cgroups: DashMap<u64, Arc<CgroupMeter>, FxBuildHasher>,
    /// Positive cache mapping a **raw** event id (the leaf cgroup a task ran in)
    /// to its canonical tracked id, so the common case — repeated events from the
    /// same leaf cgroup — resolves in O(1) without re-reading `/proc` or re-walking
    /// the tree. Pruned each [`cleanup_dead_cgroups`] for raw ids whose leaf cgroup
    /// has died (so ended SLURM steps/tasks don't accumulate).
    ///
    /// [`cleanup_dead_cgroups`]: Self::cleanup_dead_cgroups
    raw_to_canonical: DashMap<u64, u64, FxBuildHasher>,
    /// Negative cache of **raw** event ids that resolved to the root cgroup or
    /// could not be named (so they carry no meter). Kept so a flood of events from
    /// such cgroups — the norm on a busy node — is rejected in O(1) instead of
    /// redoing the resolution work per event. Cleared on every
    /// [`cleanup_dead_cgroups`] pass so the rejection can never outlive a
    /// ~cleanup-interval window: a cgroup that was only transiently unresolvable
    /// (e.g. its emitting task had already exited) gets retried.
    ///
    /// [`cleanup_dead_cgroups`]: Self::cleanup_dead_cgroups
    unresolved: DashMap<u64, (), FxBuildHasher>,
    /// Which hierarchy (v1/v2) we track; selects the `/proc/<tgid>/cgroup` line
    /// and which mount [`root`](Self::root) is anchored/walked.
    mode: CgroupMode,
    /// The mount the tracked hierarchy lives under (cgroup2 mount for v2, the cpu
    /// v1 mount for v1). Names, path resolution and the liveness walk are all
    /// anchored here.
    root: PathBuf,
    resource: Resource,
    exporter: SharedExporter,
    /// Per-provider metric views contributed by features (see [`CgroupView`]),
    /// applied to each cgroup's provider as it is created.
    views: Vec<CgroupView>,
}

impl CgroupRegistry {
    /// Create a new (empty) registry tracking the `mode` hierarchy. Providers are
    /// created lazily on first use, each configured with the feature-contributed
    /// `views` (e.g. the IO histogram aggregations from
    /// [`crate::metrics::io::histogram_views`]).
    pub fn new(views: Vec<CgroupView>, mode: CgroupMode) -> Self {
        let exporter = MetricExporter::builder()
            .with_tonic()
            .with_protocol(Protocol::Grpc)
            .with_compression(Compression::Zstd)
            .with_tls_config(crate::telemetry::otlp_tls_config())
            .build()
            .expect("failed to create OTLP metric exporter");

        let root = match mode {
            CgroupMode::V2 => cgroup2_mount_point().to_path_buf(),
            CgroupMode::V1 => cpu_v1_mount_point().to_path_buf(),
        };

        Self {
            cgroups: DashMap::default(),
            raw_to_canonical: DashMap::default(),
            unresolved: DashMap::default(),
            mode,
            root,
            resource: build_resource(),
            exporter: SharedExporter(Arc::new(exporter)),
            views,
        }
    }

    /// Return the [`CgroupMeter`] for `cgroup_id`, creating its provider on first
    /// use. Returns `None` for the root cgroup (empty name, which Pyroscope and
    /// most dashboards reject anyway) or a cgroup that could not be named.
    ///
    /// `tgid` is an optional resolution hint: the id of a task that was running in
    /// the cgroup when the event was produced. When given, the name is read
    /// straight from `/proc/<tgid>/cgroup` (one small file) instead of walking all
    /// of `/sys/fs/cgroup` looking for the matching inode — the walk is O(number of
    /// cgroups on the machine) and, on a busy node (especially a hybrid
    /// cgroup v1+v2 layout, where the walk also traverses every v1 controller tree
    /// whose inodes never match the v2 id), dominates the event-processing cost.
    /// Callers without a task in hand (e.g. profile draining) pass `None` and fall
    /// back to the walk.
    pub async fn get_or_create(
        &self,
        cgroup_id: u64,
        tgid: Option<u32>,
    ) -> Option<Arc<CgroupMeter>> {
        // Fast path: a raw event id we've already mapped to its canonical tracked
        // cgroup. Drop the `Ref` before touching `cgroups` to keep it short.
        if let Some(canonical) = self.raw_to_canonical.get(&cgroup_id).map(|r| *r)
            && let Some(cg) = self.cgroups.get(&canonical)
        {
            return Some(Arc::clone(&cg));
        }
        if self.unresolved.contains_key(&cgroup_id) {
            return None;
        }

        // Resolve the leaf cgroup's path, then fold it onto its canonical (SLURM
        // job, or itself) tracked cgroup.
        let leaf = match self.resolve_leaf(cgroup_id, tgid).await {
            LeafResolution::Path(path) => path,
            // Root or no matching inode in the tree (dead): remember it so the next
            // event from the same id is rejected without redoing the work (until the
            // next cleanup clears the negative cache).
            LeafResolution::Unnameable => {
                self.unresolved.insert(cgroup_id, ());
                return None;
            }
            // Could only fail to confirm via `/proc` (the hinting task has since
            // exited, or migrated cgroups). The id itself may well be live, so don't
            // poison the negative cache — just skip this event and let the next one,
            // hopefully from a resident task, resolve it.
            LeafResolution::Unconfirmed => return None,
        };

        // Resolving the canonical id may stat the SLURM job dir; a failure there is
        // a transient race, not cacheable.
        let info = self.canonicalize(&leaf, cgroup_id).await?;

        let canonical_id = info.canonical_id;
        let meter = Arc::clone(
            &self
                .cgroups
                .entry(canonical_id)
                .or_insert_with(|| Arc::new(self.create_meter(info))),
        );
        // Record the raw -> canonical mapping for the O(1) fast path next time.
        self.raw_to_canonical.insert(cgroup_id, canonical_id);
        Some(meter)
    }

    /// Resolve a raw event id to the path of the leaf cgroup the task ran in,
    /// preferring the cheap `/proc/<tgid>/cgroup` read when a `tgid` hint is
    /// available and only walking the tracked mount as a fallback (no hint, e.g.
    /// the profiler). The path is verified to actually have inode `cgroup_id`.
    async fn resolve_leaf(&self, cgroup_id: u64, tgid: Option<u32>) -> LeafResolution {
        match tgid {
            Some(tgid) => self.resolve_leaf_via_proc(cgroup_id, tgid).await,
            None => self.resolve_leaf_via_walk(cgroup_id).await,
        }
    }

    /// Read `/proc/<tgid>/cgroup`, pick the line for the tracked hierarchy
    /// (`0::<path>` for v2, the `cpu`-controller line for v1), anchor it under the
    /// tracked mount, and confirm the directory's inode is in fact `cgroup_id`
    /// (guarding against the task migrating cgroups between the eBPF event and now).
    async fn resolve_leaf_via_proc(&self, cgroup_id: u64, tgid: u32) -> LeafResolution {
        use std::os::unix::fs::MetadataExt;

        // The hinting task has exited (or /proc is unreadable): can't confirm.
        let Ok(content) = tokio::fs::read_to_string(format!("/proc/{tgid}/cgroup")).await else {
            return LeafResolution::Unconfirmed;
        };
        let Some(rel) = self.proc_cgroup_path(&content) else {
            return LeafResolution::Unconfirmed;
        };
        // `rel` is absolute within the hierarchy ("/system.slice/...", or "/" for
        // the root). Join onto the mount without letting the leading slash reset it.
        if rel == "/" {
            return LeafResolution::Unnameable; // root cgroup: no usable name
        }
        let full = self.root.join(rel.trim_start_matches('/'));

        let Ok(meta) = tokio::fs::metadata(&full).await else {
            return LeafResolution::Unconfirmed;
        };
        if meta.ino() != cgroup_id {
            // The task moved cgroups since the event; this path names the wrong one.
            return LeafResolution::Unconfirmed;
        }
        LeafResolution::Path(full)
    }

    /// Walk the tracked mount for the directory whose inode is `cgroup_id`.
    async fn resolve_leaf_via_walk(&self, cgroup_id: u64) -> LeafResolution {
        match find_cgroup_path(&self.root, cgroup_id).await {
            // The mount root itself: the root cgroup, no usable name.
            Some(path) if path == self.root => LeafResolution::Unnameable,
            Some(path) => LeafResolution::Path(path),
            None => LeafResolution::Unnameable,
        }
    }

    /// Extract the tracked hierarchy's cgroup path from `/proc/<pid>/cgroup`
    /// content: the `0::<path>` unified line for v2, or the line whose controller
    /// list contains `cpu` for v1.
    fn proc_cgroup_path<'a>(&self, content: &'a str) -> Option<&'a str> {
        match self.mode {
            CgroupMode::V2 => content.lines().find_map(|l| l.strip_prefix("0::")),
            CgroupMode::V1 => content.lines().find_map(|l| {
                // Format: `hierarchy-id:controller-list:path`.
                let mut fields = l.splitn(3, ':');
                let _hid = fields.next()?;
                let controllers = fields.next()?;
                let path = fields.next()?;
                controllers.split(',').any(|c| c == "cpu").then_some(path)
            }),
        }
    }

    /// Map a resolved leaf cgroup path to the **canonical** cgroup we track it
    /// under: for a SLURM job (`.../job_<N>/...`) that's the job cgroup (so its
    /// `step_*/task_*` sub-cgroups collapse into one series), otherwise the leaf
    /// itself. Returns `None` only when the SLURM job dir can't be stat'd right now
    /// (a transient race — not cached).
    async fn canonicalize(&self, leaf: &Path, raw_id: u64) -> Option<ResolvedInfo> {
        use std::os::unix::fs::MetadataExt;

        // Path relative to the tracked mount, for SLURM detection.
        let rel = leaf.strip_prefix(&self.root).unwrap_or(leaf);

        if let Some(job) = parse_slurm(rel) {
            // The job cgroup is the first `job.depth` components under the mount.
            let job_dir: PathBuf = self
                .root
                .join(rel.iter().take(job.depth).collect::<PathBuf>());
            let Ok(meta) = tokio::fs::metadata(&job_dir).await else {
                return None; // job dir vanished mid-resolve: retry next event
            };
            Some(ResolvedInfo {
                canonical_id: meta.ino(),
                name: format!("job_{}", job.job.job_id),
                slurm: Some(job.job),
            })
        } else {
            // Non-SLURM: track the leaf as-is.
            let name = leaf
                .strip_prefix(&self.root)
                .unwrap_or(leaf)
                .to_string_lossy()
                .into_owned();
            Some(ResolvedInfo {
                canonical_id: raw_id,
                name,
                slurm: None,
            })
        }
    }

    /// Walk the tracked mount, shut down + drop providers whose cgroup no longer
    /// exists, and return the set of still-live cgroup ids so callers can prune
    /// their own per-cgroup state against the same snapshot.
    pub async fn cleanup_dead_cgroups(&self) -> FxHashSet<u64> {
        let live = collect_live_cgroup_ids(&self.root).await;

        // Drop the negative cache so a cgroup that was only transiently
        // unresolvable last window (its emitting task had already exited) gets a
        // fresh resolution attempt rather than staying suppressed.
        self.unresolved.clear();
        // Prune raw->canonical mappings whose leaf cgroup has died, so ended SLURM
        // steps/tasks don't accumulate. The canonical (job) cgroup outlives its
        // steps and stays in `cgroups` as long as its own dir is live.
        self.raw_to_canonical.retain(|raw, _| live.contains(raw));

        let dead: Vec<u64> = self
            .cgroups
            .iter()
            .map(|elem| *elem.key())
            .filter(|id| !live.contains(id))
            .collect();

        // Drop dead cgroups from the map and shut their providers down. With a
        // `ManualReader` there is no background thread to join and no final
        // blocking export — `shutdown()` just marks the reader closed so any later
        // `collect()` is a no-op — so this is cheap and runs inline.
        for id in dead {
            if let Some((_, cg)) = self.cgroups.remove(&id) {
                log::info!("Removing cgroup {}", cg.name);
                if let Err(e) = cg.provider.shutdown() {
                    log::warn!("Failed to shut down provider for cgroup {}: {e}", cg.name);
                }
            }
        }

        live
    }

    fn create_meter(&self, info: ResolvedInfo) -> CgroupMeter {
        let ResolvedInfo {
            canonical_id,
            name,
            slurm,
        } = info;
        log::info!("Adding cgroup {name}");

        // A thread-free `ManualReader` per provider. The registry's single export
        // timer (`collect_and_export_all`) pulls it through the shared OTLP
        // exporter, so — unlike a `PeriodicReader` — no per-cgroup background
        // thread is spawned. Match the exporter's temporality so collected data is
        // aggregated the way the collector expects.
        let reader = SharedManualReader(Arc::new(
            ManualReader::builder()
                .with_temporality(self.exporter.temporality())
                .build(),
        ));

        let mut builder = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .with_resource(self.resource.clone());
        // Apply each feature-contributed view (e.g. the IO histogram aggregations).
        for view in &self.views {
            let view = Arc::clone(view);
            builder = builder.with_view(move |inst: &Instrument| view(inst));
        }
        let provider = builder.build();

        let meter = provider.meter("hpc-otel-exporter");

        CgroupMeter {
            id: canonical_id,
            name,
            slurm,
            meter,
            provider,
            reader,
        }
    }

    /// Collect every live cgroup's [`ManualReader`] and push it through the shared
    /// OTLP exporter, each cgroup in its own tokio task. Driven by a single timer in
    /// [`crate::app`], this replaces the per-provider background threads a
    /// [`PeriodicReader`] would otherwise spawn.
    ///
    /// [`PeriodicReader`]: opentelemetry_sdk::metrics::PeriodicReader
    pub fn collect_and_export_all(&self) {
        // Snapshot the providers so we hold no DashMap guard while spawning (a guard
        // held across the spawned tasks' work risks deadlocking `get_or_create`).
        let cgroups: Vec<Arc<CgroupMeter>> =
            self.cgroups.iter().map(|e| Arc::clone(e.value())).collect();

        for cg in cgroups {
            let exporter = self.exporter.clone();
            tokio::spawn(async move {
                let mut rm = ResourceMetrics::default();
                match cg.reader.collect(&mut rm) {
                    Err(e) => log::warn!("Failed to collect metrics for cgroup {}: {e}", cg.name),
                    // Skip a genuinely empty payload — a provider whose instruments
                    // recorded nothing this window (delta) and so has no data points.
                    Ok(()) if rm.scope_metrics().next().is_none() => {}
                    Ok(()) => {
                        let start = Instant::now();
                        let result = exporter.export(&rm).await;
                        let elapsed = start.elapsed();
                        match result {
                            // Flag a slow-but-successful export
                            Ok(()) if elapsed >= SLOW_EXPORT_THRESHOLD => log::warn!(
                                "Slow metric export for cgroup {} took {:.1}s",
                                cg.name,
                                elapsed.as_secs_f64()
                            ),
                            Ok(()) => {}
                            Err(e) => log::warn!(
                                "Failed to export metrics for cgroup {} after {:.1}s: {e}",
                                cg.name,
                                elapsed.as_secs_f64()
                            ),
                        }
                    }
                }
            });
        }
    }
}

/// Per-feature, per-cgroup state of type `T` (instruments, symbol caches, …),
/// scoped to live cgroups.
///
/// Each feature that keeps per-cgroup state holds one of these instead of its own
/// map plus get-or-create/prune logic. [`get_or_create`](Self::get_or_create)
/// resolves the cgroup's shared [`CgroupMeter`] through the registry and builds the
/// state from it on first sight; [`retain_live`](Self::retain_live) drops the state
/// of cgroups absent from the registry's liveness snapshot.
///
/// Backed by a [`DashMap`] so features can record from a `&self` hot path. **Never
/// hold a returned [`Ref`]/[`RefMut`] across an `.await`** — that risks a deadlock.
/// `get_or_create` upholds this itself: it awaits the registry *before* touching
/// its own map, so it never holds its own guard across the await.
pub struct PerCgroup<T> {
    registry: Arc<CgroupRegistry>,
    map: DashMap<u64, T, FxBuildHasher>,
}

impl<T> PerCgroup<T> {
    /// Create empty per-cgroup state sharing `registry` for cgroup identity and
    /// liveness.
    pub fn new(registry: Arc<CgroupRegistry>) -> Self {
        Self {
            registry,
            map: DashMap::default(),
        }
    }

    /// The shared registry, for the occasional caller that needs to resolve a
    /// cgroup directly (e.g. its name for a span) beyond this map's state.
    pub fn registry(&self) -> &Arc<CgroupRegistry> {
        &self.registry
    }

    /// Get the per-cgroup state for the raw event id `id`, building it from the
    /// cgroup's shared meter via `init` on first sight. Returns `None` for the root
    /// cgroup or one that vanished before its name could be resolved (no meter), so
    /// callers can drop work for cgroups that have no metrics destination.
    ///
    /// The map is keyed by the registry's **canonical** id (see [`CgroupMeter::id`]),
    /// so a SLURM job's many sub-cgroups share a single entry. The returned
    /// [`RefMut`]'s key is that canonical id — callers that key sibling maps by
    /// cgroup should use it, not the raw `id`.
    ///
    /// `tgid` is the [resolution hint](CgroupRegistry::get_or_create) forwarded to
    /// the registry: pass the id of the task the event came from when known.
    pub async fn get_or_create<F>(
        &self,
        id: u64,
        tgid: Option<u32>,
        init: F,
    ) -> Option<RefMut<'_, u64, T>>
    where
        F: FnOnce(&Arc<CgroupMeter>) -> T,
    {
        // Resolve (and canonicalize) through the registry first — its raw->canonical
        // cache makes the steady state an O(1) lookup — then key our own map by the
        // canonical id. Awaiting before touching the map upholds the never-hold-a-
        // guard-across-await invariant.
        let meter = self.registry.get_or_create(id, tgid).await?;
        Some(self.map.entry(meter.id).or_insert_with(|| init(&meter)))
    }

    /// Read access to a cgroup's state, if present.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, T>> {
        self.map.get(&id)
    }

    /// Mutable access to a cgroup's state, if present.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, T>> {
        self.map.get_mut(&id)
    }

    /// Iterate all live cgroups' state (e.g. to refresh gauges across cgroups).
    pub fn iter(&self) -> dashmap::iter::Iter<'_, u64, T, FxBuildHasher> {
        self.map.iter()
    }

    /// Mutably iterate all live cgroups' state (e.g. to clear a per-cgroup cache
    /// across cgroups). As with the returned guards, do not `.await` while
    /// iterating.
    pub fn iter_mut(&self) -> dashmap::iter::IterMut<'_, u64, T, FxBuildHasher> {
        self.map.iter_mut()
    }

    /// Drop state for cgroups absent from `live` (the registry's snapshot from
    /// [`CgroupRegistry::cleanup_dead_cgroups`]), so stale state is released once a
    /// workload exits.
    pub fn retain_live(&self, live: &FxHashSet<u64>) {
        self.map.retain(|id, _| live.contains(id));
    }
}

/// Outcome of resolving a raw event id to the leaf cgroup directory it ran in,
/// distinguishing the cacheable "no usable name" verdict from the "couldn't
/// confirm right now" one, which must not be cached (see
/// [`CgroupRegistry::get_or_create`]).
enum LeafResolution {
    /// A verified leaf cgroup directory (its inode equals the raw event id).
    Path(PathBuf),
    /// The root cgroup, or an id with no matching cgroup at all. Cacheable.
    Unnameable,
    /// Resolution via `/proc` could not be confirmed (the hinting task exited or
    /// migrated). Not cacheable — the id may still be live.
    Unconfirmed,
}

/// The tracked-cgroup identity a leaf path canonicalizes to (see
/// [`CgroupRegistry::canonicalize`]).
struct ResolvedInfo {
    /// The canonical tracked id (SLURM job dir inode, or the raw leaf id).
    canonical_id: u64,
    /// Display name (`job_<N>` for SLURM, else the `/sys/fs/cgroup`-relative path).
    name: String,
    slurm: Option<SlurmJob>,
}

/// A parsed SLURM job cgroup path: the [`SlurmJob`] identity plus how many leading
/// path components form the job cgroup (everything below it — `step_*`, `task_*`,
/// `user`, … — is aggregated into the job).
struct SlurmParse {
    job: SlurmJob,
    /// Number of leading components of the mount-relative path, up to and
    /// including `job_<N>`, that name the job cgroup directory.
    depth: usize,
}

/// Detect a SLURM job in a mount-relative cgroup path and find the job cgroup to
/// aggregate it into. Generic across the v1 layout (`slurm/uid_<U>/job_<J>/step_*/
/// task_*`) and v2 layouts (which may differ and may omit the `uid_` segment): we
/// key purely off the first `job_<digits>` component, and pick up an `uid_<digits>`
/// component preceding it when present. Returns `None` for non-SLURM cgroups.
fn parse_slurm(rel: &Path) -> Option<SlurmParse> {
    let comps: Vec<&str> = rel
        .iter()
        .filter_map(|c| c.to_str())
        .filter(|c| !c.is_empty())
        .collect();

    let job_idx = comps
        .iter()
        .position(|c| parse_prefixed_u64(c, "job_").is_some())?;
    let job_id = parse_prefixed_u64(comps[job_idx], "job_")?;

    // The owning uid, from a `uid_<N>` segment before the job component (v1).
    let uid = comps[..job_idx]
        .iter()
        .rev()
        .find_map(|c| parse_prefixed_u64(c, "uid_"))
        .and_then(|u| u32::try_from(u).ok());

    Some(SlurmParse {
        job: SlurmJob { job_id, uid },
        depth: job_idx + 1,
    })
}

/// Parse `<prefix><digits>` (e.g. `job_1349782`) into the trailing number, or
/// `None` if the component doesn't have the prefix or isn't all-digits after it.
fn parse_prefixed_u64(component: &str, prefix: &str) -> Option<u64> {
    let digits = component.strip_prefix(prefix)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The cgroup v2 (unified) mount point, as reported by `/proc/self/mountinfo`,
/// resolved once and cached. Defaults to `/sys/fs/cgroup` if no `cgroup2` mount is
/// found. On a hybrid layout this is typically `/sys/fs/cgroup/unified`.
fn cgroup2_mount_point() -> &'static Path {
    use std::sync::OnceLock;
    static MOUNT: OnceLock<PathBuf> = OnceLock::new();
    MOUNT.get_or_init(|| detect_cgroup2_mount().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup")))
}

fn detect_cgroup2_mount() -> Option<PathBuf> {
    parse_cgroup2_mount(&std::fs::read_to_string("/proc/self/mountinfo").ok()?)
}

fn parse_cgroup2_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        // mountinfo: `... root mountpoint opts <optional fields> - fstype source super`.
        // The fstype sits just past the ` - ` separator; the mount point is the 5th
        // space-separated field of the part before it.
        let (pre, post) = line.split_once(" - ")?;
        (post.split_whitespace().next() == Some("cgroup2"))
            .then(|| pre.split_whitespace().nth(4).map(PathBuf::from))
            .flatten()
    })
}

/// The cgroup v1 `cpu,cpuacct` mount point, as reported by `/proc/self/mountinfo`,
/// resolved once and cached. Defaults to `/sys/fs/cgroup/cpu,cpuacct` if no such
/// mount is found. Used as the tracked-hierarchy root in [`CgroupMode::V1`].
fn cpu_v1_mount_point() -> &'static Path {
    use std::sync::OnceLock;
    static MOUNT: OnceLock<PathBuf> = OnceLock::new();
    MOUNT.get_or_init(|| {
        detect_cpu_v1_mount().unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/cpu,cpuacct"))
    })
}

fn detect_cpu_v1_mount() -> Option<PathBuf> {
    parse_cpu_v1_mount(&std::fs::read_to_string("/proc/self/mountinfo").ok()?)
}

fn parse_cpu_v1_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        // `... mountpoint opts <optional> - cgroup <source> <superopts>`. A v1
        // cgroup mount lists its controllers in the super options; pick the one
        // carrying the `cpu` controller.
        let (pre, post) = line.split_once(" - ")?;
        let mut post_fields = post.split_whitespace();
        if post_fields.next() != Some("cgroup") {
            return None;
        }
        let _source = post_fields.next()?;
        let superopts = post_fields.next()?;
        superopts
            .split(',')
            .any(|o| o == "cpu")
            .then(|| pre.split_whitespace().nth(4).map(PathBuf::from))
            .flatten()
    })
}

/// Walk `root` for the directory whose inode is `id`, returning its full path.
/// `root` is the tracked hierarchy's mount, so only that mount's inode space is
/// searched: on a hybrid layout the v1 controller trees and the v2 tree are
/// separate kernfs filesystems whose inode spaces collide, and searching the
/// wrong one would name a different cgroup.
async fn find_cgroup_path(root: &Path, id: u64) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(meta) = tokio::fs::metadata(&current).await else {
            continue;
        };
        if meta.ino() == id {
            return Some(current);
        }

        let Ok(mut entries) = tokio::fs::read_dir(&current).await else {
            continue;
        };
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let Ok(ft) = entry.file_type().await else {
                continue;
            };
            if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    None
}

/// Collect the inodes of every directory under the tracked hierarchy's mount
/// (`root`), the liveness snapshot [`CgroupRegistry::cleanup_dead_cgroups`] prunes
/// against. Confined to the one mount so v1/v2 inode-space collisions can't make a
/// dead cgroup look alive (the duplicate-"Adding", never-"Removing" leak).
pub(crate) async fn collect_live_cgroup_ids(root: &Path) -> FxHashSet<u64> {
    walk_cgroup_dir(root).await
}

async fn walk_cgroup_dir(dir: &Path) -> FxHashSet<u64> {
    use std::os::unix::fs::MetadataExt;

    let mut ids = FxHashSet::default();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(meta) = tokio::fs::metadata(&current).await else {
            continue;
        };
        ids.insert(meta.ino());

        let Ok(mut entries) = tokio::fs::read_dir(&current).await else {
            continue;
        };
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let Ok(ft) = entry.file_type().await else {
                continue;
            };
            if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }

    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn parse_cgroup2_mount_picks_the_cgroup2_line() {
        // Hybrid layout: v1 controllers under /sys/fs/cgroup, v2 under /unified.
        let mountinfo = "\
25 30 0:23 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
26 25 0:24 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec shared:10 - cgroup2 cgroup2 rw,nsdelegate
27 25 0:25 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec shared:11 - cgroup cgroup rw,memory
";
        assert_eq!(
            parse_cgroup2_mount(mountinfo),
            Some(PathBuf::from("/sys/fs/cgroup/unified"))
        );
    }

    #[test]
    fn parse_cgroup2_mount_handles_pure_v2_and_absence() {
        let unified = "31 25 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw,nsdelegate\n";
        assert_eq!(
            parse_cgroup2_mount(unified),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );

        let legacy_only = "27 25 0:25 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
        assert_eq!(parse_cgroup2_mount(legacy_only), None);
    }

    #[test]
    fn parse_cpu_v1_mount_picks_the_cpu_controller() {
        // Hybrid layout: several v1 controller mounts plus the v2 unified mount.
        let mountinfo = "\
26 25 0:24 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw,nsdelegate
27 25 0:25 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory
28 25 0:26 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct
29 25 0:27 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids
";
        assert_eq!(
            parse_cpu_v1_mount(mountinfo),
            Some(PathBuf::from("/sys/fs/cgroup/cpu,cpuacct"))
        );

        // Pure v2: no v1 cgroup mount at all.
        let v2_only = "26 25 0:24 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegate\n";
        assert_eq!(parse_cpu_v1_mount(v2_only), None);
    }

    #[test]
    fn parse_slurm_v1_layout() {
        // v1: /slurm/uid_<U>/job_<J>/step_<S>/task_<T>.
        let parsed = parse_slurm(Path::new(
            "slurm/uid_38262/job_1349782/step_interactive/task_0",
        ))
        .expect("recognized as a SLURM job");
        assert_eq!(parsed.job.job_id, 1349782);
        assert_eq!(parsed.job.uid, Some(38262));
        // Canonical job dir = slurm/uid_38262/job_1349782 (3 components).
        assert_eq!(parsed.depth, 3);
    }

    #[test]
    fn parse_slurm_v2_layout_without_uid() {
        // A v2-style layout that carries no uid_ segment: uid is omitted, the job
        // is still recognized and aggregated at the job_ component.
        let parsed = parse_slurm(Path::new(
            "system.slice/slurmstepd.scope/job_42/step_0/user/task_special",
        ))
        .expect("recognized as a SLURM job");
        assert_eq!(parsed.job.job_id, 42);
        assert_eq!(parsed.job.uid, None);
        assert_eq!(parsed.depth, 3); // system.slice/slurmstepd.scope/job_42
    }

    #[test]
    fn parse_slurm_rejects_non_slurm_and_malformed() {
        assert!(parse_slurm(Path::new("system.slice/chronyd.service")).is_none());
        assert!(parse_slurm(Path::new("user.slice/user-1000.slice")).is_none());
        // `job_` with no digits, or non-numeric, is not a job component.
        assert!(parse_slurm(Path::new("slurm/job_/step_0")).is_none());
        assert!(parse_slurm(Path::new("slurm/job_abc")).is_none());
    }

    /// On a cgroup v2 host, resolving our own pid's cgroup id via `/proc` must
    /// agree with the full-tree walk — the two resolvers have to find the same
    /// directory so they don't split a series. Skips on hosts without a v2
    /// hierarchy.
    #[tokio::test]
    async fn proc_resolution_matches_the_tree_walk_for_self() {
        // Our own v2 cgroup id is the inode of the dir named by /proc/self/cgroup's
        // `0::` line under the cgroup2 mount.
        let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
            return;
        };
        let Some(rel) = content.lines().find_map(|l| l.strip_prefix("0::")) else {
            return;
        };
        let mount = cgroup2_mount_point();
        let via_proc = if rel == "/" {
            mount.to_path_buf()
        } else {
            mount.join(rel.trim_start_matches('/'))
        };
        let Ok(meta) = std::fs::metadata(&via_proc) else {
            return;
        };
        let cgroup_id = meta.ino();

        // The walk over the same mount must land on the same directory.
        let via_walk = find_cgroup_path(mount, cgroup_id).await;
        assert_eq!(via_walk, Some(via_proc));
    }
}
