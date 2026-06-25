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
    pub name: String,
    pub meter: Meter,
    provider: SdkMeterProvider,
    /// The provider's reader, shared so [`CgroupRegistry::collect_and_export_all`]
    /// can pull this cgroup's metrics on the registry's single export timer.
    reader: SharedManualReader,
}

impl CgroupMeter {
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
            name: name.to_owned(),
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
    cgroups: DashMap<u64, Arc<CgroupMeter>, FxBuildHasher>,
    /// Negative cache of cgroup ids that resolved to the root cgroup or could not
    /// be named (so they carry no meter). Kept so a flood of events from such
    /// cgroups — the norm on a busy node — is rejected in O(1) instead of redoing
    /// the resolution work per event. Cleared on every [`cleanup_dead_cgroups`]
    /// pass so the rejection can never outlive a ~cleanup-interval window: a cgroup
    /// that was only transiently unresolvable (e.g. its emitting task had already
    /// exited) gets retried.
    ///
    /// [`cleanup_dead_cgroups`]: Self::cleanup_dead_cgroups
    unresolved: DashMap<u64, (), FxBuildHasher>,
    resource: Resource,
    exporter: SharedExporter,
    /// Per-provider metric views contributed by features (see [`CgroupView`]),
    /// applied to each cgroup's provider as it is created.
    views: Vec<CgroupView>,
}

impl CgroupRegistry {
    /// Create a new (empty) registry. Providers are created lazily on first use,
    /// each configured with the feature-contributed `views` (e.g. the IO
    /// histogram aggregations from [`crate::metrics::io::histogram_views`]).
    pub fn new(views: Vec<CgroupView>) -> Self {
        let exporter = MetricExporter::builder()
            .with_tonic()
            .with_protocol(Protocol::Grpc)
            .with_compression(Compression::Zstd)
            .with_tls_config(crate::telemetry::otlp_tls_config())
            .build()
            .expect("failed to create OTLP metric exporter");

        Self {
            cgroups: DashMap::default(),
            unresolved: DashMap::default(),
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
        if let Some(cg) = self.cgroups.get(&cgroup_id) {
            return Some(Arc::clone(&cg));
        }
        if self.unresolved.contains_key(&cgroup_id) {
            return None;
        }

        match self.resolve_name(cgroup_id, tgid).await {
            // A real, nameable cgroup: create (or pick up the racing create of) its
            // provider.
            Resolution::Named(name) => Some(Arc::clone(
                &self
                    .cgroups
                    .entry(cgroup_id)
                    .or_insert_with(|| Arc::new(self.create_meter(name))),
            )),
            // Root or genuinely unnameable: remember it so the next event from the
            // same id is rejected without redoing the work (until the next cleanup
            // clears the negative cache).
            Resolution::Unnameable => {
                self.unresolved.insert(cgroup_id, ());
                None
            }
            // Could only fail to confirm via `/proc` (the hinting task has since
            // exited, or migrated cgroups). The id itself may well be live, so don't
            // poison the negative cache — just skip this event and let the next one,
            // hopefully from a resident task, resolve it.
            Resolution::Unconfirmed => None,
        }
    }

    /// Resolve `cgroup_id` to a name, preferring the cheap `/proc/<tgid>/cgroup`
    /// path when a `tgid` hint is available and only walking `/sys/fs/cgroup` as a
    /// fallback (no hint, e.g. the profiler).
    async fn resolve_name(&self, cgroup_id: u64, tgid: Option<u32>) -> Resolution {
        if let Some(tgid) = tgid {
            return resolve_cgroup_name_via_proc(cgroup_id, tgid).await;
        }
        match resolve_cgroup_name(cgroup_id).await {
            Some(name) if !name.is_empty() => Resolution::Named(name),
            // No name (root) or no matching inode in the tree (dead): cacheable.
            _ => Resolution::Unnameable,
        }
    }

    /// Walk `/sys/fs/cgroup`, shut down + drop providers whose cgroup no longer
    /// exists, and return the set of still-live cgroup ids so callers can prune
    /// their own per-cgroup state against the same snapshot.
    pub async fn cleanup_dead_cgroups(&self) -> FxHashSet<u64> {
        let live = collect_live_cgroup_ids().await;

        // Drop the negative cache so a cgroup that was only transiently
        // unresolvable last window (its emitting task had already exited) gets a
        // fresh resolution attempt rather than staying suppressed.
        self.unresolved.clear();

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

    fn create_meter(&self, name: String) -> CgroupMeter {
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
            name,
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

    /// Get the per-cgroup state for `id`, building it from the cgroup's shared
    /// meter via `init` on first sight. Returns `None` for the root cgroup or one
    /// that vanished before its name could be resolved (no meter), so callers can
    /// drop work for cgroups that have no metrics destination.
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
        if let Some(existing) = self.map.get_mut(&id) {
            return Some(existing);
        }
        // Miss: the get_mut guard above is dropped before this await.
        let meter = self.registry.get_or_create(id, tgid).await?;
        Some(self.map.entry(id).or_insert_with(|| init(&meter)))
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

/// Outcome of resolving a cgroup id to a name, distinguishing the cacheable
/// "this id has no usable name" verdict from the "couldn't confirm right now"
/// one, which must not be cached (see [`CgroupRegistry::get_or_create`]).
enum Resolution {
    /// A real cgroup with a non-empty name.
    Named(String),
    /// The root cgroup, or an id with no matching cgroup at all. Cacheable.
    Unnameable,
    /// Resolution via `/proc` could not be confirmed (the hinting task exited or
    /// migrated). Not cacheable — the id may still be live.
    Unconfirmed,
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

/// Resolve a cgroup id to its name using `/proc/<tgid>/cgroup`, avoiding the
/// full-tree walk in [`resolve_cgroup_name`]. Reads the task's unified-hierarchy
/// (`0::<path>`) entry, anchors it under the cgroup v2 mount, and confirms the
/// resulting directory's inode is in fact `cgroup_id` — guarding against the task
/// having migrated cgroups between the eBPF event and now.
async fn resolve_cgroup_name_via_proc(cgroup_id: u64, tgid: u32) -> Resolution {
    use std::os::unix::fs::MetadataExt;

    // The hinting task has exited (or /proc is unreadable): can't confirm.
    let Ok(content) = tokio::fs::read_to_string(format!("/proc/{tgid}/cgroup")).await else {
        return Resolution::Unconfirmed;
    };
    // The unified-hierarchy line: `0::<path>`. Always present on v2 and hybrid.
    let Some(rel) = content.lines().find_map(|l| l.strip_prefix("0::")) else {
        return Resolution::Unconfirmed;
    };

    let mount = cgroup2_mount_point();
    // `rel` is absolute ("/system.slice/...", or "/" for the root). Join onto the
    // mount point without letting the leading slash reset the path.
    let full = if rel == "/" {
        mount.to_path_buf()
    } else {
        mount.join(rel.trim_start_matches('/'))
    };

    let Ok(meta) = tokio::fs::metadata(&full).await else {
        return Resolution::Unconfirmed;
    };
    if meta.ino() != cgroup_id {
        // The task moved cgroups since the event; this path names the wrong one.
        return Resolution::Unconfirmed;
    }

    // Name relative to /sys/fs/cgroup, matching the walk-based resolver's output so
    // both paths produce the same series. Empty for the root cgroup.
    let name = full
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(&full)
        .to_string_lossy()
        .into_owned();
    if name.is_empty() {
        Resolution::Unnameable
    } else {
        Resolution::Named(name)
    }
}

pub(crate) async fn resolve_cgroup_name(id: u64) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    // Walk only the cgroup v2 (unified) mount: ids come from
    // `bpf_get_current_cgroup_id` (v2 inodes), and on a hybrid layout the v1
    // controller trees are separate kernfs filesystems whose inode spaces collide
    // with v2 ids — matching one would name the wrong cgroup.
    let cgroup_root = cgroup2_mount_point();
    let mut stack = vec![cgroup_root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(meta) = tokio::fs::metadata(&current).await else {
            continue;
        };
        if meta.ino() == id {
            // Name relative to the tmpfs root (not the v2 mount), so on a hybrid
            // layout this yields `unified/...` — matching the `/proc` resolver's
            // output so the two paths never split a series.
            return current
                .strip_prefix("/sys/fs/cgroup")
                .unwrap_or(&current)
                .to_string_lossy()
                .into_owned()
                .into();
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

pub(crate) async fn collect_live_cgroup_ids() -> FxHashSet<u64> {
    // Walk only the cgroup v2 (unified) mount. Tracked ids are v2 inodes; on a
    // hybrid v1+v2 layout the v1 controller trees under `/sys/fs/cgroup` are
    // separate kernfs filesystems with their own inode spaces that collide with v2
    // ids. Folding those in here makes a dead v2 cgroup look alive whenever some
    // unrelated live v1 directory shares its inode, so its provider is never torn
    // down — the duplicate-"Adding cgroup", never-"Removing cgroup" leak.
    walk_cgroup_dir(cgroup2_mount_point()).await
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

    /// On a cgroup v2 host, resolving our own pid's cgroup id via `/proc` must
    /// agree with the full-tree walk — the two resolvers have to produce identical
    /// names so they don't split a series. Skips on hosts without a v2 hierarchy.
    #[tokio::test]
    async fn proc_resolution_matches_the_tree_walk_for_self() {
        let pid = std::process::id();
        // Our own v2 cgroup id is the inode of the dir named by /proc/self/cgroup's
        // `0::` line under the cgroup2 mount.
        let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
            return;
        };
        let Some(rel) = content.lines().find_map(|l| l.strip_prefix("0::")) else {
            return;
        };
        let mount = cgroup2_mount_point();
        let path = if rel == "/" {
            mount.to_path_buf()
        } else {
            mount.join(rel.trim_start_matches('/'))
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            return;
        };
        let cgroup_id = meta.ino();

        let via_walk = resolve_cgroup_name(cgroup_id).await;
        match resolve_cgroup_name_via_proc(cgroup_id, pid).await {
            // Non-root: both resolvers must agree on the name.
            Resolution::Named(name) => assert_eq!(Some(name), via_walk),
            // Root cgroup: the walk yields an empty name (or None).
            Resolution::Unnameable => {
                assert!(via_walk.as_deref().unwrap_or("").is_empty());
            }
            Resolution::Unconfirmed => panic!("self pid must resolve via /proc"),
        }
    }
}
