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
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::one::{Ref, RefMut};
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{
    Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality,
};
use rustc_hash::{FxBuildHasher, FxHashSet};

use crate::telemetry::build_resource;

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

/// One cgroup's [`SdkMeterProvider`], shared by every feature that emits metrics
/// for that cgroup (IO tracing, CPU profiling, …).
///
/// Each provider carries hostname as a *resource* attribute; per-event attributes
/// are recorded on the instruments instead. A provider is created the first time
/// any feature touches a cgroup and is shut down + dropped by
/// [`CgroupRegistry::cleanup_dead_cgroups`] once the cgroup disappears, so stale
/// series stop being exported. Features build their own instruments from
/// [`meter`](Self::meter) and hold an `Arc<CgroupMeter>` so the provider keeps
/// exporting as long as anyone references it.
pub struct CgroupMeter {
    pub name: String,
    pub meter: Meter,
    provider: SdkMeterProvider,
}

impl CgroupMeter {
    /// Build a standalone meter backed by a no-op provider, for tests in other
    /// modules that need a [`CgroupMeter`] without OTLP plumbing.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str) -> Arc<Self> {
        let provider = SdkMeterProvider::builder().build();
        let meter = provider.meter("test");
        Arc::new(CgroupMeter {
            name: name.to_owned(),
            meter,
            provider,
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
            .build()
            .expect("failed to create OTLP metric exporter");

        Self {
            cgroups: DashMap::default(),
            resource: build_resource(),
            exporter: SharedExporter(Arc::new(exporter)),
            views,
        }
    }

    /// Return the [`CgroupMeter`] for `cgroup_id`, creating its provider on first
    /// use. Returns `None` for the root cgroup (empty name, which Pyroscope and
    /// most dashboards reject anyway) or a cgroup that vanished before its name
    /// could be resolved.
    pub async fn get_or_create(&self, cgroup_id: u64) -> Option<Arc<CgroupMeter>> {
        if let Some(cg) = self.cgroups.get(&cgroup_id) {
            return Some(Arc::clone(&cg));
        }
        let name = resolve_cgroup_name(cgroup_id).await?;
        if name.is_empty() {
            return None;
        }
        Some(Arc::clone(
            &self
                .cgroups
                .entry(cgroup_id)
                .or_insert_with(|| Arc::new(self.create_meter(name))),
        ))
    }

    /// Walk `/sys/fs/cgroup`, shut down + drop providers whose cgroup no longer
    /// exists, and return the set of still-live cgroup ids so callers can prune
    /// their own per-cgroup state against the same snapshot.
    pub async fn cleanup_dead_cgroups(&self) -> FxHashSet<u64> {
        let live = collect_live_cgroup_ids().await;
        let dead: Vec<u64> = self
            .cgroups
            .iter()
            .map(|elem| *elem.key())
            .filter(|id| !live.contains(id))
            .collect();

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

        // A fresh PeriodicReader per provider, reusing the shared Grpc exporter.
        let reader = PeriodicReader::builder(self.exporter.clone()).build();

        let mut builder = SdkMeterProvider::builder()
            .with_reader(reader)
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
    pub async fn get_or_create<F>(&self, id: u64, init: F) -> Option<RefMut<'_, u64, T>>
    where
        F: FnOnce(&Arc<CgroupMeter>) -> T,
    {
        if let Some(existing) = self.map.get_mut(&id) {
            return Some(existing);
        }
        // Miss: the get_mut guard above is dropped before this await.
        let meter = self.registry.get_or_create(id).await?;
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

pub(crate) async fn resolve_cgroup_name(id: u64) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let cgroup_root = Path::new("/sys/fs/cgroup");
    let mut stack = vec![cgroup_root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(meta) = tokio::fs::metadata(&current).await else {
            continue;
        };
        if meta.ino() == id {
            return current
                .strip_prefix(cgroup_root)
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
    walk_cgroup_dir(Path::new("/sys/fs/cgroup")).await
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
