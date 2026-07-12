//! Userspace half of the native unwinder: keeps the BPF maps the in-kernel
//! walker reads populated, using hash-of-maps so total memory tracks what is
//! actually mapped and tables are reclaimed as processes exit.
//!
//! Each distinct backing file is parsed once (via [`unwind`]) into a single flat,
//! PC-sorted table of CFI rows, written into its own inner BPF array map (sized to
//! its row count) and inserted into `UNWIND_ROWS` keyed by `exec_id`; `EXECUTABLES`
//! carries the row count (the binary-search bound) and `PROC_MAPPINGS` records,
//! per process, which file backs each address range and how to translate a runtime
//! PC into that file's address space.
//!
//! Loading is demand-driven: the BPF program pushes the tgid of any sample whose
//! PC it can't map to the `UNWIND_MISSES` ring buffer, and [`ensure_pid`] reacts
//! by reading `/proc/<pid>/maps`. Because that re-read also fires when a loaded
//! process maps new code (e.g. a Python C-extension via `dlopen`), comparing the
//! maps signature lets us rebuild exactly when it changed — handling `dlopen`
//! while a permanent gap (vDSO/JIT) simply no-ops.
//!
//! Inner tables are reference-counted by the live processes mapping each file;
//! [`evict_dead`] drops a process' references on exit and frees any table whose
//! count reaches zero.
//!
//! [`ensure_pid`]: UnwindLoader::ensure_pid
//! [`evict_dead`]: UnwindLoader::evict_dead

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::Arc;

use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use log::{debug, info, warn};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundCounter, Gauge};
use rustc_hash::FxHashSet;

use crate::bindings::{ExecInfo, MAX_ROWS_PER_EXEC, MappingEntry, ProcessMappings, UnwindRow};
use crate::cgroup::{CgroupMeter, CgroupRegistry, PerCgroup};
use crate::telemetry::record_span_error;

use super::proc_maps::{self, RawMapping};
use super::unwind::{self, LoadSegment};

/// Per-cgroup metrics for the on-demand unwind loader, attached to the cgroup's
/// shared [`CgroupMeter`] (mirroring the IO and profiling metrics).
///
/// The counters are cumulative (load *work* triggered by misses); the gauges are
/// a snapshot of how much in-kernel unwind state the cgroup's live processes
/// currently hold, refreshed by [`UnwindLoader::record_table_gauges`] each
/// cleanup tick. Because the unwind tables are keyed by `exec_id` (a file is
/// stored once kernel-wide), the gauges count each distinct file **once per
/// cgroup that maps it** — so they measure a workload's unwind footprint, not the
/// (smaller, deduplicated) total kernel allocation. Gauges are synchronous
/// (recorded with the bound `cgroup.name` attribute on each refresh) rather than
/// bound, since `Gauge` has no bound form and the refresh is off the hot path.
struct UnwindMetrics {
    process_loads: BoundCounter<u64>,
    libraries_read: BoundCounter<u64>,
    libraries_failed: BoundCounter<u64>,
    /// FDEs (functions with unwind info) across the executables the cgroup maps.
    /// Informational: the kernel no longer stores an FDE index (rows are searched
    /// directly), so this does not contribute to resident kernel memory.
    fdes_resident: Gauge<u64>,
    /// Unwind rows across the executables the cgroup maps — the data actually
    /// resident in the kernel inner maps.
    rows_resident: Gauge<u64>,
    /// Estimated kernel bytes of those row tables (`rows · sizeof(UnwindRow)`).
    table_bytes_resident: Gauge<u64>,
    /// Distinct executables (`exec_id`s) the cgroup's processes map.
    executables_resident: Gauge<u64>,
    /// Processes in the cgroup with unwind tables currently loaded.
    processes_resident: Gauge<u64>,
    /// The `cgroup.name` attribute the gauges are recorded with.
    attrs: Vec<KeyValue>,
}

impl UnwindMetrics {
    fn new(cgroup: &CgroupMeter) -> Self {
        let meter = &cgroup.meter;
        let attrs = vec![KeyValue::new("cgroup.name", cgroup.name.clone())];
        UnwindMetrics {
            process_loads: meter
                .u64_counter("unwind.process_loads")
                .with_description(
                    "Processes whose native unwind tables were (re)loaded after a sample miss",
                )
                .build()
                .bind(&attrs),
            libraries_read: meter
                .u64_counter("unwind.libraries_read")
                .with_description("Backing files parsed for .eh_frame unwind info")
                .build()
                .bind(&attrs),
            libraries_failed: meter
                .u64_counter("unwind.libraries_failed")
                .with_description("Backing files that could not be parsed for unwind info")
                .build()
                .bind(&attrs),
            fdes_resident: meter
                .u64_gauge("unwind.fdes")
                .with_description(
                    "FDEs (functions with unwind info) in the executables this cgroup's \
                     processes map, each executable counted once per cgroup (informational: \
                     no FDE index is stored in the kernel)",
                )
                .build(),
            rows_resident: meter
                .u64_gauge("unwind.rows")
                .with_description(
                    "Unwind rows resident in the kernel for the executables this cgroup's \
                     processes map (each executable counted once per cgroup)",
                )
                .build(),
            table_bytes_resident: meter
                .u64_gauge("unwind.table_bytes")
                .with_description(
                    "Estimated kernel bytes of the row unwind tables this cgroup maps \
                     (each executable counted once per cgroup)",
                )
                .with_unit("By")
                .build(),
            executables_resident: meter
                .u64_gauge("unwind.executables")
                .with_description("Distinct executables this cgroup's processes map")
                .build(),
            processes_resident: meter
                .u64_gauge("unwind.processes")
                .with_description("Processes in this cgroup with unwind tables loaded")
                .build(),
            attrs,
        }
    }
}

/// Best-effort process name (`/proc/<pid>/comm`), used as a span/log attribute.
/// Falls back to `"unknown"` for an exited or unreadable process.
async fn process_name(pid: u32) -> String {
    tokio::fs::read_to_string(format!("/proc/{pid}/comm"))
        .await
        .map(|s| s.trim_end().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

const MAX_MAPPINGS: usize = crate::bindings::MAX_MAPPINGS_PER_PROC as usize;
/// `BPF_F_INNER_MAP`: a created inner map may differ in size from the template.
const BPF_F_INNER_MAP: u32 = 1 << 12;

/// What we know about one backing file after trying to load its unwind info.
enum ExecEntry {
    /// Published to `EXECUTABLES` (and, when `published`, to `UNWIND_ROWS`).
    /// `refs` counts the live processes mapping this file; at 0 it is freed.
    Mapped {
        refs: u32,
        /// Whether the inner rows map was inserted (false when the file has no
        /// usable unwind info, so it unwinds to one frame).
        published: bool,
        /// Entry counts of the published inner maps (0 when not `published`),
        /// for the per-cgroup resident-table gauges.
        fde_count: u32,
        row_count: u32,
        segments: Vec<LoadSegment>,
    },
    /// Could not be parsed; cached so we don't retry. Its mappings are skipped,
    /// so the kernel never references it — no refcount needed.
    Failed,
}

/// What we loaded for one process, so changes can be detected and refs released.
struct PidEntry {
    /// Signature of the `/proc/<pid>/maps` we last loaded from.
    sig: u64,
    /// The cgroup whose sample triggered the (most recent) load, used to
    /// attribute this process' resident unwind tables in the per-cgroup gauges.
    cgroup_id: u64,
    /// Distinct `exec_id`s this process references (each holds one ref).
    execs: FxHashSet<u64>,
}

pub struct UnwindLoader {
    /// Backing files we've processed, keyed by `exec_id`. A file's unwind info
    /// is parsed and written to its inner maps exactly once.
    execs: HashMap<u64, ExecEntry>,
    /// Processes we've loaded, for change detection and reference release.
    pids: HashMap<u32, PidEntry>,
    /// Per-cgroup unwind counters/gauges, created on first load for a cgroup and
    /// pruned by [`retain_live`](Self::retain_live) when the cgroup exits. Also
    /// the handle to the shared registry (via [`PerCgroup::registry`]) used to
    /// resolve a cgroup's name for spans.
    cgroup_metrics: PerCgroup<UnwindMetrics>,
}

impl UnwindLoader {
    pub fn new(registry: Arc<CgroupRegistry>) -> Self {
        UnwindLoader {
            execs: HashMap::new(),
            pids: HashMap::new(),
            cgroup_metrics: PerCgroup::new(registry),
        }
    }

    /// Load (or reload, if its maps changed) unwind info for `pid`, which a
    /// sample in `cgroup_id` couldn't be unwound for. Idempotent; best-effort,
    /// logging failures. `rows`/`execs`/`procs` are the `UNWIND_ROWS`,
    /// `EXECUTABLES` and `PROC_MAPPINGS` maps.
    ///
    /// When the process' maps actually changed (a genuinely new process, or one
    /// that `dlopen`ed new code) this emits a `unwind.load_process` span — with a
    /// child `unwind.read_library` span per backing file parsed — and increments
    /// the cgroup's unwind counters, so the demand-driven loading the in-kernel
    /// walker triggers is observable. Unchanged re-misses (permanent vDSO/JIT
    /// gaps) return early and emit nothing.
    pub async fn ensure_pid(
        &mut self,
        pid: u32,
        cgroup_id: u64,
        rows: &impl MapCore,
        execs: &impl MapCore,
        procs: &impl MapCore,
    ) {
        // Resolve the cgroup first, through the same registry interface the metrics
        // recorders use: `get_or_create` returns `None` for a cgroup no filter
        // tracks (dropped by `--cgroup-filters`/`--drop-unhandled`, or the
        // root/unnameable). Such a cgroup is ignored entirely — skip before doing
        // any work (reading maps, parsing unwind info) for its processes. On a
        // tracked cgroup it also gives us the shared meter: its name (for spans/logs)
        // and canonical (job-aggregated) id.
        let Some(meter) = self
            .cgroup_metrics
            .registry()
            .get_or_create(cgroup_id, Some(pid))
        else {
            return;
        };
        // Track this pid under the canonical cgroup so its unwind footprint groups
        // with the rest of the SLURM job.
        let canonical_id = meter.id;
        let cgroup_name = meter.name.clone();

        let content = match tokio::fs::read_to_string(format!("/proc/{pid}/maps")).await {
            Ok(c) => c,
            // The process exited; forget it and release its table references.
            Err(_) => {
                self.evict(pid, rows, execs, procs);
                return;
            }
        };
        let raw = proc_maps::parse_maps(&content);
        let sig = maps_signature(&raw);
        if self.pids.get(&pid).map(|p| p.sig) == Some(sig) {
            return; // already loaded and unchanged (covers permanent-gap re-misses)
        }

        let process_name = process_name(pid).await;

        // Parent span: the demand-driven load triggered by an unwind miss. The
        // per-file `unwind.read_library` child spans nest under it through the
        // shared `tracing` span stack. The synchronous load runs inside
        // `span.in_scope` rather than under a held `enter()` guard: that guard is
        // thread-local, so holding it across an `.await` — this future is polled
        // on a multi-threaded runtime and can migrate worker threads — would
        // silently misattribute spans. `in_scope` confines the span to this
        // synchronous region; if a future edit needs to `.await` here it won't
        // compile until it's instrumented explicitly (`.instrument(span).await`),
        // so the failure is loud rather than silent.
        let span = tracing::info_span!(
            "unwind.load_process",
            "cgroup.name" = cgroup_name.as_str(),
            "process.name" = process_name.as_str(),
            "process.pid" = pid,
            "unwind.reload" = self.pids.contains_key(&pid),
            "unwind.mappings" = tracing::field::Empty,
            "unwind.libraries_read" = tracing::field::Empty,
            "unwind.libraries_failed" = tracing::field::Empty,
            "otel.status_code" = tracing::field::Empty,
            "otel.status_description" = tracing::field::Empty,
        );

        // The synchronous load returns the counter deltas to fold into the
        // per-cgroup metrics afterwards (the `PerCgroup` lookup is async, so it
        // can't run inside the sync `in_scope`), or `None` if publishing the
        // mapping set failed.
        let load = span.in_scope(|| {
            info!("loading unwind info for pid {pid} ({process_name}) in cgroup {cgroup_name}");

            let mut entries: Vec<MappingEntry> = Vec::with_capacity(raw.len());
            let mut referenced: FxHashSet<u64> = FxHashSet::default();
            let mut libraries_read = 0u64;
            let mut libraries_failed = 0u64;
            for m in &raw {
                let id = proc_maps::exec_id(m.dev, m.inode);
                // A file already parsed (this or another process mapped it) is
                // reused without a read; only genuinely new files get a read span
                // + metric.
                let newly_read = !self.execs.contains_key(&id);
                // Read the backing file through /proc/<pid>/map_files/<range>: that
                // symlink resolves to the mapped inode inside the target's mount
                // namespace (so containerized jobs work) and survives unlinking.
                let open_path = format!("/proc/{pid}/map_files/{:x}-{:x}", m.begin, m.end);
                let segments = self.ensure_exec(
                    id,
                    &open_path,
                    &m.path,
                    &cgroup_name,
                    &process_name,
                    rows,
                    execs,
                );
                if newly_read {
                    match segments {
                        Some(_) => libraries_read += 1,
                        None => libraries_failed += 1,
                    }
                }
                let Some(segments) = segments else {
                    continue; // unparseable file: skip its mappings
                };
                referenced.insert(id);
                let Some(seg) =
                    proc_maps::segment_for_mapping(&segments, m.file_offset, m.end - m.begin)
                else {
                    // No executable segment overlaps this mapping's file range, so
                    // we can't translate its PCs to module VAs — skip it.
                    warn!(
                        "{}: executable mapping {:#x}-{:#x} (file offset {:#x}) overlaps no \
                         executable segment; its PCs will not unwind",
                        m.path, m.begin, m.end, m.file_offset
                    );
                    continue;
                };
                entries.push(MappingEntry {
                    begin: m.begin,
                    end: m.end,
                    load_offset: proc_maps::compute_load_offset(m.begin, m.file_offset, seg),
                    exec_id: id,
                });
            }
            entries.sort_unstable_by_key(|e| e.begin);
            entries.truncate(MAX_MAPPINGS);

            // Always publish the mapping set, even when empty, so a process with
            // no unwindable code stops being re-reported as a miss on every sample.
            let mut pm = ProcessMappings {
                len: entries.len() as u32,
                ..Default::default()
            };
            pm.entries[..entries.len()].copy_from_slice(&entries);
            if let Err(e) = procs.update(&pid.to_ne_bytes(), as_bytes(&pm), MapFlags::ANY) {
                warn!("failed to write PROC_MAPPINGS for pid {pid}: {e}");
                record_span_error(&span, &e);
                return None;
            }

            self.commit_refs(pid, sig, canonical_id, referenced, rows, execs);

            span.record("unwind.mappings", entries.len());
            span.record("unwind.libraries_read", libraries_read);
            span.record("unwind.libraries_failed", libraries_failed);
            info!(
                "loaded unwind info for pid {pid} ({process_name}) in cgroup {cgroup_name}: \
                 {} mappings, {libraries_read} new libraries read ({libraries_failed} unparseable)",
                entries.len()
            );

            Some((libraries_read, libraries_failed))
        });

        // Fold the load's counter deltas into the cgroup's metrics. The cgroup is
        // known tracked here (resolved above), so `get_or_create` is a registry
        // cache hit that lazily builds this cgroup's `UnwindMetrics` on first load.
        if let Some((libraries_read, libraries_failed)) = load
            && let Some(metrics) =
                self.cgroup_metrics
                    .get_or_create(cgroup_id, Some(pid), |meter| UnwindMetrics::new(meter))
        {
            metrics.process_loads.add(1);
            metrics.libraries_read.add(libraries_read);
            metrics.libraries_failed.add(libraries_failed);
        }
    }

    /// Drop per-cgroup unwind counters for cgroups absent from `live` (the
    /// registry's snapshot from [`CgroupRegistry::cleanup_dead_cgroups`]), so
    /// stale series stop being exported once a workload exits.
    pub fn retain_live(&mut self, live: &FxHashSet<u64>) {
        self.cgroup_metrics.retain_live(live);
    }

    /// Refresh the per-cgroup resident-table gauges from the current loader
    /// state. Call once per cleanup tick (after loads and evictions) so the
    /// gauges reflect the live working set.
    ///
    /// The unwind tables are keyed by `exec_id`, so a file shared across cgroups
    /// is stored once kernel-wide; here it is counted **once per cgroup that maps
    /// it**, making each gauge a workload's unwind footprint rather than the
    /// (deduplicated, smaller) total kernel allocation. Recomputed from scratch
    /// each tick rather than maintained incrementally, so it can't drift from the
    /// authoritative `pids`/`execs` state; this is cheap (bounded by the number of
    /// sampled processes and their distinct mappings, off the sampling hot path).
    pub fn record_table_gauges(&self) {
        // Distinct executables and process counts per cgroup.
        let mut execs_by_cgroup: HashMap<u64, FxHashSet<u64>> = HashMap::new();
        let mut procs_by_cgroup: HashMap<u64, u64> = HashMap::new();
        for entry in self.pids.values() {
            *procs_by_cgroup.entry(entry.cgroup_id).or_default() += 1;
            execs_by_cgroup
                .entry(entry.cgroup_id)
                .or_default()
                .extend(entry.execs.iter().copied());
        }

        // Only the flat rows occupy kernel inner-map memory now; the FDE count is
        // surfaced separately (informational) and is not stored in the kernel.
        let row_sz = size_of::<UnwindRow>() as u64;

        // Record for every cgroup we have instruments for — including ones whose
        // processes have all exited this tick, so their gauges fall back to 0
        // rather than reporting a stale last value until the cgroup itself dies.
        for entry in self.cgroup_metrics.iter() {
            let cgroup_id = entry.key();
            let metrics = entry.value();
            let (mut fdes, mut rows, mut executables) = (0u64, 0u64, 0u64);
            if let Some(set) = execs_by_cgroup.get(cgroup_id) {
                executables = set.len() as u64;
                for id in set {
                    if let Some(ExecEntry::Mapped {
                        fde_count,
                        row_count,
                        ..
                    }) = self.execs.get(id)
                    {
                        fdes += u64::from(*fde_count);
                        rows += u64::from(*row_count);
                    }
                }
            }
            let processes = procs_by_cgroup.get(cgroup_id).copied().unwrap_or(0);
            let bytes = rows * row_sz;

            let attrs = &metrics.attrs;
            metrics.fdes_resident.record(fdes, attrs);
            metrics.rows_resident.record(rows, attrs);
            metrics.table_bytes_resident.record(bytes, attrs);
            metrics.executables_resident.record(executables, attrs);
            metrics.processes_resident.record(processes, attrs);
        }
    }

    /// Drop tracking for processes that have exited, releasing their table
    /// references (and freeing any table no live process maps) and deleting
    /// their `PROC_MAPPINGS` so a reused PID re-loads fresh. Cheap: one `stat()`
    /// per tracked process, no `/proc/<pid>/maps` re-parsing.
    pub fn evict_dead(&mut self, rows: &impl MapCore, execs: &impl MapCore, procs: &impl MapCore) {
        let dead: Vec<u32> = self
            .pids
            .keys()
            .copied()
            .filter(|pid| !Path::new(&format!("/proc/{pid}")).exists())
            .collect();
        for pid in dead {
            self.evict(pid, rows, execs, procs);
        }
    }

    /// Parse (once) the unwind info for one backing file and publish it.
    /// `open_path` is read for the bytes (a `map_files` symlink); `display` names
    /// it in logs and spans. Returns its executable segments (for load-offset
    /// math), or `None` if it couldn't be parsed. Does not touch refcounts — the
    /// caller adjusts those via [`commit_refs`](Self::commit_refs).
    ///
    /// A cache hit returns immediately and emits nothing. A miss (a file not yet
    /// parsed) is the "library read" the caller's parent span covers, so it gets
    /// its own `unwind.read_library` child span timing the parse, plus a log line.
    #[allow(clippy::too_many_arguments)]
    fn ensure_exec(
        &mut self,
        id: u64,
        open_path: &str,
        display: &str,
        cgroup_name: &str,
        process_name: &str,
        rows: &impl MapCore,
        execs: &impl MapCore,
    ) -> Option<Vec<LoadSegment>> {
        if let Some(entry) = self.execs.get(&id) {
            return match entry {
                ExecEntry::Mapped { segments, .. } => Some(segments.clone()),
                ExecEntry::Failed => None,
            };
        }

        // Reading + parsing a not-yet-seen backing file: time it under its own
        // span, which nests in the entered `load_process` span via the `tracing`
        // span stack. `parse_executable` is synchronous, so entering here is sound.
        // Bound to a local: a bare `display` value in the macro would resolve to
        // `tracing::field::display` rather than this `&str` parameter.
        let file_name = display;
        let span = tracing::info_span!(
            "unwind.read_library",
            "cgroup.name" = cgroup_name,
            "process.name" = process_name,
            "file.name" = file_name,
            "unwind.fdes" = tracing::field::Empty,
            "unwind.rows" = tracing::field::Empty,
            "unwind.published" = tracing::field::Empty,
            "otel.status_code" = tracing::field::Empty,
            "otel.status_description" = tracing::field::Empty,
        );
        let _entered = span.enter();

        let info = match unwind::parse_executable(Path::new(open_path)) {
            Ok(info) => info,
            Err(e) => {
                debug!("no unwind info for {display}: {e}");
                record_span_error(&span, &e);
                self.execs.insert(id, ExecEntry::Failed);
                return None;
            }
        };

        let published = publish_exec(id, &info.rows, display, rows, execs);
        info!(
            "read unwind info for {display} (cgroup {cgroup_name}): \
             {} FDEs, {} rows, published={published}",
            info.fde_count,
            info.rows.len()
        );
        span.record("unwind.fdes", info.fde_count);
        span.record("unwind.rows", info.rows.len());
        span.record("unwind.published", published);
        // Only a published table actually occupies a kernel inner map; an
        // unpublished file unwinds to one frame and stores nothing, so it counts
        // as zero. `fde_count` is informational (no FDE index is stored).
        let (fde_count, row_count) = if published {
            (info.fde_count, info.rows.len() as u32)
        } else {
            (0, 0)
        };
        self.execs.insert(
            id,
            ExecEntry::Mapped {
                refs: 0,
                published,
                fde_count,
                row_count,
                segments: info.exec_segments.clone(),
            },
        );
        Some(info.exec_segments)
    }

    /// Update the process' set of referenced executables: bump refs for newly
    /// referenced files, release refs for ones it no longer maps (freeing tables
    /// that reach zero references).
    fn commit_refs(
        &mut self,
        pid: u32,
        sig: u64,
        cgroup_id: u64,
        referenced: FxHashSet<u64>,
        rows: &impl MapCore,
        execs: &impl MapCore,
    ) {
        let previous = self.pids.insert(
            pid,
            PidEntry {
                sig,
                cgroup_id,
                execs: referenced.clone(),
            },
        );
        let old = previous.map(|p| p.execs).unwrap_or_default();

        for id in referenced.difference(&old) {
            if let Some(ExecEntry::Mapped { refs, .. }) = self.execs.get_mut(id) {
                *refs += 1;
            }
        }
        for id in old.difference(&referenced) {
            self.release_exec(*id, rows, execs);
        }
    }

    /// Drop one reference to an executable's table; free it (delete from the BPF
    /// maps, letting the kernel reclaim the inner map) when none remain.
    fn release_exec(&mut self, id: u64, rows: &impl MapCore, execs: &impl MapCore) {
        let Some(ExecEntry::Mapped {
            refs, published, ..
        }) = self.execs.get_mut(&id)
        else {
            return;
        };
        *refs = refs.saturating_sub(1);
        if *refs > 0 {
            return;
        }
        let published = *published;
        self.execs.remove(&id);
        let _ = execs.delete(&id.to_ne_bytes());
        if published {
            let _ = rows.delete(&id.to_ne_bytes());
        }
    }

    /// Forget a process: delete its `PROC_MAPPINGS` and release its table refs.
    fn evict(&mut self, pid: u32, rows: &impl MapCore, execs: &impl MapCore, procs: &impl MapCore) {
        let Some(entry) = self.pids.remove(&pid) else {
            return;
        };
        let _ = procs.delete(&pid.to_ne_bytes());
        for id in entry.execs {
            self.release_exec(id, rows, execs);
        }
    }
}

/// Build this executable's inner rows map, insert it into `UNWIND_ROWS`, and
/// record its row count in `EXECUTABLES`. Returns whether the inner map was
/// published (false when the file has no usable unwind info, is too large, or a
/// map op failed — in which case it unwinds to a single frame but still gets an
/// `EXECUTABLES` entry, so the kernel stops cleanly instead of re-missing).
fn publish_exec(
    id: u64,
    rows: &[UnwindRow],
    display: &str,
    rows_map: &impl MapCore,
    execs: &impl MapCore,
) -> bool {
    let published = publish_inner_maps(id, rows, display, rows_map);
    let info = if published {
        ExecInfo {
            row_count: rows.len() as u32,
        }
    } else {
        ExecInfo { row_count: 0 }
    };
    let _ = execs.update(&id.to_ne_bytes(), as_bytes(&info), MapFlags::ANY);
    published
}

/// Create the executable's inner rows map and insert it into the hash-of-maps.
fn publish_inner_maps(id: u64, rows: &[UnwindRow], display: &str, rows_map: &impl MapCore) -> bool {
    if rows.is_empty() {
        return false; // no usable unwind info: one frame only
    }
    if rows.len() > MAX_ROWS_PER_EXEC as usize {
        warn!(
            "{display}: {} unwind rows exceed the per-executable cap; one frame only",
            rows.len()
        );
        return false;
    }

    let rows_inner = match create_inner_array("unwind_rows", rows) {
        Ok(m) => m,
        Err(e) => {
            warn!("{display}: failed to build unwind rows: {e}");
            return false;
        }
    };

    // The fd stays valid until this function returns, after which the
    // hash-of-maps holds the only reference.
    let key = id.to_ne_bytes();
    if let Err(e) = rows_map.update(
        &key,
        &rows_inner.as_fd().as_raw_fd().to_ne_bytes(),
        MapFlags::ANY,
    ) {
        warn!("{display}: failed to insert unwind rows: {e}");
        return false;
    }
    true
}

/// Create a right-sized inner array map and batch-write `elems` into it.
fn create_inner_array<T: Copy>(name: &str, elems: &[T]) -> libbpf_rs::Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as _,
        map_flags: BPF_F_INNER_MAP,
        ..Default::default()
    };
    let inner = MapHandle::create(
        MapType::Array,
        Some(name),
        size_of::<u32>() as u32,
        size_of::<T>() as u32,
        elems.len() as u32,
        &opts,
    )?;

    let mut keys: Vec<u8> = Vec::with_capacity(elems.len() * size_of::<u32>());
    for i in 0..elems.len() as u32 {
        keys.extend_from_slice(&i.to_ne_bytes());
    }
    inner.update_batch(
        &keys,
        slice_as_bytes(elems),
        elems.len() as u32,
        MapFlags::ANY,
        MapFlags::ANY,
    )?;
    Ok(inner)
}

/// A change-detecting digest of a process' executable mappings.
fn maps_signature(raw: &[RawMapping]) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    for m in raw {
        m.begin.hash(&mut h);
        m.end.hash(&mut h);
        m.file_offset.hash(&mut h);
        m.inode.hash(&mut h);
    }
    h.finish()
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    // Safety: T is a #[repr(C)] POD from bindgen; we expose its bytes read-only.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

fn slice_as_bytes<T: Copy>(v: &[T]) -> &[u8] {
    // Safety: as above, for a contiguous slice of POD.
    unsafe { std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), std::mem::size_of_val(v)) }
}
