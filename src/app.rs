//! Application wiring and the main event loop.
//!
//! [`run`] loads the eBPF object, builds the shared [`CgroupRegistry`] and each
//! telemetry feature, hooks their ringbuffer consumers, and then drives them from
//! one `tokio::select!` loop. The loop stays feature-agnostic: ringbuffer events
//! go to a feature's `record`/sink, and the two timers fan out to each feature's
//! own `retain_live` / `on_cleanup` / `collect_and_push`, so adding a feature means
//! constructing it and adding a line per tick — not growing the loop body.

use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::signal;

use crate::bindings::UnwindMiss;
use crate::bpf::{self, ExporterSkelBuilder};
use crate::cgroup::{CgroupMode, CgroupRegistry};
use crate::metrics::{self, IoMetrics, MetadataMetrics};
use crate::numa::{self, RawEvent};
use crate::profiling::Profiler;
use crate::telemetry;

/// How often dead cgroups are reaped and every feature's per-cgroup state is
/// pruned (and the profiler services unwind misses / evicts dead processes).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

/// A telemetry signal the exporter can collect, selected via `--signals`. Each
/// maps to a feature: an eBPF program set that is attached (or not) and the
/// userspace half that records it. With none given on the CLI, all are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Signal {
    /// VFS metadata-operation duration metrics (the `meta_*` eBPF programs).
    #[value(name = "vfs_metadata")]
    VfsMetadata,
    /// VFS data read/write operation metrics (the `record_*` eBPF programs).
    #[value(name = "io_requests")]
    IoRequests,
    /// CPU profiles sampled via perf_event.
    #[value(name = "cpu_profiles")]
    CpuProfiles,
}

#[derive(Debug, Parser)]
pub struct Args {
    /// test whether attaching the eBPF programs succeeds and exit
    #[arg(long)]
    test_attach: bool,

    /// CPU sampling frequency in Hz for the profiler
    #[arg(long, default_value_t = 97)]
    profile_frequency: u64,

    /// Interval in seconds between draining and pushing CPU profiles
    #[arg(long, default_value_t = 5)]
    profile_interval_secs: u64,

    /// Interval in seconds between collecting and exporting metrics
    #[arg(long, default_value_t = 5)]
    metrics_interval_secs: u64,

    /// Base URL of the Pyroscope ingest endpoint
    #[arg(long, default_value = "http://localhost:4040")]
    pyroscope_url: String,

    /// Comma-separated list of signals to collect.
    /// Known: `vfs_metadata`, `io_requests`, `cpu_profiles`.
    /// Empty (the default) enables every signal.
    #[arg(long, value_delimiter = ',', value_enum)]
    signals: Vec<Signal>,

    /// Number of threads to use for the tokio runtime (default: number of CPUs)
    #[arg(long)]
    num_threads: Option<usize>,

    /// Group events by cgroup v1 `cpu,cpuacct` hierarchy instead of v2 (unified)
    #[arg(long)]
    use_cgroups_v1: bool,

    /// Comma-separated cgroup coalescing filters, applied in order.
    /// Known: `slurm`, `user-session`.
    /// Empty (the default) tracks every cgroup unfiltered.
    #[arg(long, value_delimiter = ',')]
    cgroup_filters: Vec<String>,

    /// Drop cgroups no `--cgroup-filters` filter handled, tracking only
    /// filter-claimed cgroups (a whitelist). With no filters this drops everything.
    #[arg(long)]
    drop_unhandled: bool,
}

/// Detect the cgroup v1 `cpu,cpuacct` hierarchy id from `/proc/self/cgroup` (the
/// leading `N:` field of the line whose controller list contains `cpu`). The eBPF
/// side passes it to `bpf_task_get_cgroup1` to fetch that hierarchy's cgroup.
fn detect_cpu_v1_hierarchy_id() -> Option<i32> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    content.lines().find_map(|line| {
        // Format: `hierarchy-id:controller-list:path`.
        let mut fields = line.splitn(3, ':');
        let hid = fields.next()?;
        let controllers = fields.next()?;
        controllers
            .split(',')
            .any(|c| c == "cpu")
            .then(|| hid.parse().ok())
            .flatten()
    })
}

/// Load and attach the eBPF object, wire up the telemetry features, and run the
/// event loop until Ctrl-C. The logging guard is owned by the caller; the tracing
/// provider is installed here and lives for the whole run.
pub fn run(args: Args) -> Result<()> {
    let nproc = std::thread::available_parallelism()?.get();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.num_threads.unwrap_or(nproc))
        .enable_all()
        .build()?;

    runtime.block_on(run_async(args))
}

async fn run_async(args: Args) -> Result<()> {
    // Console logging (env_logger) plus OTLP log export via the OpenTelemetry
    // appender. Installed first so setup-time logs are captured too; the guard
    // flushes buffered records on exit and must outlive the whole run.
    let env_logger = env_logger::Env::default().filter_or("RUST_LOG", "debug");
    let _logging_guard = telemetry::init_logging(env_logger);

    // Validate & build the coalescing filters up front,
    // so a bad `--cgroup-filters` value fails fast with a clear error.
    let filters = crate::cgroup_filter::parse_filters(&args.cgroup_filters)
        .map_err(|e| anyhow::anyhow!(e))?;

    // Which signals to collect. With none given on the CLI, enable all of them;
    // otherwise each feature is gated on being named in `--signals`.
    let all_signals = args.signals.is_empty();
    let metadata_enabled = all_signals || args.signals.contains(&Signal::VfsMetadata);
    let io_enabled = all_signals || args.signals.contains(&Signal::IoRequests);
    let profiling_enabled = all_signals || args.signals.contains(&Signal::CpuProfiles);

    // Optional self-profiling of the exporter itself (separate from the target
    // profiling in `profiling`); kept alive for the process' lifetime.
    #[cfg(feature = "pyroscope")]
    let _pyroscope_agent =
        crate::self_profile::setup_pyroscope(&args.pyroscope_url, &telemetry::build_resource());

    // Bump the memlock rlimit before loading (needed on older kernels).
    bpf::bump_memlock_rlimit();

    // Open the BPF object (embedded in the binary).
    let builder = ExporterSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object)?;

    // Select v1 vs v2 cgroup tracking before load: the eBPF side reads these
    // rodata knobs (see src/bpf/cgroup_id.bpf.h) and the registry resolves the
    // matching hierarchy. For v1 we pass the cpu,cpuacct hierarchy id so
    // bpf_task_get_cgroup1 fetches the right cgroup.
    let cgroup_mode = if args.use_cgroups_v1 {
        let hierarchy_id = detect_cpu_v1_hierarchy_id()
            .ok_or_else(|| anyhow::anyhow!("could not detect the cpu,cpuacct v1 hierarchy id"))?;
        info!("tracking cgroup v1 (cpu,cpuacct hierarchy id {hierarchy_id})");
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("BPF .rodata section present");
        rodata.USE_CGROUPS_V1 = true;
        rodata.CGROUP_V1_HID = hierarchy_id;
        CgroupMode::V1
    } else {
        CgroupMode::V2
    };

    // The perf_event sampler needs a per-CPU perf fd, so it is attached by the
    // profiler below; keep skel.attach() from trying to auto-attach it.
    open_skel.progs.do_sample.set_autoattach(false);

    // Suppress the eBPF programs behind any disabled signal so skel.attach()
    // skips them: no probes on the kernel VFS paths whose events nobody consumes.
    // The IO feature's programs are named `record_*`, the metadata feature's
    // `meta_*` (the profiler's `do_sample` is already handled above).
    if !io_enabled || !metadata_enabled {
        for mut prog in open_skel.open_object_mut().progs_mut() {
            let name = prog.name().to_string_lossy();
            let disabled = (!io_enabled && name.starts_with("record_"))
                || (!metadata_enabled && name.starts_with("meta_"));
            if disabled {
                prog.set_autoattach(false);
            }
        }
    }

    let mut skel = open_skel.load()?;

    info!("eBPF program loaded!");

    if args.test_attach {
        skel.attach()?;
        info!("eBPF program attached!");
        return Ok(());
    }

    // Per-NUMA-node event ring buffers. Created and inserted into the outer
    // ARRAY_OF_MAPS *before* attaching, so every event finds a populated ring
    // for its node; the draining threads start now and buffer into the channel
    // until the record task (spawned below) drains it. Counts events dropped on
    // channel overflow.
    let dropped_events = Arc::new(AtomicU64::new(0));
    let (mut event_rx, drainers) = numa::setup(
        &skel.maps.EVENTS,
        &skel.maps.METADATA_EVENTS,
        Arc::clone(&dropped_events),
    )?;

    // Attach all auto-attachable programs now that their rings are wired up.
    skel.attach()?;
    info!("eBPF program attached!");

    // Install the global tracer provider (OTLP/gRPC), kept alive for the whole run
    // so buffered spans flush on exit. The demand-driven unwind loader and
    // symbolization create spans against it.
    let _tracing_guard = telemetry::init_tracing();

    // Single owner of per-cgroup meter providers and cgroup liveness, shared by
    // every feature. IO and metadata each contribute their histogram aggregation
    // views.
    let mut histogram_views = metrics::io::histogram_views();
    histogram_views.extend(metrics::metadata::histogram_views());
    let registry = Arc::new(CgroupRegistry::new(
        histogram_views,
        cgroup_mode,
        filters,
        args.drop_unhandled,
    ));

    // IO + metadata metrics: shared behind an `Arc` so the ringbuffer callbacks
    // (`'static` closures) can record into them. `None` when the signal is off.
    let io_metrics = io_enabled.then(|| Arc::new(IoMetrics::new(Arc::clone(&registry))));
    let metadata_metrics =
        metadata_enabled.then(|| Arc::new(MetadataMetrics::new(Arc::clone(&registry))));

    // CPU profiler facade: owns the perf sampler, the native unwinder's userspace
    // half, and the per-cgroup symbol caches. `None` when profiling is disabled.
    let mut profiler = profiling_enabled.then(|| {
        Profiler::new(
            args.pyroscope_url.clone(),
            telemetry::hostname(),
            args.profile_frequency,
            args.profile_interval_secs,
            Arc::clone(&registry),
        )
    });
    if let Some(profiler) = &mut profiler {
        profiler.attach(&skel.progs.do_sample, args.profile_frequency)?;
    }

    // The unwind-miss sink is a cloneable `Arc<Mutex<..>>` the ringbuffer callback
    // writes into; grab it now, before the profiler is moved behind its own mutex.
    let miss_sink = profiler.as_ref().map(|p| p.miss_sink());

    // Owned, fd-dup'd handles to the maps the periodic tasks touch. `MapHandle` is
    // `Send + Sync + 'static` (unlike the skel-borrowed `Map`), so it can move into
    // independently spawned tasks without tying them to the skel's lifetime.
    let unwind_rows = MapHandle::try_from(&skel.maps.UNWIND_ROWS)?;
    let executables = MapHandle::try_from(&skel.maps.EXECUTABLES)?;
    let proc_mappings = MapHandle::try_from(&skel.maps.PROC_MAPPINGS)?;
    let stack_counts = MapHandle::try_from(&skel.maps.STACK_COUNTS)?;
    let stacks = MapHandle::try_from(&skel.maps.STACKS)?;

    // Share the profiler between the cleanup task (needs `&mut` for `on_cleanup`)
    // and the profile task; an async mutex because both hold the guard across
    // `.await`.
    let profiler = profiler.map(|p| Arc::new(tokio::sync::Mutex::new(p)));

    // IO + metadata events arrive via the per-NUMA-node draining threads (see
    // `numa::setup` above) over `event_rx`; one task drains the channel and runs
    // the async `record` path, serially as the single consume loop did before.
    let record_task = tokio::spawn({
        let io_metrics = io_metrics.clone();
        let metadata_metrics = metadata_metrics.clone();
        async move {
            // Drain in batches to amortize the per-event await overhead.
            let mut batch = Vec::with_capacity(1024);
            loop {
                let n = event_rx.recv_many(&mut batch, 1024).await;
                if n == 0 {
                    break; // all draining threads have stopped
                }
                for event in batch.drain(..) {
                    // The matching program set is only attached when its signal is
                    // enabled, so the `None` arm never actually fires; guard anyway.
                    match event {
                        RawEvent::Io(e) => {
                            if let Some(m) = &io_metrics {
                                m.record(&e).await;
                            }
                        }
                        RawEvent::Meta(e) => {
                            if let Some(m) = &metadata_metrics {
                                m.record(&e).await;
                            }
                        }
                    }
                }
            }
        }
    });

    // Unwind-miss ring buffer (a single global ring — low volume, only written
    // when profiling is on). Drained on the tokio runtime via its epoll fd; when
    // profiling is off there is no ring and the main loop just waits for Ctrl-C.
    let misses_ringbuf = if let Some(misses) = miss_sink {
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder.add(&skel.maps.UNWIND_MISSES, move |data: &[u8]| {
            if data.len() >= std::mem::size_of::<UnwindMiss>() {
                // Safety: the BPF program writes a UnwindMiss into this ring buffer;
                // read unaligned since the slice has no alignment guarantee.
                let miss = unsafe { (data.as_ptr() as *const UnwindMiss).read_unaligned() };
                misses.lock().unwrap().insert(miss.tgid, miss.cgroup_id);
            }
            0
        })?;
        Some(rb_builder.build()?)
    } else {
        None
    };

    // Wrap the unwind-miss ring's epoll fd with tokio's AsyncFd for async polling.
    let misses_fd = misses_ringbuf
        .as_ref()
        .map(|rb| {
            AsyncFd::with_interest(
                unsafe { BorrowedFd::borrow_raw(rb.epoll_fd()) },
                tokio::io::Interest::READABLE,
            )
        })
        .transpose()?;

    info!("Waiting for events... Press Ctrl-C to exit.");

    // Metrics export: pull every live cgroup's ManualReader and push it through the
    // shared OTLP exporter. Also surfaces the per-NUMA-node draining channel's
    // overflow count, so a record loop that can't keep up is visible.
    let metrics_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let dropped_events = Arc::clone(&dropped_events);
        let mut interval =
            tokio::time::interval(Duration::from_secs(args.metrics_interval_secs.max(1)));
        async move {
            loop {
                interval.tick().await;
                // Returns immediately after spawning one export task per cgroup, so a
                // slow export never delays the next tick.
                registry.collect_and_export_all();
                let dropped = dropped_events.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    log::warn!("dropped {dropped} events: record loop fell behind");
                }
            }
        }
    });

    // Dead-cgroup reaping + per-feature pruning: one walk of /sys/fs/cgroup tears
    // down dead providers and yields the live snapshot every feature prunes against.
    let cleanup_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let io_metrics = io_metrics.clone();
        let metadata_metrics = metadata_metrics.clone();
        let profiler = profiler.clone();
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let live = registry.cleanup_dead_cgroups().await;
                if let Some(m) = &io_metrics {
                    m.retain_live(&live);
                }
                if let Some(m) = &metadata_metrics {
                    m.retain_live(&live);
                }
                if let Some(profiler) = &profiler {
                    let mut profiler = profiler.lock().await;
                    profiler
                        .on_cleanup(&live, &unwind_rows, &executables, &proc_mappings)
                        .await;
                }
            }
        }
    });

    // CPU profile drain + push, only when profiling is enabled.
    let profile_task = profiler.as_ref().map(|profiler| {
        let profiler = Arc::clone(profiler);
        let mut interval =
            tokio::time::interval(Duration::from_secs(args.profile_interval_secs.max(1)));
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                profiler
                    .lock()
                    .await
                    .collect_and_push(&stack_counts, &stacks)
                    .await;
            }
        })
    });

    loop {
        match (&misses_fd, &misses_ringbuf) {
            // Profiling on: drain the unwind-miss ring alongside watching for Ctrl-C.
            (Some(async_fd), Some(ringbuf)) => {
                tokio::select! {
                    _ = async_fd.async_io(tokio::io::Interest::READABLE, |_| {
                        let consumed = ringbuf.consume_raw();
                        match consumed {
                            n if n > 0 => Ok(n),
                            0 => Err(std::io::ErrorKind::WouldBlock.into()),
                            n => Err(std::io::Error::from_raw_os_error(-n)),
                        }
                    }) => {},
                    _ = signal::ctrl_c() => {
                        info!("Ctrl-C received, exiting...");
                        break;
                    }
                }
            }
            // Profiling off: nothing else to poll, just wait for Ctrl-C.
            _ => {
                let _ = signal::ctrl_c().await;
                info!("Ctrl-C received, exiting...");
                break;
            }
        }
    }

    // Stop the periodic tasks before the skel drops. They hold only Arcs and
    // fd-dup'd MapHandles (independent of the skel), so aborting is clean.
    metrics_task.abort();
    cleanup_task.abort();
    record_task.abort();
    if let Some(profile_task) = profile_task {
        profile_task.abort();
    }
    // Stop and join the per-NUMA-node draining threads before the skel (and its
    // ring buffer maps) drop.
    drainers.shutdown();

    Ok(())
}
