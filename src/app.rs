//! Application wiring: the feature-agnostic composition root.
//!
//! [`run`] builds the shared [`CgroupRegistry`], constructs one [`Collector`]
//! per enabled signal (each owns its eBPF object, channels and tasks — see
//! [`crate::collector`]), starts the per-NUMA-node draining threads, attaches
//! everyone, and then only drives the two shared timers: the metrics-export
//! tick (registry-owned) and the cleanup tick (fanned out to every collector's
//! `on_cleanup`). Adding a signal means adding a [`Signal`] variant and its
//! construction arm below — the loop body never grows.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use log::info;
use tokio::signal;

use crate::cgroup::{CgroupMode, CgroupRegistry, CgroupView};
use crate::collector::{BuildCtx, CHANNEL_CAPACITY, Collector};
use crate::metrics::{self, IoCollector, MetadataCollector, Recorders};
use crate::numa;
use crate::profiling::CpuProfileCollector;
use crate::telemetry;

/// How often dead cgroups are reaped and every collector's per-cgroup state is
/// pruned (and the profiler services unwind misses / evicts dead processes).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

/// A telemetry signal the exporter can collect, selected via `--signals`. Each
/// maps to a [`Collector`]: its own eBPF object plus the userspace half that
/// records it. With none given on the CLI, all are enabled.
///
/// This enum is the single per-signal list: adding a signal means adding a
/// variant plus its [`views`](Self::views) / [`build`](Self::build) arms (and
/// the eBPF object in `build.rs`'s `BPF_SRCS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Signal {
    /// VFS metadata-operation duration metrics.
    #[value(name = "vfs_metadata")]
    VfsMetadata,
    /// VFS data read/write operation metrics.
    #[value(name = "io_requests")]
    IoRequests,
    /// CPU profiles sampled via perf_event.
    #[value(name = "cpu_profiles")]
    CpuProfiles,
}

impl Signal {
    /// Every signal, in construction order.
    const ALL: [Signal; 3] = [Signal::VfsMetadata, Signal::IoRequests, Signal::CpuProfiles];

    /// The metric views this signal contributes to every per-cgroup meter
    /// provider (registered at registry build time, before any collector runs).
    fn views(self) -> Vec<CgroupView> {
        match self {
            Signal::VfsMetadata => metrics::metadata::histogram_views(),
            Signal::IoRequests => metrics::io::histogram_views(),
            Signal::CpuProfiles => Vec::new(),
        }
    }

    /// Construct the signal's collector: open + load its eBPF object, register
    /// its rings with the shared drainer, and spawn its tasks (see
    /// [`crate::collector`] for the lifecycle).
    fn build(self, ctx: &mut BuildCtx, args: &Args) -> Result<Box<dyn Collector>> {
        Ok(match self {
            Signal::VfsMetadata => Box::new(MetadataCollector::new(ctx)?),
            Signal::IoRequests => Box::new(IoCollector::new(ctx)?),
            Signal::CpuProfiles => Box::new(CpuProfileCollector::new(
                ctx,
                args.pyroscope_url.clone(),
                args.profile_frequency,
                args.profile_interval_secs,
            )?),
        })
    }
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

    // Which signals to collect. With none given on the CLI, enable all of
    // them; walking `ALL` also dedups a repeated CLI value.
    let enabled: Vec<Signal> = Signal::ALL
        .into_iter()
        .filter(|s| args.signals.is_empty() || args.signals.contains(s))
        .collect();

    // Optional self-profiling of the exporter itself (separate from the target
    // profiling in `profiling`); kept alive for the process' lifetime.
    #[cfg(feature = "pyroscope")]
    let _pyroscope_agent =
        crate::self_profile::setup_pyroscope(&args.pyroscope_url, &telemetry::build_resource());

    // Bump the memlock rlimit before loading (needed on older kernels).
    crate::bpf::bump_memlock_rlimit();

    // Select v1 vs v2 cgroup tracking before load: every signal object reads
    // the same rodata knobs (see src/bpf/cgroup_id.bpf.h) and the registry
    // resolves the matching hierarchy. For v1 we pass the cpu,cpuacct hierarchy
    // id so bpf_task_get_cgroup1 fetches the right cgroup.
    let (cgroup_mode, v1_hierarchy_id) = if args.use_cgroups_v1 {
        let hierarchy_id = detect_cpu_v1_hierarchy_id()
            .ok_or_else(|| anyhow::anyhow!("could not detect the cpu,cpuacct v1 hierarchy id"))?;
        info!("tracking cgroup v1 (cpu,cpuacct hierarchy id {hierarchy_id})");
        (CgroupMode::V1, Some(hierarchy_id))
    } else {
        (CgroupMode::V2, None)
    };

    // Install the global tracer provider (OTLP/gRPC), kept alive for the whole run
    // so buffered spans flush on exit. The demand-driven unwind loader and
    // symbolization create spans against it.
    let _tracing_guard = telemetry::init_tracing();

    // Single owner of per-cgroup meter providers and cgroup liveness, shared by
    // every collector. Each enabled signal contributes its histogram
    // aggregation views.
    let histogram_views = enabled.iter().flat_map(|s| s.views()).collect();
    let registry = Arc::new(CgroupRegistry::new(
        histogram_views,
        cgroup_mode,
        filters,
        args.drop_unhandled,
    ));

    // The single shared metric-event channel: every metric collector's decode
    // callback sends its tagged event here, and one record task (spawned below)
    // drains it.
    let (tx, rx) = tokio::sync::mpsc::channel::<metrics::MetricEvent>(CHANNEL_CAPACITY);
    let mut recorders = Recorders::default();

    // Build one collector per enabled signal. Each opens + loads its own BPF
    // object (a disabled signal costs no verification and creates no maps),
    // registers its per-NUMA-node rings with the shared drainer, and (for metric
    // signals) registers its recording state on `recorders`. Nothing is attached
    // yet.
    let mut drainer = numa::DrainerBuilder::new();
    let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
    {
        let mut ctx = BuildCtx {
            registry: Arc::clone(&registry),
            v1_hierarchy_id,
            drainer: &mut drainer,
            events: tx,
            recorders: &mut recorders,
        };
        for signal in &enabled {
            collectors.push(signal.build(&mut ctx, &args)?);
        }
    }
    info!("eBPF objects loaded!");

    if args.test_attach {
        for collector in &mut collectors {
            collector.attach()?;
        }
        info!("eBPF programs attached!");
        return Ok(());
    }

    // The single record task draining the shared channel: dispatches each event
    // to the matching signal's recorder. Spawned before attach so it is ready to
    // consume the very first event.
    let record_task = tokio::spawn(recorders.run(rx));

    // Start the per-NUMA-node draining threads, then attach: every ring is
    // populated before any program can produce an event.
    let drainers = drainer.start()?;
    for collector in &mut collectors {
        collector.attach()?;
    }
    info!("eBPF programs attached!");

    // Shared with the cleanup task below; shutdown still walks them at the end.
    let collectors: Arc<[Box<dyn Collector>]> = Arc::from(collectors);

    info!("Waiting for events... Press Ctrl-C to exit.");

    // Metrics export: pull every live cgroup's ManualReader and push it through
    // the shared OTLP exporter, on one timer for all collectors.
    let metrics_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let mut interval =
            tokio::time::interval(Duration::from_secs(args.metrics_interval_secs.max(1)));
        async move {
            loop {
                interval.tick().await;
                // Returns immediately after spawning one export task per cgroup, so a
                // slow export never delays the next tick.
                registry.collect_and_export_all();
            }
        }
    });

    // Dead-cgroup reaping + per-collector pruning: one walk of /sys/fs/cgroup
    // tears down dead providers and yields the live snapshot every collector
    // prunes against.
    let cleanup_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let collectors = Arc::clone(&collectors);
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let live = registry.cleanup_dead_cgroups().await;
                for collector in collectors.iter() {
                    collector.on_cleanup(&live).await;
                }
            }
        }
    });

    let _ = signal::ctrl_c().await;
    info!("Ctrl-C received, exiting...");

    // Stop the shared timers, the shared record task, and every collector's own
    // tasks before the skeletons drop; the tasks hold only Arcs and fd-dup'd
    // MapHandles (independent of the skels), so aborting is clean.
    metrics_task.abort();
    cleanup_task.abort();
    record_task.abort();
    for collector in collectors.iter() {
        collector.shutdown();
    }
    // Stop and join the per-NUMA-node draining threads before the collectors
    // (and their ring buffer maps) drop.
    drainers.shutdown();

    Ok(())
}
