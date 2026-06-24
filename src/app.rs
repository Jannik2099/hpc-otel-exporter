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
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::signal;

use crate::bindings::{IOEvent, MetadataEvent, UnwindMiss};
use crate::bpf::{self, ExporterSkelBuilder};
use crate::cgroup::CgroupRegistry;
use crate::metrics::{self, IoMetrics, MetadataMetrics};
use crate::profiling::Profiler;
use crate::telemetry;

/// How often dead cgroups are reaped and every feature's per-cgroup state is
/// pruned (and the profiler services unwind misses / evicts dead processes).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

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

    /// Disable CPU profiling entirely
    #[arg(long)]
    no_profiling: bool,

    /// Number of threads to use for the tokio runtime (default: number of CPUs)
    #[arg(long)]
    num_threads: Option<usize>,
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

    // Optional self-profiling of the exporter itself (separate from the target
    // profiling in `profiling`); kept alive for the process' lifetime.
    #[cfg(feature = "pyroscope")]
    let _pyroscope_agent = crate::self_profile::setup_pyroscope(&args.pyroscope_url);

    // Bump the memlock rlimit before loading (needed on older kernels).
    bpf::bump_memlock_rlimit();

    // Open the BPF object (embedded in the binary).
    let builder = ExporterSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object)?;

    // The perf_event sampler needs a per-CPU perf fd, so it is attached by the
    // profiler below; keep skel.attach() from trying to auto-attach it.
    open_skel.progs.do_sample.set_autoattach(false);

    // Load + attach all auto-attachable programs (fentry/fexit on vfs_read/write).
    let mut skel = open_skel.load()?;
    skel.attach()?;

    info!("eBPF program loaded and attached!");

    if args.test_attach {
        return Ok(());
    }

    // Install the global tracer provider (OTLP/gRPC), kept alive for the whole run
    // so buffered spans flush on exit. The demand-driven unwind loader and
    // symbolization create spans against it.
    let _tracing_guard = telemetry::init_tracing();

    // Single owner of per-cgroup meter providers and cgroup liveness, shared by
    // every feature. IO and metadata each contribute their histogram aggregation
    // views.
    let mut histogram_views = metrics::io::histogram_views();
    histogram_views.extend(metrics::metadata::histogram_views());
    let registry = Arc::new(CgroupRegistry::new(histogram_views));

    // IO + metadata metrics: shared behind an `Arc` so the ringbuffer callbacks
    // (`'static` closures) can record into them.
    let io_metrics = Arc::new(IoMetrics::new(Arc::clone(&registry)));
    let metadata_metrics = Arc::new(MetadataMetrics::new(Arc::clone(&registry)));

    // CPU profiler facade: owns the perf sampler, the native unwinder's userspace
    // half, and the per-cgroup symbol caches. `None` when profiling is disabled.
    let mut profiler = (!args.no_profiling).then(|| {
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

    // Ring buffers: IO events -> IoMetrics; metadata events -> MetadataMetrics;
    // unwind misses -> the profiler's sink (only wired when profiling is on —
    // nothing writes misses otherwise).
    let mut rb_builder = RingBufferBuilder::new();
    let io_for_cb = Arc::clone(&io_metrics);
    rb_builder.add(&skel.maps.EVENTS, move |data: &[u8]| {
        if data.len() < std::mem::size_of::<IOEvent>() {
            return 0;
        }
        // Safety: BPF ringbuf data is 8-byte aligned (IOEvent needs 4); the length
        // check guarantees sufficient size. Read unaligned to be safe regardless.
        let event = unsafe { (data.as_ptr() as *const IOEvent).read_unaligned() };
        // Block on the async record call (multi-threaded runtime, so block_in_place
        // is sound).
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(io_for_cb.record(&event))
        });
        0
    })?;
    let metadata_for_cb = Arc::clone(&metadata_metrics);
    rb_builder.add(&skel.maps.METADATA_EVENTS, move |data: &[u8]| {
        if data.len() < std::mem::size_of::<MetadataEvent>() {
            return 0;
        }
        // Safety: as above — the length check guarantees sufficient size, and we
        // read unaligned since the slice carries no alignment guarantee.
        let event = unsafe { (data.as_ptr() as *const MetadataEvent).read_unaligned() };
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(metadata_for_cb.record(&event))
        });
        0
    })?;
    if let Some(misses) = miss_sink {
        rb_builder.add(&skel.maps.UNWIND_MISSES, move |data: &[u8]| {
            if data.len() >= std::mem::size_of::<UnwindMiss>() {
                // Safety: the BPF program writes a UnwindMiss into this ring buffer;
                // read unaligned since the slice has no alignment guarantee.
                let miss = unsafe { (data.as_ptr() as *const UnwindMiss).read_unaligned() };
                misses.lock().unwrap().insert(miss.tgid, miss.cgroup_id);
            }
            0
        })?;
    }
    let ringbuf = rb_builder.build()?;

    // Wrap the ring buffer's epoll fd with tokio's AsyncFd for async polling.
    let epoll_fd = ringbuf.epoll_fd();
    let async_fd = AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(epoll_fd) },
        tokio::io::Interest::READABLE,
    )?;

    info!("Waiting for events... Press Ctrl-C to exit.");

    // Metrics export: pull every live cgroup's ManualReader and push it through the
    // shared OTLP exporter.
    let metrics_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let mut interval =
            tokio::time::interval(Duration::from_secs(args.metrics_interval_secs.max(1)));
        async move {
            loop {
                interval.tick().await;
                registry.collect_and_export_all().await;
            }
        }
    });

    // Dead-cgroup reaping + per-feature pruning: one walk of /sys/fs/cgroup tears
    // down dead providers and yields the live snapshot every feature prunes against.
    let cleanup_task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let io_metrics = Arc::clone(&io_metrics);
        let metadata_metrics = Arc::clone(&metadata_metrics);
        let profiler = profiler.clone();
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let live = registry.cleanup_dead_cgroups().await;
                io_metrics.retain_live(&live);
                metadata_metrics.retain_live(&live);
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

    // Stop the periodic tasks before the skel drops. They hold only Arcs and
    // fd-dup'd MapHandles (independent of the skel), so aborting is clean.
    metrics_task.abort();
    cleanup_task.abort();
    if let Some(profile_task) = profile_task {
        profile_task.abort();
    }

    Ok(())
}
