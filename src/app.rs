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
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::signal;

use crate::bindings::{IOEvent, UnwindMiss};
use crate::bpf::{self, ExporterSkelBuilder};
use crate::cgroup::CgroupRegistry;
use crate::metrics::{self, IoMetrics};
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

    /// Base URL of the Pyroscope ingest endpoint
    #[arg(long, default_value = "http://localhost:4040")]
    pyroscope_url: String,

    /// Disable CPU profiling entirely
    #[arg(long)]
    no_profiling: bool,
}

/// Load and attach the eBPF object, wire up the telemetry features, and run the
/// event loop until Ctrl-C. The logging guard is owned by the caller; the tracing
/// provider is installed here and lives for the whole run.
pub async fn run(args: Args) -> Result<()> {
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
    // every feature. IO contributes its histogram aggregation views.
    let registry = Arc::new(CgroupRegistry::new(metrics::io::histogram_views()));

    // IO metrics: shared behind an `Arc` so the EVENTS ringbuffer callback (a
    // `'static` closure) can record into it.
    let io_metrics = Arc::new(IoMetrics::new(Arc::clone(&registry)));

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

    // Ring buffers: IO events -> IoMetrics; unwind misses -> the profiler's sink
    // (only wired when profiling is on — nothing writes misses otherwise).
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
    if let Some(profiler) = &profiler {
        let misses = profiler.miss_sink();
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

    let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
    let mut profile_interval =
        tokio::time::interval(Duration::from_secs(args.profile_interval_secs.max(1)));

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
            _ = cleanup_interval.tick() => {
                // One walk of /sys/fs/cgroup tears down dead providers and yields
                // the live snapshot every feature prunes its own state against.
                let live = registry.cleanup_dead_cgroups().await;
                io_metrics.retain_live(&live);
                if let Some(profiler) = &mut profiler {
                    profiler.on_cleanup(
                        &live,
                        &skel.maps.UNWIND_ROWS,
                        &skel.maps.EXECUTABLES,
                        &skel.maps.PROC_MAPPINGS,
                    ).await;
                }
            }
            _ = profile_interval.tick() => {
                if let Some(profiler) = &profiler {
                    profiler.collect_and_push(&skel.maps.STACK_COUNTS, &skel.maps.STACKS).await;
                }
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, exiting...");
                break;
            }
        }
    }

    Ok(())
}
