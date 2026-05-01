use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, info};
use tokio::io::unix::AsyncFd;
use tokio::signal;

mod bindings;
mod telemetry;

// Include the generated skeleton module
mod example {
    include!(concat!(env!("OUT_DIR"), "/example.skel.rs"));
}

use example::*;

use crate::bindings::IOEvent;

/// Context passed to ring buffer callbacks
struct CallbackContext {
    event_count: std::sync::atomic::AtomicU64,
    io_metrics: telemetry::IoMetrics,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Open the BPF object (embedded in the binary)
    let builder = ExampleSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;

    // Load the BPF programs into the kernel
    let mut skel = open_skel.load()?;

    // Attach all BPF programs (fentry/fexit on vfs_read)
    skel.attach()?;

    info!("eBPF program loaded and attached!");

    // Create callback context
    let context = Arc::new(CallbackContext {
        event_count: std::sync::atomic::AtomicU64::new(0),
        io_metrics: telemetry::IoMetrics::new(),
    });
    let callback_context = Arc::clone(&context);

    let event_callback = |data: &[u8]| {
        if data.len() < std::mem::size_of::<IOEvent>() {
            return 0;
        }
        // Safety: BPF ringbuf data is aligned to 8 bytes
        // Event requires 4-byte alignment.
        // The length check above guarantees sufficient size.
        let event = unsafe { &*(data.as_ptr() as *const IOEvent) };

        callback_context
            .event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        callback_context.io_metrics.record(&event);

        0
    };

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.EVENTS, event_callback)?;
    let ringbuf = rb_builder.build()?;

    // Wrap the ring buffer's epoll fd with tokio's AsyncFd for async polling.
    let epoll_fd = ringbuf.epoll_fd();
    let async_fd = AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(epoll_fd) },
        tokio::io::Interest::READABLE,
    )?;

    info!("Waiting for events... Press Ctrl-C to exit.");

    // Periodically clean up providers for cgroups that no longer exist.
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));

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
                context.io_metrics.cleanup_dead_cgroups();
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, exiting...");
                break;
            }
        }
    }

    Ok(())
}
