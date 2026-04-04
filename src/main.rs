use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::signal;

mod telemetry;

// Include the generated skeleton module
mod example {
    include!(concat!(env!("OUT_DIR"), "/example.skel.rs"));
}

// Include the generated bindings from common_shared.h
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use example::*;

/// Wrapper around libbpf_sys ring_buffer for safe usage
struct RingBuffer {
    ptr: NonNull<libbpf_sys::ring_buffer>,
}

impl RingBuffer {
    unsafe fn new(
        map_fd: i32,
        sample_cb: libbpf_sys::ring_buffer_sample_fn,
        ctx: *mut std::ffi::c_void,
    ) -> Result<Self> {
        let opts = libbpf_sys::ring_buffer_opts {
            sz: std::mem::size_of::<libbpf_sys::ring_buffer_opts>() as libbpf_sys::size_t,
        };

        let ptr = unsafe { libbpf_sys::ring_buffer__new(map_fd, sample_cb, ctx, &opts) };

        NonNull::new(ptr)
            .context("ring_buffer__new returned null")
            .map(|ptr| Self { ptr })
    }

    fn epoll_fd(&self) -> i32 {
        unsafe { libbpf_sys::ring_buffer__epoll_fd(self.ptr.as_ptr()) }
    }

    fn consume(&self) -> std::io::Result<i32> {
        let ret = unsafe { libbpf_sys::ring_buffer__consume(self.ptr.as_ptr()) };
        if ret < 0 {
            return Err(std::io::Error::from_raw_os_error(-ret));
        }
        Ok(ret)
    }

    fn poll(&self, timeout_ms: i32) -> std::io::Result<i32> {
        let ret = unsafe { libbpf_sys::ring_buffer__poll(self.ptr.as_ptr(), timeout_ms) };
        if ret < 0 {
            return Err(std::io::Error::from_raw_os_error(-ret));
        }
        Ok(ret)
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        unsafe { libbpf_sys::ring_buffer__free(self.ptr.as_ptr()) }
    }
}

unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

/// Context passed to ring buffer callbacks
struct CallbackContext {
    event_count: std::sync::atomic::AtomicU64,
    io_metrics: telemetry::IoMetrics,
}

/// C-compatible callback for ring buffer events
unsafe extern "C" fn event_callback(
    ctx: *mut std::ffi::c_void,
    data: *mut std::ffi::c_void,
    size: libbpf_sys::size_t,
) -> i32 {
    if size < std::mem::size_of::<bindings::IOEvent>() as libbpf_sys::size_t {
        warn!("received truncated event ({} bytes)", size);
        return 0;
    }

    let event = unsafe { (data as *const bindings::IOEvent).read_unaligned() };

    if !ctx.is_null() {
        let context = unsafe { &*(ctx as *const CallbackContext) };
        context
            .event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        context.io_metrics.record(&event);
    }

    0
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
    let io_metrics = telemetry::IoMetrics::new();
    let context = Arc::new(CallbackContext {
        event_count: std::sync::atomic::AtomicU64::new(0),
        io_metrics,
    });
    let ctx_ptr = Arc::as_ptr(&context) as *mut std::ffi::c_void;

    let map_fd = skel.maps.EVENTS.as_fd().as_raw_fd();
    let ring = unsafe { RingBuffer::new(map_fd, Some(event_callback), ctx_ptr)? };

    // Wrap the ring buffer's epoll fd with tokio's AsyncFd for async polling.
    let epoll_fd = ring.epoll_fd();
    let async_fd = AsyncFd::with_interest(
        unsafe { BorrowedFd::borrow_raw(epoll_fd) },
        tokio::io::Interest::READABLE,
    )?;

    info!("Waiting for events... Press Ctrl-C to exit.");

    // Keep context alive for the duration of the program
    let context_guard = context;

    // Periodically clean up providers for cgroups that no longer exist.
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));
    // Fallback poll to recover from potential missed readiness notifications.
    let mut fallback_poll_interval = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            readable = async_fd.readable() => {
                let mut guard = readable?;
                // Drain until no data is left. `try_io` avoids missing wakeups
                // if readiness changes between consume and readiness bookkeeping.
                loop {
                    match guard.try_io(|_| {
                        let consumed = ring.consume()?;
                        if consumed == 0 {
                            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                        } else {
                            Ok(consumed)
                        }
                    }) {
                        Ok(Ok(_consumed)) => {}
                        Ok(Err(err)) => {
                            return Err(anyhow::anyhow!("ring_buffer__consume failed: {err}"));
                        }
                        Err(_would_block) => break,
                    }
                }
            }
            _ = fallback_poll_interval.tick() => {
                if let Err(err) = ring.poll(0) {
                    return Err(anyhow::anyhow!("ring_buffer__poll fallback failed: {err}"));
                }
            }
            _ = cleanup_interval.tick() => {
                context_guard.io_metrics.cleanup_dead_cgroups();
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, exiting...");
                break;
            }
        }
    }

    Ok(())
}
