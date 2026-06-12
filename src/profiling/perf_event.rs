//! Perf-event CPU sampling setup: opens one `PERF_COUNT_SW_CPU_CLOCK` event per
//! online CPU at a target frequency and attaches the `do_sample` BPF program to
//! each. The kernel side does the actual stack walking; this module only wires up
//! the sampling sources.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, ProgramMut};
use log::debug;

mod perf {
    #![allow(warnings)]
    include!(concat!(env!("OUT_DIR"), "/perf_event_bindings.rs"));
}

/// `exclude_kernel` bit in `perf_event_attr` flags (bit 5). Without it the
/// counter also samples while the CPU is in kernel mode, so the sampled `rip`
/// (recorded as the leaf) is a kernel address the user-space symbolizer can't
/// resolve. Restricting to user mode yields a user-stack profile comparable to
/// the pyroscope crate's SIGPROF sampler.
const PERF_ATTR_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
/// `freq` bit in `perf_event_attr` flags: sample at a target frequency rather
/// than a fixed period (bit index 10, after disabled..comm).
const PERF_ATTR_FLAG_FREQ: u64 = 1 << 10;
/// `PERF_FLAG_FD_CLOEXEC`.
const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

/// First 64 bytes of the kernel `perf_event_attr` (`PERF_ATTR_SIZE_VER0`). The
/// kernel zero-extends any trailing fields it knows about, so this prefix is a
/// stable, sufficient subset for frequency-based sampling.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    /// Union of `sample_period` / `sample_freq`; we use the freq interpretation.
    sample_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == 64);

/// Open a CPU-cycles perf event sampling at `freq` Hz on `cpu`, across all
/// processes. Requires `CAP_PERFMON`/root (which we already have for eBPF).
fn perf_event_open(freq: u64, cpu: i32, exclude_kernel: bool) -> std::io::Result<OwnedFd> {
    let mut flags = PERF_ATTR_FLAG_FREQ;
    if exclude_kernel {
        flags |= PERF_ATTR_FLAG_EXCLUDE_KERNEL;
    }
    let attr = PerfEventAttr {
        type_: perf::perf_type_id_PERF_TYPE_SOFTWARE,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: perf::perf_sw_ids_PERF_COUNT_SW_CPU_CLOCK as u64,
        sample_freq: freq,
        flags,
        ..Default::default()
    };

    // perf_event_open(attr, pid = -1 (any process), cpu, group_fd = -1, flags)
    let ret = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            -1i32,
            cpu,
            -1i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Safety: a successful perf_event_open returns a fresh, owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Holds the perf-event fds and their BPF attachments alive. Dropping this
/// detaches the sampler.
pub(crate) struct PerfSampler {
    _fds: Vec<OwnedFd>,
    _links: Vec<Link>,
}

/// Open one CPU-cycles perf event per online CPU and attach `prog` to each.
pub(crate) fn attach_perf_samplers(prog: &ProgramMut, freq: u64) -> Result<PerfSampler> {
    let n_cpus = num_configured_cpus();
    let mut fds = Vec::new();
    let mut links = Vec::new();

    for cpu in 0..n_cpus {
        match perf_event_open(freq, cpu, true) {
            Ok(fd) => {
                let link = prog
                    .attach_perf_event(fd.as_raw_fd())
                    .with_context(|| format!("attaching perf event on CPU {cpu}"))?;
                fds.push(fd);
                links.push(link);
            }
            // Offline CPUs report ENODEV/EINVAL; skip them.
            Err(e) => debug!("skipping CPU {cpu}: {e}"),
        }
    }

    if fds.is_empty() {
        return Err(anyhow!("failed to open a perf event on any CPU"));
    }
    debug!("attached CPU sampler on {} CPUs at {freq} Hz", fds.len());

    Ok(PerfSampler {
        _fds: fds,
        _links: links,
    })
}

pub(crate) fn num_configured_cpus() -> i32 {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    if n < 1 { 1 } else { n as i32 }
}
