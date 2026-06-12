//! eBPF object glue: the generated skeleton plus the memlock rlimit bump needed
//! to load it on older kernels.

use log::debug;

#[allow(warnings)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/exporter.skel.rs"));
}
pub use skel::*;

/// Bump the memlock rlimit to infinity. Needed for older kernels that don't use
/// the new memcg-based BPF memory accounting, see
/// <https://lwn.net/Articles/837122/>.
pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}
