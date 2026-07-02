//! eBPF object glue: one generated skeleton per signal (see `build.rs`'s
//! `BPF_SRCS`), plus the memlock rlimit bump needed to load them on older
//! kernels.
//!
//! Each signal is its own BPF object, so only the enabled signals' programs
//! are verified and only their maps are created. The skeletons live in
//! separate modules because each generated file defines same-named internals.

use log::debug;

#[allow(warnings)]
pub mod io {
    include!(concat!(env!("OUT_DIR"), "/io.skel.rs"));
}

#[allow(warnings)]
pub mod metadata {
    include!(concat!(env!("OUT_DIR"), "/metadata.skel.rs"));
}

#[allow(warnings)]
pub mod profiling {
    include!(concat!(env!("OUT_DIR"), "/profiling.skel.rs"));
}

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
