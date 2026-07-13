#[cfg(feature = "tcmalloc")]
use tcmalloc_better::TCMalloc;
#[cfg(feature = "tcmalloc")]
#[global_allocator]
static GLOBAL: TCMalloc = TCMalloc;

use anyhow::Result;
use clap::Parser;

mod app;
mod bindings;
mod bpf;
mod cgroup;
mod cgroup_filter;
mod collector;
mod metrics;
mod numa;
mod profiling;
mod sandbox;
#[cfg(feature = "pyroscope")]
mod self_profile;
mod telemetry;

fn main() -> Result<()> {
    #[cfg(feature = "tcmalloc")]
    TCMalloc::process_background_actions_thread();

    let args = app::Args::parse();

    app::run(args)
}
