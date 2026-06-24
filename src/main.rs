#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use anyhow::Result;
use clap::Parser;

mod app;
mod bindings;
mod bpf;
mod cgroup;
mod metrics;
mod profiling;
#[cfg(feature = "pyroscope")]
mod self_profile;
mod telemetry;

fn main() -> Result<()> {
    let args = app::Args::parse();

    app::run(args)
}
