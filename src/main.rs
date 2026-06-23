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

#[tokio::main]
async fn main() -> Result<()> {
    let args = app::Args::parse();

    // Console logging (env_logger) plus OTLP log export via the OpenTelemetry
    // appender. Installed first so setup-time logs are captured too; the guard
    // flushes buffered records on exit and must outlive the whole run.
    let env_logger = env_logger::Env::default().filter_or("RUST_LOG", "debug");
    let _logging_guard = telemetry::init_logging(env_logger);

    app::run(args).await
}
