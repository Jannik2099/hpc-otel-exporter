//! Optional self-profiling: runs the `pyroscope` crate's in-process SIGPROF
//! sampler so the exporter's *own* CPU usage is profiled and pushed to Pyroscope.
//! This is unrelated to [`crate::profiling`], which profiles the *target* HPC
//! jobs; this only exists to debug the exporter itself, behind the `pyroscope`
//! Cargo feature.

use anyhow::Result;
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
use pyroscope::pyroscope::{PyroscopeAgent, PyroscopeAgentBuilder, PyroscopeAgentRunning};

pub fn setup_pyroscope() -> Result<PyroscopeAgent<PyroscopeAgentRunning>> {
    // Configure Pyroscope Agent
    let agent = PyroscopeAgentBuilder::new(
        "http://localhost:4040",
        "hpc-otel-exporter",
        100, // sample rate in Hz
        "pyroscope-rs",
        env!("CARGO_PKG_VERSION"),
        pprof_backend(PprofConfig { sample_rate: 100 }, BackendConfig::default()),
    )
    .tags(vec![("env", "dev")])
    .build()?;

    Ok(agent.start()?)
}
