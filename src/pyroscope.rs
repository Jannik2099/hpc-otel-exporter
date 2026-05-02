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
