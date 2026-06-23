//! Optional self-profiling: runs the `pyroscope` crate's in-process SIGPROF
//! sampler so the exporter's *own* CPU usage is profiled and pushed to Pyroscope.
//! This is unrelated to [`crate::profiling`], which profiles the *target* HPC
//! jobs; this only exists to debug the exporter itself, behind the `pyroscope`
//! Cargo feature.

use std::collections::HashMap;

use anyhow::Result;
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
use pyroscope::pyroscope::{PyroscopeAgent, PyroscopeAgentBuilder, PyroscopeAgentRunning};

pub fn setup_pyroscope(url: &str) -> Result<PyroscopeAgent<PyroscopeAgentRunning>> {
    let pyroscope_token = std::env::var("PYROSCOPE_BEARER_TOKEN").ok();
    let mut headers = HashMap::new();
    if let Some(pyroscope_token) = pyroscope_token {
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", pyroscope_token),
        );
    }
    // Configure Pyroscope Agent
    let agent = PyroscopeAgentBuilder::new(
        url,
        "hpc-otel-exporter",
        97, // sample rate in Hz
        "pyroscope-rs",
        env!("CARGO_PKG_VERSION"),
        pprof_backend(PprofConfig { sample_rate: 97 }, BackendConfig::default()),
    )
    .http_headers(headers)
    .tags(vec![("env", "dev")])
    .build()?;

    Ok(agent.start()?)
}
