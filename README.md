# HPC OTEL Exporter

Disclaimer: This is a PoC, don't expect anything useful

A daemon for collecting metrics on SLURM jobs, with a focus on negligible overhead in the face of common HPC workloads.

## Status

The exporter currently records all synchronous file IO on the system, grouped by process cgroup.  
IO events are recorded as histograms over request size and duration.

## Usage

A `cargo run --release` will spin up the exporter + lgtm stack with Grafana on `http://localhost:3000`  
Root permissions are required to load the eBPF programs.

## Dependencies

A Rust and eBPF toolchain is required. This includes:

- rustc & cargo
- clang with eBPF backend
- libelf & headers (usually provided by elfutils)
- bpftool
