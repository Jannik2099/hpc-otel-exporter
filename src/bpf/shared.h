#pragma once

// Aggregator header: the single entry point bindgen parses to generate
// crate::bindings (see build.rs). It pulls in every per-feature shared-type
// header so all shared structs/enums/constants land in one Rust bindings module.
// The BPF programs themselves do NOT include this; each feature's .bpf.c
// includes its own type header (io.h / profiling.h) directly.

#include "io.h"
#include "profiling.h"
