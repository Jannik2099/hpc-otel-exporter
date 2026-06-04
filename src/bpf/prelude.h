#pragma once

// Shared between BPF C and userspace Rust (via bindgen). Under the BPF target we
// pull fixed-width types from vmlinux.h; for the bindgen pass (host build) we use
// the standard C headers instead.
#ifndef __BPF__
#include <stdbool.h>
#include <stdint.h>
#else
#include "vmlinux.h" // IWYU pragma: keep
#endif
