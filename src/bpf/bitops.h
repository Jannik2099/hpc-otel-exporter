#pragma once

#include <vmlinux.h>
//
#include <bpf/bpf_helpers.h>

#define BITS_PER_LONG 64
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

static __always_inline bool
generic_test_bit(unsigned long nr, const volatile unsigned long *addr) {
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}

#define test_bit(nr, addr)                                                     \
    generic_test_bit(nr, (const volatile unsigned long *)(addr))
