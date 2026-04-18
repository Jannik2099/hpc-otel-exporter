#pragma once

#include <vmlinux.h>
//
#include "bitops.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// this is taken mostly from mm.h
// we assume 64bit + memcg
// older kernels use _folio_nr_pages, newer ones use _nr_pages

#define FOLIO_PF_ANY 0
#define FOLIO_PF_HEAD 0
#define FOLIO_PF_NO_TAIL 0
#define FOLIO_PF_NO_COMPOUND 0
#define FOLIO_PF_SECOND 1

#define FOLIO_HEAD_PAGE 0
#define FOLIO_SECOND_PAGE 1

struct folio___old {
    unsigned long _folio_nr_pages;
} __attribute__((preserve_access_index));

struct folio___new {
    unsigned long _nr_pages;
} __attribute__((preserve_access_index));

static __always_inline unsigned int
folio_large_order(const struct folio *folio) {
    return folio->_flags_1 & 0xff;
}

static __always_inline unsigned long
folio_large_nr_pages(const struct folio___new *folio) {
    return folio->_nr_pages;
}

static const __always_inline unsigned long *
const_folio_flags(const struct folio *folio, unsigned n) {
    const struct page *page = &folio->page;
    return &page[n].flags.f;
}

static __always_inline bool folio_test_head(const struct folio *folio) {
    return test_bit(PG_head, const_folio_flags(folio, FOLIO_PF_ANY));
}

static __always_inline bool folio_test_large(const struct folio *folio) {
    return folio_test_head(folio);
}

static __always_inline unsigned int folio_order(const struct folio *folio) {
    if (!folio_test_large(folio))
        return 0;
    return folio_large_order(folio);
}

static __always_inline unsigned long folio_nr_pages(const struct folio *folio) {
    if (!folio_test_large(folio))
        return 1;
    if (bpf_core_field_exists(struct folio___new, _nr_pages)) {
        return folio_large_nr_pages((const struct folio___new *)folio);
    } else {
        return ((struct folio___old *)folio)->_folio_nr_pages;
    }
}

static __always_inline size_t folio_size(const struct folio *folio) {
    return __PAGE_SIZE << folio_order(folio);
}
