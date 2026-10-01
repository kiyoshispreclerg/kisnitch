/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Compact set of byte strings, used for blocklists (lists.domains, lists.ips,
 * lists.hash.md5), which can hold hundreds of thousands of entries.
 *
 * Strings live in one arena ([u32 length][bytes][NUL] each); the table holds
 * 32-bit offsets into it, so an entry costs its length + 9 bytes plus ~6
 * bytes of table. The hash is seeded per set to resist crafted lists.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the set owns the arena and the table. Not thread-safe.
 */
#ifndef KS_COMMON_STRSET_H
#define KS_COMMON_STRSET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ks_strset {
    char *arena;
    size_t alen, acap;
    uint32_t *slots; /* 0 = empty, otherwise arena offset + 1 */
    size_t nslots;   /* power of two, or 0 */
    size_t count;
    uint64_t seed;
};

/* A zeroed struct is an empty set; this only picks a random seed. */
void ks_strset_init(struct ks_strset *set);

/* Returns 1 if added, 0 if already present, -1 on OOM or if the set would
 * exceed 4 GiB of strings. */
int ks_strset_add(struct ks_strset *set, const char *s, size_t len);

bool ks_strset_has(const struct ks_strset *set, const char *s, size_t len);

/* Frees everything and leaves an empty set (keeping the seed). */
void ks_strset_clear(struct ks_strset *set);

#endif
