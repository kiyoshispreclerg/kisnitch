/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Hash map from strings to pointers, with removal and iteration. Used by
 * the process monitor caches.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the map owns copies of its keys, not the values. Not thread-safe.
 */
#ifndef KS_COMMON_STRMAP_H
#define KS_COMMON_STRMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ks_strmap_entry {
    char *key;
    void *value;
    struct ks_strmap_entry *next;
};

struct ks_strmap {
    struct ks_strmap_entry **buckets;
    size_t nbuckets; /* power of two, or 0 */
    size_t count;
    uint64_t seed;
};

/* A zeroed struct is an empty map; this only picks a random seed. */
void ks_strmap_init(struct ks_strmap *m);

void *ks_strmap_get(const struct ks_strmap *m, const char *key);

/* Inserts or replaces. Returns the previous value (NULL if none) through
 * `old` and 0, or -1 on OOM (the map is unchanged). */
int ks_strmap_set(struct ks_strmap *m, const char *key, void *value, void **old);

/* Removes `key` and returns its value, or NULL. */
void *ks_strmap_del(struct ks_strmap *m, const char *key);

/* Calls `fn` for every entry; if it returns true the entry is removed (the
 * callback owns the value then). */
void ks_strmap_filter(struct ks_strmap *m,
                      bool (*fn)(const char *key, void *value, void *ctx),
                      void *ctx);

/* Frees the map; values are passed to `free_value` if it's not NULL. */
void ks_strmap_clear(struct ks_strmap *m, void (*free_value)(void *));

#endif
