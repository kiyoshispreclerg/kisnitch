/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bump allocator for short-lived object graphs (protobuf messages built to
 * be packed and dropped). Everything is freed at once.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the arena owns every block it handed out; ks_arena_free()
 * releases them all. A zeroed struct is an empty arena. Not thread-safe.
 */
#ifndef KS_COMMON_ARENA_H
#define KS_COMMON_ARENA_H

#include <stddef.h>

struct ks_arena_block;

struct ks_arena {
    struct ks_arena_block *head;
    int failed; /* an allocation failed since the arena was created */
};

/* Zeroed, max-aligned memory. NULL on OOM (and `failed` is set). */
void *ks_arena_alloc(struct ks_arena *a, size_t size);
/* `n` zeroed elements of `size` bytes; NULL on overflow or OOM. */
void *ks_arena_calloc(struct ks_arena *a, size_t n, size_t size);
char *ks_arena_strdup(struct ks_arena *a, const char *s);
char *ks_arena_strndup(struct ks_arena *a, const char *s, size_t n);
/* printf into the arena. */
char *ks_arena_printf(struct ks_arena *a, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

void ks_arena_free(struct ks_arena *a);

#endif
