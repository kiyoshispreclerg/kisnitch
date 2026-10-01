/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/strset.h"

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

void ks_strset_init(struct ks_strset *set)
{
    memset(set, 0, sizeof(*set));
    if (getrandom(&set->seed, sizeof(set->seed), GRND_NONBLOCK) !=
        (ssize_t)sizeof(set->seed)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        set->seed = (uint64_t)ts.tv_nsec * 0x9E3779B97F4A7C15ull ^
                    (uint64_t)(uintptr_t)set;
    }
}

/* FNV-1a over the seed and the bytes, finished with the murmur3 mixer. */
static uint64_t hash(uint64_t seed, const char *s, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ull ^ seed;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001b3ull;
    }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33;
    return h;
}

static uint32_t entry_len(const struct ks_strset *set, uint32_t off)
{
    uint32_t len;
    memcpy(&len, set->arena + off, sizeof(len));
    return len;
}

static bool entry_eq(const struct ks_strset *set, uint32_t off, const char *s,
                     size_t len)
{
    return entry_len(set, off) == len &&
           memcmp(set->arena + off + sizeof(uint32_t), s, len) == 0;
}

/* Returns the slot holding `s`, or the empty slot where it would go. */
static size_t find_slot(const struct ks_strset *set, const char *s, size_t len,
                        uint64_t h)
{
    size_t mask = set->nslots - 1;
    size_t i = (size_t)h & mask;
    while (set->slots[i] != 0 && !entry_eq(set, set->slots[i] - 1, s, len))
        i = (i + 1) & mask;
    return i;
}

static int grow(struct ks_strset *set)
{
    size_t n = set->nslots ? set->nslots * 2 : 64;
    uint32_t *slots = calloc(n, sizeof(*slots));
    if (slots == NULL)
        return -1;

    for (size_t i = 0; i < set->nslots; i++) {
        uint32_t v = set->slots[i];
        if (v == 0)
            continue;
        uint32_t off = v - 1;
        uint32_t len = entry_len(set, off);
        uint64_t h = hash(set->seed, set->arena + off + sizeof(uint32_t), len);
        size_t j = (size_t)h & (n - 1);
        while (slots[j] != 0)
            j = (j + 1) & (n - 1);
        slots[j] = v;
    }
    free(set->slots);
    set->slots = slots;
    set->nslots = n;
    return 0;
}

int ks_strset_add(struct ks_strset *set, const char *s, size_t len)
{
    /* Keep the load factor under 3/4. */
    if ((set->count + 1) * 4 > set->nslots * 3 && grow(set) < 0)
        return -1;

    uint64_t h = hash(set->seed, s, len);
    size_t slot = find_slot(set, s, len, h);
    if (set->slots[slot] != 0)
        return 0;

    size_t need = sizeof(uint32_t) + len + 1;
    if (len > UINT32_MAX || set->alen + need >= UINT32_MAX)
        return -1;
    if (set->alen + need > set->acap) {
        size_t cap = set->acap ? set->acap : 4096;
        while (cap < set->alen + need)
            cap *= 2;
        char *arena = realloc(set->arena, cap);
        if (arena == NULL)
            return -1;
        set->arena = arena;
        set->acap = cap;
    }

    uint32_t len32 = (uint32_t)len;
    uint32_t off = (uint32_t)set->alen;
    memcpy(set->arena + off, &len32, sizeof(len32));
    memcpy(set->arena + off + sizeof(uint32_t), s, len);
    set->arena[off + sizeof(uint32_t) + len] = '\0';
    set->alen += need;
    set->slots[slot] = off + 1;
    set->count++;
    return 1;
}

bool ks_strset_has(const struct ks_strset *set, const char *s, size_t len)
{
    if (set->count == 0)
        return false;
    size_t slot = find_slot(set, s, len, hash(set->seed, s, len));
    return set->slots[slot] != 0;
}

void ks_strset_clear(struct ks_strset *set)
{
    uint64_t seed = set->seed;
    free(set->arena);
    free(set->slots);
    memset(set, 0, sizeof(*set));
    set->seed = seed;
}
