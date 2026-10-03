/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * MD5 (RFC 1321) and SHA-1 (FIPS 180-1), for the process.hash.md5/sha1 rule
 * operands. Streaming, so executables are hashed without loading them whole.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_COMMON_HASH_H
#define KS_COMMON_HASH_H

#include <stddef.h>
#include <stdint.h>

struct ks_md5 {
    uint32_t s[4];
    uint64_t len;
    uint8_t buf[64];
};

struct ks_sha1 {
    uint32_t s[5];
    uint64_t len;
    uint8_t buf[64];
};

void ks_md5_init(struct ks_md5 *c);
void ks_md5_update(struct ks_md5 *c, const void *data, size_t n);
void ks_md5_final(struct ks_md5 *c, uint8_t out[16]);

void ks_sha1_init(struct ks_sha1 *c);
void ks_sha1_update(struct ks_sha1 *c, const void *data, size_t n);
void ks_sha1_final(struct ks_sha1 *c, uint8_t out[20]);

/* Lowercase hex, like Go's hex.EncodeToString. `out` holds 2 * n + 1. */
void ks_hex_encode(const uint8_t *in, size_t n, char *out);

#endif
