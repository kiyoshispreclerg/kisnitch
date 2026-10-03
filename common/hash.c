/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/hash.h"

#include <string.h>

/* 0x80 followed by zeros: the padding of both algorithms. */
static const uint8_t padding[64] = {0x80};

/* Bytes of padding that bring `len` to 56 mod 64. */
static size_t pad_len(uint64_t len)
{
    size_t used = (size_t)(len % 64);
    return used < 56 ? 56 - used : 120 - used;
}

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* ---- MD5 -------------------------------------------------------------- */

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};
static const int md5_r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_block(struct ks_md5 *c, const uint8_t *p)
{
    uint32_t w[16], a = c->s[0], b = c->s[1], cc = c->s[2], d = c->s[3];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8 |
               (uint32_t)p[4 * i + 2] << 16 | (uint32_t)p[4 * i + 3] << 24;
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = (b & cc) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & cc);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ cc ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = cc ^ (b | ~d);
            g = (7 * i) % 16;
        }
        uint32_t t = d;
        d = cc;
        cc = b;
        b = b + rol(a + f + md5_k[i] + w[g], md5_r[i]);
        a = t;
    }
    c->s[0] += a;
    c->s[1] += b;
    c->s[2] += cc;
    c->s[3] += d;
}

void ks_md5_init(struct ks_md5 *c)
{
    c->s[0] = 0x67452301;
    c->s[1] = 0xefcdab89;
    c->s[2] = 0x98badcfe;
    c->s[3] = 0x10325476;
    c->len = 0;
}

void ks_md5_update(struct ks_md5 *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t used = (size_t)(c->len % 64);
    c->len += n;
    if (used > 0) {
        size_t take = 64 - used < n ? 64 - used : n;
        memcpy(c->buf + used, p, take);
        p += take;
        n -= take;
        if (used + take < 64)
            return;
        md5_block(c, c->buf);
    }
    for (; n >= 64; p += 64, n -= 64)
        md5_block(c, p);
    memcpy(c->buf, p, n);
}

void ks_md5_final(struct ks_md5 *c, uint8_t out[16])
{
    uint64_t bits = c->len * 8;
    uint8_t len[8];
    ks_md5_update(c, padding, pad_len(c->len));
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (8 * i));
    ks_md5_update(c, len, 8);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            out[4 * i + j] = (uint8_t)(c->s[i] >> (8 * j));
}

/* ---- SHA-1 ------------------------------------------------------------ */

static void sha1_block(struct ks_sha1 *c, const uint8_t *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->s[0], b = c->s[1], cc = c->s[2], d = c->s[3], e = c->s[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & cc) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ cc ^ d;
            k = 0xca62c1d6;
        }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = rol(b, 30);
        b = a;
        a = t;
    }
    c->s[0] += a;
    c->s[1] += b;
    c->s[2] += cc;
    c->s[3] += d;
    c->s[4] += e;
}

void ks_sha1_init(struct ks_sha1 *c)
{
    c->s[0] = 0x67452301;
    c->s[1] = 0xefcdab89;
    c->s[2] = 0x98badcfe;
    c->s[3] = 0x10325476;
    c->s[4] = 0xc3d2e1f0;
    c->len = 0;
}

void ks_sha1_update(struct ks_sha1 *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t used = (size_t)(c->len % 64);
    c->len += n;
    if (used > 0) {
        size_t take = 64 - used < n ? 64 - used : n;
        memcpy(c->buf + used, p, take);
        p += take;
        n -= take;
        if (used + take < 64)
            return;
        sha1_block(c, c->buf);
    }
    for (; n >= 64; p += 64, n -= 64)
        sha1_block(c, p);
    memcpy(c->buf, p, n);
}

void ks_sha1_final(struct ks_sha1 *c, uint8_t out[20])
{
    uint64_t bits = c->len * 8;
    uint8_t len[8];
    ks_sha1_update(c, padding, pad_len(c->len));
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    ks_sha1_update(c, len, 8);
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 4; j++)
            out[4 * i + j] = (uint8_t)(c->s[i] >> (24 - 8 * j));
}

void ks_hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 15];
    }
    out[2 * n] = '\0';
}
