/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test vectors from RFC 1321 (MD5) and RFC 3174 / FIPS 180-1 (SHA-1).
 */
#include "common/hash.h"

#include <stdlib.h>

#include "tests/harness.h"

static const char *md5_hex(const char *s, size_t chunk)
{
    static char out[33];
    struct ks_md5 c;
    uint8_t d[16];
    size_t n = strlen(s);
    ks_md5_init(&c);
    for (size_t i = 0; i < n; i += chunk)
        ks_md5_update(&c, s + i, n - i < chunk ? n - i : chunk);
    ks_md5_final(&c, d);
    ks_hex_encode(d, 16, out);
    return out;
}

static const char *sha1_hex(const char *s, size_t chunk)
{
    static char out[41];
    struct ks_sha1 c;
    uint8_t d[20];
    size_t n = strlen(s);
    ks_sha1_init(&c);
    for (size_t i = 0; i < n; i += chunk)
        ks_sha1_update(&c, s + i, n - i < chunk ? n - i : chunk);
    ks_sha1_final(&c, d);
    ks_hex_encode(d, 20, out);
    return out;
}

TEST(md5_vectors)
{
    static const char *const v[][2] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
        for (size_t chunk = 1; chunk <= 65; chunk += 16)
            CHECK_STR_EQ(md5_hex(v[i][0], chunk), v[i][1]);
}

TEST(sha1_vectors)
{
    static const char *const v[][2] = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"The quick brown fox jumps over the lazy dog",
         "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++)
        for (size_t chunk = 1; chunk <= 65; chunk += 16)
            CHECK_STR_EQ(sha1_hex(v[i][0], chunk), v[i][1]);
}

TEST(million_a)
{
    char *a = malloc(1000000 + 1);
    CHECK(a != NULL);
    memset(a, 'a', 1000000);
    a[1000000] = '\0';
    CHECK_STR_EQ(sha1_hex(a, 4096), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    CHECK_STR_EQ(md5_hex(a, 999), "7707d6ae4e027c70eea2a935c2296f21");
    free(a);
}

int main(void)
{
    RUN(md5_vectors);
    RUN(sha1_vectors);
    RUN(million_a);
    return harness_report();
}
