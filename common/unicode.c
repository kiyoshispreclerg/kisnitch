/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/unicode.h"

#include <locale.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>

size_t ks_utf8_decode(const char *str, size_t n, uint32_t *rune)
{
    const unsigned char *s = (const unsigned char *)str;
    unsigned char c = s[0];

    if (c < 0x80) {
        *rune = c;
        return 1;
    }

    size_t need;
    uint32_t r, min;
    if (c >= 0xC2 && c <= 0xDF) {
        need = 2; r = c & 0x1F; min = 0x80;
    } else if (c >= 0xE0 && c <= 0xEF) {
        need = 3; r = c & 0x0F; min = 0x800;
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 4; r = c & 0x07; min = 0x10000;
    } else {
        *rune = KS_RUNE_ERROR;
        return 1;
    }
    if (n < need) {
        *rune = KS_RUNE_ERROR;
        return 1;
    }
    for (size_t i = 1; i < need; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            *rune = KS_RUNE_ERROR;
            return 1;
        }
        r = (r << 6) | (s[i] & 0x3F);
    }
    if (r < min || r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF)) {
        *rune = KS_RUNE_ERROR;
        return 1;
    }
    *rune = r;
    return need;
}

size_t ks_utf8_encode(uint32_t r, char *buf)
{
    unsigned char *b = (unsigned char *)buf;

    if (r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF))
        r = KS_RUNE_ERROR;
    if (r < 0x80) {
        b[0] = (unsigned char)r;
        return 1;
    }
    if (r < 0x800) {
        b[0] = (unsigned char)(0xC0 | (r >> 6));
        b[1] = (unsigned char)(0x80 | (r & 0x3F));
        return 2;
    }
    if (r < 0x10000) {
        b[0] = (unsigned char)(0xE0 | (r >> 12));
        b[1] = (unsigned char)(0x80 | ((r >> 6) & 0x3F));
        b[2] = (unsigned char)(0x80 | (r & 0x3F));
        return 3;
    }
    b[0] = (unsigned char)(0xF0 | (r >> 18));
    b[1] = (unsigned char)(0x80 | ((r >> 12) & 0x3F));
    b[2] = (unsigned char)(0x80 | ((r >> 6) & 0x3F));
    b[3] = (unsigned char)(0x80 | (r & 0x3F));
    return 4;
}

bool ks_utf8_valid(const char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t w = ks_utf8_decode(s + i, n - i, &r);
        if (r == KS_RUNE_ERROR && w == 1)
            return false;
        i += w;
    }
    return true;
}

char *ks_utf8_sanitize(const char *s, size_t n, size_t *out_len)
{
    char *out = malloc(n * 3 + 1);
    if (out == NULL)
        return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t w = ks_utf8_decode(s + i, n - i, &r);
        if (r == KS_RUNE_ERROR && w == 1) {
            o += ks_utf8_encode(KS_RUNE_ERROR, out + o);
        } else {
            memcpy(out + o, s + i, w);
            o += w;
        }
        i += w;
    }
    out[o] = '\0';
    if (out_len != NULL)
        *out_len = o;
    return out;
}

static pthread_once_t locale_once = PTHREAD_ONCE_INIT;
static locale_t utf8_locale = (locale_t)0;

static void init_locale(void)
{
    utf8_locale = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
}

static locale_t get_locale(void)
{
    pthread_once(&locale_once, init_locale);
    return utf8_locale;
}

static uint32_t to_lower(uint32_t r)
{
    if (r < 0x80)
        return (r >= 'A' && r <= 'Z') ? r + 32 : r;
    locale_t loc = get_locale();
    return loc != (locale_t)0 ? (uint32_t)towlower_l((wint_t)r, loc) : r;
}

static uint32_t to_upper(uint32_t r)
{
    if (r < 0x80)
        return (r >= 'a' && r <= 'z') ? r - 32 : r;
    locale_t loc = get_locale();
    return loc != (locale_t)0 ? (uint32_t)towupper_l((wint_t)r, loc) : r;
}

char *ks_str_to_lower(const char *s)
{
    size_t n = strlen(s);
    bool ascii = true;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] >= 0x80)
            ascii = false;

    if (ascii) {
        char *out = malloc(n + 1);
        if (out == NULL)
            return NULL;
        for (size_t i = 0; i <= n; i++)
            out[i] = (s[i] >= 'A' && s[i] <= 'Z') ? (char)(s[i] + 32) : s[i];
        return out;
    }

    /* A lowercase rune takes at most 4 bytes and an input byte at least 1,
     * but an invalid byte (1 byte in) becomes U+FFFD (3 bytes out). */
    char *out = malloc(n * 3 + 1);
    if (out == NULL)
        return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t w = ks_utf8_decode(s + i, n - i, &r);
        o += ks_utf8_encode(to_lower(r), out + o);
        i += w;
    }
    out[o] = '\0';
    return out;
}

bool ks_str_equal_fold(const char *a, const char *b)
{
    size_t na = strlen(a), nb = strlen(b);
    size_t i = 0, j = 0;

    while (i < na && j < nb) {
        uint32_t ra, rb;
        i += ks_utf8_decode(a + i, na - i, &ra);
        j += ks_utf8_decode(b + j, nb - j, &rb);
        if (ra == rb)
            continue;
        if (ra < 0x80 && rb < 0x80) {
            if (to_lower(ra) != to_lower(rb))
                return false;
            continue;
        }
        /* Go walks the SimpleFold orbit; comparing both case mappings
         * covers the same equivalences for the runes that have them. */
        if (to_lower(ra) != to_lower(rb) && to_upper(ra) != to_upper(rb))
            return false;
    }
    return i == na && j == nb;
}
