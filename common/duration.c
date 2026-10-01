/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ks_parse_duration() is a line-by-line translation of ParseDuration from Go's
 * src/time/format.go (Go 1.23, the version upstream builds with).
 * Copyright 2010 The Go Authors (BSD-3-Clause).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/duration.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define U63 (UINT64_C(1) << 63)

static int invalid(char *err, size_t errlen, const char *orig)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "time: invalid duration \"%s\"", orig);
    return -1;
}

/* Consumes the leading [0-9]*. Returns -1 on overflow. */
static int leading_int(const char **s, uint64_t *x)
{
    const char *p = *s;
    uint64_t v = 0;

    for (; *p >= '0' && *p <= '9'; p++) {
        if (v > U63 / 10)
            return -1;
        v = v * 10 + (uint64_t)(*p - '0');
        if (v > U63)
            return -1;
    }
    *s = p;
    *x = v;
    return 0;
}

/* Consumes the leading [0-9]* of a fraction. Never fails: on overflow it just
 * stops accumulating precision. */
static void leading_fraction(const char **s, uint64_t *x, double *scale)
{
    const char *p = *s;
    bool overflow = false;
    uint64_t v = 0;
    double sc = 1;

    for (; *p >= '0' && *p <= '9'; p++) {
        if (overflow)
            continue;
        if (v > (U63 - 1) / 10) {
            overflow = true;
            continue;
        }
        uint64_t y = v * 10 + (uint64_t)(*p - '0');
        if (y > U63) {
            overflow = true;
            continue;
        }
        v = y;
        sc *= 10;
    }
    *s = p;
    *x = v;
    *scale = sc;
}

static uint64_t unit_value(const char *u, size_t len)
{
    static const struct {
        const char *name;
        uint64_t value;
    } units[] = {
        {"ns", (uint64_t)KS_NANOSECOND},
        {"us", (uint64_t)KS_MICROSECOND},
        {"\xc2\xb5s", (uint64_t)KS_MICROSECOND}, /* U+00B5 micro sign */
        {"\xce\xbcs", (uint64_t)KS_MICROSECOND}, /* U+03BC greek mu */
        {"ms", (uint64_t)KS_MILLISECOND},
        {"s", (uint64_t)KS_SECOND},
        {"m", (uint64_t)KS_MINUTE},
        {"h", (uint64_t)KS_HOUR},
    };
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++)
        if (strlen(units[i].name) == len && memcmp(units[i].name, u, len) == 0)
            return units[i].value;
    return 0;
}

int ks_parse_duration(const char *orig, int64_t *ns, char *err, size_t errlen)
{
    const char *s = orig;
    uint64_t d = 0;
    bool neg = false;

    if (*s == '-' || *s == '+') {
        neg = *s == '-';
        s++;
    }
    /* Special case: if all that is left is "0", this is zero. */
    if (strcmp(s, "0") == 0) {
        *ns = 0;
        return 0;
    }
    if (*s == '\0')
        return invalid(err, errlen, orig);

    while (*s != '\0') {
        uint64_t v, f = 0; /* integers before, after decimal point */
        double scale = 1;  /* value = v + f/scale */

        /* The next character must be [0-9.] */
        if (!(*s == '.' || (*s >= '0' && *s <= '9')))
            return invalid(err, errlen, orig);

        /* Consume [0-9]* */
        const char *start = s;
        if (leading_int(&s, &v) < 0)
            return invalid(err, errlen, orig);
        bool pre = s != start;

        /* Consume (\.[0-9]*)? */
        bool post = false;
        if (*s == '.') {
            s++;
            start = s;
            leading_fraction(&s, &f, &scale);
            post = s != start;
        }
        if (!pre && !post) /* no digits (e.g. ".s" or "-.s") */
            return invalid(err, errlen, orig);

        /* Consume unit. */
        size_t i = 0;
        while (s[i] != '\0' && s[i] != '.' && !(s[i] >= '0' && s[i] <= '9'))
            i++;
        if (i == 0) {
            if (err != NULL && errlen > 0)
                snprintf(err, errlen, "time: missing unit in duration \"%s\"",
                         orig);
            return -1;
        }
        uint64_t unit = unit_value(s, i);
        if (unit == 0) {
            char u[64];
            snprintf(u, sizeof(u), "%.*s", (int)(i < 63 ? i : 63), s);
            if (err != NULL && errlen > 0)
                snprintf(err, errlen,
                         "time: unknown unit \"%s\" in duration \"%s\"", u, orig);
            return -1;
        }
        s += i;

        if (v > U63 / unit) /* overflow */
            return invalid(err, errlen, orig);
        v *= unit;
        if (f > 0) {
            /* float64 is needed to be nanosecond accurate for fractions of
             * hours. v >= 0 && (f*unit/scale) <= 3.6e+12 (ns/h, h is the
             * largest unit) */
            v += (uint64_t)((double)f * ((double)unit / scale));
            if (v > U63) /* overflow */
                return invalid(err, errlen, orig);
        }
        d += v;
        if (d > U63)
            return invalid(err, errlen, orig);
    }
    if (neg) {
        /* -(1<<63) is representable; wrap like Go's -Duration(d). */
        *ns = d == U63 ? INT64_MIN : -(int64_t)d;
        return 0;
    }
    if (d > U63 - 1)
        return invalid(err, errlen, orig);
    *ns = (int64_t)d;
    return 0;
}

enum ks_rule_duration ks_rule_duration_kind(const char *s)
{
    if (strcmp(s, KS_DURATION_ONCE) == 0)
        return KS_RULE_ONCE;
    if (strcmp(s, KS_DURATION_RESTART) == 0)
        return KS_RULE_UNTIL_RESTART;
    if (strcmp(s, KS_DURATION_ALWAYS) == 0)
        return KS_RULE_ALWAYS;
    return KS_RULE_TEMPORARY;
}
