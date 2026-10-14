/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Python's json.dumps() with its default arguments (separators ", " and
 * ": ", ensure_ascii=True, no indent): the upstream UI builds JSON strings
 * with it (the operator list of a rule, the configuration it sends back on
 * Subscribe) and they end up in messages and in the rules table.
 *
 * cJSON doesn't keep the number literal: integral values below 1e16 are
 * written as Python ints ("1", not "1.0"), others as repr(float).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the buffer API appends to a struct ks_pybuf the caller owns
 * (free `s`); ks_pyjson_dumps() returns a malloc'd string.
 */
#ifndef KS_UI_PYJSON_H
#define KS_UI_PYJSON_H

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"

struct ks_pybuf {
    char *s;
    size_t len, cap;
    bool oom;
};

void ks_pybuf_add(struct ks_pybuf *b, const char *s, size_t n);
void ks_pybuf_adds(struct ks_pybuf *b, const char *s);
/* A JSON string literal: quotes, escapes, \uXXXX for everything outside
 * ASCII (surrogate pairs above U+FFFF), as ensure_ascii does. */
void ks_pybuf_add_json_str(struct ks_pybuf *b, const char *s);
/* Returns the string (never NULL unless OOM, which also frees it). */
char *ks_pybuf_finish(struct ks_pybuf *b);

/* json.dumps(v). NULL on OOM. */
char *ks_pyjson_dumps(const cJSON *v);

#endif
