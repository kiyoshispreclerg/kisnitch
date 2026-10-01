/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Helpers over the vendored cJSON (common/vendor/cjson).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_COMMON_JSON_UTIL_H
#define KS_COMMON_JSON_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "cJSON.h"

/* Reads the whole file at `path`. Returns a NUL-terminated buffer owned by the
 * caller (free()), with its length (excluding the NUL) in *len. Fails on files
 * larger than `max_size`. On failure returns NULL and writes a message to
 * `err`. */
char *ks_read_file(const char *path, size_t max_size, size_t *len, char *err,
                   size_t errlen);

/* Parses exactly one JSON value from buf[0..len); trailing whitespace is
 * allowed, anything else is an error (as in Go's json.Unmarshal).
 * Returns a tree owned by the caller (cJSON_Delete()). On failure returns NULL
 * and writes "line L, column C: ..." to `err`. The column comes from where
 * cJSON stopped, which for some errors is the token after the culprit. */
cJSON *ks_json_parse(const char *buf, size_t len, char *err, size_t errlen);

/* Semantic equality: object key order is ignored, numbers compare by value,
 * key names are case-sensitive. */
bool ks_json_equal(const cJSON *a, const cJSON *b);

/* True if every member of `sub` exists in `super` with an equal value,
 * recursing into objects. Arrays must be equal element by element, with each
 * element also compared as a subset. Non-object values must be equal. */
bool ks_json_is_subset(const cJSON *sub, const cJSON *super);

/* Serializes like Go: json.Marshal when `indent` is false, otherwise
 * json.MarshalIndent(v, "", "  "). Strings are escaped as Go does by default
 * (HTML characters <, > and & as \u003c..., U+2028/U+2029, invalid UTF-8 as
 * \ufffd), so files we write match the ones upstream writes byte for byte.
 * Returns a malloc'd string owned by the caller, or NULL on OOM. */
char *ks_json_print_go(const cJSON *v, bool indent);

/* Writes `len` bytes of `data` to `path`, creating it with `mode` or
 * truncating it. Returns 0 or -1 with `err` filled. */
int ks_write_file(const char *path, const char *data, size_t len, mode_t mode,
                  char *err, size_t errlen);

#endif
