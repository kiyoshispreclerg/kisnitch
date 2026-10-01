/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Table-driven mapping between JSON and C structs, following the rules of
 * Go's encoding/json for the types upstream uses (string, bool, int, uint16,
 * *int32, nested structs and slices of structs).
 *
 * Decoding:
 *   - Missing keys keep the zero value; unknown keys are ignored.
 *   - Key matching is case-insensitive (ASCII); with duplicate keys the last
 *     one wins.
 *   - `null` leaves strings, bools, numbers and structs untouched, and resets
 *     *int32 (KS_T_OPT_INT32) and slices (KS_T_ARRAY) to nil.
 *   - Wrong JSON types and out-of-range integers are errors naming the field,
 *     e.g. "FwOptions.QueueNum: expected uint16, got string".
 * Encoding emits every field in table order, like json.Marshal does with
 * struct field order; nil pointers and slices become null.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a decoded struct owns every string and array reachable through its
 * schema. Release with ks_schema_free(). After a successful decode no string
 * is NULL (absent values are ""), but all functions accept NULL strings, as
 * found in a zero-initialized struct.
 */
#ifndef KS_COMMON_JSON_SCHEMA_H
#define KS_COMMON_JSON_SCHEMA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

enum ks_ftype {
    KS_T_STRING,    /* char * */
    KS_T_BOOL,      /* bool */
    KS_T_INT,       /* int64_t (Go int) */
    KS_T_UINT16,    /* uint16_t */
    KS_T_OPT_INT32, /* struct ks_opt_int32 (Go *int32) */
    KS_T_STRUCT,    /* nested struct described by `sub` */
    KS_T_ARRAY,     /* struct ks_array of `sub` elements (Go slice) */
};

struct ks_schema;

struct ks_field {
    const char *name; /* JSON key, exactly as upstream */
    enum ks_ftype type;
    size_t off;
    const struct ks_schema *sub; /* KS_T_STRUCT and KS_T_ARRAY */
};

struct ks_schema {
    const char *go_type; /* for error messages, e.g. "config.FwOptions" */
    size_t size;         /* sizeof the C struct */
    const struct ks_field *fields;
    size_t n;
};

/* A Go *int32: `set` is false for nil. */
struct ks_opt_int32 {
    bool set;
    int32_t value;
};

/* A Go slice of structs. `items` points to `len` elements of the element
 * schema's C type; `non_nil` distinguishes [] from null. Owns `items`. */
struct ks_array {
    void *items;
    size_t len;
    bool non_nil;
};

#define KS_ARRAY_ITEM(arr, type, i) (&((type *)(arr).items)[i])

#define KS_FIELD(st, key, type, member) {key, type, offsetof(st, member), NULL}
#define KS_FIELD_SUB(st, key, type, member, schema) \
    {key, type, offsetof(st, member), &(schema)}
#define KS_SCHEMA(go_type, st, fields) \
    {go_type, sizeof(st), fields, sizeof(fields) / sizeof((fields)[0])}

/* Decodes `json` into `out` (sizeof == s->size), which is zeroed first.
 * On error returns -1, leaves `out` zeroed and fills `err`. */
int ks_schema_decode(const struct ks_schema *s, const cJSON *json, void *out,
                     char *err, size_t errlen);

/* Parses `len` bytes of JSON text and decodes them. */
int ks_schema_decode_buf(const struct ks_schema *s, const char *buf, size_t len,
                         void *out, char *err, size_t errlen);

/* Decodes a JSON array (or null) into a slice of `elem` structs, as
 * json.Unmarshal into a Go []T. `out` is zeroed first. */
int ks_schema_decode_array(const struct ks_schema *elem, const cJSON *json,
                           struct ks_array *out, char *err, size_t errlen);

/* Returns a new tree owned by the caller, or NULL on OOM. */
cJSON *ks_schema_encode(const struct ks_schema *s, const void *in);

/* Deep comparison of all schema fields (NULL and "" strings are equal). */
bool ks_schema_equal(const struct ks_schema *s, const void *a, const void *b);

/* Deep copy of all schema fields into `dst` (zeroed first). -1 on OOM. */
int ks_schema_copy(const struct ks_schema *s, void *dst, const void *src);

/* Frees everything the struct owns through the schema and zeroes it. */
void ks_schema_free(const struct ks_schema *s, void *obj);

/* Frees the elements of a slice and the slice itself, and zeroes it. */
void ks_schema_free_array(const struct ks_schema *elem, struct ks_array *arr);

#endif
