/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/json_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/json_util.h"
#include "common/unicode.h"

#define AT(base, f) ((void *)((char *)(base) + (f)->off))
#define AT_C(base, f) ((const void *)((const char *)(base) + (f)->off))

/* ---- free ------------------------------------------------------------- */

void ks_schema_free_array(const struct ks_schema *elem, struct ks_array *arr)
{
    for (size_t i = 0; i < arr->len; i++)
        ks_schema_free(elem, (char *)arr->items + i * elem->size);
    free(arr->items);
    memset(arr, 0, sizeof(*arr));
}

static void free_strs(struct ks_strs *a)
{
    for (size_t i = 0; i < a->len; i++)
        free(a->v[i]);
    free(a->v);
    memset(a, 0, sizeof(*a));
}

void ks_schema_free(const struct ks_schema *s, void *obj)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct ks_schema_field *f = &s->fields[i];
        switch (f->type) {
        case KS_T_STRING: {
            char **p = AT(obj, f);
            free(*p);
            *p = NULL;
            break;
        }
        case KS_T_STRUCT:
            ks_schema_free(f->sub, AT(obj, f));
            break;
        case KS_T_PTR: {
            void **p = AT(obj, f);
            if (*p != NULL)
                ks_schema_free(f->sub, *p);
            free(*p);
            *p = NULL;
            break;
        }
        case KS_T_ARRAY:
            ks_schema_free_array(f->sub, AT(obj, f));
            break;
        case KS_T_STRS:
            free_strs(AT(obj, f));
            break;
        case KS_T_INTS: {
            struct ks_ints *a = AT(obj, f);
            free(a->v);
            memset(a, 0, sizeof(*a));
            break;
        }
        case KS_T_BOOL:
        case KS_T_INT:
        case KS_T_UINT16:
        case KS_T_UINT32:
        case KS_T_UINT64_STR:
        case KS_T_OPT_INT32:
            break;
        }
    }
}

/* ---- decode ----------------------------------------------------------- */

struct dctx {
    char *err;
    size_t errlen;
};

/* Paths only appear in error messages, so truncating them is harmless.
 * Using snprintf's result tells gcc the truncation is expected. */
#define PATH_MAX_LEN 256
#define JOIN_PATH(dst, ...)                                                  \
    do {                                                                     \
        if (snprintf(dst, sizeof(dst), __VA_ARGS__) >= (int)sizeof(dst))     \
            dst[sizeof(dst) - 1] = '\0';                                     \
    } while (0)

static const char *json_kind(const cJSON *v)
{
    if (cJSON_IsString(v)) return "string";
    if (cJSON_IsNumber(v)) return "number";
    if (cJSON_IsBool(v)) return "bool";
    if (cJSON_IsArray(v)) return "array";
    if (cJSON_IsObject(v)) return "object";
    if (cJSON_IsNull(v)) return "null";
    return "invalid value";
}

static int type_error(struct dctx *c, const char *path, const char *want,
                      const cJSON *v)
{
    snprintf(c->err, c->errlen, "%s: expected %s, got %s",
             path[0] ? path : "(root)", want, json_kind(v));
    return -1;
}

static int oom(struct dctx *c)
{
    snprintf(c->err, c->errlen, "out of memory");
    return -1;
}

/* Go's encoding/json matches keys case-insensitively (preferring an exact
 * match, which makes no difference while no two fields of a struct collide
 * when folded). ASCII folding only; see docs/UPSTREAM.md. */
static int key_equal_fold(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y)
            return 0;
    }
    return *a == *b;
}

/* Validates that `v` is an integer in [min, max]. Go rejects fractions and
 * out-of-range values. (Go also rejects integral literals written as 1.0 or
 * 1e2; cJSON doesn't keep the literal, so those are accepted here.) */
static int decode_int(struct dctx *c, const char *path, const cJSON *v,
                      double min, double max, const char *go_type, int64_t *out)
{
    if (!cJSON_IsNumber(v))
        return type_error(c, path, go_type, v);
    double d = v->valuedouble;
    /* `max` is exclusive for int64 (2^63 isn't representable), inclusive
     * otherwise. */
    int too_big = (max == 9223372036854775808.0) ? d >= max : d > max;
    if (!(d >= min) || too_big || d != (double)(int64_t)d) {
        snprintf(c->err, c->errlen, "%s: number %.17g does not fit in %s",
                 path, d, go_type);
        return -1;
    }
    *out = (int64_t)d;
    return 0;
}

/* A uint64 field tagged `json:",string"`: Go wants a JSON string holding a
 * decimal number ("0"); an unquoted value is an error. */
static int decode_uint64_str(struct dctx *c, const char *path, const cJSON *v,
                             uint64_t *out)
{
    if (!cJSON_IsString(v)) {
        snprintf(c->err, c->errlen,
                 "%s: invalid use of ,string struct tag, trying to unmarshal "
                 "unquoted value into uint64", path);
        return -1;
    }
    const char *s = v->valuestring;
    if (s[0] != '-' && (s[0] < '0' || s[0] > '9')) {
        snprintf(c->err, c->errlen,
                 "%s: invalid use of ,string struct tag, trying to unmarshal "
                 "\"%.64s\" into uint64", path, s);
        return -1;
    }
    uint64_t n = 0;
    bool ok = s[0] != '-';
    for (const char *q = s; ok && *q; q++) {
        if (*q < '0' || *q > '9' || n > (UINT64_MAX - (uint64_t)(*q - '0')) / 10)
            ok = false;
        else
            n = n * 10 + (uint64_t)(*q - '0');
    }
    if (!ok) {
        snprintf(c->err, c->errlen, "%s: number %.64s does not fit in uint64", path, s);
        return -1;
    }
    *out = n;
    return 0;
}

static int decode_struct(struct dctx *c, const struct ks_schema *s,
                         const cJSON *obj, void *base, const char *path);

static int decode_array(struct dctx *c, const struct ks_schema *elem,
                        const cJSON *v, struct ks_array *arr, const char *path)
{
    if (cJSON_IsNull(v)) { /* null resets a slice to nil */
        ks_schema_free_array(elem, arr);
        return 0;
    }
    if (!cJSON_IsArray(v)) {
        char want[96];
        JOIN_PATH(want, "array of %s", elem->go_type);
        return type_error(c, path, want, v);
    }

    /* Go reuses the existing slice; replacing it gives the same result for a
     * freshly zeroed struct, which is all we decode into. */
    ks_schema_free_array(elem, arr);
    size_t n = (size_t)cJSON_GetArraySize(v);
    arr->non_nil = true;
    if (n == 0)
        return 0;
    arr->items = calloc(n, elem->size);
    if (arr->items == NULL)
        return oom(c);
    arr->len = n;

    size_t i = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, v) {
        char sub[PATH_MAX_LEN];
        JOIN_PATH(sub, "%s[%zu]", path, i);
        if (decode_struct(c, elem, item, (char *)arr->items + i * elem->size,
                          sub) < 0)
            return -1;
        i++;
    }
    return 0;
}

static int decode_string(struct dctx *c, const char *path, const cJSON *v, char **out)
{
    if (!cJSON_IsString(v))
        return type_error(c, path, "string", v);
    /* encoding/json replaces invalid UTF-8 with U+FFFD. */
    size_t slen = strlen(v->valuestring);
    char *dup = ks_utf8_valid(v->valuestring, slen) ? strdup(v->valuestring)
                                                    : ks_utf8_sanitize(v->valuestring, slen, NULL);
    if (dup == NULL)
        return oom(c);
    free(*out);
    *out = dup;
    return 0;
}

static int decode_scalars(struct dctx *c, const struct ks_schema_field *f, const cJSON *v,
                          void *p, const char *path)
{
    bool strs = f->type == KS_T_STRS;
    struct ks_strs *as = p;
    struct ks_ints *ai = p;
    if (strs)
        free_strs(as);
    else {
        free(ai->v);
        memset(ai, 0, sizeof(*ai));
    }
    if (cJSON_IsNull(v))
        return 0;
    if (!cJSON_IsArray(v))
        return type_error(c, path, strs ? "array of string" : "array of int", v);
    size_t n = (size_t)cJSON_GetArraySize(v);
    if (strs)
        as->non_nil = true;
    else
        ai->non_nil = true;
    if (n == 0)
        return 0;
    if (strs ? (as->v = calloc(n, sizeof(*as->v))) == NULL
             : (ai->v = calloc(n, sizeof(*ai->v))) == NULL)
        return oom(c);
    size_t i = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, v) {
        char sub[PATH_MAX_LEN];
        JOIN_PATH(sub, "%s[%zu]", path, i);
        if (strs) {
            as->len = i + 1;
            if (!cJSON_IsNull(item) && decode_string(c, sub, item, &as->v[i]) < 0)
                return -1;
            if (as->v[i] == NULL && (as->v[i] = strdup("")) == NULL)
                return oom(c);
        } else {
            ai->len = i + 1;
            if (!cJSON_IsNull(item) &&
                decode_int(c, sub, item, -9223372036854775808.0, 9223372036854775808.0,
                           "int", &ai->v[i]) < 0)
                return -1;
        }
        i++;
    }
    return 0;
}

static int decode_field(struct dctx *c, const struct ks_schema_field *f,
                        const cJSON *v, void *base, const char *path)
{
    void *p = AT(base, f);
    int64_t n;

    /* `null` is a no-op except for pointers and slices. */
    if (cJSON_IsNull(v) && f->type != KS_T_OPT_INT32 && f->type != KS_T_ARRAY &&
        f->type != KS_T_PTR && f->type != KS_T_STRS && f->type != KS_T_INTS)
        return 0;

    switch (f->type) {
    case KS_T_STRING:
        return decode_string(c, path, v, p);
    case KS_T_BOOL:
        if (!cJSON_IsBool(v))
            return type_error(c, path, "bool", v);
        *(bool *)p = cJSON_IsTrue(v);
        return 0;
    case KS_T_INT:
        if (decode_int(c, path, v, -9223372036854775808.0, 9223372036854775808.0,
                       "int", &n) < 0)
            return -1;
        *(int64_t *)p = n;
        return 0;
    case KS_T_UINT16:
        if (decode_int(c, path, v, 0, 65535, "uint16", &n) < 0)
            return -1;
        *(uint16_t *)p = (uint16_t)n;
        return 0;
    case KS_T_OPT_INT32: {
        struct ks_opt_int32 *o = p;
        if (cJSON_IsNull(v)) {
            o->set = false;
            o->value = 0;
            return 0;
        }
        if (decode_int(c, path, v, -2147483648.0, 2147483647.0, "int32", &n) < 0)
            return -1;
        o->set = true;
        o->value = (int32_t)n;
        return 0;
    }
    case KS_T_UINT32:
        if (decode_int(c, path, v, 0, 4294967295.0, "uint32", &n) < 0)
            return -1;
        *(uint32_t *)p = (uint32_t)n;
        return 0;
    case KS_T_UINT64_STR:
        return decode_uint64_str(c, path, v, p);
    case KS_T_STRUCT:
        return decode_struct(c, f->sub, v, p, path);
    case KS_T_PTR: {
        void **pp = p;
        if (cJSON_IsNull(v)) {
            if (*pp != NULL)
                ks_schema_free(f->sub, *pp);
            free(*pp);
            *pp = NULL;
            return 0;
        }
        if (!cJSON_IsObject(v))
            return type_error(c, path, f->sub->go_type, v);
        /* Go decodes into the existing pointee, if any. */
        if (*pp == NULL && (*pp = calloc(1, f->sub->size)) == NULL)
            return oom(c);
        return decode_struct(c, f->sub, v, *pp, path);
    }
    case KS_T_ARRAY:
        return decode_array(c, f->sub, v, p, path);
    case KS_T_STRS:
    case KS_T_INTS:
        return decode_scalars(c, f, v, p, path);
    }
    return 0;
}

static int decode_struct(struct dctx *c, const struct ks_schema *s,
                         const cJSON *obj, void *base, const char *path)
{
    if (cJSON_IsNull(obj))
        return 0;
    if (!cJSON_IsObject(obj))
        return type_error(c, path, s->go_type, obj);

    /* Iterating the members (rather than looking fields up) makes duplicate
     * keys resolve like Go: the last one wins. */
    const cJSON *item;
    cJSON_ArrayForEach(item, obj) {
        for (size_t i = 0; i < s->n; i++) {
            const struct ks_schema_field *f = &s->fields[i];
            if (!key_equal_fold(item->string, f->name))
                continue;
            char sub[PATH_MAX_LEN];
            JOIN_PATH(sub, "%s%s%s", path, path[0] ? "." : "", f->name);
            if (decode_field(c, f, item, base, sub) < 0)
                return -1;
            break;
        }
    }
    return 0;
}

static int fill_strings(const struct ks_schema *s, void *base);

static int fill_array(const struct ks_schema *elem, struct ks_array *arr)
{
    for (size_t j = 0; j < arr->len; j++)
        if (fill_strings(elem, (char *)arr->items + j * elem->size) < 0)
            return -1;
    return 0;
}

/* Replaces NULL strings with "" so callers never see NULL after a decode. */
static int fill_strings(const struct ks_schema *s, void *base)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct ks_schema_field *f = &s->fields[i];
        if (f->type == KS_T_STRING) {
            char **p = AT(base, f);
            if (*p == NULL && (*p = strdup("")) == NULL)
                return -1;
        } else if (f->type == KS_T_STRUCT) {
            if (fill_strings(f->sub, AT(base, f)) < 0)
                return -1;
        } else if (f->type == KS_T_PTR) {
            void *pp = *(void **)AT(base, f);
            if (pp != NULL && fill_strings(f->sub, pp) < 0)
                return -1;
        } else if (f->type == KS_T_ARRAY) {
            if (fill_array(f->sub, AT(base, f)) < 0)
                return -1;
        }
    }
    return 0;
}

int ks_schema_decode(const struct ks_schema *s, const cJSON *json, void *out,
                     char *err, size_t errlen)
{
    struct dctx c = {err, errlen};

    memset(out, 0, s->size);
    int ret = decode_struct(&c, s, json, out, "");
    if (ret == 0 && fill_strings(s, out) < 0)
        ret = oom(&c);
    if (ret < 0) {
        ks_schema_free(s, out);
        memset(out, 0, s->size);
    }
    return ret;
}

int ks_schema_decode_array(const struct ks_schema *elem, const cJSON *json,
                           struct ks_array *out, char *err, size_t errlen)
{
    struct dctx c = {err, errlen};

    memset(out, 0, sizeof(*out));
    int ret = decode_array(&c, elem, json, out, "");
    if (ret == 0 && fill_array(elem, out) < 0)
        ret = oom(&c);
    if (ret < 0)
        ks_schema_free_array(elem, out);
    return ret;
}

int ks_schema_decode_buf(const struct ks_schema *s, const char *buf, size_t len,
                         void *out, char *err, size_t errlen)
{
    char perr[200];

    memset(out, 0, s->size);
    cJSON *root = ks_json_parse(buf, len, perr, sizeof(perr));
    if (root == NULL) {
        snprintf(err, errlen, "%s", perr);
        return -1;
    }
    int ret = ks_schema_decode(s, root, out, err, errlen);
    cJSON_Delete(root);
    return ret;
}

/* ---- encode ----------------------------------------------------------- */

static cJSON *encode_array(const struct ks_schema *elem, const struct ks_array *arr)
{
    if (!arr->non_nil)
        return cJSON_CreateNull();
    cJSON *out = cJSON_CreateArray();
    for (size_t i = 0; out != NULL && i < arr->len; i++) {
        cJSON *item = ks_schema_encode(elem, (const char *)arr->items + i * elem->size);
        if (item == NULL || !cJSON_AddItemToArray(out, item)) {
            cJSON_Delete(item);
            cJSON_Delete(out);
            return NULL;
        }
    }
    return out;
}

static cJSON *encode_field(const struct ks_schema_field *f, const void *base)
{
    const void *p = AT_C(base, f);

    switch (f->type) {
    case KS_T_STRING: {
        const char *str = *(char *const *)p;
        return cJSON_CreateString(str != NULL ? str : "");
    }
    case KS_T_BOOL:
        return cJSON_CreateBool(*(const bool *)p);
    case KS_T_INT:
        return cJSON_CreateNumber((double)*(const int64_t *)p);
    case KS_T_UINT16:
        return cJSON_CreateNumber(*(const uint16_t *)p);
    case KS_T_UINT32:
        return cJSON_CreateNumber(*(const uint32_t *)p);
    case KS_T_UINT64_STR: {
        char num[24];
        snprintf(num, sizeof(num), "%llu", (unsigned long long)*(const uint64_t *)p);
        return cJSON_CreateString(num);
    }
    case KS_T_OPT_INT32: {
        const struct ks_opt_int32 *o = p;
        return o->set ? cJSON_CreateNumber(o->value) : cJSON_CreateNull();
    }
    case KS_T_STRUCT:
        return ks_schema_encode(f->sub, p);
    case KS_T_PTR: {
        const void *pp = *(void *const *)p;
        return pp != NULL ? ks_schema_encode(f->sub, pp) : cJSON_CreateNull();
    }
    case KS_T_ARRAY:
        return encode_array(f->sub, p);
    case KS_T_STRS: {
        const struct ks_strs *a = p;
        if (!a->non_nil)
            return cJSON_CreateNull();
        cJSON *out = cJSON_CreateArray();
        for (size_t i = 0; out != NULL && i < a->len; i++) {
            cJSON *item = cJSON_CreateString(a->v[i] != NULL ? a->v[i] : "");
            if (item == NULL || !cJSON_AddItemToArray(out, item)) {
                cJSON_Delete(item);
                cJSON_Delete(out);
                return NULL;
            }
        }
        return out;
    }
    case KS_T_INTS: {
        const struct ks_ints *a = p;
        if (!a->non_nil)
            return cJSON_CreateNull();
        cJSON *out = cJSON_CreateArray();
        for (size_t i = 0; out != NULL && i < a->len; i++) {
            cJSON *item = cJSON_CreateNumber((double)a->v[i]);
            if (item == NULL || !cJSON_AddItemToArray(out, item)) {
                cJSON_Delete(item);
                cJSON_Delete(out);
                return NULL;
            }
        }
        return out;
    }
    }
    return NULL;
}

cJSON *ks_schema_encode(const struct ks_schema *s, const void *in)
{
    cJSON *obj = cJSON_CreateObject();
    for (size_t i = 0; obj != NULL && i < s->n; i++) {
        cJSON *v = encode_field(&s->fields[i], in);
        if (v == NULL || !cJSON_AddItemToObject(obj, s->fields[i].name, v)) {
            cJSON_Delete(v);
            cJSON_Delete(obj);
            return NULL;
        }
    }
    return obj;
}

/* ---- compare / copy --------------------------------------------------- */

static bool str_equal(const char *a, const char *b)
{
    return strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0;
}

bool ks_schema_equal(const struct ks_schema *s, const void *a, const void *b)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct ks_schema_field *f = &s->fields[i];
        const void *pa = AT_C(a, f), *pb = AT_C(b, f);
        switch (f->type) {
        case KS_T_STRING:
            if (!str_equal(*(char *const *)pa, *(char *const *)pb))
                return false;
            break;
        case KS_T_BOOL:
            if (*(const bool *)pa != *(const bool *)pb)
                return false;
            break;
        case KS_T_INT:
            if (*(const int64_t *)pa != *(const int64_t *)pb)
                return false;
            break;
        case KS_T_UINT16:
            if (*(const uint16_t *)pa != *(const uint16_t *)pb)
                return false;
            break;
        case KS_T_UINT32:
            if (*(const uint32_t *)pa != *(const uint32_t *)pb)
                return false;
            break;
        case KS_T_UINT64_STR:
            if (*(const uint64_t *)pa != *(const uint64_t *)pb)
                return false;
            break;
        case KS_T_OPT_INT32: {
            const struct ks_opt_int32 *x = pa, *y = pb;
            if (x->set != y->set || (x->set && x->value != y->value))
                return false;
            break;
        }
        case KS_T_STRUCT:
            if (!ks_schema_equal(f->sub, pa, pb))
                return false;
            break;
        case KS_T_PTR: {
            const void *x = *(void *const *)pa, *y = *(void *const *)pb;
            if ((x == NULL) != (y == NULL) || (x != NULL && !ks_schema_equal(f->sub, x, y)))
                return false;
            break;
        }
        case KS_T_ARRAY: {
            const struct ks_array *x = pa, *y = pb;
            if (x->non_nil != y->non_nil || x->len != y->len)
                return false;
            for (size_t j = 0; j < x->len; j++)
                if (!ks_schema_equal(f->sub,
                                     (const char *)x->items + j * f->sub->size,
                                     (const char *)y->items + j * f->sub->size))
                    return false;
            break;
        }
        case KS_T_STRS: {
            const struct ks_strs *x = pa, *y = pb;
            if (x->non_nil != y->non_nil || x->len != y->len)
                return false;
            for (size_t j = 0; j < x->len; j++)
                if (!str_equal(x->v[j], y->v[j]))
                    return false;
            break;
        }
        case KS_T_INTS: {
            const struct ks_ints *x = pa, *y = pb;
            if (x->non_nil != y->non_nil || x->len != y->len ||
                (x->len > 0 && memcmp(x->v, y->v, x->len * sizeof(*x->v)) != 0))
                return false;
            break;
        }
        }
    }
    return true;
}

static int copy_fields(const struct ks_schema *s, void *dst, const void *src)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct ks_schema_field *f = &s->fields[i];
        void *pd = AT(dst, f);
        const void *ps = AT_C(src, f);
        switch (f->type) {
        case KS_T_STRING: {
            const char *str = *(char *const *)ps;
            if (str != NULL && (*(char **)pd = strdup(str)) == NULL)
                return -1;
            break;
        }
        case KS_T_BOOL:
            *(bool *)pd = *(const bool *)ps;
            break;
        case KS_T_INT:
            *(int64_t *)pd = *(const int64_t *)ps;
            break;
        case KS_T_UINT16:
            *(uint16_t *)pd = *(const uint16_t *)ps;
            break;
        case KS_T_UINT32:
            *(uint32_t *)pd = *(const uint32_t *)ps;
            break;
        case KS_T_UINT64_STR:
            *(uint64_t *)pd = *(const uint64_t *)ps;
            break;
        case KS_T_OPT_INT32:
            *(struct ks_opt_int32 *)pd = *(const struct ks_opt_int32 *)ps;
            break;
        case KS_T_STRUCT:
            if (copy_fields(f->sub, pd, ps) < 0)
                return -1;
            break;
        case KS_T_PTR: {
            const void *src_p = *(void *const *)ps;
            if (src_p == NULL)
                break;
            void *np = calloc(1, f->sub->size);
            if (np == NULL)
                return -1;
            *(void **)pd = np;
            if (copy_fields(f->sub, np, src_p) < 0)
                return -1;
            break;
        }
        case KS_T_ARRAY: {
            const struct ks_array *as = ps;
            struct ks_array *ad = pd;
            ad->non_nil = as->non_nil;
            if (as->len == 0)
                break;
            ad->items = calloc(as->len, f->sub->size);
            if (ad->items == NULL)
                return -1;
            ad->len = as->len;
            for (size_t j = 0; j < as->len; j++)
                if (copy_fields(f->sub, (char *)ad->items + j * f->sub->size,
                                (const char *)as->items + j * f->sub->size) < 0)
                    return -1;
            break;
        }
        case KS_T_STRS: {
            const struct ks_strs *as = ps;
            struct ks_strs *ad = pd;
            ad->non_nil = as->non_nil;
            if (as->len == 0)
                break;
            if ((ad->v = calloc(as->len, sizeof(*ad->v))) == NULL)
                return -1;
            for (size_t j = 0; j < as->len; j++, ad->len++)
                if ((ad->v[j] = strdup(as->v[j] != NULL ? as->v[j] : "")) == NULL)
                    return -1;
            break;
        }
        case KS_T_INTS: {
            const struct ks_ints *as = ps;
            struct ks_ints *ad = pd;
            ad->non_nil = as->non_nil;
            if (as->len == 0)
                break;
            if ((ad->v = malloc(as->len * sizeof(*ad->v))) == NULL)
                return -1;
            memcpy(ad->v, as->v, as->len * sizeof(*ad->v));
            ad->len = as->len;
            break;
        }
        }
    }
    return 0;
}

int ks_schema_copy(const struct ks_schema *s, void *dst, const void *src)
{
    memset(dst, 0, s->size);
    if (copy_fields(s, dst, src) < 0) {
        ks_schema_free(s, dst);
        return -1;
    }
    return 0;
}
