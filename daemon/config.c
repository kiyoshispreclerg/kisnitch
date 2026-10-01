/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/ui/config/config.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Every Go struct is described by a table of fields (`struct schema`); one
 * generic walker per operation (decode, encode, compare, free) handles them
 * all, so adding a field upstream added is a one-line change here.
 */
#include "daemon/config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/json_util.h"
#include "common/log.h"

enum ftype {
    T_STRING,    /* char * */
    T_BOOL,      /* bool */
    T_INT,       /* int64_t (Go int) */
    T_UINT16,    /* uint16_t */
    T_OPT_INT32, /* struct ks_opt_int32 (Go *int32) */
    T_STRUCT,    /* nested struct described by `sub` */
    T_LOGGERS,   /* struct ks_logger_list (Go []loggers.LoggerConfig) */
};

struct schema;

struct field {
    const char *name; /* JSON key, exactly as upstream */
    enum ftype type;
    size_t off;
    const struct schema *sub; /* T_STRUCT and T_LOGGERS */
};

struct schema {
    const char *go_type; /* for error messages */
    const struct field *fields;
    size_t n;
};

#define F(st, key, type, member) {key, type, offsetof(st, member), NULL}
#define S(st, key, member, schema) {key, T_STRUCT, offsetof(st, member), &schema}
#define SCHEMA(go_type, fields) {go_type, fields, sizeof(fields) / sizeof(fields[0])}

static const struct field tls_fields[] = {
    F(struct ks_tls_options, "CACert", T_STRING, ca_cert),
    F(struct ks_tls_options, "ServerCert", T_STRING, server_cert),
    F(struct ks_tls_options, "ServerKey", T_STRING, server_key),
    F(struct ks_tls_options, "ClientCert", T_STRING, client_cert),
    F(struct ks_tls_options, "ClientKey", T_STRING, client_key),
    F(struct ks_tls_options, "ClientAuthType", T_STRING, client_auth_type),
    F(struct ks_tls_options, "SkipVerify", T_BOOL, skip_verify),
};
static const struct schema tls_schema = SCHEMA("config.ServerTLSOptions", tls_fields);

static const struct field auth_fields[] = {
    F(struct ks_server_auth, "Type", T_STRING, type),
    S(struct ks_server_auth, "TLSOptions", tls, tls_schema),
};
static const struct schema auth_schema = SCHEMA("config.ServerAuth", auth_fields);

static const struct field logger_fields[] = {
    F(struct ks_logger_config, "Name", T_STRING, name),
    F(struct ks_logger_config, "Format", T_STRING, format),
    F(struct ks_logger_config, "Protocol", T_STRING, protocol),
    F(struct ks_logger_config, "Server", T_STRING, server),
    F(struct ks_logger_config, "WriteTimeout", T_STRING, write_timeout),
    F(struct ks_logger_config, "ConnectTimeout", T_STRING, connect_timeout),
    F(struct ks_logger_config, "Tag", T_STRING, tag),
    F(struct ks_logger_config, "Workers", T_INT, workers),
    F(struct ks_logger_config, "MaxConnectAttempts", T_UINT16, max_connect_attempts),
};
static const struct schema logger_schema = SCHEMA("loggers.LoggerConfig", logger_fields);

static const struct field server_fields[] = {
    F(struct ks_server_config, "Address", T_STRING, address),
    S(struct ks_server_config, "Authentication", auth, auth_schema),
    F(struct ks_server_config, "LogFile", T_STRING, log_file),
    {"Loggers", T_LOGGERS, offsetof(struct ks_server_config, loggers), &logger_schema},
};
static const struct schema server_schema = SCHEMA("config.ServerConfig", server_fields);

static const struct field rules_fields[] = {
    F(struct ks_rules_options, "Path", T_STRING, path),
    F(struct ks_rules_options, "EnableChecksums", T_BOOL, enable_checksums),
};
static const struct schema rules_schema = SCHEMA("config.RulesOptions", rules_fields);

static const struct field fw_fields[] = {
    F(struct ks_fw_options, "Firewall", T_STRING, firewall),
    F(struct ks_fw_options, "ConfigPath", T_STRING, config_path),
    F(struct ks_fw_options, "MonitorInterval", T_STRING, monitor_interval),
    F(struct ks_fw_options, "QueueNum", T_UINT16, queue_num),
    F(struct ks_fw_options, "QueueBypass", T_BOOL, queue_bypass),
};
static const struct schema fw_schema = SCHEMA("config.FwOptions", fw_fields);

static const struct field tasks_fields[] = {
    F(struct ks_tasks_options, "ConfigPath", T_STRING, config_path),
};
static const struct schema tasks_schema = SCHEMA("config.TasksOptions", tasks_fields);

static const struct field internal_fields[] = {
    F(struct ks_internal_options, "GCPercent", T_INT, gc_percent),
    F(struct ks_internal_options, "FlushConnsOnStart", T_BOOL, flush_conns_on_start),
};
static const struct schema internal_schema = SCHEMA("config.InternalOptions", internal_fields);

static const struct field audit_fields[] = {
    F(struct ks_audit_config, "AudispSocketPath", T_STRING, audisp_socket_path),
};
static const struct schema audit_schema = SCHEMA("audit.Config", audit_fields);

static const struct field ebpf_fields[] = {
    F(struct ks_ebpf_config, "ModulesPath", T_STRING, modules_path),
    F(struct ks_ebpf_config, "RingBuffSize", T_INT, ring_buff_size),
    F(struct ks_ebpf_config, "EventsWorkers", T_INT, events_workers),
    F(struct ks_ebpf_config, "QueueEventsSize", T_INT, queue_events_size),
};
static const struct schema ebpf_schema = SCHEMA("ebpf.Config", ebpf_fields);

static const struct field stats_fields[] = {
    F(struct ks_stats_config, "MaxEvents", T_INT, max_events),
    F(struct ks_stats_config, "MaxStats", T_INT, max_stats),
    F(struct ks_stats_config, "Workers", T_INT, workers),
};
static const struct schema stats_schema = SCHEMA("statistics.StatsConfig", stats_fields);

static const struct field config_fields[] = {
    F(struct ks_config, "LogLevel", T_OPT_INT32, log_level),
    F(struct ks_config, "Firewall", T_STRING, firewall),
    F(struct ks_config, "DefaultAction", T_STRING, default_action),
    F(struct ks_config, "DefaultDuration", T_STRING, default_duration),
    F(struct ks_config, "ProcMonitorMethod", T_STRING, proc_monitor_method),
    S(struct ks_config, "FwOptions", fw_options, fw_schema),
    S(struct ks_config, "Audit", audit, audit_schema),
    S(struct ks_config, "Ebpf", ebpf, ebpf_schema),
    S(struct ks_config, "Server", server, server_schema),
    S(struct ks_config, "Rules", rules, rules_schema),
    S(struct ks_config, "Internal", internal, internal_schema),
    S(struct ks_config, "Stats", stats, stats_schema),
    S(struct ks_config, "Tasks", tasks, tasks_schema),
    F(struct ks_config, "InterceptUnknown", T_BOOL, intercept_unknown),
    F(struct ks_config, "LogUTC", T_BOOL, log_utc),
    F(struct ks_config, "LogMicro", T_BOOL, log_micro),
};
static const struct schema config_schema = SCHEMA("config.Config", config_fields);

#define AT(base, f) ((void *)((char *)(base) + (f)->off))
#define AT_C(base, f) ((const void *)((const char *)(base) + (f)->off))

/* ---- free ------------------------------------------------------------- */

static void free_struct(const struct schema *s, void *base);

static void free_loggers(struct ks_logger_list *l)
{
    for (size_t i = 0; i < l->len; i++)
        free_struct(&logger_schema, &l->items[i]);
    free(l->items);
    memset(l, 0, sizeof(*l));
}

static void free_struct(const struct schema *s, void *base)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct field *f = &s->fields[i];
        switch (f->type) {
        case T_STRING: {
            char **p = AT(base, f);
            free(*p);
            *p = NULL;
            break;
        }
        case T_STRUCT:
            free_struct(f->sub, AT(base, f));
            break;
        case T_LOGGERS:
            free_loggers(AT(base, f));
            break;
        case T_BOOL:
        case T_INT:
        case T_UINT16:
        case T_OPT_INT32:
            break;
        }
    }
}

void ks_config_free(struct ks_config *cfg)
{
    free_struct(&config_schema, cfg);
    memset(cfg, 0, sizeof(*cfg));
}

/* ---- decode ----------------------------------------------------------- */

/* Error context: the dotted path of the value being decoded. */
struct dctx {
    char *err;
    size_t errlen;
};

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
 * match, which can't make a difference here since our field names don't
 * collide when folded). ASCII folding only; see docs/UPSTREAM.md. */
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

/* Paths only appear in error messages, so truncating them is harmless.
 * Using snprintf's result tells gcc the truncation is expected. */
#define PATH_MAX_LEN 256
#define JOIN_PATH(dst, ...)                                                  \
    do {                                                                     \
        if (snprintf(dst, sizeof(dst), __VA_ARGS__) >= (int)sizeof(dst))     \
            dst[sizeof(dst) - 1] = '\0';                                     \
    } while (0)

static int decode_struct(struct dctx *c, const struct schema *s,
                         const cJSON *obj, void *base, const char *path);

static int decode_loggers(struct dctx *c, const cJSON *v,
                          struct ks_logger_list *l, const char *path)
{
    if (cJSON_IsNull(v)) { /* null resets a slice to nil */
        free_loggers(l);
        return 0;
    }
    if (!cJSON_IsArray(v))
        return type_error(c, path, "array of loggers.LoggerConfig", v);

    /* Go reuses the existing slice; replacing it gives the same result for a
     * freshly zeroed config, which is all we decode into. */
    free_loggers(l);
    size_t n = (size_t)cJSON_GetArraySize(v);
    l->non_nil = true;
    if (n == 0)
        return 0;
    l->items = calloc(n, sizeof(*l->items));
    if (l->items == NULL)
        return oom(c);
    l->len = n;

    size_t i = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, v) {
        char sub[PATH_MAX_LEN];
        JOIN_PATH(sub, "%s[%zu]", path, i);
        if (decode_struct(c, &logger_schema, item, &l->items[i], sub) < 0)
            return -1;
        i++;
    }
    return 0;
}

static int decode_field(struct dctx *c, const struct field *f, const cJSON *v,
                        void *base, const char *path)
{
    void *p = AT(base, f);
    int64_t n;

    /* `null` is a no-op except for pointers and slices. */
    if (cJSON_IsNull(v) && f->type != T_OPT_INT32 && f->type != T_LOGGERS)
        return 0;

    switch (f->type) {
    case T_STRING: {
        if (!cJSON_IsString(v))
            return type_error(c, path, "string", v);
        char *dup = strdup(v->valuestring);
        if (dup == NULL)
            return oom(c);
        free(*(char **)p);
        *(char **)p = dup;
        return 0;
    }
    case T_BOOL:
        if (!cJSON_IsBool(v))
            return type_error(c, path, "bool", v);
        *(bool *)p = cJSON_IsTrue(v);
        return 0;
    case T_INT:
        if (decode_int(c, path, v, -9223372036854775808.0, 9223372036854775808.0,
                       "int", &n) < 0)
            return -1;
        *(int64_t *)p = n;
        return 0;
    case T_UINT16:
        if (decode_int(c, path, v, 0, 65535, "uint16", &n) < 0)
            return -1;
        *(uint16_t *)p = (uint16_t)n;
        return 0;
    case T_OPT_INT32: {
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
    case T_STRUCT:
        return decode_struct(c, f->sub, v, p, path);
    case T_LOGGERS:
        return decode_loggers(c, v, p, path);
    }
    return 0;
}

static int decode_struct(struct dctx *c, const struct schema *s,
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
            const struct field *f = &s->fields[i];
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

/* Replaces NULL strings with "" so callers never see NULL after a parse. */
static int fill_strings(const struct schema *s, void *base)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct field *f = &s->fields[i];
        if (f->type == T_STRING) {
            char **p = AT(base, f);
            if (*p == NULL && (*p = strdup("")) == NULL)
                return -1;
        } else if (f->type == T_STRUCT) {
            if (fill_strings(f->sub, AT(base, f)) < 0)
                return -1;
        } else if (f->type == T_LOGGERS) {
            struct ks_logger_list *l = AT(base, f);
            for (size_t j = 0; j < l->len; j++)
                if (fill_strings(f->sub, &l->items[j]) < 0)
                    return -1;
        }
    }
    return 0;
}

int ks_config_parse(const char *json, size_t len, struct ks_config *out,
                    char *err, size_t errlen)
{
    struct dctx c = {err, errlen};
    char perr[200];

    memset(out, 0, sizeof(*out));

    cJSON *root = ks_json_parse(json, len, perr, sizeof(perr));
    if (root == NULL) {
        snprintf(err, errlen, "%s", perr);
        return -1;
    }

    int ret = decode_struct(&c, &config_schema, root, out, "");
    cJSON_Delete(root);
    if (ret == 0 && fill_strings(&config_schema, out) < 0)
        ret = oom(&c);
    if (ret < 0)
        ks_config_free(out);
    return ret;
}

int ks_config_load(const char *path, struct ks_config *out, char *err,
                   size_t errlen)
{
    char e[512];
    size_t len;

    memset(out, 0, sizeof(*out));
    char *raw = ks_read_file(path, KS_CONFIG_MAX_SIZE, &len, e, sizeof(e));
    if (raw == NULL) {
        snprintf(err, errlen, "Error loading configuration %s: %s", path, e);
        return -1;
    }
    if (len == 0) {
        free(raw);
        snprintf(err, errlen, "Error loading configuration %s: empty file", path);
        return -1;
    }
    int ret = ks_config_parse(raw, len, out, e, sizeof(e));
    free(raw);
    if (ret < 0)
        snprintf(err, errlen, "Error parsing configuration %s: %s", path, e);
    return ret;
}

int ks_config_reload(const char *path, struct ks_config *cfg, char *err,
                     size_t errlen)
{
    struct ks_config fresh;
    if (ks_config_load(path, &fresh, err, errlen) < 0)
        return -1;
    ks_config_free(cfg);
    *cfg = fresh;
    return 0;
}

int ks_config_save_raw(const char *path, const char *raw, size_t len,
                       char *err, size_t errlen)
{
    struct ks_config tmp;
    char e[512];

    if (ks_config_parse(raw, len, &tmp, e, sizeof(e)) < 0) {
        snprintf(err, errlen, "Error parsing configuration: %s", e);
        return -1;
    }
    ks_config_free(&tmp);

    if (chmod(path, 0600) < 0)
        ks_warning("unable to set permissions to default config: %s",
                   strerror(errno));
    if (ks_write_file(path, raw, len, 0644, e, sizeof(e)) < 0) {
        ks_error("writing configuration to disk: %s", e);
        snprintf(err, errlen, "%s", e);
        return -1;
    }
    return 0;
}

/* ---- encode ----------------------------------------------------------- */

static cJSON *encode_struct(const struct schema *s, const void *base);

static cJSON *encode_field(const struct field *f, const void *base)
{
    const void *p = AT_C(base, f);

    switch (f->type) {
    case T_STRING: {
        const char *str = *(char *const *)p;
        return cJSON_CreateString(str != NULL ? str : "");
    }
    case T_BOOL:
        return cJSON_CreateBool(*(const bool *)p);
    case T_INT:
        return cJSON_CreateNumber((double)*(const int64_t *)p);
    case T_UINT16:
        return cJSON_CreateNumber(*(const uint16_t *)p);
    case T_OPT_INT32: {
        const struct ks_opt_int32 *o = p;
        return o->set ? cJSON_CreateNumber(o->value) : cJSON_CreateNull();
    }
    case T_STRUCT:
        return encode_struct(f->sub, p);
    case T_LOGGERS: {
        const struct ks_logger_list *l = p;
        if (!l->non_nil)
            return cJSON_CreateNull();
        cJSON *arr = cJSON_CreateArray();
        for (size_t i = 0; arr != NULL && i < l->len; i++) {
            cJSON *item = encode_struct(f->sub, &l->items[i]);
            if (item == NULL || !cJSON_AddItemToArray(arr, item)) {
                cJSON_Delete(item);
                cJSON_Delete(arr);
                return NULL;
            }
        }
        return arr;
    }
    }
    return NULL;
}

static cJSON *encode_struct(const struct schema *s, const void *base)
{
    cJSON *obj = cJSON_CreateObject();
    for (size_t i = 0; obj != NULL && i < s->n; i++) {
        cJSON *v = encode_field(&s->fields[i], base);
        if (v == NULL || !cJSON_AddItemToObject(obj, s->fields[i].name, v)) {
            cJSON_Delete(v);
            cJSON_Delete(obj);
            return NULL;
        }
    }
    return obj;
}

char *ks_config_to_json(const struct ks_config *cfg, bool pretty)
{
    cJSON *root = encode_struct(&config_schema, cfg);
    if (root == NULL)
        return NULL;
    char *out = pretty ? cJSON_Print(root) : cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

/* ---- compare ---------------------------------------------------------- */

static bool str_equal(const char *a, const char *b)
{
    return strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0;
}

static bool struct_equal(const struct schema *s, const void *a, const void *b)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct field *f = &s->fields[i];
        const void *pa = AT_C(a, f), *pb = AT_C(b, f);
        switch (f->type) {
        case T_STRING:
            if (!str_equal(*(char *const *)pa, *(char *const *)pb))
                return false;
            break;
        case T_BOOL:
            if (*(const bool *)pa != *(const bool *)pb)
                return false;
            break;
        case T_INT:
            if (*(const int64_t *)pa != *(const int64_t *)pb)
                return false;
            break;
        case T_UINT16:
            if (*(const uint16_t *)pa != *(const uint16_t *)pb)
                return false;
            break;
        case T_OPT_INT32: {
            const struct ks_opt_int32 *x = pa, *y = pb;
            if (x->set != y->set || (x->set && x->value != y->value))
                return false;
            break;
        }
        case T_STRUCT:
            if (!struct_equal(f->sub, pa, pb))
                return false;
            break;
        case T_LOGGERS: {
            const struct ks_logger_list *x = pa, *y = pb;
            if (x->non_nil != y->non_nil || x->len != y->len)
                return false;
            for (size_t j = 0; j < x->len; j++)
                if (!struct_equal(f->sub, &x->items[j], &y->items[j]))
                    return false;
            break;
        }
        }
    }
    return true;
}

bool ks_config_equal(const struct ks_config *a, const struct ks_config *b)
{
    return struct_equal(&config_schema, a, b);
}
