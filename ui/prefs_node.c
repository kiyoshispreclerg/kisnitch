/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the node configuration part of upstream
 * ui/opensnitch/dialogs/preferences.py. See prefs_node.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/prefs_node.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/json_util.h"
#include "ui/pyjson.h"

const char *const ks_node_actions[3] = {"deny", "allow", "reject"};
const char *const ks_node_monitors[3] = {"proc", "ebpf", "audit"};
const char *const ks_node_auth_types[3] = {"simple", "tls-simple", "tls-mutual"};
const char *const ks_node_verify_types[5] = {"no-client-cert", "req-cert", "req-any-cert",
                                             "verify-cert", "req-and-verify-cert"};

/* ---- the form ------------------------------------------------------------------------- */

void ks_nform_set(char **dst, const char *text)
{
    char *t = g_strdup(text != NULL ? text : "");
    g_free(*dst);
    *dst = t;
}

void ks_nform_reset(struct ks_nform *f)
{
    f->action = 0;
    f->monitor = 0;
    f->intercept_unknown = false;
    f->log_level = 0;
    f->log_utc = true;
    f->log_micro = false;
    ks_nform_set(&f->name, "");
    ks_nform_set(&f->version, "");
    f->auth_type = 0; /* AUTH_SIMPLE */
    ks_nform_set(&f->ca_cert, "");
    ks_nform_set(&f->server_cert, "");
    ks_nform_set(&f->client_cert, "");
    ks_nform_set(&f->client_key, "");
    f->skip_verify = false;
    f->verify_type = 0;
    /* _cb_combo_node_auth_type_changed(0) */
    f->ca_enabled = false;
    f->certs_enabled = false;
    f->needs_update = true;
}

void ks_nform_init(struct ks_nform *f)
{
    memset(f, 0, sizeof(*f));
    /* the widgets as the .ui builds them */
    ks_nform_set(&f->version, "");
    ks_nform_set(&f->name, "");
    ks_nform_set(&f->address, "unix:///tmp/osui.sock"); /* the only item of the combo */
    ks_nform_set(&f->log_file, "/var/log/opensnitchd.log");
    ks_nform_set(&f->ca_cert, "");
    ks_nform_set(&f->server_cert, "");
    ks_nform_set(&f->client_cert, "");
    ks_nform_set(&f->client_key, "");
    ks_nform_set(&f->rules_path, "");
    ks_nform_set(&f->fw_interval, "");
    ks_nform_set(&f->max_events, "250");
    ks_nform_set(&f->max_stats, "50");
    f->gc = 100;
    f->log_utc = false;
    f->server_enabled = true;
    f->ca_enabled = true;
    f->certs_enabled = true;
}

void ks_nform_free(struct ks_nform *f)
{
    g_free(f->version);
    g_free(f->name);
    g_free(f->address);
    g_free(f->log_file);
    g_free(f->ca_cert);
    g_free(f->server_cert);
    g_free(f->client_cert);
    g_free(f->client_key);
    g_free(f->rules_path);
    g_free(f->fw_interval);
    g_free(f->max_events);
    g_free(f->max_stats);
    memset(f, 0, sizeof(*f));
}

int ks_node_auth_index(const char *type)
{
    for (int i = 0; i < 3; i++) {
        if (strcmp(ks_node_auth_types[i], type) == 0)
            return i;
    }
    return -1;
}

int ks_node_verify_index(const char *type)
{
    for (int i = 0; i < 5; i++) {
        if (strcmp(ks_node_verify_types[i], type) == 0)
            return i;
    }
    return -1;
}

/* ---- Python's dict and number behaviour ------------------------------------------------ */

static cJSON *get(const cJSON *o, const char *k)
{
    return cJSON_IsObject(o) ? cJSON_GetObjectItemCaseSensitive(o, k) : NULL;
}

/* `d.get(k) == None`: missing or null */
static bool none(const cJSON *v)
{
    return v == NULL || cJSON_IsNull(v);
}

/* the object under `k`, made (replacing a null) if there's none */
static cJSON *sub(cJSON *o, const char *k)
{
    cJSON *v = get(o, k);
    if (none(v) || !cJSON_IsObject(v)) {
        cJSON *n = cJSON_CreateObject();
        if (v != NULL)
            cJSON_ReplaceItemInObjectCaseSensitive(o, k, n);
        else
            cJSON_AddItemToObject(o, k, n);
        return n;
    }
    return v;
}

/* d[k] = value, keeping the position of an existing key */
static void put(cJSON *o, const char *k, cJSON *value)
{
    if (get(o, k) != NULL)
        cJSON_ReplaceItemInObjectCaseSensitive(o, k, value);
    else
        cJSON_AddItemToObject(o, k, value);
}

static void put_str(cJSON *o, const char *k, const char *s)
{
    put(o, k, cJSON_CreateString(s));
}

static void put_bool(cJSON *o, const char *k, bool b)
{
    put(o, k, cJSON_CreateBool(b));
}

static void put_num(cJSON *o, const char *k, double n)
{
    put(o, k, cJSON_CreateNumber(n));
}

/* bool(value) */
static bool truthy(const cJSON *v)
{
    if (cJSON_IsBool(v))
        return cJSON_IsTrue(v);
    if (cJSON_IsNumber(v))
        return v->valuedouble != 0;
    if (cJSON_IsString(v))
        return v->valuestring[0] != '\0';
    if (cJSON_IsArray(v) || cJSON_IsObject(v))
        return v->child != NULL;
    return false;
}

/* int(text) of Python: spaces around, a sign, digits */
static bool py_int_text(const char *s, long *out)
{
    char *t = g_strstrip(g_strdup(s));
    char *p = t;
    if (*p == '+' || *p == '-')
        p++;
    bool ok = *p != '\0';
    GString *digits = g_string_new(*t == '-' ? "-" : "");
    bool prev_digit = false;
    for (char *q = p; *q && ok; q++) {
        if (*q >= '0' && *q <= '9') {
            g_string_append_c(digits, *q);
            prev_digit = true;
        } else if (*q == '_' && prev_digit && q[1] >= '0' && q[1] <= '9') {
            prev_digit = false; /* "1_0": one underscore between digits */
        } else {
            ok = false;
        }
    }
    if (ok)
        *out = strtol(digits->str, NULL, 10);
    g_string_free(digits, TRUE);
    g_free(t);
    return ok;
}

/* str(value) for what the settings hold */
static char *py_str(const cJSON *v)
{
    if (cJSON_IsString(v))
        return g_strdup(v->valuestring);
    if (cJSON_IsBool(v))
        return g_strdup(cJSON_IsTrue(v) ? "True" : "False");
    char *s = ks_pyjson_dumps(v);
    char *r = g_strdup(s != NULL ? s : "");
    free(s);
    return r;
}

static void key_error(char *err, size_t n, const char *key)
{
    snprintf(err, n, "'%s'", key);
}

/* setCurrentText() on a combo with fixed items: the index, or unchanged */
static void set_current_text(int *idx, const char *const *items, int n, const cJSON *v)
{
    if (!cJSON_IsString(v))
        return;
    for (int i = 0; i < n; i++) {
        if (strcmp(items[i], v->valuestring) == 0)
            *idx = i;
    }
}

/* ---- loading ----------------------------------------------------------------------------- */

/* _load_node_auth_settings(): `server` is node_config['Server'] */
static void load_auth(struct ks_nform *f, cJSON *server, char *err, size_t errlen)
{
    cJSON *auth = get(server, "Authentication");
    int idx = 0;
    if (!none(auth)) {
        const cJSON *t = get(auth, "Type");
        if (!none(t))
            idx = cJSON_IsString(t) ? ks_node_auth_index(t->valuestring) : -1;
    } else {
        auth = sub(server, "Authentication");
    }
    const cJSON *tls = get(auth, "TLSOptions");
    if (!none(tls) && idx >= 0) {
        const cJSON *v;
        if (!none(v = get(tls, "CACert")))
            ks_nform_set(&f->ca_cert, cJSON_IsString(v) ? v->valuestring : "");
        if (!none(v = get(tls, "ServerCert")))
            ks_nform_set(&f->server_cert, cJSON_IsString(v) ? v->valuestring : "");
        if (!none(v = get(tls, "ClientCert")))
            ks_nform_set(&f->client_cert, cJSON_IsString(v) ? v->valuestring : "");
        if (!none(v = get(tls, "ClientKey")))
            ks_nform_set(&f->client_key, cJSON_IsString(v) ? v->valuestring : "");
        if (!none(v = get(tls, "SkipVerify")))
            f->skip_verify = truthy(v);
        if (!none(v = get(tls, "ClientAuthType"))) {
            int c = cJSON_IsString(v) ? ks_node_verify_index(v->valuestring) : -1;
            if (c >= 0)
                f->verify_type = c;
        }
    }
    f->auth_type = idx;
    /* _cb_combo_node_auth_type_changed(idx): the fields' state, and the node needs an update */
    f->ca_enabled = idx == 2;     /* mutual TLS */
    f->certs_enabled = idx >= 1;  /* from "tls-simple" on */
    f->needs_update = true;
    (void)err;
    (void)errlen;
}

bool ks_prefs_load_node(struct ks_nform *f, const char *version, const char *name,
                        unsigned log_level, const char *config, char **normalized, char *err,
                        size_t errlen)
{
    *normalized = NULL;
    err[0] = '\0';
    ks_nform_set(&f->version, version);
    ks_nform_set(&f->name, name);
    f->log_level = log_level < 6 ? (int)log_level : -1;

    char jerr[160];
    cJSON *nc = ks_json_parse(config, strlen(config), jerr, sizeof(jerr));
    if (nc == NULL || !cJSON_IsObject(nc)) {
        snprintf(err, errlen, "%s", nc == NULL ? jerr : "not a JSON object");
        cJSON_Delete(nc);
        return false;
    }
    const cJSON *v;
    bool ok = false;
    do {
        if ((v = get(nc, "DefaultAction")) == NULL) {
            key_error(err, errlen, "DefaultAction");
            break;
        }
        if (!cJSON_IsString(v)) {
            snprintf(err, errlen, "%s", "TypeError");
            break;
        }
        set_current_text(&f->action, ks_node_actions, 3, v);
        if ((v = get(nc, "ProcMonitorMethod")) == NULL) {
            key_error(err, errlen, "ProcMonitorMethod");
            break;
        }
        if (!cJSON_IsString(v)) {
            snprintf(err, errlen, "%s", "TypeError");
            break;
        }
        set_current_text(&f->monitor, ks_node_monitors, 3, v);
        if ((v = get(nc, "InterceptUnknown")) == NULL) {
            key_error(err, errlen, "InterceptUnknown");
            break;
        }
        f->intercept_unknown = truthy(v);
        if ((v = get(nc, "LogLevel")) == NULL) {
            key_error(err, errlen, "LogLevel");
            break;
        }
        long ll;
        if (cJSON_IsNumber(v)) {
            ll = (long)v->valuedouble;
        } else if (!cJSON_IsString(v)) {
            snprintf(err, errlen, "%s", "TypeError"); /* int(None), int([]), ... */
            break;
        } else if (!py_int_text(v->valuestring, &ll)) {
            snprintf(err, errlen, "%s", "ValueError");
            break;
        }
        f->log_level = ll >= 0 && ll < 6 ? (int)ll : -1;

        if (none(get(nc, "LogUTC")))
            put_bool(nc, "LogUTC", false);
        f->log_utc = truthy(get(nc, "LogUTC"));
        if (none(get(nc, "LogMicro")))
            put_bool(nc, "LogMicro", false);
        f->log_micro = truthy(get(nc, "LogMicro"));

        cJSON *server = get(nc, "Server");
        if (!none(server)) {
            f->server_enabled = true;
            const cJSON *a = get(server, "Address");
            if (a == NULL) {
                key_error(err, errlen, "Address");
                break;
            }
            if (!cJSON_IsString(a)) {
                snprintf(err, errlen, "%s", "TypeError");
                break;
            }
            ks_nform_set(&f->address, a->valuestring);
            const cJSON *lf = get(server, "LogFile");
            if (lf == NULL) {
                key_error(err, errlen, "LogFile");
                break;
            }
            if (!cJSON_IsString(lf)) {
                snprintf(err, errlen, "%s", "TypeError");
                break;
            }
            ks_nform_set(&f->log_file, lf->valuestring);
            load_auth(f, server, err, errlen);
        } else {
            f->server_enabled = false;
        }

        cJSON *rules = sub(nc, "Rules");
        if (none(get(rules, "EnableChecksums")))
            put_bool(rules, "EnableChecksums", false);
        const cJSON *path = get(rules, "Path");
        if (none(path) || (cJSON_IsString(path) && path->valuestring[0] == '\0'))
            put_str(rules, "Path", KS_DEFAULT_RULES_PATH);
        f->checksums = truthy(get(rules, "EnableChecksums"));
        ks_nform_set(&f->rules_path, cJSON_IsString(get(rules, "Path")) ? get(rules, "Path")->valuestring : "");

        cJSON *internal = sub(nc, "Internal");
        if (none(get(internal, "FlushConnsOnStart")))
            put_bool(internal, "FlushConnsOnStart", false);
        if (none(get(internal, "GCPercent")))
            put_num(internal, "GCPercent", 100);
        f->flush_conns = truthy(get(internal, "FlushConnsOnStart"));
        f->gc = (int)get(internal, "GCPercent")->valuedouble;

        cJSON *fw = sub(nc, "FwOptions");
        const cJSON *mi = get(fw, "MonitorInterval");
        if (none(mi) || (cJSON_IsString(mi) && mi->valuestring[0] == '\0'))
            put_str(fw, "MonitorInterval", "15s");
        if (none(get(fw, "QueueBypass")))
            put_bool(fw, "QueueBypass", true);
        mi = get(fw, "MonitorInterval");
        if (!cJSON_IsString(mi)) {
            snprintf(err, errlen, "%s", "object is not subscriptable");
            break;
        }
        /* MonitorInterval[:-1] */
        char *iv = g_strdup(mi->valuestring);
        size_t l = g_utf8_strlen(iv, -1);
        if (l > 0)
            *g_utf8_offset_to_pointer(iv, (glong)l - 1) = '\0';
        ks_nform_set(&f->fw_interval, iv);
        g_free(iv);
        f->block_on_fail = !truthy(get(fw, "QueueBypass"));

        cJSON *stats = sub(nc, "Stats");
        if (none(get(stats, "MaxEvents")))
            put_num(stats, "MaxEvents", 250);
        if (none(get(stats, "MaxStats")))
            put_num(stats, "MaxStats", 50);
        char *me = py_str(get(stats, "MaxEvents")), *ms = py_str(get(stats, "MaxStats"));
        ks_nform_set(&f->max_events, me);
        ks_nform_set(&f->max_stats, ms);
        g_free(me);
        g_free(ms);
        ok = true;
    } while (0);
    if (ok)
        *normalized = ks_pyjson_dumps_indent(nc, 4);
    cJSON_Delete(nc);
    return ok && *normalized != NULL;
}

/* ---- building ---------------------------------------------------------------------------- */

/* _save_node_auth_config(): objects the configuration already has are changed in place (and stay
 * changed if a later step fails); new ones only join it at the end */
static bool save_auth(const struct ks_nform *f, cJSON *server, char *err, size_t errlen)
{
    cJSON *auth = get(server, "Authentication");
    bool auth_new = none(auth) || !cJSON_IsObject(auth);
    if (auth_new)
        auth = cJSON_CreateObject();
    bool ok = false;
    cJSON *tls = NULL;
    bool tls_new = false;
    do {
        if (f->auth_type < 0 || f->auth_type > 2) {
            key_error(err, errlen, "-1"); /* NODE_AUTH[-1] */
            break;
        }
        put_str(auth, "Type", ks_node_auth_types[f->auth_type]);
        tls = get(auth, "TLSOptions");
        tls_new = none(tls) || !cJSON_IsObject(tls);
        if (tls_new)
            tls = cJSON_CreateObject();
        put_str(tls, "CACert", f->ca_cert);
        put_str(tls, "ServerCert", f->server_cert);
        put_str(tls, "ClientCert", f->client_cert);
        put_str(tls, "ClientKey", f->client_key);
        put_bool(tls, "SkipVerify", f->skip_verify);
        if (f->verify_type < 0 || f->verify_type > 4) {
            key_error(err, errlen, "-1");
            break;
        }
        put_str(tls, "ClientAuthType", ks_node_verify_types[f->verify_type]);
        ok = true;
    } while (0);
    if (ok && tls_new)
        put(auth, "TLSOptions", tls);
    else if (tls_new)
        cJSON_Delete(tls);
    if (ok && auth_new)
        put(server, "Authentication", auth);
    else if (auth_new)
        cJSON_Delete(auth);
    return ok;
}

bool ks_prefs_build_node(struct ks_nform *f, const char *addr, const char *config, char **out,
                         char *err, size_t errlen)
{
    *out = NULL;
    err[0] = '\0';
    if (f->address[0] == '\0') {
        snprintf(err, errlen, "%s", "Server address can not be empty");
        return false;
    }
    if (config == NULL) {
        snprintf(err, errlen, "%s", " "); /* no configuration for the node */
        return false;
    }
    char jerr[160];
    cJSON *nc = ks_json_parse(config, strlen(config), jerr, sizeof(jerr));
    if (!cJSON_IsObject(nc)) {
        snprintf(err, errlen, "Error loading %s configuration", addr);
        cJSON_Delete(nc);
        return false;
    }
    bool ok = false;
    do {
        const char *action = f->action == 1 ? "allow" : f->action == 2 ? "reject" : "deny";
        put_str(nc, "DefaultAction", action);
        put_str(nc, "DefaultDuration", "once");
        put_str(nc, "ProcMonitorMethod",
                f->monitor >= 0 && f->monitor < 3 ? ks_node_monitors[f->monitor] : "");
        put_num(nc, "LogLevel", f->log_level);
        put_bool(nc, "LogUTC", f->log_utc);
        put_bool(nc, "LogMicro", f->log_micro);
        put_bool(nc, "InterceptUnknown", f->intercept_unknown);

        cJSON *server = get(nc, "Server");
        if (!none(server)) {
            put_str(server, "Address", f->address);
            put_str(server, "LogFile", f->log_file);
            if (!save_auth(f, server, err, errlen)) {
                /* upstream shows the error but goes on without the auth part */
                err[0] = '\0';
            }
        }

        cJSON *rules = sub(nc, "Rules");
        if (none(get(rules, "EnableChecksums"))) {
            put_bool(rules, "EnableChecksums", false);
            f->checksums = false;
        }
        const cJSON *path = get(rules, "Path");
        if (none(path) || (cJSON_IsString(path) && path->valuestring[0] == '\0')) {
            put_str(rules, "Path", KS_DEFAULT_RULES_PATH);
            ks_nform_set(&f->rules_path, KS_DEFAULT_RULES_PATH);
        }
        put_bool(rules, "EnableChecksums", f->checksums);
        put_str(rules, "Path", f->rules_path);

        cJSON *internal = sub(nc, "Internal");
        if (none(get(internal, "FlushConnsOnStart"))) {
            put_bool(internal, "FlushConnsOnStart", false);
            f->flush_conns = false;
        }
        if (none(get(internal, "GCPercent"))) {
            put_num(internal, "GCPercent", 100);
            f->gc = 100;
        }
        put_bool(internal, "FlushConnsOnStart", f->flush_conns);
        put_num(internal, "GCPercent", f->gc);

        cJSON *fw = sub(nc, "FwOptions");
        if (none(get(fw, "MonitorInterval")))
            put_str(fw, "MonitorInterval", "15s");
        if (none(get(fw, "QueueBypass")))
            put_bool(fw, "QueueBypass", true);
        put_bool(fw, "QueueBypass", !f->block_on_fail);
        char *mi = g_strdup_printf("%ss", f->fw_interval);
        put_str(fw, "MonitorInterval", mi);
        g_free(mi);

        cJSON *stats = sub(nc, "Stats");
        if (none(get(stats, "MaxEvents"))) {
            put_num(stats, "MaxEvents", 250);
            ks_nform_set(&f->max_events, "250");
        }
        if (none(get(stats, "MaxStats"))) {
            put_num(stats, "MaxStats", 50);
            ks_nform_set(&f->max_stats, "50");
        }
        long me, ms;
        if (!py_int_text(f->max_events, &me)) {
            snprintf(err, errlen, "Error loading %s configuration", addr);
            break;
        }
        put_num(stats, "MaxEvents", (double)me);
        if (!py_int_text(f->max_stats, &ms)) {
            snprintf(err, errlen, "Error loading %s configuration", addr);
            break;
        }
        put_num(stats, "MaxStats", (double)ms);
        ok = true;
    } while (0);
    if (ok)
        *out = ks_pyjson_dumps_indent(nc, 4);
    cJSON_Delete(nc);
    return ok && *out != NULL;
}
