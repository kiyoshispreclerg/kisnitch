/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See rulesops.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/rulesops.h"

#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "common/arena.h"
#include "common/json_util.h"
#include "common/log.h"
#include "ui/pyjson.h"
#include "ui/slug.h"

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

/* A notification with one rule, sent to `node`. */
static uint64_t send_rule(struct ks_nodes *nodes, const char *node, Protocol__Action type,
                          Protocol__Rule *rule, ks_ntf_reply_cb cb, void *ud)
{
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    Protocol__Rule *rules[1] = {rule};
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.data = (char *)(uintptr_t) "";
    n.type = type;
    n.rules = rules;
    n.n_rules = 1;
    return ks_nodes_send(nodes, node, &n, cb, ud);
}

bool ks_rops_change_field(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                          const char *name, enum ks_rule_field field, const char *value,
                          ks_ntf_reply_cb cb, void *ud)
{
    if (field != KS_RF_ACTION && field != KS_RF_DURATION)
        return false;
    const struct ks_ui_rule *row = ks_rulesdb_get(rules, name, node);
    if (row == NULL)
        return false;
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    bool ok = r != NULL;
    if (ok) {
        ks_rulesdb_set_field(rules, node, name, field, value);
        if (field == KS_RF_ACTION)
            r->action = ks_arena_strdup(&a, value);
        else
            r->duration = ks_arena_strdup(&a, value);
        send_rule(nodes, node, PROTOCOL__ACTION__CHANGE_RULE, r, cb, ud);
    }
    ks_arena_free(&a);
    return ok;
}

bool ks_rops_enable(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                    const char *name, const char *enabled, ks_ntf_reply_cb cb, void *ud)
{
    bool was = strcmp(nz(enabled), "True") == 0;
    const struct ks_ui_rule *row = ks_rulesdb_get(rules, name, node);
    if (row == NULL)
        return false;
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    bool ok = r != NULL;
    if (ok) {
        ks_rulesdb_set_field(rules, node, name, KS_RF_ENABLED, was ? "False" : "True");
        send_rule(nodes, node, was ? PROTOCOL__ACTION__DISABLE_RULE : PROTOCOL__ACTION__ENABLE_RULE,
                  r, cb, ud);
    }
    ks_arena_free(&a);
    return ok;
}

bool ks_rops_duplicate(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                       const char *name, ks_ntf_reply_cb cb, void *ud)
{
    const struct ks_ui_rule *row = ks_rulesdb_get(rules, name, node);
    if (row == NULL)
        return false;
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    if (r == NULL) {
        ks_arena_free(&a);
        return false;
    }
    /* temp_name = temp_name.split("-duplicated-")[0] + "-duplicated-N" */
    char *temp = g_strdup(name);
    for (int idx = 0; idx < 100; idx++) {
        char *cut = strstr(temp, "-duplicated-");
        if (cut != NULL)
            *cut = '\0';
        char *nn = g_strdup_printf("%s-duplicated-%d", temp, idx);
        g_free(temp);
        temp = nn;
        if (ks_rulesdb_get(rules, temp, node) == NULL) {
            r->name = ks_arena_strdup(&a, temp);
            Protocol__Rule *one[1] = {r};
            ks_rulesdb_add_pb(rules, node, one, 1);
            break;
        }
    }
    g_free(temp);
    /* upstream sends it whether it was added or not (QSqlQuery.size() is
     * always -1 on SQLite) */
    send_rule(nodes, node, PROTOCOL__ACTION__CHANGE_RULE, r, cb, ud);
    ks_arena_free(&a);
    return true;
}

bool ks_rops_apply_to_node(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *name,
                           const char *target, ks_ntf_reply_cb cb, void *ud)
{
    const struct ks_ui_rule *row = ks_rulesdb_get(rules, name, NULL);
    if (row == NULL)
        return false;
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    bool ok = r != NULL;
    if (ok) {
        send_rule(nodes, target, PROTOCOL__ACTION__CHANGE_RULE, r, cb, ud);
        Protocol__Rule *one[1] = {r};
        ks_rulesdb_add_pb(rules, target, one, 1);
    }
    ks_arena_free(&a);
    return ok;
}

bool ks_rops_delete(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *name,
                    const char *node, ks_ntf_reply_cb cb, void *ud)
{
    if (name == NULL)
        return false;
    /* a NULL node: the rule of that name on every node (Nodes.delete_rule(addr=None)) */
    ks_rulesdb_delete(rules, name, node);
    Protocol__Rule r = PROTOCOL__RULE__INIT;
    Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
    r.name = (char *)(uintptr_t)name;
    r.action = (char *)(uintptr_t) "";
    r.duration = (char *)(uintptr_t) "";
    r.operator_ = &op;
    op.type = (char *)(uintptr_t) "";
    op.operand = (char *)(uintptr_t) "";
    op.data = (char *)(uintptr_t) "";
    if (node != NULL) {
        send_rule(nodes, node, PROTOCOL__ACTION__DELETE_RULE, &r, cb, ud);
    } else {
        Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
        Protocol__Rule *rules_arr[1] = {&r};
        n.clientname = (char *)(uintptr_t) "";
        n.servername = (char *)(uintptr_t) "";
        n.data = (char *)(uintptr_t) "";
        n.type = PROTOCOL__ACTION__DELETE_RULE;
        n.rules = rules_arr;
        n.n_rules = 1;
        ks_nodes_send_all(nodes, &n, cb, ud);
    }
    return true;
}

/* ---- JSON ---------------------------------------------------------------- */

static void add_str(cJSON *o, const char *k, const char *v)
{
    if (v != NULL && v[0] != '\0')
        cJSON_AddStringToObject(o, k, v);
}

/* MessageToJson of an Operator: what is not at its default, in field order */
static cJSON *op_json(const Protocol__Operator *op)
{
    cJSON *o = cJSON_CreateObject();
    if (o == NULL)
        return NULL;
    add_str(o, "type", op->type);
    add_str(o, "operand", op->operand);
    add_str(o, "data", op->data);
    if (op->sensitive)
        cJSON_AddTrueToObject(o, "sensitive");
    if (op->n_list > 0) {
        cJSON *l = cJSON_AddArrayToObject(o, "list");
        for (size_t i = 0; l != NULL && i < op->n_list; i++)
            cJSON_AddItemToArray(l, op_json(op->list[i]));
    }
    return o;
}

/* _timestamp_to_rfc3339() */
static char *rfc3339(int64_t t)
{
    time_t tt = (time_t)t;
    struct tm tm;
    char buf[64] = "";
    if (localtime_r(&tt, &tm) != NULL)
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return g_strdup_printf("%s.000000Z", buf);
}

static char *rule_json(const Protocol__Rule *r)
{
    cJSON *j = cJSON_CreateObject();
    if (j == NULL)
        return NULL;
    char *created = rfc3339(r->created);
    cJSON_AddStringToObject(j, "created", created);
    g_free(created);
    add_str(j, "name", r->name);
    add_str(j, "description", r->description);
    if (r->enabled)
        cJSON_AddTrueToObject(j, "enabled");
    if (r->precedence)
        cJSON_AddTrueToObject(j, "precedence");
    if (r->nolog)
        cJSON_AddTrueToObject(j, "nolog");
    add_str(j, "action", r->action);
    add_str(j, "duration", r->duration);
    if (r->operator_ != NULL)
        cJSON_AddItemToObject(j, "operator", op_json(r->operator_));
    char *s = ks_pyjson_dumps_indent(j, 4);
    cJSON_Delete(j);
    return s;
}

char *ks_rops_rule_json(const struct ks_rulesdb *rules, const char *node, const char *name)
{
    const struct ks_ui_rule *row = ks_rulesdb_get(rules, name, node);
    if (row == NULL)
        return NULL;
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    char *s = r != NULL ? rule_json(r) : NULL;
    ks_arena_free(&a);
    return s;
}

bool ks_rops_export(const struct ks_rulesdb *rules, const char *node, const char *name,
                    const char *outdir)
{
    char *json = ks_rops_rule_json(rules, node, name);
    if (json == NULL)
        return false;
    char *slug = ks_slugify(node);
    char *dir = g_strdup_printf("%s/%s", outdir, slug != NULL ? slug : "");
    free(slug);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        ks_warning("exception creating dirs: %s", strerror(errno));
    char *file = g_strdup_printf("%s/%s%s", dir, name, strstr(name, ".json") ? "" : ".json");
    FILE *f = fopen(file, "w");
    bool ok = f != NULL && fputs(json, f) >= 0;
    if (f != NULL && fclose(f) != 0)
        ok = false;
    if (!ok)
        ks_warning("export_rule(%s, %s) failed: %s", node, name, strerror(errno));
    g_free(file);
    g_free(dir);
    free(json);
    return ok;
}

bool ks_rops_export_all(const struct ks_rulesdb *rules, const char *node, const char *outdir)
{
    bool ok = true;
    for (size_t i = 0; i < rules->len; i++) {
        if (strcmp(rules->rows[i].f[KS_RF_NODE], nz(node)) != 0)
            continue;
        if (!ks_rops_export(rules, node, rules->rows[i].f[KS_RF_NAME], outdir))
            ok = false;
    }
    return ok;
}

/* ---- import --------------------------------------------------------------- */

static bool get_str(const cJSON *o, const char *k, struct ks_arena *a, char **out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (v == NULL || cJSON_IsNull(v))
        return true;
    if (!cJSON_IsString(v))
        return false;
    *out = ks_arena_strdup(a, v->valuestring);
    return *out != NULL;
}

static bool get_bool(const cJSON *o, const char *k, protobuf_c_boolean *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (v == NULL || cJSON_IsNull(v))
        return true;
    if (!cJSON_IsBool(v))
        return false;
    *out = cJSON_IsTrue(v);
    return true;
}

static bool parse_op(struct ks_arena *a, const cJSON *j, Protocol__Operator *op)
{
    if (!cJSON_IsObject(j))
        return false;
    if (!get_str(j, "type", a, &op->type) || !get_str(j, "operand", a, &op->operand) ||
        !get_str(j, "data", a, &op->data) || !get_bool(j, "sensitive", &op->sensitive))
        return false;
    const cJSON *l = cJSON_GetObjectItemCaseSensitive(j, "list");
    if (l != NULL && !cJSON_IsNull(l)) {
        if (!cJSON_IsArray(l))
            return false;
        size_t n = (size_t)cJSON_GetArraySize(l), k = 0;
        Protocol__Operator **items = ks_arena_calloc(a, n ? n : 1, sizeof(*items));
        if (items == NULL)
            return false;
        const cJSON *it;
        cJSON_ArrayForEach(it, l)
        {
            Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
            if (o == NULL)
                return false;
            protocol__operator__init(o);
            if (!parse_op(a, it, o))
                return false;
            items[k++] = o;
        }
        op->list = items;
        op->n_list = k;
    }
    return true;
}

/* "created": an int64 (number or digits in a string), or the RFC 3339 form
 * the export writes ("%Y-%m-%dT%H:%M:%S.%fZ", local time). */
static bool parse_created(const cJSON *v, int64_t *out)
{
    if (v == NULL || cJSON_IsNull(v))
        return true;
    if (cJSON_IsNumber(v)) {
        *out = (int64_t)v->valuedouble;
        return true;
    }
    if (!cJSON_IsString(v))
        return false;
    const char *s = v->valuestring;
    char *end;
    errno = 0;
    long long n = strtoll(s, &end, 10);
    if (end != s && *end == '\0' && errno == 0) {
        *out = n;
        return true;
    }
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    int pos = 0, digits = 0;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d.%n", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
               &tm.tm_min, &tm.tm_sec, &pos) < 6 || pos == 0)
        return false;
    while (s[pos + digits] >= '0' && s[pos + digits] <= '9')
        digits++;
    if (digits < 1 || digits > 6 || strcmp(s + pos + digits, "Z") != 0)
        return false;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    *out = (int64_t)mktime(&tm);
    return true;
}

static Protocol__Rule *parse_rule(struct ks_arena *a, const char *text, size_t len)
{
    char err[128];
    cJSON *j = ks_json_parse(text, len, err, sizeof(err));
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        return NULL;
    }
    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    bool ok = r != NULL;
    if (ok) {
        protocol__rule__init(r);
        ok = get_str(j, "name", a, &r->name) && get_str(j, "description", a, &r->description) &&
             get_bool(j, "enabled", &r->enabled) && get_bool(j, "precedence", &r->precedence) &&
             get_bool(j, "nolog", &r->nolog) && get_str(j, "action", a, &r->action) &&
             get_str(j, "duration", a, &r->duration) &&
             parse_created(cJSON_GetObjectItemCaseSensitive(j, "created"), &r->created);
    }
    const cJSON *op = ok ? cJSON_GetObjectItemCaseSensitive(j, "operator") : NULL;
    if (ok && op != NULL && !cJSON_IsNull(op)) {
        Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
        if (o == NULL) {
            ok = false;
        } else {
            protocol__operator__init(o);
            ok = parse_op(a, op, o);
            r->operator_ = o;
        }
    }
    cJSON_Delete(j);
    return ok ? r : NULL;
}

bool ks_rops_import_parse(struct ks_arena *a, const char *dir, Protocol__Rule ***out, size_t *n)
{
    *out = NULL;
    *n = 0;
    GDir *d = g_dir_open(dir, 0, NULL);
    if (d == NULL)
        return false;
    GPtrArray *list = g_ptr_array_new();
    bool ok = true;
    const char *name;
    while (ok && (name = g_dir_read_name(d)) != NULL) {
        char *path = g_build_filename(dir, name, NULL);
        gchar *text = NULL;
        gsize len = 0;
        if (!g_file_get_contents(path, &text, &len, NULL)) {
            ok = false;
        } else {
            Protocol__Rule *r = parse_rule(a, text, len);
            if (r == NULL)
                ok = false;
            else
                g_ptr_array_add(list, r);
        }
        g_free(text);
        g_free(path);
    }
    g_dir_close(d);
    if (ok) {
        Protocol__Rule **arr = ks_arena_calloc(a, list->len ? list->len : 1, sizeof(*arr));
        if (arr == NULL) {
            ok = false;
        } else {
            for (guint i = 0; i < list->len; i++)
                arr[i] = g_ptr_array_index(list, i);
            *out = arr;
            *n = list->len;
        }
    }
    g_ptr_array_free(list, TRUE);
    return ok;
}

int ks_rops_import(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                   const char *dir, ks_ntf_reply_cb cb, void *ud)
{
    struct ks_arena a = {0};
    Protocol__Rule **list;
    size_t n;
    if (!ks_rops_import_parse(&a, dir, &list, &n)) {
        ks_arena_free(&a);
        return -1;
    }
    Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
    ntf.clientname = (char *)(uintptr_t) "";
    ntf.servername = (char *)(uintptr_t) "";
    ntf.data = (char *)(uintptr_t) "";
    ntf.type = PROTOCOL__ACTION__CHANGE_RULE;
    ntf.rules = list;
    ntf.n_rules = n;
    if (node != NULL)
        ks_nodes_send(nodes, node, &ntf, cb, ud);
    else
        ks_nodes_send_all(nodes, &ntf, cb, ud);
    /* "TODO: add rules per node and after receiving the notification" */
    for (size_t i = 0; i < nodes->len; i++)
        ks_rulesdb_add_pb(rules, nodes->items[i]->addr, list, n);
    ks_arena_free(&a);
    return (int)n;
}
