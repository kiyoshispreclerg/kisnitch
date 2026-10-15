/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the rules part of upstream ui/opensnitch/rules.py and
 * ui/opensnitch/database/__init__.py, in memory.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/rulesdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/json_util.h"
#include "common/log.h"
#include "ui/pyjson.h"

const char *const ks_rules_temporary_list[8] = {"once", "30s", "5m",  "15m",
                                                "30m",  "1h",  "12h", "until restart"};

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

void ks_rulesdb_init(struct ks_rulesdb *db)
{
    memset(db, 0, sizeof(*db));
}

static void free_row(struct ks_ui_rule *r)
{
    for (int i = 0; i < KS_RF_COUNT; i++)
        free(r->f[i]);
}

void ks_rulesdb_free(struct ks_rulesdb *db)
{
    for (size_t i = 0; i < db->len; i++)
        free_row(&db->rows[i]);
    free(db->rows);
    for (size_t i = 0; i < db->ndur_filter; i++)
        free(db->dur_filter[i]);
    memset(db, 0, sizeof(*db));
}

void ks_rulesdb_set_duration_filter(struct ks_rulesdb *db, bool ignore, int temp_rules)
{
    for (size_t i = 0; i < db->ndur_filter; i++)
        free(db->dur_filter[i]);
    db->ndur_filter = 0;
    if (!ignore)
        return;
    /* [rule for rule in RULES_TEMPORARY_LIST if index(rule) < temp_rules] */
    for (int i = 0; i < 8 && i < temp_rules; i++) {
        char *d = strdup(ks_rules_temporary_list[i]);
        if (d != NULL)
            db->dur_filter[db->ndur_filter++] = d;
    }
}

bool ks_rulesdb_duration_filtered(const struct ks_rulesdb *db, const char *duration)
{
    for (size_t i = 0; i < db->ndur_filter; i++) {
        if (strcmp(db->dur_filter[i], nz(duration)) == 0)
            return true;
    }
    return false;
}

static void remove_at(struct ks_rulesdb *db, size_t i)
{
    free_row(&db->rows[i]);
    memmove(&db->rows[i], &db->rows[i + 1], (db->len - i - 1) * sizeof(db->rows[0]));
    db->len--;
}

static void sql_run(struct ks_rulesdb *db, const char *sql, const char *const *args,
                    int nargs)
{
    ks_db_run(db->sql, sql, args, nargs, NULL);
}

static void sql_write_row(struct ks_rulesdb *db, char *const f[KS_RF_COUNT])
{
    if (db->sql == NULL)
        return;
    /* Database.insert(..., "REPLACE"); columns by name, as upstream */
    sql_run(db,
            "INSERT OR REPLACE INTO rules (time, node, name, enabled, precedence, action, "
            "duration, operator_type, operator_sensitive, operator_operand, operator_data, "
            "description, nolog, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (const char *const *)f, KS_RF_COUNT);
}

bool ks_rulesdb_attach(struct ks_rulesdb *db, struct ks_db *sql)
{
    sqlite3_stmt *st;
    sqlite3 *h = ks_db_handle(sql);
    /* NULL (columns added by a migration on old rows) reads as "" */
    if (sqlite3_prepare_v2(h,
                           "SELECT time, node, name, enabled, precedence, action, duration, "
                           "operator_type, operator_sensitive, operator_operand, "
                           "operator_data, description, nolog, created FROM rules "
                           "ORDER BY rowid",
                           -1, &st, NULL) != SQLITE_OK) {
        ks_error("rulesdb: %s", sqlite3_errmsg(h));
        return false;
    }
    struct ks_rulesdb tmp;
    ks_rulesdb_init(&tmp);
    bool ok = true;
    while (ok && sqlite3_step(st) == SQLITE_ROW) {
        const char *v[KS_RF_COUNT];
        for (int i = 0; i < KS_RF_COUNT; i++)
            v[i] = (const char *)sqlite3_column_text(st, i);
        if (tmp.len == tmp.cap) {
            size_t ncap = tmp.cap ? tmp.cap * 2 : 64;
            struct ks_ui_rule *nr = realloc(tmp.rows, ncap * sizeof(*nr));
            if (nr == NULL) {
                ok = false;
                break;
            }
            tmp.rows = nr;
            tmp.cap = ncap;
        }
        struct ks_ui_rule *row = &tmp.rows[tmp.len];
        for (int i = 0; i < KS_RF_COUNT; i++) {
            row->f[i] = strdup(nz(v[i]));
            if (row->f[i] == NULL) {
                for (int j = 0; j < i; j++)
                    free(row->f[j]);
                ok = false;
                break;
            }
        }
        if (ok)
            tmp.len++;
    }
    sqlite3_finalize(st);
    if (!ok) {
        ks_rulesdb_free(&tmp);
        return false;
    }
    for (size_t i = 0; i < db->len; i++)
        free_row(&db->rows[i]);
    free(db->rows);
    db->rows = tmp.rows;
    db->len = tmp.len;
    db->cap = tmp.cap;
    db->sql = sql;
    return true;
}

int ks_rulesdb_add_row(struct ks_rulesdb *db, const char *const v[KS_RF_COUNT])
{
    if (ks_rulesdb_duration_filtered(db, v[KS_RF_DURATION]))
        return 0;
    struct ks_ui_rule row;
    for (int i = 0; i < KS_RF_COUNT; i++) {
        row.f[i] = strdup(nz(v[i]));
        if (row.f[i] == NULL) {
            for (int j = 0; j < i; j++)
                free(row.f[j]);
            return -1;
        }
    }
    /* OR REPLACE: the conflicting row goes, the new one is appended */
    for (size_t i = 0; i < db->len; i++) {
        if (strcmp(db->rows[i].f[KS_RF_NODE], row.f[KS_RF_NODE]) == 0 &&
            strcmp(db->rows[i].f[KS_RF_NAME], row.f[KS_RF_NAME]) == 0) {
            remove_at(db, i);
            break;
        }
    }
    if (db->len == db->cap) {
        size_t ncap = db->cap ? db->cap * 2 : 64;
        struct ks_ui_rule *nr = realloc(db->rows, ncap * sizeof(*nr));
        if (nr == NULL) {
            free_row(&row);
            return -1;
        }
        db->rows = nr;
        db->cap = ncap;
    }
    db->rows[db->len++] = row;
    sql_write_row(db, row.f);
    return 0;
}

void ks_db_date(int64_t t, char *buf, size_t len)
{
    time_t tt = (time_t)t;
    struct tm tm;
    if (localtime_r(&tt, &tm) == NULL || strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm) == 0)
        snprintf(buf, len, "%s", "");
}

static void list_json(struct ks_pybuf *b, Protocol__Operator *const *list, size_t n)
{
    ks_pybuf_adds(b, "[");
    for (size_t i = 0; i < n; i++) {
        const Protocol__Operator *o = list[i];
        /* MessageToJson: only fields that aren't at their default, in the
         * order of the .proto */
        const char *sep = "";
        ks_pybuf_adds(b, "{");
        if (o->type != NULL && o->type[0] != '\0') {
            ks_pybuf_adds(b, "\"type\": ");
            ks_pybuf_add_json_str(b, o->type);
            sep = ", ";
        }
        if (o->operand != NULL && o->operand[0] != '\0') {
            ks_pybuf_adds(b, sep);
            ks_pybuf_adds(b, "\"operand\": ");
            ks_pybuf_add_json_str(b, o->operand);
            sep = ", ";
        }
        if (o->data != NULL && o->data[0] != '\0') {
            ks_pybuf_adds(b, sep);
            ks_pybuf_adds(b, "\"data\": ");
            ks_pybuf_add_json_str(b, o->data);
            sep = ", ";
        }
        if (o->sensitive) {
            ks_pybuf_adds(b, sep);
            ks_pybuf_adds(b, "\"sensitive\": true");
            sep = ", ";
        }
        if (o->n_list > 0) {
            ks_pybuf_adds(b, sep);
            ks_pybuf_adds(b, "\"list\": ");
            list_json(b, o->list, o->n_list);
        }
        ks_pybuf_adds(b, "}");
        if (i + 1 < n)
            ks_pybuf_adds(b, ", ");
    }
    ks_pybuf_adds(b, "]");
}

char *ks_rulesdb_list_json(Protocol__Operator *const *list, size_t n)
{
    struct ks_pybuf b = {0};
    list_json(&b, list, n);
    return ks_pybuf_finish(&b);
}

static const char *pybool(protobuf_c_boolean b)
{
    return b ? "True" : "False";
}

int ks_rulesdb_add_pb(struct ks_rulesdb *db, const char *node, Protocol__Rule *const *rules,
                      size_t n)
{
    char now[32];
    ks_db_date((int64_t)time(NULL), now, sizeof(now));
    int rc = 0;
    for (size_t i = 0; i < n; i++) {
        const Protocol__Rule *r = rules[i];
        const Protocol__Operator *op = r->operator_;
        char created[32];
        ks_db_date(r->created, created, sizeof(created));
        char *list = NULL;
        if (op != NULL && strcmp(nz(op->type), "list") == 0 && op->n_list > 0) {
            list = ks_rulesdb_list_json(op->list, op->n_list);
            if (list == NULL)
                return -1;
        }
        const char *v[KS_RF_COUNT] = {
            [KS_RF_TIME] = now,
            [KS_RF_NODE] = node,
            [KS_RF_NAME] = r->name,
            [KS_RF_ENABLED] = pybool(r->enabled),
            [KS_RF_PRECEDENCE] = pybool(r->precedence),
            [KS_RF_ACTION] = r->action,
            [KS_RF_DURATION] = r->duration,
            [KS_RF_OP_TYPE] = op ? op->type : "",
            [KS_RF_OP_SENSITIVE] = pybool(op ? op->sensitive : 0),
            [KS_RF_OP_OPERAND] = op ? op->operand : "",
            [KS_RF_OP_DATA] = list ? list : (op ? op->data : ""),
            [KS_RF_DESCRIPTION] = r->description,
            [KS_RF_NOLOG] = pybool(r->nolog),
            [KS_RF_CREATED] = created,
        };
        if (ks_rulesdb_add_row(db, v) < 0)
            rc = -1;
        free(list);
    }
    return rc;
}

bool ks_rulesdb_exists(const struct ks_rulesdb *db, const char *node, const Protocol__Rule *r)
{
    const Protocol__Operator *op = r->operator_;
    for (size_t i = 0; i < db->len; i++) {
        char *const *f = db->rows[i].f;
        if (strcmp(f[KS_RF_NAME], nz(r->name)) == 0 && strcmp(f[KS_RF_NODE], nz(node)) == 0 &&
            strcmp(f[KS_RF_ACTION], nz(r->action)) == 0 &&
            strcmp(f[KS_RF_DURATION], nz(r->duration)) == 0 &&
            strcmp(f[KS_RF_OP_TYPE], op ? nz(op->type) : "") == 0 &&
            strcmp(f[KS_RF_OP_OPERAND], op ? nz(op->operand) : "") == 0 &&
            strcmp(f[KS_RF_OP_DATA], op ? nz(op->data) : "") == 0)
            return true;
    }
    return false;
}

const struct ks_ui_rule *ks_rulesdb_get(const struct ks_rulesdb *db, const char *name,
                                        const char *node)
{
    for (size_t i = 0; i < db->len; i++) {
        if (strcmp(db->rows[i].f[KS_RF_NAME], nz(name)) == 0 &&
            (node == NULL || strcmp(db->rows[i].f[KS_RF_NODE], node) == 0))
            return &db->rows[i];
    }
    return NULL;
}

char *ks_rulesdb_new_unique_name(const struct ks_rulesdb *db, const char *name,
                                 const char *node)
{
    if (ks_rulesdb_get(db, name, node) == NULL)
        return strdup(name);
    size_t n = strlen(name) + 8;
    char *buf = malloc(n);
    if (buf == NULL)
        return NULL;
    for (int idx = 0; idx < 100; idx++) {
        snprintf(buf, n, "%s-%d", name, idx);
        if (ks_rulesdb_get(db, buf, node) == NULL)
            return buf;
    }
    snprintf(buf, n, "%s", name);
    return buf;
}

static int ascii_lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* patternCompare() of sqlite, for LIKE without ESCAPE: "%" matches any
 * sequence, "_" one character (UTF-8 aware), ASCII letters match in any
 * case. */
bool ks_sql_like(const char *p, const char *s)
{
    while (*p) {
        if (*p == '%') {
            while (*p == '%' || *p == '_') {
                if (*p == '_') {
                    if (*s == '\0')
                        return false;
                    s++;
                    while ((*s & 0xC0) == 0x80)
                        s++;
                }
                p++;
            }
            if (*p == '\0')
                return true;
            for (; *s; s++) {
                if (ks_sql_like(p, s))
                    return true;
            }
            return false;
        }
        if (*s == '\0')
            return false;
        if (*p == '_') {
            p++;
            s++;
            while ((*s & 0xC0) == 0x80)
                s++;
            continue;
        }
        if (ascii_lower((unsigned char)*p) != ascii_lower((unsigned char)*s))
            return false;
        p++;
        s++;
    }
    return *s == '\0';
}

size_t ks_rulesdb_find_like(const struct ks_rulesdb *db, const char *node,
                            enum ks_rule_field field, const char *value, size_t *out,
                            size_t max)
{
    size_t vl = strlen(nz(value));
    char *pat = malloc(vl + 3);
    if (pat == NULL)
        return 0;
    snprintf(pat, vl + 3, "%%%s%%", nz(value));
    size_t n = 0;
    for (size_t i = 0; i < db->len && n < max; i++) {
        if (node != NULL && strcmp(db->rows[i].f[KS_RF_NODE], node) != 0)
            continue;
        if (ks_sql_like(pat, db->rows[i].f[field]))
            out[n++] = i;
    }
    free(pat);
    return n;
}

void ks_rulesdb_disable(struct ks_rulesdb *db, const char *node, const char *name)
{
    if (db->sql != NULL) {
        const char *a[2] = {name, node};
        sql_run(db, "UPDATE OR REPLACE rules SET enabled='False' WHERE name=? AND node=?", a, 2);
    }
    for (size_t i = 0; i < db->len; i++) {
        struct ks_ui_rule *r = &db->rows[i];
        if (strcmp(r->f[KS_RF_NAME], nz(name)) == 0 && strcmp(r->f[KS_RF_NODE], nz(node)) == 0) {
            char *f = strdup("False");
            if (f != NULL) {
                free(r->f[KS_RF_ENABLED]);
                r->f[KS_RF_ENABLED] = f;
            }
        }
    }
}

void ks_rulesdb_delete(struct ks_rulesdb *db, const char *name, const char *node)
{
    if (db->sql != NULL) {
        const char *a[2] = {name, node};
        sql_run(db, node != NULL ? "DELETE FROM rules WHERE name=? AND node=?"
                                 : "DELETE FROM rules WHERE name=?",
                a, node != NULL ? 2 : 1);
    }
    for (size_t i = db->len; i > 0; i--) {
        struct ks_ui_rule *r = &db->rows[i - 1];
        if (strcmp(r->f[KS_RF_NAME], nz(name)) == 0 &&
            (node == NULL || strcmp(r->f[KS_RF_NODE], node) == 0))
            remove_at(db, i - 1);
    }
}

static const char *const field_columns[KS_RF_COUNT] = {
    [KS_RF_TIME] = "time",
    [KS_RF_NODE] = "node",
    [KS_RF_NAME] = "name",
    [KS_RF_ENABLED] = "enabled",
    [KS_RF_PRECEDENCE] = "precedence",
    [KS_RF_ACTION] = "action",
    [KS_RF_DURATION] = "duration",
    [KS_RF_OP_TYPE] = "operator_type",
    [KS_RF_OP_SENSITIVE] = "operator_sensitive",
    [KS_RF_OP_OPERAND] = "operator_operand",
    [KS_RF_OP_DATA] = "operator_data",
    [KS_RF_DESCRIPTION] = "description",
    [KS_RF_NOLOG] = "nolog",
    [KS_RF_CREATED] = "created",
};

const char *ks_rule_field_column(enum ks_rule_field f)
{
    return f >= 0 && f < KS_RF_COUNT ? field_columns[f] : "";
}

bool ks_rulesdb_set_field(struct ks_rulesdb *db, const char *node, const char *name,
                          enum ks_rule_field f, const char *value)
{
    if (f < 0 || f >= KS_RF_COUNT)
        return false;
    bool found = false;
    for (size_t i = 0; i < db->len; i++) {
        struct ks_ui_rule *r = &db->rows[i];
        if (strcmp(r->f[KS_RF_NAME], nz(name)) == 0 && strcmp(r->f[KS_RF_NODE], nz(node)) == 0) {
            char *v = strdup(nz(value));
            if (v == NULL)
                return false;
            free(r->f[f]);
            r->f[f] = v;
            found = true;
        }
    }
    if (found && db->sql != NULL) {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE rules SET %s=? WHERE name=? AND node=?",
                 field_columns[f]);
        const char *a[3] = {value, name, node};
        sql_run(db, sql, a, 3);
    }
    return found;
}

void ks_rulesdb_update_time(struct ks_rulesdb *db, const char *time_s, const char *name,
                            const char *node)
{
    if (db->sql != NULL) {
        const char *a[3] = {time_s, name, node};
        sql_run(db, "UPDATE OR REPLACE rules SET time=? WHERE name=? AND node=?", a, 3);
    }
    for (size_t i = 0; i < db->len; i++) {
        struct ks_ui_rule *r = &db->rows[i];
        if (strcmp(r->f[KS_RF_NAME], nz(name)) == 0 && strcmp(r->f[KS_RF_NODE], nz(node)) == 0) {
            char *f = strdup(nz(time_s));
            if (f != NULL) {
                free(r->f[KS_RF_TIME]);
                r->f[KS_RF_TIME] = f;
            }
        }
    }
}

void ks_rulesdb_delete_filtered(struct ks_rulesdb *db)
{
    for (size_t i = 0; db->sql != NULL && i < db->ndur_filter; i++)
        sql_run(db, "DELETE FROM rules WHERE duration=?", (const char *const *)&db->dur_filter[i],
                1);
    for (size_t i = db->len; i > 0; i--) {
        if (ks_rulesdb_duration_filtered(db, db->rows[i - 1].f[KS_RF_DURATION]))
            remove_at(db, i - 1);
    }
}

static protobuf_c_boolean to_bool(const char *s)
{
    return strcmp(nz(s), "True") == 0;
}

static int64_t parse_db_date(const char *s)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (sscanf(s, "%d-%d-%d %d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
               &tm.tm_min, &tm.tm_sec) != 6)
        return -1;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    return (int64_t)mktime(&tm);
}

Protocol__Rule *ks_rulesdb_to_pb(struct ks_arena *a, const struct ks_ui_rule *row)
{
    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    Protocol__Operator *op = ks_arena_alloc(a, sizeof(*op));
    if (r == NULL || op == NULL)
        return NULL;
    protocol__rule__init(r);
    protocol__operator__init(op);
    char *const *f = row->f;
    r->name = ks_arena_strdup(a, f[KS_RF_NAME]);
    r->enabled = to_bool(f[KS_RF_ENABLED]);
    r->precedence = to_bool(f[KS_RF_PRECEDENCE]);
    r->action = ks_arena_strdup(a, f[KS_RF_ACTION]);
    r->duration = ks_arena_strdup(a, f[KS_RF_DURATION]);
    op->type = ks_arena_strdup(a, f[KS_RF_OP_TYPE]);
    op->sensitive = to_bool(f[KS_RF_OP_SENSITIVE]);
    op->operand = ks_arena_strdup(a, f[KS_RF_OP_OPERAND]);
    op->data = ks_arena_strdup(a, f[KS_RF_OP_DATA]);
    r->description = ks_arena_strdup(a, f[KS_RF_DESCRIPTION]);
    r->nolog = to_bool(f[KS_RF_NOLOG]);
    int64_t created = time(NULL);
    if (f[KS_RF_CREATED][0] != '\0') {
        int64_t t = parse_db_date(f[KS_RF_CREATED]);
        if (t >= 0)
            created = t;
    }
    r->created = created;
    r->operator_ = op;

    /* the operator list is a JSON string in the table */
    if (strcmp(op->type, "list") == 0) {
        char err[128];
        cJSON *j = ks_json_parse(op->data, strlen(op->data), err, sizeof(err));
        if (cJSON_IsArray(j)) {
            size_t n = (size_t)cJSON_GetArraySize(j), k = 0;
            Protocol__Operator **items = ks_arena_calloc(a, n ? n : 1, sizeof(*items));
            const cJSON *it;
            cJSON_ArrayForEach(it, j)
            {
                if (items == NULL)
                    break;
                Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
                if (o == NULL)
                    break;
                protocol__operator__init(o);
                const cJSON *t = cJSON_GetObjectItemCaseSensitive(it, "type");
                const cJSON *opd = cJSON_GetObjectItemCaseSensitive(it, "operand");
                const cJSON *sens = cJSON_GetObjectItemCaseSensitive(it, "sensitive");
                const cJSON *d = cJSON_GetObjectItemCaseSensitive(it, "data");
                o->type = ks_arena_strdup(a, cJSON_IsString(t) ? t->valuestring : "");
                o->operand = ks_arena_strdup(a, cJSON_IsString(opd) ? opd->valuestring : "");
                o->sensitive = cJSON_IsTrue(sens);
                o->data = ks_arena_strdup(a, cJSON_IsString(d) ? d->valuestring : "");
                items[k++] = o;
            }
            op->list = items;
            op->n_list = k;
            op->data = ks_arena_strdup(a, "");
        }
        cJSON_Delete(j);
    }
    return a->failed ? NULL : r;
}
