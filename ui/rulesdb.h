/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI's copy of every node's rules: the `rules` table of the upstream
 * UI database (ui/opensnitch/database/__init__.py) and the Rules class
 * around it (ui/opensnitch/rules.py), as far as the pop-up needs them:
 * naming new rules (exists, new_unique_name), the checksum warning
 * (get_by_field) and temporary rules expiring (disable).
 *
 * The rows live in memory; when a database is attached
 * (ks_rulesdb_attach) every change is written through to its `rules`
 * table, which has the schema of the original UI (ui/db.c). Values are strings, as in the table: booleans are
 * Python's str(bool) ("True"/"False"), dates "%Y-%m-%d %H:%M:%S" (local
 * time), and the operator list of a "list" rule is a JSON string in
 * operator_data.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_rulesdb owns its rows and their strings. Pointers to
 * rows are valid until the next change.
 */
#ifndef KS_UI_RULESDB_H
#define KS_UI_RULESDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/arena.h"
#include "common/pb/ui.pb-c.h"
#include "ui/db.h"

/* Columns, in the table's order (database/enums.py RuleFields). */
enum ks_rule_field {
    KS_RF_TIME,
    KS_RF_NODE,
    KS_RF_NAME,
    KS_RF_ENABLED,
    KS_RF_PRECEDENCE,
    KS_RF_ACTION,
    KS_RF_DURATION,
    KS_RF_OP_TYPE,
    KS_RF_OP_SENSITIVE,
    KS_RF_OP_OPERAND,
    KS_RF_OP_DATA,
    KS_RF_DESCRIPTION,
    KS_RF_NOLOG,
    KS_RF_CREATED,
    KS_RF_COUNT
};

struct ks_ui_rule {
    char *f[KS_RF_COUNT];
};

struct ks_rulesdb {
    struct ks_ui_rule *rows;
    size_t len, cap;
    /* Config.RULES_DURATION_FILTER: rules with these durations are not
     * stored. */
    char *dur_filter[8];
    size_t ndur_filter;
    struct ks_db *sql; /* borrowed; NULL = memory only */
};

/* Loads the `rules` table into the rows (replacing them) and writes every
 * later change through to it. `sql` must outlive `db`. false on a
 * database error (the rows are then unchanged). */
bool ks_rulesdb_attach(struct ks_rulesdb *db, struct ks_db *sql);

/* Config.RULES_TEMPORARY_LIST */
extern const char *const ks_rules_temporary_list[8];

void ks_rulesdb_init(struct ks_rulesdb *db);
void ks_rulesdb_free(struct ks_rulesdb *db);

/* Config.setRulesDurationFilter(ignore_temporary_rules, temp_rules). */
void ks_rulesdb_set_duration_filter(struct ks_rulesdb *db, bool ignore, int temp_rules);
bool ks_rulesdb_duration_filtered(const struct ks_rulesdb *db, const char *duration);

/* Rules.add(): INSERT OR REPLACE (UNIQUE(node, name)); skipped if the
 * duration is filtered. `v` has KS_RF_COUNT strings (NULL = ""). */
int ks_rulesdb_add_row(struct ks_rulesdb *db, const char *const v[KS_RF_COUNT]);

/* Rules.add_rules(): every rule of a node, as the daemon sent them. */
int ks_rulesdb_add_pb(struct ks_rulesdb *db, const char *node, Protocol__Rule *const *rules,
                      size_t n);

/* json.dumps() of the operator list as MessageToJson() renders it, which
 * is what add_rules() stores in operator_data for "list" rules. */
char *ks_rulesdb_list_json(Protocol__Operator *const *list, size_t n);

/* Database.rule_exists(): same name, node, action, duration, operator
 * type, operand and data. */
bool ks_rulesdb_exists(const struct ks_rulesdb *db, const char *node, const Protocol__Rule *r);
const struct ks_ui_rule *ks_rulesdb_get(const struct ks_rulesdb *db, const char *name,
                                        const char *node);
/* Rules.new_unique_name(): `name`, or "name-0" ... "name-99", the first
 * free one (`name` if all are taken). malloc'd. */
char *ks_rulesdb_new_unique_name(const struct ks_rulesdb *db, const char *name,
                                 const char *node);

/* Database.get_rule_by_field(node, field, value): rows where `field` LIKE
 * '%value%' (SQLite LIKE: ASCII case-insensitive, "%" and "_" in `value`
 * are wildcards). Fills `out` with up to `max` row indexes; returns the
 * count. */
size_t ks_rulesdb_find_like(const struct ks_rulesdb *db, const char *node,
                            enum ks_rule_field field, const char *value, size_t *out,
                            size_t max);

/* Rules.disable(): enabled = 'False'. */
void ks_rulesdb_disable(struct ks_rulesdb *db, const char *node, const char *name);
/* The SQL column of a field ("operator_type" ...). */
const char *ks_rule_field_column(enum ks_rule_field f);
/* Database.update("rules", "<field>=?", ..., "name=? AND node=?"): sets one
 * column of the rule (memory and table). false if there is no such rule. */
bool ks_rulesdb_set_field(struct ks_rulesdb *db, const char *node, const char *name,
                          enum ks_rule_field f, const char *value);
/* Rules.update_time(): the time of the rule that matched a connection. */
void ks_rulesdb_update_time(struct ks_rulesdb *db, const char *time_s, const char *name,
                            const char *node);
/* Database.delete_rule(); NULL `node` deletes the name on every node. */
void ks_rulesdb_delete(struct ks_rulesdb *db, const char *name, const char *node);
/* Database.delete_rules_by_field(KS_RF_DURATION, filter): what the UI does
 * on start when default_ignore_rules is on. */
void ks_rulesdb_delete_filtered(struct ks_rulesdb *db);

/* Rule.new_from_records(): a Rule message from a row, in `a`. */
Protocol__Rule *ks_rulesdb_to_pb(struct ks_arena *a, const struct ks_ui_rule *row);

/* sqlite LIKE with "%" and "_" and no ESCAPE. Exposed for tests. */
bool ks_sql_like(const char *pattern, const char *s);

/* datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") */
void ks_db_date(int64_t t, char *buf, size_t len);

#endif
