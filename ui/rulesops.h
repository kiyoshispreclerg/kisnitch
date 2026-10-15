/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What the statistics window's rules menu does to a rule: port of
 * _table_menu_change_rule_field, _table_menu_enable, _table_menu_duplicate,
 * _table_menu_apply_to_node and _del_rule (ui/opensnitch/dialogs/stats.py),
 * and of Rules.rule_to_json / export_rule (ui/opensnitch/rules.py). Each
 * operation changes the UI's rules table and notifies the node(s), as
 * upstream does.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: nothing is kept; strings returned are malloc'd. The rules and
 * nodes are borrowed.
 */
#ifndef KS_UI_RULESOPS_H
#define KS_UI_RULESOPS_H

#include <stdbool.h>

#include "ui/nodes.h"
#include "ui/rulesdb.h"

/* Config.DURATION_* */
#define KS_DUR_ALWAYS "always"
#define KS_DUR_UNTIL_RESTART "until restart"

/* Sets action (KS_RF_ACTION) or duration (KS_RF_DURATION) of the rule and
 * sends CHANGE_RULE with it. false if the rule isn't there. */
bool ks_rops_change_field(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                          const char *name, enum ks_rule_field field, const char *value,
                          ks_ntf_reply_cb cb, void *ud);
/* Enable or disable (`enabled` is the current state, "True"/"False" as in
 * the table): updates the table and sends ENABLE_RULE or DISABLE_RULE. */
bool ks_rops_enable(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                    const char *name, const char *enabled, ks_ntf_reply_cb cb, void *ud);
/* Adds "<name>-duplicated-N" (the first free N below 100) and sends
 * CHANGE_RULE. */
bool ks_rops_duplicate(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                       const char *name, ks_ntf_reply_cb cb, void *ud);
/* Sends CHANGE_RULE with the rule (of whichever node has it) to `target`
 * and stores it for that node. */
bool ks_rops_apply_to_node(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *name,
                           const char *target, ks_ntf_reply_cb cb, void *ud);
/* Nodes.delete_rule(): deletes it from the table and sends DELETE_RULE (to
 * every node if `node` is NULL). */
bool ks_rops_delete(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *name,
                    const char *node, ks_ntf_reply_cb cb, void *ud);

/* Rules.rule_to_json(): json.dumps(MessageToJson(rule), indent=4) with
 * "created" in RFC 3339. NULL if there is no such rule. */
char *ks_rops_rule_json(const struct ks_rulesdb *rules, const char *node, const char *name);
/* Rules.export_rule(): writes <outdir>/<slug(node)>/<name>.json. */
bool ks_rops_export(const struct ks_rulesdb *rules, const char *node, const char *name,
                    const char *outdir);

/* Rules.export_rules(): every rule of the node, to <outdir>/<slug(node)>/. */
bool ks_rops_export_all(const struct ks_rulesdb *rules, const char *node, const char *outdir);

/* Rules.import_rules(): reads every file of `dir` as a rule in JSON (what
 * ks_rops_export writes; "created" as RFC 3339 or as a timestamp). All or
 * nothing: any file that can't be read or doesn't parse makes it fail.
 * The rules are allocated in `a`; *out is an array of *n pointers. */
bool ks_rops_import_parse(struct ks_arena *a, const char *dir, Protocol__Rule ***out, size_t *n);
/* Nodes.import_rules() + the stats window's handling: sends CHANGE_RULE with
 * the rules to `node` and adds them to the table of every node. Returns
 * the number of rules, -1 on error. */
int ks_rops_import(struct ks_rulesdb *rules, struct ks_nodes *nodes, const char *node,
                   const char *dir, ks_ntf_reply_cb cb, void *ud);

#endif
