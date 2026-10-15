/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The SQL behind the tabs of the statistics window: port of the query
 * building in upstream ui/opensnitch/dialogs/stats.py (_set_events_query,
 * _set_nodes_query, _set_rules_query, _set_hosts_query, _set_process_query,
 * _set_addrs_query, _set_ports_query, _set_users_query, _set_rules_filter,
 * _get_filter_line_clause, _get_nodes_filter_query,
 * _get_indetail_filter_query, TABLES[...]['display_fields']).
 *
 * The upstream code pastes the user's text into the SQL; here single
 * quotes are doubled, so a filter like "it's" works instead of failing
 * (divergence 64). The text still goes inside LIKE '%text%', so "%" and
 * "_" are wildcards, as upstream.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: every function returns a malloc'd string (NULL on OOM), owned by
 * the caller.
 */
#ifndef KS_UI_STATSQ_H
#define KS_UI_STATSQ_H

#include <stdbool.h>

/* StatsDialog.TAB_* */
enum ks_tab {
    KS_TAB_MAIN,
    KS_TAB_NODES,
    KS_TAB_RULES,
    KS_TAB_HOSTS,
    KS_TAB_PROCS,
    KS_TAB_ADDRS,
    KS_TAB_PORTS,
    KS_TAB_USERS,
    KS_TAB_NETSTAT,
    KS_TAB_FIREWALL, /* in the rules tab */
    KS_TAB_ALERTS,   /* in the rules tab */
    KS_TAB_COUNT
};

/* StatsDialog.LIMITS: 50, 100, 200, 300, none */
#define KS_SQ_LIMITS 5
/* StatsDialog.SORT_ORDER: 0 ASC, 1 DESC */

/* TABLES[tab]['last_order_by'] and ['last_order_to'] at start. */
const char *ks_sq_default_order_by(enum ks_tab tab);
int ks_sq_default_order_to(enum ks_tab tab);
/* TABLES[tab]['name']: the SQL table. */
const char *ks_sq_table_name(enum ks_tab tab);

/* _get_limit(): " LIMIT 50" ... or " " (idx out of range = none) */
const char *ks_sq_limit(int limit_idx);

/* A tab's rows when it is not in a detail view: _set_events_query for the
 * events (action_idx: 0 all, 1 allow, 2 deny, 3 reject), and for the
 * others the query _cb_events_filter_line_changed / _cb_cmd_back_clicked
 * build from display_fields + _get_filter_line_clause + _get_order
 * (+ limit, but not when there is a filter text; nodes keep it). */
char *ks_sq_list(enum ks_tab tab, const char *filter, int action_idx, const char *order_by,
                 int order_to, int limit_idx);

/* The detail view of an item of a tab: the connections of a node, host,
 * process, address, port or user (`data` is the value shown in the first
 * column; for users "name (uid)" is accepted), or of a rule
 * (rules: `data` is the rule name and `node` its node; NULL elsewhere).
 * `filter` is the text of the filter line (_get_indetail_filter_query). */
char *ks_sq_detail(enum ks_tab tab, const char *data, const char *node, const char *filter,
                   const char *order_by, int order_to, int limit_idx);

/* _set_rules_filter() for the rules tree: which = 0 all, 1 permanent, 2
 * temporary, 3 a node's rules (`node`). `filter` is the name filter. */
enum ks_rules_which { KS_RULES_ALL, KS_RULES_PERMANENT, KS_RULES_TEMPORARY, KS_RULES_NODE };
char *ks_sq_rules(enum ks_rules_which which, const char *node, const char *filter,
                  const char *order_by, int order_to, int limit_idx);

/* The alerts list (RULES_TREE_ALERTS). */
char *ks_sq_alerts(const char *order_by, int order_to, int limit_idx);

/* Doubles the single quotes of `s`. */
char *ks_sq_escape(const char *s);

#endif
