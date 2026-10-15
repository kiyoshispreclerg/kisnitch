/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the query building of upstream ui/opensnitch/dialogs/stats.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/statsq.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>

static const struct {
    const char *name;
    const char *display_fields;
    const char *order_by;
    int order_to;
} tabs[KS_TAB_COUNT] = {
    [KS_TAB_MAIN] = {"connections",
                     "time as Time, node, action, src_port, src_ip, dst_ip, dst_host, "
                     "dst_port, protocol, uid, pid, process, process_args, rule",
                     "1", 1},
    [KS_TAB_NODES] = {"nodes",
                      "last_connection as LastConnection, addr as Addr, status as Status, "
                      "hostname as Hostname, daemon_version as Version, daemon_uptime as Uptime, "
                      "daemon_rules as Rules,cons as Connections,cons_dropped as Dropped,"
                      "version as Version",
                      "3,2,1", 1},
    [KS_TAB_RULES] = {"rules",
                      "time as Time,node as Node,name as Name,enabled as Enabled,"
                      "action as Action,duration as Duration,description as Description, "
                      "created as Created",
                      "2", 0},
    [KS_TAB_HOSTS] = {"hosts", "*", "2", 1},
    [KS_TAB_PROCS] = {"procs", "*", "2", 1},
    [KS_TAB_ADDRS] = {"addrs", "*", "2", 1},
    [KS_TAB_PORTS] = {"ports", "*", "2", 1},
    [KS_TAB_USERS] = {"users", "*", "2", 1},
    [KS_TAB_NETSTAT] = {"sockets",
                        "proc_comm as Comm,proc_path as Process, state as State, "
                        "src_port as SrcPort, src_ip as SrcIP, dst_ip as DstIP, "
                        "dst_port as DstPort, proto as Protocol, uid as UID, proc_pid as PID, "
                        "family as Family, iface as IFace, "
                        "'inode: ' || inode || ', cookies: '|| cookies || ', rqueue: ' || rqueue "
                        "|| ', wqueue: ' || wqueue || ', expires: ' || expires || ', retrans: ' "
                        "|| retrans || ', timer: ' || timer as Metadata ",
                        "2", 1},
    [KS_TAB_FIREWALL] = {"firewall", "*", "2", 0},
    [KS_TAB_ALERTS] = {"alerts",
                       "time as Time, node as Node, type as Type, "
                       "substr(what, 0, 128) as What, substr(body, 0, 128) as Description ",
                       "1", 0},
};

static const char *const limits[KS_SQ_LIMITS] = {" LIMIT 50", " LIMIT 100", " LIMIT 200",
                                                 " LIMIT 300", " "};

const char *ks_sq_default_order_by(enum ks_tab tab)
{
    return tabs[tab].order_by;
}

int ks_sq_default_order_to(enum ks_tab tab)
{
    return tabs[tab].order_to;
}

const char *ks_sq_table_name(enum ks_tab tab)
{
    return tabs[tab].name;
}

const char *ks_sq_limit(int idx)
{
    return idx >= 0 && idx < KS_SQ_LIMITS ? limits[idx] : " ";
}

char *ks_sq_escape(const char *s)
{
    GString *g = g_string_new(NULL);
    for (; s != NULL && *s; s++) {
        if (*s == '\'')
            g_string_append_c(g, '\'');
        g_string_append_c(g, *s);
    }
    return g_string_free(g, FALSE);
}

/* _get_order(field) */
static void order(GString *g, const char *by, int to)
{
    g_string_append_printf(g, " ORDER BY %s %s", by, to ? "DESC" : "ASC");
}

static char *done(GString *g)
{
    return g_string_free(g, FALSE);
}

static void like_any(GString *g, const char *const *cols, const char *text, const char *join)
{
    for (int i = 0; cols[i] != NULL; i++) {
        g_string_append_printf(g, "%s%s LIKE '%%%s%%'", i > 0 ? join : "", cols[i], text);
    }
}

/* ---- list of a tab --------------------------------------------------- */

static char *events_query(const char *filter, int action_idx, const char *by, int to,
                          int limit_idx)
{
    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "SELECT %s FROM %s", tabs[KS_TAB_MAIN].display_fields,
                           tabs[KS_TAB_MAIN].name);
    const char *action = action_idx == 1   ? "action = \"allow\""
                         : action_idx == 2 ? "action = \"deny\""
                         : action_idx == 3 ? "action = \"reject\""
                                           : "";
    if (filter == NULL || filter[0] == '\0') {
        if (action[0] != '\0')
            g_string_append_printf(g, " WHERE %s", action);
    } else {
        char *t = ks_sq_escape(filter);
        static const char *const cols[] = {"process", "process_args", "src_port", "src_ip",
                                           "dst_ip",  "dst_host",     "dst_port", "rule",
                                           "node",    "time",         "uid",      "pid",
                                           "protocol", NULL};
        g_string_append_printf(g, " WHERE %s%s (", action, action[0] ? " AND" : "");
        like_any(g, cols, t, " OR ");
        g_string_append(g, ")");
        g_free(t);
    }
    order(g, by, to);
    g_string_append(g, ks_sq_limit(limit_idx));
    return done(g);
}

static char *filter_clause(enum ks_tab tab, const char *text)
{
    if (text == NULL || text[0] == '\0')
        return g_strdup("");
    char *t = ks_sq_escape(text);
    GString *g = g_string_new(NULL);
    if (tab == KS_TAB_RULES) {
        g_string_append_printf(g, " WHERE rules.name LIKE '%%%s%%' OR rules.operator_data LIKE '%%%s%%' ",
                               t, t);
    } else if (tab >= KS_TAB_HOSTS && tab <= KS_TAB_USERS) {
        g_string_append_printf(g, " WHERE what LIKE '%%%s%%' ", t);
    } else if (tab == KS_TAB_NETSTAT) {
        static const char *const cols[] = {"proc_comm", "proc_path", "state", "src_port",
                                           "src_ip", "dst_ip", "dst_port", "proto", "uid",
                                           "proc_pid", "family", "iface", "inode", NULL};
        g_string_append(g, " WHERE ");
        like_any(g, cols, t, " OR ");
    }
    g_free(t);
    return done(g);
}

char *ks_sq_list(enum ks_tab tab, const char *filter, int action_idx, const char *by, int to,
                 int limit_idx)
{
    if (tab == KS_TAB_MAIN)
        return events_query(filter, action_idx, by, to, limit_idx);

    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "SELECT %s FROM %s", tabs[tab].display_fields, tabs[tab].name);
    if (tab == KS_TAB_NODES) {
        /* _get_nodes_filter_query(): the limit stays */
        if (filter != NULL && filter[0] != '\0') {
            char *t = ks_sq_escape(filter);
            static const char *const cols[] = {"last_connection", "addr", "status", "hostname",
                                               "version", NULL};
            g_string_append(g, " WHERE (");
            like_any(g, cols, t, " OR ");
            g_string_append(g, ")");
            g_free(t);
        }
        order(g, by, to);
        g_string_append(g, ks_sq_limit(limit_idx));
        return done(g);
    }
    char *w = filter_clause(tab, filter);
    g_string_append(g, w);
    g_free(w);
    order(g, by, to);
    if (filter == NULL || filter[0] == '\0')
        g_string_append(g, ks_sq_limit(limit_idx));
    return done(g);
}

/* ---- rules tree and alerts ------------------------------------------- */

char *ks_sq_rules(enum ks_rules_which which, const char *node, const char *filter,
                  const char *by, int to, int limit_idx)
{
    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "SELECT %s FROM rules as r ", tabs[KS_TAB_RULES].display_fields);
    bool where = false;
    if (which == KS_RULES_TEMPORARY) {
        g_string_append(g, "WHERE r.duration != 'always'");
        where = true;
    } else if (which == KS_RULES_PERMANENT) {
        g_string_append(g, "WHERE r.duration = 'always'");
        where = true;
    } else if (which == KS_RULES_NODE && node != NULL && node[0] != '\0') {
        char *n = ks_sq_escape(node);
        g_string_append_printf(g, "WHERE r.node = '%s'", n);
        g_free(n);
        where = true;
    }
    if (filter != NULL && filter[0] != '\0') {
        char *t = ks_sq_escape(filter);
        g_string_append_printf(g, "%s r.name LIKE '%%%s%%'", where ? " AND" : "WHERE", t);
        g_free(t);
    }
    g_string_append_c(g, ' ');
    order(g, by, to);
    g_string_append(g, ks_sq_limit(limit_idx));
    return done(g);
}

char *ks_sq_alerts(const char *by, int to, int limit_idx)
{
    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "SELECT %s FROM alerts ", tabs[KS_TAB_ALERTS].display_fields);
    order(g, by, to);
    g_string_append(g, ks_sq_limit(limit_idx));
    return done(g);
}

/* ---- detail views ---------------------------------------------------- */

/* the columns every detail view starts with */
#define SEL_TIME "MAX(c.time) as Time, "

static void detail_filter(GString *g, enum ks_tab tab, const char *text)
{
    if (text == NULL || text[0] == '\0')
        return;
    char *t = ks_sq_escape(text);
    if (tab == KS_TAB_NODES) {
        static const char *const cols[] = {"c.time", "c.action", "c.uid", "c.pid",
                                           "c.src_port", "c.dst_port", "c.src_ip", "c.dst_ip",
                                           "c.dst_host", "c.process", "c.process_cwd",
                                           "c.process_args", NULL};
        g_string_append(g, " AND (");
        like_any(g, cols, t, " OR ");
        g_string_append(g, ")");
    } else {
        g_string_append_printf(g,
                               " AND (c.time LIKE '%%%s%%' OR c.action LIKE '%%%s%%' OR "
                               "c.pid LIKE '%%%s%%' OR c.protocol LIKE '%%%s%%' OR "
                               "c.src_port LIKE '%%%s%%' OR c.src_ip LIKE '%%%s%%' OR "
                               "c.process_cwd LIKE '%%%s%%' OR c.rule LIKE '%%%s%%' OR ",
                               t, t, t, t, t, t, t, t);
        /* the field of the view we're filtering by is left out */
        if (tab != KS_TAB_PORTS)
            g_string_append_printf(g, "c.dst_port LIKE '%%%s%%' OR ", t);
        if (tab != KS_TAB_ADDRS)
            g_string_append_printf(g, "c.dst_ip LIKE '%%%s%%' OR ", t);
        if (tab != KS_TAB_HOSTS)
            g_string_append_printf(g, "c.dst_host LIKE '%%%s%%' OR ", t);
        if (tab != KS_TAB_PROCS)
            g_string_append_printf(g, "c.process LIKE '%%%s%%' OR ", t);
        if (tab != KS_TAB_USERS)
            g_string_append_printf(g, "c.uid LIKE '%%%s%%' OR ", t);
        g_string_append_printf(g, "c.process_args LIKE '%%%s%%')", t);
    }
    g_free(t);
}

char *ks_sq_detail(enum ks_tab tab, const char *data, const char *node, const char *filter,
                   const char *by, int to, int limit_idx)
{
    GString *g = g_string_new(NULL);
    char *d = ks_sq_escape(data);
    switch (tab) {
    case KS_TAB_NODES:
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.action as Action, count(c.process) as Hits, c.uid as UserID, "
               "c.protocol as Protocol, c.src_port as SrcPort, c.src_ip as SrcIP, "
               "c.dst_ip as DstIP, c.dst_host as DstHost, c.dst_port as DstPort, "
               "c.pid as PID, c.process as Process, c.process_args as Cmdline, "
               "c.process_cwd as CWD, c.rule as Rule "
               "FROM connections as c WHERE c.node = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY Process, c.process_args, c.uid, c.src_ip, c.dst_ip, "
                           "c.dst_host, c.dst_port, c.protocol ");
        break;
    case KS_TAB_RULES: {
        char *n = ks_sq_escape(node);
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.process) as Hits, c.uid as UserID, "
               "c.protocol as Protocol, c.src_port as SrcPort, c.src_ip as SrcIP, "
               "c.dst_ip as DstIP, c.dst_host as DstHost, c.dst_port as DstPort, "
               "c.pid as PID, c.process as Process, c.process_args as Cmdline, "
               "c.process_cwd as CWD "
               "FROM connections as c WHERE c.rule = '%s' AND c.node = '%s'",
            d, n);
        g_free(n);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.process, c.process_args, c.uid, c.dst_ip, c.dst_host, "
                           "c.dst_port ");
        break;
    }
    case KS_TAB_HOSTS:
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.process) as Hits, c.action as Action, "
               "c.uid as UserID, c.protocol as Protocol, c.src_port as SrcPort, "
               "c.src_ip as SrcIP, c.dst_ip as DstIP, c.dst_port as DstPort, c.pid as PID, "
               "c.process as Process, c.process_args as Cmdline, c.process_cwd as CWD, "
               "c.rule as Rule FROM connections as c WHERE c.dst_host = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.pid, Process, c.process_args, c.src_ip, c.dst_ip, "
                           "c.dst_port, c.protocol, c.action, c.node ");
        break;
    case KS_TAB_PROCS:
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.dst_ip) as Hits, c.action as Action, "
               "c.uid as UserID, c.protocol as Protocol, c.src_port as SrcPort, "
               "c.src_ip as SrcIP, c.dst_ip as DstIP, c.dst_host as DstHost, "
               "c.dst_port as DstPort, c.pid as PID, c.process_args as Cmdline, "
               "c.process_cwd as CWD, c.rule as Rule "
               "FROM connections as c WHERE c.process = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.uid, "
                           "c.action, c.node, c.pid, c.process_args ");
        break;
    case KS_TAB_ADDRS:
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.dst_ip) as Hits, c.action as Action, "
               "c.uid as UserID, c.protocol as Protocol, c.src_port as SrcPort, "
               "c.src_ip as SrcIP, c.dst_host as DstHost, c.dst_port as DstPort, "
               "c.pid as PID, c.process as Process, c.process_args as Cmdline, "
               "c.process_cwd as CWD, c.rule as Rule "
               "FROM connections as c WHERE c.dst_ip = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.pid, Process, c.process_args, c.src_ip, c.dst_port, "
                           "DstHost, c.protocol, c.action, c.uid, c.node ");
        break;
    case KS_TAB_PORTS:
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.dst_ip) as Hits, c.action as Action, "
               "c.uid as UserID, c.protocol as Protocol, c.src_port as SrcPort, "
               "c.src_ip as SrcIP, c.dst_ip as DstIP, c.dst_host as DstHost, c.pid as PID, "
               "c.process as Process, c.process_args as Cmdline, c.process_cwd as CWD, "
               "c.rule as Rule FROM connections as c WHERE c.dst_port = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.pid, Process, c.process_args, DstHost, c.src_ip, "
                           "c.dst_ip, c.protocol, c.action, c.uid, c.node ");
        break;
    case KS_TAB_USERS: {
        /* "name (uid)" -> uid */
        char **parts = g_strsplit(data, " ", -1);
        const char *uid = parts[0];
        char *tmp = NULL;
        if (parts[0] != NULL && parts[1] != NULL && parts[2] == NULL) {
            tmp = g_strdup(parts[1]);
            g_strstrip(tmp);
            /* strip("()") */
            char *s = tmp;
            while (*s == '(' || *s == ')')
                s++;
            size_t l = strlen(s);
            while (l > 0 && (s[l - 1] == '(' || s[l - 1] == ')'))
                s[--l] = '\0';
            uid = s;
        }
        g_free(d);
        d = ks_sq_escape(uid);
        g_free(tmp);
        g_strfreev(parts);
        g_string_append_printf(
            g, "SELECT " SEL_TIME
               "c.node as Node, count(c.dst_ip) as Hits, c.action as Action, "
               "c.protocol as Protocol, c.src_port as SrcPort, c.src_ip as SrcIP, "
               "c.dst_ip as DstIP, c.dst_host as DstHost, c.dst_port as DstPort, "
               "c.pid as PID, c.process as Process, c.process_args as Cmdline, "
               "c.process_cwd as CWD, c.rule as Rule "
               "FROM connections as c WHERE c.uid = '%s'",
            d);
        detail_filter(g, tab, filter);
        g_string_append(g, " GROUP BY c.pid, Process, c.process_args, c.src_ip, c.dst_ip, "
                           "c.dst_host, c.dst_port, c.protocol, c.action, c.node ");
        break;
    }
    default:
        g_string_free(g, TRUE);
        g_free(d);
        return NULL;
    }
    g_free(d);
    order(g, by, to);
    g_string_append(g, ks_sq_limit(limit_idx));
    return done(g);
}
