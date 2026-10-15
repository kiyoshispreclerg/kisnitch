/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What the pieces of the statistics window (stats_win.c, stats_menu.c,
 * stats_node.c) share. Not for the rest of the UI.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_UI_STATS_WIN_PRIV_H
#define KS_UI_STATS_WIN_PRIV_H

#include <gtk/gtk.h>
#include <stdbool.h>

#include "ui/desktop.h"
#include "ui/qstore.h"
#include "ui/service.h"
#include "ui/settings.h"
#include "ui/stats_win.h"
#include "ui/statsq.h"

#define KS_NTABS 9

/* stats.py COL_* of the events, nodes and rules tables */
#define COL_TIME 0
#define COL_NODE 1
#define COL_DSTIP 5
#define COL_DSTHOST 6
#define COL_DSTPORT 7
#define COL_UID 9
#define COL_PID 10
#define COL_RULES 13
#define COL_R_NODE 1
#define COL_R_NAME 2
#define COL_R_ENABLED 3
#define COL_N_HOSTNAME 3
#define COL_N_VERSION 4
#define COL_N_UPTIME 5
#define COL_N_KERNEL 9
#define COL_PROC_PID 11
/* the netstat table */
#define COL_NET_PROC 1
#define COL_NET_DST_IP 5
#define COL_NET_DST_PORT 6
#define COL_NET_UID 8
#define COL_NET_PID 9

struct tabview {
    enum ks_tab tab;
    GtkWidget *page, *tree, *back, *label, *clean;
    KsQStore *store;
    bool detail;
    char data[512];
    char node[KS_NODE_ADDR_MAX];
    char *order_by; /* list view */
    int order_to;
    char *det_order_by; /* detail view */
    int det_order_to;
    char *colsig; /* the column names the view was built with */
};

struct ks_stats_win {
    struct ks_service *svc;
    struct ks_settings *settings;
    GtkWidget *win, *nb;
    GtkWidget *filter, *combo_action, *combo_limit, *rows_label, *clean_button;
    GtkWidget *combo_rules;
    GtkWidget *status_label, *start_button;
    GtkWidget *l_cons, *l_dropped, *l_uptime, *l_rules, *l_ver;
    struct tabview tv[KS_NTABS];
    bool loading; /* signals fired while we set widgets */
    int last_tab;

    /* the nodes tab (stats_node.c) */
    GtkWidget *np_box, *np_name, *np_details, *np_ram_l, *np_ram_p, *np_swap_l, *np_swap_p,
        *np_procs, *np_load, *np_uptime;
    GtkWidget *node_start, *node_prefs, *node_delete, *node_actions;
    char monitored[KS_NODE_ADDR_MAX]; /* LAST_SELECTED_ITEM of the nodes tab */

    /* the netstat tab (stats_netstat.c) */
    GtkWidget *ns_interval, *ns_nodes, *ns_proto, *ns_family, *ns_state, *ns_label;
    char ns_node[KS_NODE_ADDR_MAX]; /* LAST_NETSTAT_NODE: "" if none */

    /* the process details dialog (stats_proc.c) */
    struct ks_procdlg *proc;
    struct ks_desktop *desktop;
    GtkWidget *proc_button; /* the "process details" button of the applications tab */

    /* the rules editor (rules_editor.c), made on first use */
    struct ks_ruleed *ruleed;
    /* the preferences dialog (prefs.c), made on first use */
    struct ks_prefs *prefs;
    gint64 last_update; /* _last_update, monotonic microseconds */
    GtkWidget *rule_edit, *rule_delete; /* the buttons of a rule's detail view */
};

struct ks_procdlg;
struct ks_ruleed;
struct ks_prefs;

/* stats_win.c */
struct tabview *ks_sw_cur_tab(struct ks_stats_win *w);
void ks_sw_refresh(struct ks_stats_win *w);
void ks_sw_run_query(struct ks_stats_win *w, struct tabview *tv, bool refresh_only);
const char *ks_sw_cell(struct tabview *tv, gint64 row, int col);
struct tabview *ks_sw_tab(struct ks_stats_win *w, enum ks_tab tab);
/* the detail view of an item of a tab (enter_detail()) */
void ks_sw_enter_detail(struct ks_stats_win *w, enum ks_tab tab, const char *data, const char *node);
/* the rows selected in the view, as arrays of cells (g_strfreev each) */
GPtrArray *ks_sw_selected_rows(struct tabview *tv);
/* _del_by_field() for one item of a tab; false if nothing to delete */
bool ks_sw_del_by_field(struct ks_stats_win *w, enum ks_tab tab, const char *value);

/* the rules editor of the window (created on first use) */
struct ks_ruleed *ks_sw_ruleed(struct ks_stats_win *w);
struct ks_prefs *ks_sw_prefs(struct ks_stats_win *w);

/* stats_menu.c */
void ks_sw_menu_attach(struct ks_stats_win *w, struct tabview *tv);
void ks_sw_delete_selected(struct ks_stats_win *w);
void ks_sw_copy_selected(struct ks_stats_win *w);
void ks_sw_message(struct ks_stats_win *w, GtkMessageType type, const char *primary,
                   const char *secondary);
bool ks_sw_confirm(struct ks_stats_win *w, const char *primary);
/* the generic reply callback of a notification (a dialog on error) */
void ks_sw_ntf_reply(const char *addr, const Protocol__NotificationReply *r, void *ud);
/* ConnDetails.showByField("time", time) and _display_alert_info() */
void ks_sw_show_conn_details(struct ks_stats_win *w, const char *time);
void ks_sw_show_alert(struct ks_stats_win *w, const char *time, const char *node);
char *ks_sw_choose_dir(struct ks_stats_win *w, const char *title);

/* stats_netstat.c */
void ks_sw_netstat_build(struct ks_stats_win *w, struct tabview *tv, GtkWidget *top);
void ks_sw_netstat_enter(struct ks_stats_win *w);  /* the tab was selected */
void ks_sw_netstat_leave(struct ks_stats_win *w);  /* another one was */
void ks_sw_netstat_activated(struct ks_stats_win *w, struct tabview *tv, gint64 row, int col);

/* stats_proc.c */
struct ks_procdlg *ks_procdlg_new(struct ks_stats_win *w);
void ks_procdlg_free(struct ks_procdlg *d);
/* ProcessDetailsDialog.monitor({pid: node}) */
void ks_sw_proc_monitor(struct ks_stats_win *w, const char *const *pids, const char *const *nodes,
                        size_t n);

/* stats_node.c */
/* Adds the node buttons to `top` and returns the panel for the right of the table. */
GtkWidget *ks_sw_node_build(struct ks_stats_win *w, struct tabview *tv, GtkWidget *top);
void ks_sw_node_clicked(struct ks_stats_win *w, struct tabview *tv, gint64 row);
void ks_sw_node_stop(struct ks_stats_win *w); /* _unmonitor_deselected_node() */
void ks_sw_node_update_buttons(struct ks_stats_win *w);

#endif
