/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The Netstat tab: port of _monitor_node_netstat, _unmonitor_node_netstat,
 * _update_netstat_table, _cb_combo_netstat_changed, _cb_nodes_updated (the
 * node combo) and the netstat part of _cb_table_double_clicked of upstream
 * ui/opensnitch/dialogs/stats.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/netstat.h"
#include "ui/stats_win_priv.h"
#include "ui/i18n.h"

#define KEY_PROTO "statsDialog/netstat_proto_filter"
#define KEY_FAMILY "statsDialog/netstat_family_filter"
#define KEY_STATE "statsDialog/netstat_state_filter"

struct item {
    const char *label;
    int value;
};

static const char *const intervals[] = {"Stop", "5s", "10s", "15s", "20s",
                                        "30s",  "45s", "1m", "5m", "10m"};

static const struct item protos[] = {{"ALL", 0},    {"TCP", 6},     {"UDP", 17},
                                     {"SCTP", 132}, {"DCCP", 33},   {"ICMP", 1},
                                     {"ICMPv6", 58}, {"IGMP", 2},   {"RAW", 255}};
static const struct item families[] = {
    {"ALL", 0}, {"AF_INET", 2}, {"AF_INET6", 10}, {"AF_PACKET", 17}, {"AF_XDP", 44}};
static const struct item states[] = {
    {"ALL", 0},           {"Established", 1},   {"TCP_SYN_SENT", 2},  {"TCP_SYN_RECV", 3},
    {"TCP_FIN_WAIT1", 4}, {"TCP_FIN_WAIT2", 5}, {"TCP_TIME_WAIT", 6},  {"CLOSE", 7},
    {"TCP_CLOSE_WAIT", 8}, {"TCP_LAST_ACK", 9}, {"LISTEN", 10},        {"TCP_CLOSING", 11},
    {"TCP_NEW_SYN_RECV", 12}};
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

static GtkWidget *combo_of(const struct item *it, int n, int active)
{
    GtkWidget *c = gtk_combo_box_new_text();
    for (int i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(c), it[i].label);
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), active >= 0 && active < n ? active : 0);
    return c;
}

static int value_of(GtkWidget *c, const struct item *it, int n)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(c));
    return i >= 0 && i < n ? it[i].value : 0;
}

/* _cb_notification_callback() for the sockets-monitor task */
static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_stats_win *w = ud;
    if (strcmp(addr, w->ns_node) != 0)
        return;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR) {
        char *m = g_strdup_printf(_("error starting netstat table: %s"), r->data);
        gtk_label_set_text(GTK_LABEL(w->ns_label), m);
        g_free(m);
        return;
    }
    char err[200] = "";
    if (ks_netstat_update(ks_service_db(w->svc), addr, r->data != NULL ? r->data : "", err,
                          sizeof(err)) < 0) {
        char *m = g_strdup_printf(_("error loading: %s"), err);
        gtk_label_set_text(GTK_LABEL(w->ns_label), m);
        g_free(m);
        return;
    }
    gtk_label_set_text(GTK_LABEL(w->ns_label), _("refreshing..."));
    if (ks_sw_cur_tab(w)->tab == KS_TAB_NETSTAT)
        ks_sw_refresh(w);
}

static void send_task(struct ks_stats_win *w, const char *addr, Protocol__Action type,
                      const char *data, ks_ntf_reply_cb cb)
{
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.type = type;
    n.data = (char *)(uintptr_t)data;
    ks_nodes_send(ks_service_nodes(w->svc), addr, &n, cb, w);
}

/* the node combo: "addr - hostname" items (_cb_nodes_updated) */
static void fill_nodes(struct ks_stats_win *w)
{
    struct ks_nodes *nodes = ks_service_nodes(w->svc);
    int prev = gtk_combo_box_get_active(GTK_COMBO_BOX(w->ns_nodes));
    bool was = w->loading;
    w->loading = true;
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(w->ns_nodes));
    gtk_list_store_clear(GTK_LIST_STORE(m));
    for (size_t i = 0; i < nodes->len; i++) {
        const struct ks_node *n = nodes->items[i];
        const char *host = n->config != NULL ? n->config->name : "";
        char *lbl = host != NULL && host[0] != '\0' ? g_strdup_printf("%s - %s", n->addr, host)
                                                      : g_strdup(n->addr);
        gtk_combo_box_append_text(GTK_COMBO_BOX(w->ns_nodes), lbl);
        g_free(lbl);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_nodes),
                             prev >= 0 && (size_t)prev < nodes->len ? prev : 0);
    gtk_widget_set_visible(w->ns_nodes, nodes->len > 1);
    if (nodes->len == 0) {
        gtk_label_set_text(GTK_LABEL(w->ns_label), "");
        gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_interval), 0);
    }
    w->loading = was;
}

static const char *selected_node(struct ks_stats_win *w)
{
    struct ks_nodes *nodes = ks_service_nodes(w->svc);
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(w->ns_nodes));
    return i >= 0 && (size_t)i < nodes->len ? nodes->items[i]->addr : "";
}

/* _unmonitor_node_netstat() */
static void unmonitor(struct ks_stats_win *w, const char *addr)
{
    gtk_widget_hide(w->ns_label);
    gtk_label_set_text(GTK_LABEL(w->ns_label), "");
    if (addr[0] == '\0') {
        ks_debug("unmonitor_netstat_node: no nodes");
        return;
    }
    const struct ks_node *n = ks_nodes_get(ks_service_nodes(w->svc), addr);
    if (n != NULL && n->online)
        send_task(w, addr, PROTOCOL__ACTION__TASK_STOP,
                  "{\"name\": \"sockets-monitor\", \"data\": {}}", ks_sw_ntf_reply);
    w->ns_node[0] = '\0';
}

/* _monitor_node_netstat() */
static void monitor(struct ks_stats_win *w)
{
    gtk_widget_show(w->ns_label);
    char addr[KS_NODE_ADDR_MAX];
    g_strlcpy(addr, selected_node(w), sizeof(addr));
    if (addr[0] == '\0') {
        ks_debug("monitor_netstat_node: no nodes");
        gtk_label_set_text(GTK_LABEL(w->ns_label), "");
        return;
    }
    const struct ks_node *n = ks_nodes_get(ks_service_nodes(w->svc), addr);
    if (n == NULL || !n->online) {
        char *m = g_strdup_printf(_("%s node is not connected"), addr);
        gtk_label_set_text(GTK_LABEL(w->ns_label), m);
        g_free(m);
        return;
    }
    int ri = gtk_combo_box_get_active(GTK_COMBO_BOX(w->ns_interval));
    if (ri <= 0) {
        unmonitor(w, addr);
        return;
    }
    char *cfg = g_strdup_printf(
        _("{\"name\": \"sockets-monitor\", \"data\": {\"interval\": \"%s\", \"state\": %d, "
        "\"proto\": %d, \"family\": %d}}"),
        intervals[ri], value_of(w->ns_state, states, N(states)),
        value_of(w->ns_proto, protos, N(protos)), value_of(w->ns_family, families, N(families)));
    char *m = g_strdup_printf(_("loading in %s..."), intervals[ri]);
    gtk_label_set_text(GTK_LABEL(w->ns_label), m);
    g_free(m);
    g_strlcpy(w->ns_node, addr, sizeof(w->ns_node));
    send_task(w, addr, PROTOCOL__ACTION__TASK_START, cfg, on_reply);
    g_free(cfg);
}

void ks_sw_netstat_enter(struct ks_stats_win *w)
{
    fill_nodes(w);
    monitor(w);
}

void ks_sw_netstat_leave(struct ks_stats_win *w)
{
    char addr[KS_NODE_ADDR_MAX];
    g_strlcpy(addr, w->ns_node, sizeof(addr));
    unmonitor(w, addr);
    bool was = w->loading;
    w->loading = true;
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_nodes), 0);
    w->loading = was;
}

/* _cb_combo_netstat_changed() */
static void on_combo(GtkComboBox *c, gpointer ud)
{
    struct ks_stats_win *w = ud;
    if (w->loading)
        return;
    GtkWidget *cw = GTK_WIDGET(c);
    char addr[KS_NODE_ADDR_MAX];
    g_strlcpy(addr, w->ns_node, sizeof(addr));
    unmonitor(w, addr);
    if (gtk_combo_box_get_active(GTK_COMBO_BOX(w->ns_interval)) > 0)
        monitor(w);
    if (cw == w->ns_proto)
        ks_settings_set_int(w->settings, KEY_PROTO, gtk_combo_box_get_active(c));
    else if (cw == w->ns_family)
        ks_settings_set_int(w->settings, KEY_FAMILY, gtk_combo_box_get_active(c));
    else if (cw == w->ns_state)
        ks_settings_set_int(w->settings, KEY_STATE, gtk_combo_box_get_active(c));
}

void ks_sw_netstat_build(struct ks_stats_win *w, struct tabview *tv, GtkWidget *top)
{
    (void)tv;
    w->ns_interval = gtk_combo_box_new_text();
    for (int i = 0; i < N(intervals); i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(w->ns_interval), intervals[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_interval), 0);
    gtk_widget_set_tooltip_text(w->ns_interval, _("Refresh interval"));
    w->ns_nodes = gtk_combo_box_new_text();
    gtk_widget_set_no_show_all(w->ns_nodes, TRUE);
    w->ns_proto = combo_of(protos, N(protos), ks_settings_get_int(w->settings, KEY_PROTO, 0));
    w->ns_family = combo_of(families, N(families), ks_settings_get_int(w->settings, KEY_FAMILY, 0));
    w->ns_state = combo_of(states, N(states), ks_settings_get_int(w->settings, KEY_STATE, 0));
    w->ns_label = gtk_label_new("");
    gtk_widget_set_no_show_all(w->ns_label, TRUE);
    gtk_box_pack_start(GTK_BOX(top), w->ns_interval, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), w->ns_nodes, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), gtk_label_new(_("Protocol")), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), w->ns_proto, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), gtk_label_new(_("Family")), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), w->ns_family, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), gtk_label_new(_("State")), FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), w->ns_state, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(top), w->ns_label, FALSE, FALSE, 8);
    GtkWidget *cs[] = {w->ns_interval, w->ns_nodes, w->ns_proto, w->ns_family, w->ns_state};
    for (size_t i = 0; i < sizeof(cs) / sizeof(cs[0]); i++)
        g_signal_connect(cs[i], "changed", G_CALLBACK(on_combo), w);
}

/* _cb_table_double_clicked() on the netstat table: a column takes to the
 * detail of its value */
void ks_sw_netstat_activated(struct ks_stats_win *w, struct tabview *tv, gint64 row, int col)
{
    enum ks_tab tab;
    const char *data;
    if (col == COL_NET_DST_IP) {
        tab = KS_TAB_ADDRS;
        data = ks_sw_cell(tv, row, COL_NET_DST_IP);
    } else if (col == COL_NET_DST_PORT) {
        tab = KS_TAB_PORTS;
        data = ks_sw_cell(tv, row, COL_NET_DST_PORT);
    } else if (col == COL_NET_UID) {
        tab = KS_TAB_USERS;
        data = ks_sw_cell(tv, row, COL_NET_UID);
    } else if (col == COL_NET_PID) {
        if (w->ns_node[0] == '\0')
            return;
        char *pid = g_strdup(ks_sw_cell(tv, row, COL_NET_PID));
        char *node = g_strdup(w->ns_node);
        const char *pids[1] = {pid}, *nodes[1] = {node};
        ks_sw_proc_monitor(w, pids, nodes, 1);
        g_free(pid);
        g_free(node);
        return;
    } else {
        tab = KS_TAB_PROCS;
        data = ks_sw_cell(tv, row, COL_NET_PROC);
        if (data[0] == '\0')
            return;
    }
    char *copy = g_strdup(data);
    ks_sw_netstat_leave(w);
    ks_sw_enter_detail(w, tab, copy, NULL);
    g_free(copy);
}
