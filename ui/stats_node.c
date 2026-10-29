/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The nodes tab of the statistics window besides its table: the panel of
 * the selected node (the "node-monitor" task), the buttons of a node's
 * detail view and its actions menu. Port of _cb_table_clicked,
 * _monitor_selected_node, _unmonitor_deselected_node, _update_node_info,
 * _update_nodes_interception_status, _cb_node_start_clicked,
 * _cb_node_delete_clicked and _on_menu_node_export/import_clicked of
 * upstream ui/opensnitch/dialogs/stats.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/nodeinfo.h"
#include "ui/rulesops.h"
#include "ui/prefs.h"
#include "ui/stats_win_priv.h"
#include "ui/i18n.h"

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

static GtkWidget *markup_label(const char *text)
{
    GtkWidget *l = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(l), text);
    gtk_misc_set_alignment(GTK_MISC(l), 0.0f, 0.5f);
    gtk_label_set_line_wrap(GTK_LABEL(l), TRUE);
    return l;
}

static void set_markup(GtkWidget *l, const char *m)
{
    gtk_label_set_markup(GTK_LABEL(l), m);
}

/* _reset_node_info() */
static void reset_info(struct ks_stats_win *w, const char *status)
{
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->np_ram_p), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(w->np_ram_p), "");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->np_swap_p), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(w->np_swap_p), "");
    set_markup(w->np_procs, "");
    set_markup(w->np_load, "");
    set_markup(w->np_uptime, "");
    set_markup(w->np_swap_l, "");
    char *m = g_markup_escape_text(status, -1);
    set_markup(w->np_ram_l, m);
    g_free(m);
}

static void progress(GtkWidget *bar, int value, int max)
{
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), max > 0 ? (double)value / max : 0.0);
    char t[16];
    snprintf(t, sizeof(t), "%d%%", max > 0 ? (int)((double)value * 100.0 / max) : 0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(bar), t);
}

/* the replies of the node-monitor task: _cb_notification_callback() for
 * TASK_START */
static void on_task_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_stats_win *w = ud;
    if (strcmp(addr, w->monitored) != 0)
        return;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR) {
        /* upstream shows this in the netstat label only; here the panel says why
         * nothing comes (divergence 67) */
        reset_info(w, r->data);
        return;
    }
    struct ks_nodeinfo n;
    if (!ks_nodeinfo_parse(nz(r->data), &n)) {
        ks_warning("exception parsing taskStart data: %s", nz(r->data));
        return;
    }
    progress(w->np_ram_p, n.ram_value, n.ram_max);
    progress(w->np_swap_p, n.swap_value, n.swap_max);
    set_markup(w->np_ram_l, n.ram);
    set_markup(w->np_swap_l, n.swap);
    set_markup(w->np_procs, n.procs);
    set_markup(w->np_load, n.loadavg);
    set_markup(w->np_uptime, n.uptime);
}

static void task(struct ks_stats_win *w, const char *addr, Protocol__Action type)
{
    char *data = g_strdup_printf(
        _("{\"name\": \"node-monitor\", \"data\": {\"node\": \"%s\", \"interval\": \"5s\"}}"), addr);
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.type = type;
    n.data = data;
    ks_nodes_send(ks_service_nodes(w->svc), addr, &n, on_task_reply, w);
    g_free(data);
}

static bool connected(struct ks_stats_win *w, const char *addr)
{
    const struct ks_node *n = ks_nodes_get(ks_service_nodes(w->svc), addr);
    return n != NULL && n->online;
}

/* _monitor_selected_node() */
static void monitor(struct ks_stats_win *w, const char *addr, const char *uptime,
                    const char *host, const char *version, const char *kernel)
{
    if (!connected(w, addr)) {
        reset_info(w, "node not connected");
        return;
    }
    task(w, addr, PROTOCOL__ACTION__TASK_START);
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(w->np_ram_p));
    char *h = g_markup_escape_text(host, -1), *u = g_markup_escape_text(uptime, -1);
    char *v = g_markup_escape_text(version, -1), *k = g_markup_escape_text(kernel, -1);
    char *name = g_strdup_printf("<big><b>%s</b></big>", h);
    char *det = g_strdup_printf(_("<b>daemon uptime:</b> %s\n<b>Version:</b> %s\n<b>Kernel:</b> %s"),
                                u, v, k);
    set_markup(w->np_name, name);
    set_markup(w->np_details, det);
    set_markup(w->np_ram_l, "loading node information...");
    g_free(det);
    g_free(name);
    g_free(k);
    g_free(v);
    g_free(u);
    g_free(h);
}

/* _unmonitor_deselected_node() */
static void unmonitor(struct ks_stats_win *w, const char *addr)
{
    if (!connected(w, addr)) {
        reset_info(w, "node not connected");
        return;
    }
    task(w, addr, PROTOCOL__ACTION__TASK_STOP);
    set_markup(w->np_details, "");
}

void ks_sw_node_stop(struct ks_stats_win *w)
{
    if (w->monitored[0] != '\0')
        unmonitor(w, w->monitored);
    w->monitored[0] = '\0';
    gtk_widget_hide(w->np_box);
}

/* _cb_table_clicked() on the nodes table */
void ks_sw_node_clicked(struct ks_stats_win *w, struct tabview *tv, gint64 row)
{
    const char *addr = ks_sw_cell(tv, row, COL_NODE);
    char addr_copy[KS_NODE_ADDR_MAX];
    g_strlcpy(addr_copy, addr, sizeof(addr_copy));
    bool last_empty = w->monitored[0] == '\0';
    bool same = strcmp(w->monitored, addr_copy) == 0;
    bool do_unmonitor = same || !last_empty;
    bool do_monitor = last_empty || !same;
    if (do_unmonitor && !last_empty)
        unmonitor(w, w->monitored);
    if (do_monitor) {
        monitor(w, addr_copy, ks_sw_cell(tv, row, COL_N_UPTIME), ks_sw_cell(tv, row, COL_N_HOSTNAME),
                ks_sw_cell(tv, row, COL_N_VERSION), ks_sw_cell(tv, row, COL_N_KERNEL));
        g_strlcpy(w->monitored, addr_copy, sizeof(w->monitored));
        gtk_widget_set_no_show_all(w->np_box, FALSE);
        gtk_widget_show_all(w->np_box);
    } else {
        w->monitored[0] = '\0';
        gtk_widget_hide(w->np_box);
    }
}

/* ---- the buttons of a node's detail view ----------------------------------- */

static const char *detail_addr(struct ks_stats_win *w)
{
    struct tabview *tv = ks_sw_tab(w, KS_TAB_NODES);
    return tv->detail ? tv->data : "";
}

/* _cb_node_prefs_clicked() */
static void on_node_prefs(GtkButton *b, gpointer ud)
{
    struct ks_stats_win *w = ud;
    (void)b;
    ks_prefs_show_node(ks_sw_prefs(w), detail_addr(w));
}

/* _update_nodes_interception_status() */
void ks_sw_node_update_buttons(struct ks_stats_win *w)
{
    struct tabview *tv = ks_sw_tab(w, KS_TAB_NODES);
    const struct ks_node *n = tv->detail ? ks_nodes_get(ks_service_nodes(w->svc), tv->data) : NULL;
    bool show = tv->detail && n != NULL;
    gtk_widget_set_visible(w->node_start, show);
    gtk_widget_set_visible(w->node_prefs, show);
    gtk_widget_set_visible(w->node_delete, tv->detail);
    gtk_widget_set_visible(w->node_actions, show);
    if (show) {
        bool running = n->config != NULL && n->config->isfirewallrunning;
        bool was = w->loading;
        w->loading = true;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->node_start), running);
        w->loading = was;
    }
}

/* _cb_node_start_clicked() */
static void on_node_start(GtkToggleButton *b, gpointer ud)
{
    struct ks_stats_win *w = ud;
    if (w->loading)
        return;
    const char *addr = detail_addr(w);
    if (addr[0] == '\0')
        return;
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.data = (char *)(uintptr_t) "";
    n.type = gtk_toggle_button_get_active(b) ? PROTOCOL__ACTION__ENABLE_INTERCEPTION
                                              : PROTOCOL__ACTION__DISABLE_INTERCEPTION;
    ks_nodes_send(ks_service_nodes(w->svc), addr, &n, ks_sw_ntf_reply, w);
}

/* _cb_node_delete_clicked() */
static void on_node_delete(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_stats_win *w = ud;
    char addr[KS_NODE_ADDR_MAX];
    g_strlcpy(addr, detail_addr(w), sizeof(addr));
    if (addr[0] == '\0' || !ks_sw_confirm(w, "    You are about to delete this node.    "))
        return;
    const char *a[1] = {addr};
    if (!ks_db_run(ks_service_db(w->svc), "DELETE FROM nodes WHERE addr = ?", a, 1, NULL)) {
        char *m = g_strdup_printf(_("Error deleting node\n\n%s"), addr);
        ks_sw_message(w, GTK_MESSAGE_WARNING, m, "");
        g_free(m);
        return;
    }
    ks_service_node_delete(w->svc, addr);
    struct tabview *tv = ks_sw_tab(w, KS_TAB_NODES);
    gtk_button_clicked(GTK_BUTTON(tv->back)); /* cmd.click() */
    ks_sw_refresh(w);
}

/* _on_menu_node_export_clicked() */
static void on_node_export(GtkMenuItem *item, gpointer ud)
{
    (void)item;
    struct ks_stats_win *w = ud;
    char *dir = ks_sw_choose_dir(w, _("Select a directory to export rules"));
    if (dir == NULL)
        return;
    if (!ks_rops_export_all(ks_service_rules(w->svc), detail_addr(w), dir)) {
        ks_sw_message(w, GTK_MESSAGE_WARNING, _("Rules export error"), _("Error exporting rules"));
    } else {
        char *m = g_strdup_printf(_("Rules exported to %s"), dir);
        ks_sw_message(w, GTK_MESSAGE_INFO, _("Rules export"), m);
        g_free(m);
    }
    g_free(dir);
}

/* _on_menu_node_import_clicked() */
static void on_node_import(GtkMenuItem *item, gpointer ud)
{
    (void)item;
    struct ks_stats_win *w = ud;
    char *dir = ks_sw_choose_dir(w, _("Select a directory with rules to import (JSON files)"));
    if (dir == NULL)
        return;
    int n = ks_rops_import(ks_service_rules(w->svc), ks_service_nodes(w->svc), detail_addr(w),
                           dir, ks_sw_ntf_reply, w);
    if (n >= 0) {
        ks_sw_message(w, GTK_MESSAGE_INFO, _("Rules import"), _("Rules imported fine"));
        if (ks_sw_cur_tab(w)->tab == KS_TAB_RULES)
            ks_sw_refresh(w);
    } else {
        char *m = g_strdup_printf(_("Error importing rules from %s"), dir);
        ks_sw_message(w, GTK_MESSAGE_WARNING, _("Rules import error"), m);
        g_free(m);
    }
    g_free(dir);
}

static void on_actions_clicked(GtkButton *b, gpointer ud)
{
    struct ks_stats_win *w = ud;
    GtkWidget *menu = gtk_menu_new();
    GtkWidget *ex = gtk_menu_item_new_with_label(_("Export rules"));
    GtkWidget *im = gtk_menu_item_new_with_label(_("Import rules"));
    g_signal_connect(ex, "activate", G_CALLBACK(on_node_export), w);
    g_signal_connect(im, "activate", G_CALLBACK(on_node_import), w);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), ex);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), im);
    gtk_widget_show_all(menu);
    g_object_ref_sink(menu);
    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 1, gtk_get_current_event_time());
    (void)b;
}

/* ---- construction ----------------------------------------------------------- */

GtkWidget *ks_sw_node_build(struct ks_stats_win *w, struct tabview *tv, GtkWidget *top)
{
    (void)tv;
    w->node_start = gtk_toggle_button_new_with_label(_("Start/Stop"));
    gtk_widget_set_tooltip_text(w->node_start, _("Start or stop interception of this node"));
    w->node_prefs = gtk_button_new_from_stock(GTK_STOCK_PREFERENCES);
    gtk_widget_set_tooltip_text(w->node_prefs, _("Show the preferences of this node"));
    g_signal_connect(w->node_prefs, "clicked", G_CALLBACK(on_node_prefs), w);
    w->node_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);
    gtk_widget_set_tooltip_text(w->node_delete, _("Delete this node"));
    w->node_actions = gtk_button_new_with_label(_("Actions"));
    g_signal_connect(w->node_start, "toggled", G_CALLBACK(on_node_start), w);
    g_signal_connect(w->node_delete, "clicked", G_CALLBACK(on_node_delete), w);
    g_signal_connect(w->node_actions, "clicked", G_CALLBACK(on_actions_clicked), w);
    GtkWidget *btns[] = {w->node_actions, w->node_delete, w->node_prefs, w->node_start};
    for (size_t i = 0; i < 4; i++) {
        gtk_widget_set_no_show_all(btns[i], TRUE);
        gtk_box_pack_end(GTK_BOX(top), btns[i], FALSE, FALSE, 2);
    }

    /* the panel */
    w->np_box = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(w->np_box), 8);
    w->np_name = markup_label("<big><b>Node</b></big>");
    w->np_details = markup_label("");
    w->np_ram_l = markup_label("");
    w->np_ram_p = gtk_progress_bar_new();
    w->np_swap_l = markup_label("");
    w->np_swap_p = gtk_progress_bar_new();
    w->np_procs = markup_label("");
    w->np_load = markup_label("");
    w->np_uptime = markup_label("");
    GtkWidget *items[] = {w->np_name, w->np_details, w->np_ram_l,  w->np_ram_p,  w->np_swap_l,
                          w->np_swap_p, w->np_procs, w->np_load, w->np_uptime};
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++)
        gtk_box_pack_start(GTK_BOX(w->np_box), items[i], FALSE, FALSE, 2);
    gtk_widget_set_size_request(w->np_box, 260, -1);
    gtk_widget_set_no_show_all(w->np_box, TRUE);
    return w->np_box;
}
