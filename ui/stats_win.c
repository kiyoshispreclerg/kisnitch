/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/stats.py (the tabs: events,
 * nodes, rules, hosts, applications, addresses, ports, users) and
 * res/stats.ui. See stats_win.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/stats_win.h"
#include "ui/stats_win_priv.h"

#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/highlight.h"
#include "ui/netstat.h"
#include "ui/rules_editor.h"
#include "ui/rulesops.h"
#include "ui/statsdb.h"

/* Config.STATS_* keys */
#define KEY_LAST_TAB "statsDialog/last_tab"
#define KEY_FILTER_TEXT "statsDialog/general_filter_text"
#define KEY_FILTER_ACTION "statsDialog/general_filter_action"
#define KEY_LIMIT "statsDialog/general_limit_results"

/* The tabs the window has so far, in the order of the notebook. */
static const enum ks_tab tab_order[KS_NTABS] = {KS_TAB_MAIN,  KS_TAB_NODES, KS_TAB_RULES,
                                                KS_TAB_HOSTS, KS_TAB_PROCS, KS_TAB_ADDRS,
                                                KS_TAB_PORTS, KS_TAB_USERS, KS_TAB_NETSTAT};
#define NTABS KS_NTABS
static const char *const tab_titles[] = {"Events", "Nodes", "Rules", "Hosts",
                                         "Applications", "Addresses", "Ports", "Users",
                                         "Netstat"};

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

struct tabview *ks_sw_cur_tab(struct ks_stats_win *w)
{
    int i = gtk_notebook_get_current_page(GTK_NOTEBOOK(w->nb));
    return &w->tv[i >= 0 && i < NTABS ? i : 0];
}

static sqlite3 *dbh(struct ks_stats_win *w)
{
    return ks_db_handle(ks_service_db(w->svc));
}

/* ---- the query of a tab -------------------------------------------------- */

static int limit_idx(struct ks_stats_win *w)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_limit));
    return i < 0 ? 4 : i;
}

static char *tab_sql(struct ks_stats_win *w, struct tabview *tv)
{
    const char *filter = gtk_entry_get_text(GTK_ENTRY(w->filter));
    int lim = limit_idx(w);
    int action = gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_action));
    if (tv->detail)
        return ks_sq_detail(tv->tab, tv->data, tv->node, filter, tv->det_order_by,
                            tv->det_order_to, lim);
    if (tv->tab == KS_TAB_RULES) {
        /* the combo: 0 all, 1 permanent, 2 temporary, 3 alerts, 4.. a node */
        int sel = gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_rules));
        if (sel == 3)
            return ks_sq_alerts("1", 0, lim);
        if (sel >= 4) {
            gchar *node = gtk_combo_box_get_active_text(GTK_COMBO_BOX(w->combo_rules));
            char *q = ks_sq_rules(KS_RULES_NODE, node, filter, tv->order_by, tv->order_to, lim);
            g_free(node);
            return q;
        }
        if (sel == 1 || sel == 2)
            return ks_sq_rules(sel == 1 ? KS_RULES_PERMANENT : KS_RULES_TEMPORARY, NULL, filter,
                               tv->order_by, tv->order_to, lim);
    }
    return ks_sq_list(tv->tab, filter, action, tv->order_by, tv->order_to, lim);
}

/* ---- columns ------------------------------------------------------------- */

static void on_header_clicked(GtkTreeViewColumn *col, gpointer ud);
static void apply_columns_visibility(struct ks_stats_win *w, struct tabview *tv);

static int default_width(const char *name)
{
    if (strcmp(name, "Time") == 0 || strcmp(name, "LastConnection") == 0)
        return 200;
    if (strcmp(name, "Process") == 0 || strcmp(name, "Cmdline") == 0 ||
        strcmp(name, "what") == 0 || strcmp(name, "Description") == 0 ||
        strcmp(name, "Metadata") == 0)
        return 240;
    if (strcmp(name, "Hits") == 0 || strcmp(name, "hits") == 0 ||
        strcmp(name, "SrcPort") == 0 || strcmp(name, "DstPort") == 0 ||
        strcmp(name, "PID") == 0 || strcmp(name, "UserID") == 0 || strcmp(name, "Enabled") == 0)
        return 70;
    return 120;
}

/* ColorizedDelegate + the highlight plugin, with the default configurations */
static void highlight_cell(GtkTreeViewColumn *col, GtkCellRenderer *r, GtkTreeModel *m,
                           GtkTreeIter *it, gpointer ud)
{
    struct tabview *tv = ud;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), "idx"));
    gchar *text = NULL;
    gtk_tree_model_get(m, it, idx, &text, -1);
    struct ks_hl_style st = {NULL, false};
    bool hit = text != NULL && ks_highlight(ks_highlight_for_tab(tv->tab), idx, text, &st);
    g_free(text);
    /* a selected row keeps the selection's colors, as upstream paints it */
    bool selected = hit && gtk_tree_selection_iter_is_selected(
                               gtk_tree_view_get_selection(GTK_TREE_VIEW(tv->tree)), it);
    if (hit && !selected && st.color != NULL)
        g_object_set(r, "foreground", st.color, "foreground-set", TRUE, NULL);
    else
        g_object_set(r, "foreground-set", FALSE, NULL);
    g_object_set(r, "xalign", hit && st.center ? 0.5f : 0.0f, NULL);
}

static void build_columns(struct ks_stats_win *w, struct tabview *tv)
{
    struct ks_qmodel *q = ks_qstore_model(tv->store);
    GString *sig = g_string_new(NULL);
    for (int i = 0; i < ks_qmodel_cols(q); i++)
        g_string_append_printf(sig, "%s|", ks_qmodel_colname(q, i));
    if (tv->colsig != NULL && strcmp(tv->colsig, sig->str) == 0) {
        g_string_free(sig, TRUE);
        return;
    }
    g_free(tv->colsig);
    tv->colsig = g_string_free(sig, FALSE);

    GtkTreeView *view = GTK_TREE_VIEW(tv->tree);
    gtk_tree_view_set_fixed_height_mode(view, FALSE);
    GList *old = gtk_tree_view_get_columns(view);
    for (GList *l = old; l != NULL; l = l->next)
        gtk_tree_view_remove_column(view, l->data);
    g_list_free(old);
    for (int i = 0; i < ks_qmodel_cols(q); i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        g_object_set(r, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
        GtkTreeViewColumn *c =
            gtk_tree_view_column_new_with_attributes(ks_qmodel_colname(q, i), r, "text", i, NULL);
        g_object_set_data(G_OBJECT(c), "idx", GINT_TO_POINTER(i));
        gtk_tree_view_column_set_cell_data_func(c, r, highlight_cell, tv, NULL);
        gtk_tree_view_column_set_sizing(c, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(c, default_width(ks_qmodel_colname(q, i)));
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_clickable(c, TRUE);
        g_object_set_data(G_OBJECT(c), "idx", GINT_TO_POINTER(i));
        g_object_set_data(G_OBJECT(c), "tv", tv);
        g_object_set_data(G_OBJECT(c), "win", w);
        g_signal_connect(c, "clicked", G_CALLBACK(on_header_clicked), NULL);
        gtk_tree_view_append_column(view, c);
    }
    gtk_tree_view_set_fixed_height_mode(view, TRUE);
}

/* _cb_table_header_clicked(): ORDER BY <column> ASC/DESC */
static void on_header_clicked(GtkTreeViewColumn *col, gpointer ud)
{
    (void)ud;
    struct tabview *tv = g_object_get_data(G_OBJECT(col), "tv");
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(col), "win");
    int pos = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), "idx"));
    /* TODO upstream: no ordering by the network name of addresses */
    char by[16];
    snprintf(by, sizeof(by), "%d", pos + 1);
    char **ob = tv->detail ? &tv->det_order_by : &tv->order_by;
    int *ot = tv->detail ? &tv->det_order_to : &tv->order_to;
    bool same = strcmp(*ob, by) == 0;
    int to = same ? !*ot : 0;
    g_free(*ob);
    *ob = g_strdup(by);
    *ot = to;
    for (GList *l = gtk_tree_view_get_columns(GTK_TREE_VIEW(tv->tree)); l != NULL; l = l->next)
        gtk_tree_view_column_set_sort_indicator(l->data, FALSE);
    gtk_tree_view_column_set_sort_indicator(col, TRUE);
    gtk_tree_view_column_set_sort_order(col, to ? GTK_SORT_DESCENDING : GTK_SORT_ASCENDING);
    ks_sw_run_query(w, tv, false);
}

/* setQuery(): detach the model from its view, run the query, attach it. */
void ks_sw_run_query(struct ks_stats_win *w, struct tabview *tv, bool refresh_only)
{
    char *sql = tab_sql(w, tv);
    if (sql == NULL)
        return;
    GtkTreeView *view = GTK_TREE_VIEW(tv->tree);
    GtkTreePath *top = NULL;
    if (refresh_only && gtk_tree_view_get_visible_range(view, &top, NULL) == FALSE)
        top = NULL;

    gtk_tree_view_set_model(view, NULL);
    struct ks_qmodel *q = ks_qstore_model(tv->store);
    if (!ks_qmodel_set_query(q, sql))
        ks_error("stats: bad query: %s", sql);
    build_columns(w, tv);
    gtk_tree_view_set_model(view, GTK_TREE_MODEL(tv->store));
    apply_columns_visibility(w, tv);
    if (top != NULL) {
        gtk_tree_view_scroll_to_cell(view, top, NULL, TRUE, 0.0f, 0.0f);
        gtk_tree_path_free(top);
    }
    g_free(sql);

    if (tv->tab != KS_TAB_MAIN) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)ks_qmodel_rows(q));
        gtk_label_set_text(GTK_LABEL(w->rows_label), buf);
    } else {
        gtk_label_set_text(GTK_LABEL(w->rows_label), "");
    }
}

static bool rows_selected(struct tabview *tv)
{
    return gtk_tree_selection_count_selected_rows(
               gtk_tree_view_get_selection(GTK_TREE_VIEW(tv->tree))) > 0;
}

/* ---- detail views -------------------------------------------------------- */

/* _set_active_widgets(): the back button and the label of the detail */
static void set_detail(struct ks_stats_win *w, struct tabview *tv, bool on, const char *label)
{
    tv->detail = on;
    if (on)
        gtk_label_set_text(GTK_LABEL(tv->label), label);
    gtk_widget_set_visible(tv->back, on);
    gtk_widget_set_visible(tv->label, on);
    /* the clean button of rules and nodes is for the detail only */
    if (tv->tab == KS_TAB_RULES || tv->tab == KS_TAB_NODES)
        gtk_widget_set_visible(w->clean_button, on);
    else
        gtk_widget_set_visible(w->clean_button, TRUE);
    if (tv->tab == KS_TAB_RULES)
        gtk_widget_set_visible(w->combo_rules, !on);
    if (tv->tab == KS_TAB_NODES)
        ks_sw_node_update_buttons(w);
    if (tv->tab == KS_TAB_PROCS)
        gtk_widget_set_visible(w->proc_button, on);
    if (tv->tab == KS_TAB_RULES) {
        gtk_widget_set_visible(w->rule_edit, on);
        gtk_widget_set_visible(w->rule_delete, on);
    }
}

void ks_sw_enter_detail(struct ks_stats_win *w, enum ks_tab tab, const char *data,
                        const char *node)
{
    int idx = 0;
    for (int i = 0; i < NTABS; i++) {
        if (tab_order[i] == tab)
            idx = i;
    }
    struct tabview *tv = &w->tv[idx];
    snprintf(tv->data, sizeof(tv->data), "%s", data);
    snprintf(tv->node, sizeof(tv->node), "%s", nz(node));
    g_free(tv->det_order_by);
    /* _get_order("1") for most; the tab's own for nodes and rules */
    tv->det_order_by = g_strdup(tab == KS_TAB_NODES || tab == KS_TAB_RULES
                                    ? ks_sq_default_order_by(tab)
                                    : "1");
    tv->det_order_to = ks_sq_default_order_to(tab);
    w->loading = true;
    gtk_notebook_set_current_page(GTK_NOTEBOOK(w->nb), idx);
    w->loading = false;
    set_detail(w, tv, true, tab == KS_TAB_RULES ? data : data);
    ks_sw_run_query(w, tv, false);
}

static void on_back(GtkButton *b, gpointer ud)
{
    (void)b;
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tv->tree), "win");
    set_detail(w, tv, false, "");
    ks_sw_run_query(w, tv, false);
}

const char *ks_sw_cell(struct tabview *tv, gint64 row, int col)
{
    return ks_qmodel_cell(ks_qstore_model(tv->store), row, col);
}

static void on_rule_saved(void *ud)
{
    ks_sw_refresh(ud); /* _cb_app_rules_updated() */
}

struct ks_ruleed *ks_sw_ruleed(struct ks_stats_win *w)
{
    if (w->ruleed == NULL)
        w->ruleed = ks_ruleed_new(w->svc, GTK_WINDOW(w->win), on_rule_saved, w);
    return w->ruleed;
}

struct tabview *ks_sw_tab(struct ks_stats_win *w, enum ks_tab tab)
{
    for (int i = 0; i < NTABS; i++) {
        if (tab_order[i] == tab)
            return &w->tv[i];
    }
    return &w->tv[0];
}

GPtrArray *ks_sw_selected_rows(struct tabview *tv)
{
    GPtrArray *rows = g_ptr_array_new();
    GtkTreeModel *m;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tv->tree));
    GList *paths = gtk_tree_selection_get_selected_rows(sel, &m);
    struct ks_qmodel *q = ks_qstore_model(tv->store);
    int n = ks_qmodel_cols(q);
    for (GList *l = paths; l != NULL; l = l->next) {
        gint64 row = gtk_tree_path_get_indices(l->data)[0];
        char **cells = g_new0(char *, (gsize)n + 1);
        for (int c = 0; c < n; c++)
            cells[c] = g_strdup(ks_qmodel_cell(q, row, c));
        g_ptr_array_add(rows, cells);
    }
    g_list_free_full(paths, (GDestroyNotify)gtk_tree_path_free);
    g_ptr_array_set_free_func(rows, (GDestroyNotify)g_strfreev);
    return rows;
}

/* `str(c) not in cols` for the QSettings value of show_columns: a list is
 * "0, 2, 3" here (membership of the items); a lone value is a string, and
 * `in` then looks for a substring, as Python does */
static bool column_listed(const char *value, int c)
{
    char num[16];
    snprintf(num, sizeof(num), "%d", c);
    if (strchr(value, ',') == NULL)
        return strstr(value, num) != NULL;
    bool found = false;
    char **items = g_strsplit(value, ",", -1);
    for (char **p = items; *p != NULL; p++) {
        if (strcmp(g_strstrip(*p), num) == 0)
            found = true;
    }
    g_strfreev(items);
    return found;
}

/* _show_columns(): the node column is for more than one node, and the
 * events table shows the columns of statsDialog/show_columns */
static void apply_columns_visibility(struct ks_stats_win *w, struct tabview *tv)
{
    bool hide_node = ks_nodes_count(ks_service_nodes(w->svc)) < 2;
    char *show = tv->tab == KS_TAB_MAIN && !tv->detail
                     ? ks_settings_get_string(w->settings, "statsDialog/show_columns")
                     : NULL;
    GList *cols = gtk_tree_view_get_columns(GTK_TREE_VIEW(tv->tree));
    for (GList *l = cols; l != NULL; l = l->next) {
        int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(l->data), "idx"));
        bool node_col = (tv->tab == KS_TAB_MAIN && idx == COL_NODE) ||
                        (tv->tab == KS_TAB_RULES && !tv->detail && idx == COL_R_NODE);
        bool visible = !(node_col && hide_node);
        if (show != NULL && idx < 14)
            visible = column_listed(show, idx);
        gtk_tree_view_column_set_visible(l->data, visible);
    }
    g_list_free(cols);
    free(show);
}

/* _cb_main_table_double_clicked() and _cb_table_double_clicked() */
static void on_row_activated(GtkTreeView *view, GtkTreePath *path, GtkTreeViewColumn *col,
                             gpointer ud)
{
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(view), "win");
    gint64 row = gtk_tree_path_get_indices(path)[0];
    int c = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), "idx"));

    if (tv->tab == KS_TAB_MAIN) {
        if (c == COL_NODE) {
            ks_sw_enter_detail(w, KS_TAB_NODES, ks_sw_cell(tv, row, COL_NODE), NULL);
        } else if (c == COL_RULES) {
            ks_sw_enter_detail(w, KS_TAB_RULES, ks_sw_cell(tv, row, COL_RULES), ks_sw_cell(tv, row, COL_NODE));
        } else if (c == COL_DSTIP) {
            ks_sw_enter_detail(w, KS_TAB_ADDRS, ks_sw_cell(tv, row, COL_DSTIP), NULL);
        } else if (c == COL_DSTHOST) {
            if (ks_sw_cell(tv, row, COL_DSTHOST)[0] != '\0')
                ks_sw_enter_detail(w, KS_TAB_HOSTS, ks_sw_cell(tv, row, COL_DSTHOST), NULL);
        } else if (c == COL_DSTPORT) {
            ks_sw_enter_detail(w, KS_TAB_PORTS, ks_sw_cell(tv, row, COL_DSTPORT), NULL);
        } else if (c == COL_UID) {
            ks_sw_enter_detail(w, KS_TAB_USERS, ks_sw_cell(tv, row, COL_UID), NULL);
        } else if (c == COL_PID) {
            char *pid = g_strdup(ks_sw_cell(tv, row, COL_PID));
            char *node = g_strdup(ks_sw_cell(tv, row, COL_NODE));
            const char *pids[1] = {pid}, *nodes[1] = {node};
            ks_sw_proc_monitor(w, pids, nodes, 1);
            g_free(pid);
            g_free(node);
        } else {
            ks_sw_enter_detail(w, KS_TAB_PROCS, ks_sw_cell(tv, row, 11), NULL);
        }
        return;
    }
    if (tv->detail)
        return;
    if (tv->tab == KS_TAB_NETSTAT) {
        ks_sw_netstat_activated(w, tv, row, c);
        return;
    }
    if (tv->tab == KS_TAB_RULES) {
        if (gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_rules)) == 3) {
            ks_sw_show_alert(w, ks_sw_cell(tv, row, COL_TIME), ks_sw_cell(tv, row, COL_NODE));
            return;
        }
        ks_sw_enter_detail(w, KS_TAB_RULES, ks_sw_cell(tv, row, COL_R_NAME), ks_sw_cell(tv, row, COL_NODE));
    } else if (tv->tab == KS_TAB_NODES) {
        ks_sw_enter_detail(w, KS_TAB_NODES, ks_sw_cell(tv, row, COL_NODE), NULL);
    } else if (tv->tab > KS_TAB_RULES) {
        ks_sw_enter_detail(w, tv->tab, ks_sw_cell(tv, row, 0), NULL);
    }
}

/* ---- controls ------------------------------------------------------------ */

void ks_sw_refresh(struct ks_stats_win *w)
{
    ks_sw_run_query(w, ks_sw_cur_tab(w), true);
}

static void on_tab_switched(GtkNotebook *nb, gpointer page, guint idx, gpointer ud)
{
    (void)nb;
    (void)page;
    struct ks_stats_win *w = ud;
    if (w->loading)
        return;
    struct tabview *tv = &w->tv[idx < (guint)NTABS ? idx : 0];
    gtk_widget_set_visible(w->combo_action, tv->tab == KS_TAB_MAIN);
    if (w->last_tab == 1 && tv->tab != KS_TAB_NODES)
        ks_sw_node_stop(w);
    if (w->last_tab == 8 && tv->tab != KS_TAB_NETSTAT)
        ks_sw_netstat_leave(w);
    if (tv->tab == KS_TAB_RULES || tv->tab == KS_TAB_NODES)
        gtk_widget_set_visible(w->clean_button, tv->detail);
    else
        gtk_widget_set_visible(w->clean_button, TRUE);
    w->last_tab = (int)idx;
    ks_settings_set_int(w->settings, KEY_LAST_TAB, (int)idx);
    if (tv->tab == KS_TAB_NETSTAT)
        ks_sw_netstat_enter(w);
    ks_sw_run_query(w, tv, false);
}

static void on_filter_changed(GtkEditable *e, gpointer ud)
{
    struct ks_stats_win *w = ud;
    (void)e;
    const char *t = gtk_entry_get_text(GTK_ENTRY(w->filter));
    /* set_filter_line_color() */
    GdkColor green;
    if (t[0] != '\0') {
        gdk_color_parse("#55ff7f", &green);
        gtk_widget_modify_base(w->filter, GTK_STATE_NORMAL, &green);
        gtk_widget_modify_text(w->filter, GTK_STATE_NORMAL, NULL);
    } else {
        gtk_widget_modify_base(w->filter, GTK_STATE_NORMAL, NULL);
    }
    if (w->loading)
        return;
    if (ks_sw_cur_tab(w)->tab == KS_TAB_MAIN)
        ks_settings_set_string(w->settings, KEY_FILTER_TEXT, t);
    ks_sw_run_query(w, ks_sw_cur_tab(w), false);
}

static void on_limit_changed(GtkComboBox *c, gpointer ud)
{
    struct ks_stats_win *w = ud;
    (void)c;
    if (w->loading)
        return;
    ks_settings_set_int(w->settings, KEY_LIMIT, gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_limit)));
    ks_sw_run_query(w, ks_sw_cur_tab(w), false);
}

static void on_action_changed(GtkComboBox *c, gpointer ud)
{
    struct ks_stats_win *w = ud;
    (void)c;
    if (w->loading || ks_sw_cur_tab(w)->tab != KS_TAB_MAIN)
        return;
    ks_settings_set_int(w->settings, KEY_FILTER_ACTION,
                        gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_action)));
    ks_sw_run_query(w, ks_sw_cur_tab(w), false);
}

static void on_rules_combo(GtkComboBox *c, gpointer ud)
{
    struct ks_stats_win *w = ud;
    (void)c;
    if (!w->loading)
        ks_sw_run_query(w, &w->tv[2], false);
}

/* _del_by_field(): the item's row of its table and the events that name it */
bool ks_sw_del_by_field(struct ks_stats_win *w, enum ks_tab tab, const char *value)
{
    struct ks_db *db = ks_service_db(w->svc);
    const char *field = "dst_host";
    switch (tab) {
    case KS_TAB_NODES: field = "node"; break;
    case KS_TAB_PROCS: field = "process"; break;
    case KS_TAB_ADDRS: field = "dst_ip"; break;
    case KS_TAB_PORTS: field = "dst_port"; break;
    case KS_TAB_USERS: field = "uid"; break;
    default: break;
    }
    const char *event_value = value;
    char uid[64];
    if (tab == KS_TAB_USERS) {
        /* the row says "name (uid)", the events have the uid (upstream
         * compares them with the whole text and deletes nothing: divergence 68) */
        const char *open = strrchr(value, '(');
        if (open != NULL) {
            snprintf(uid, sizeof(uid), "%s", open + 1);
            char *close = strchr(uid, ')');
            if (close != NULL)
                *close = '\0';
            event_value = uid;
        }
    }
    const char *a[1] = {value};
    char sql[160];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE what = ?", ks_sq_table_name(tab));
    bool ok1 = ks_db_run(db, sql, a, 1, NULL);
    snprintf(sql, sizeof(sql), "DELETE FROM connections WHERE %s = ?", field);
    a[0] = event_value;
    bool ok2 = ks_db_run(db, sql, a, 1, NULL);
    return ok1 && ok2;
}

/* _cb_clean_sql_clicked() */
static void on_clean(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_stats_win *w = ud;
    struct tabview *tv = ks_sw_cur_tab(w);
    struct ks_db *db = ks_service_db(w->svc);
    if (tv->tab == KS_TAB_RULES)
        ks_db_empty_rule(db, tv->data);
    else if (tv->detail)
        ks_sw_del_by_field(w, tv->tab, tv->data);
    else
        ks_db_clean(db, ks_sq_table_name(tv->tab));
    ks_sw_refresh(w);
}

static void on_start(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_stats_win *w = ud;
    if (w->loading)
        return;
    struct ks_service_state st = ks_service_state(w->svc);
    if (!st.connected) {
        /* _cb_start_clicked(): nothing to start */
        ks_stats_win_status_changed(w);
        return;
    }
    ks_service_toggle_interception(w->svc);
}

/* ---- construction -------------------------------------------------------- */

/* _cb_new_rule_clicked() */
static void on_new_rule(GtkButton *b, gpointer ud)
{
    (void)b;
    ks_ruleed_new_rule(ks_sw_ruleed(ud));
}

static GtkWidget *label_pair(GtkWidget *box, const char *name, GtkWidget **val)
{
    GtkWidget *l = gtk_label_new(name);
    gtk_box_pack_start(GTK_BOX(box), l, FALSE, FALSE, 4);
    *val = gtk_label_new("-");
    gtk_misc_set_alignment(GTK_MISC(*val), 0.0f, 0.5f);
    gtk_box_pack_start(GTK_BOX(box), *val, FALSE, FALSE, 4);
    return l;
}

/* _cb_edit_rule_clicked() */
static void on_rule_edit(GtkButton *b, gpointer ud)
{
    (void)b;
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tv->tree), "win");
    ks_ruleed_edit_rule(ks_sw_ruleed(w), tv->node, tv->data);
}

/* _cb_del_rule_clicked() */
static void on_rule_delete(GtkButton *b, gpointer ud)
{
    (void)b;
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tv->tree), "win");
    if (!ks_sw_confirm(w, "    You are about to delete this rule.    "))
        return;
    ks_rops_delete(ks_service_rules(w->svc), ks_service_nodes(w->svc), tv->data, tv->node,
                   ks_sw_ntf_reply, w);
    gtk_button_clicked(GTK_BUTTON(tv->back)); /* cmd.click() */
    ks_sw_refresh(w);
}

/* _cb_proc_details_clicked(): {pid: node} of every row of the table */
static void on_proc_details(GtkButton *b, gpointer ud)
{
    (void)b;
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tv->tree), "win");
    struct ks_qmodel *q = ks_qstore_model(tv->store);
    GPtrArray *pids = g_ptr_array_new_with_free_func(g_free);
    GPtrArray *nodes = g_ptr_array_new_with_free_func(g_free);
    for (gint64 r = 0; r < ks_qmodel_rows(q); r++) {
        const char *pid = ks_qmodel_cell(q, r, COL_PROC_PID);
        gboolean seen = FALSE;
        for (guint i = 0; i < pids->len; i++) {
            if (strcmp(g_ptr_array_index(pids, i), pid) == 0)
                seen = TRUE;
        }
        if (seen)
            continue;
        g_ptr_array_add(pids, g_strdup(pid));
        g_ptr_array_add(nodes, g_strdup(ks_qmodel_cell(q, r, COL_NODE)));
    }
    if (pids->len > 0)
        ks_sw_proc_monitor(w, (const char *const *)pids->pdata, (const char *const *)nodes->pdata,
                           pids->len);
    g_ptr_array_free(pids, TRUE);
    g_ptr_array_free(nodes, TRUE);
}

/* _cb_table_clicked(): a click on a row of the nodes table */
static gboolean on_nodes_click(GtkWidget *tree, GdkEventButton *ev, gpointer ud)
{
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tree), "win");
    if (ev->button != 1 || ev->type != GDK_BUTTON_PRESS || tv->detail)
        return FALSE;
    GtkTreePath *path = NULL;
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tree), (gint)ev->x, (gint)ev->y, &path, NULL,
                                      NULL, NULL)) {
        ks_sw_node_clicked(w, tv, gtk_tree_path_get_indices(path)[0]);
        gtk_tree_path_free(path);
    }
    return FALSE;
}

static void build_tab(struct ks_stats_win *w, int i)
{
    struct tabview *tv = &w->tv[i];
    tv->tab = tab_order[i];
    tv->order_by = g_strdup(ks_sq_default_order_by(tv->tab));
    tv->order_to = ks_sq_default_order_to(tv->tab);
    tv->det_order_by = g_strdup("1");
    tv->det_order_to = ks_sq_default_order_to(tv->tab);
    tv->store = ks_qstore_new(dbh(w));

    tv->page = gtk_vbox_new(FALSE, 2);
    GtkWidget *top = gtk_hbox_new(FALSE, 4);
    tv->back = gtk_button_new_from_stock(GTK_STOCK_GO_BACK);
    tv->label = gtk_label_new("");
    gtk_label_set_selectable(GTK_LABEL(tv->label), TRUE);
    gtk_box_pack_start(GTK_BOX(top), tv->back, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), tv->label, FALSE, FALSE, 4);
    if (tv->tab == KS_TAB_RULES) {
        w->combo_rules = gtk_combo_box_new_text();
        static const char *const items[] = {"All applications", "Permanent", "Temporary",
                                            "Alerts"};
        for (size_t k = 0; k < sizeof(items) / sizeof(items[0]); k++)
            gtk_combo_box_append_text(GTK_COMBO_BOX(w->combo_rules), items[k]);
        gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_rules), 0);
        g_signal_connect(w->combo_rules, "changed", G_CALLBACK(on_rules_combo), w);
        gtk_box_pack_start(GTK_BOX(top), w->combo_rules, FALSE, FALSE, 4);
    }
    GtkWidget *panel = NULL;
    if (tv->tab == KS_TAB_NODES)
        panel = ks_sw_node_build(w, tv, top);
    if (tv->tab == KS_TAB_NETSTAT) {
        ks_sw_netstat_build(w, tv, top);
        ks_qmodel_set_mapper(ks_qstore_model(tv->store), ks_netstat_display);
    }
    if (tv->tab == KS_TAB_RULES) {
        /* editRuleButton and delRuleButton, in the detail view */
        w->rule_edit = gtk_button_new_from_stock(GTK_STOCK_EDIT);
        w->rule_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);
        gtk_widget_set_no_show_all(w->rule_edit, TRUE);
        gtk_widget_set_no_show_all(w->rule_delete, TRUE);
        g_signal_connect(w->rule_edit, "clicked", G_CALLBACK(on_rule_edit), tv);
        g_signal_connect(w->rule_delete, "clicked", G_CALLBACK(on_rule_delete), tv);
        gtk_box_pack_end(GTK_BOX(top), w->rule_delete, FALSE, FALSE, 2);
        gtk_box_pack_end(GTK_BOX(top), w->rule_edit, FALSE, FALSE, 2);
    }
    if (tv->tab == KS_TAB_PROCS) {
        /* cmdProcDetails: the process details of every pid of the detail */
        w->proc_button = gtk_button_new_with_label("Process details");
        gtk_widget_set_no_show_all(w->proc_button, TRUE);
        g_signal_connect(w->proc_button, "clicked", G_CALLBACK(on_proc_details), tv);
        gtk_box_pack_end(GTK_BOX(top), w->proc_button, FALSE, FALSE, 2);
    }
    gtk_box_pack_start(GTK_BOX(tv->page), top, FALSE, FALSE, 2);

    tv->tree = gtk_tree_view_new();
    g_object_set_data(G_OBJECT(tv->tree), "win", w);
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(tv->tree), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(tv->tree), TRUE);
    gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(tv->tree)),
                                GTK_SELECTION_MULTIPLE);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), tv->tree);
    if (panel != NULL) {
        /* the splitter of the nodes tab: table | panel of the selected node */
        GtkWidget *paned = gtk_hpaned_new();
        gtk_paned_pack1(GTK_PANED(paned), sw, TRUE, FALSE);
        gtk_paned_pack2(GTK_PANED(paned), panel, FALSE, FALSE);
        gtk_box_pack_start(GTK_BOX(tv->page), paned, TRUE, TRUE, 0);
        g_signal_connect(tv->tree, "button-press-event", G_CALLBACK(on_nodes_click), tv);
    } else {
        gtk_box_pack_start(GTK_BOX(tv->page), sw, TRUE, TRUE, 0);
    }
    g_signal_connect(tv->back, "clicked", G_CALLBACK(on_back), tv);
    g_signal_connect(tv->tree, "row-activated", G_CALLBACK(on_row_activated), tv);
    ks_sw_menu_attach(w, tv);
}

struct ks_stats_win *ks_stats_win_new(struct ks_service *svc, struct ks_settings *settings,
                                      struct ks_desktop *desktop)
{
    struct ks_stats_win *w = g_new0(struct ks_stats_win, 1);
    w->svc = svc;
    w->settings = settings;
    w->desktop = desktop;
    w->loading = true;

    w->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(w->win), "Kisnitch Network Statistics " KS_UPSTREAM_VERSION);
    {
        /* not bigger than the screen */
        GdkScreen *sc = gdk_screen_get_default();
        int sw = sc ? gdk_screen_get_width(sc) : 1100, sh = sc ? gdk_screen_get_height(sc) : 700;
        gtk_window_set_default_size(GTK_WINDOW(w->win), sw > 1140 ? 1100 : sw - 20,
                                    sh > 700 ? 640 : sh - 60);
    }
    /* closeEvent(): hide, don't quit */
    g_signal_connect(w->win, "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), NULL);
    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 4);
    gtk_container_add(GTK_CONTAINER(w->win), vbox);

    /* the header: status and counters */
    GtkWidget *hdr = gtk_hbox_new(FALSE, 4);
    w->start_button = gtk_toggle_button_new_with_label("Start/Stop");
    gtk_widget_set_tooltip_text(w->start_button, "Start or Stop interception");
    g_signal_connect(w->start_button, "clicked", G_CALLBACK(on_start), w);
    gtk_box_pack_start(GTK_BOX(hdr), w->start_button, FALSE, FALSE, 4);
    GtkWidget *newrule = gtk_button_new_from_stock(GTK_STOCK_NEW);
    gtk_widget_set_tooltip_text(newrule, "Create a new rule");
    g_signal_connect(newrule, "clicked", G_CALLBACK(on_new_rule), w);
    gtk_box_pack_start(GTK_BOX(hdr), newrule, FALSE, FALSE, 4);
    GtkWidget *l;
    l = label_pair(hdr, "Status", &w->status_label);
    (void)l;
    label_pair(hdr, "Connections", &w->l_cons);
    label_pair(hdr, "Dropped", &w->l_dropped);
    label_pair(hdr, "Uptime", &w->l_uptime);
    label_pair(hdr, "Rules", &w->l_rules);
    label_pair(hdr, "Daemon version", &w->l_ver);
    gtk_box_pack_start(GTK_BOX(vbox), hdr, FALSE, FALSE, 0);

    /* the navigation bar */
    GtkWidget *nav = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(nav), gtk_label_new("Filter"), FALSE, FALSE, 4);
    w->combo_action = gtk_combo_box_new_text();
    static const char *const acts[] = {"-", "Allow", "Deny", "Reject"};
    for (size_t k = 0; k < 4; k++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(w->combo_action), acts[k]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_action), 0);
    gtk_box_pack_start(GTK_BOX(nav), w->combo_action, FALSE, FALSE, 0);
    w->filter = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(nav), w->filter, TRUE, TRUE, 0);
    w->rows_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(nav), w->rows_label, FALSE, FALSE, 8);
    w->combo_limit = gtk_combo_box_new_text();
    static const char *const lims[] = {"50", "100", "200", "300", "no limit"};
    for (size_t k = 0; k < KS_SQ_LIMITS; k++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(w->combo_limit), lims[k]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_limit), 0);
    gtk_box_pack_start(GTK_BOX(nav), w->combo_limit, FALSE, FALSE, 0);
    w->clean_button = gtk_button_new_from_stock(GTK_STOCK_CLEAR);
    gtk_widget_set_tooltip_text(w->clean_button, "Delete all intercepted events");
    g_signal_connect(w->clean_button, "clicked", G_CALLBACK(on_clean), w);
    gtk_box_pack_start(GTK_BOX(nav), w->clean_button, FALSE, FALSE, 0);

    w->nb = gtk_notebook_new();
    for (int i = 0; i < NTABS; i++) {
        build_tab(w, i);
        gtk_notebook_append_page(GTK_NOTEBOOK(w->nb), w->tv[i].page,
                                 gtk_label_new(tab_titles[i]));
    }
    gtk_box_pack_start(GTK_BOX(vbox), w->nb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), nav, FALSE, FALSE, 0);

    /* _load_settings() */
    int a = ks_settings_get_int(settings, KEY_FILTER_ACTION, 0);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_action), a >= 0 && a < 4 ? a : 0);
    int lim = ks_settings_get_int(settings, KEY_LIMIT, 0);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_limit), lim >= 0 && lim < KS_SQ_LIMITS ? lim : 0);
    char *ft = ks_settings_get_string(settings, KEY_FILTER_TEXT);
    if (ft != NULL)
        gtk_entry_set_text(GTK_ENTRY(w->filter), ft);
    free(ft);
    int tab = ks_settings_get_int(settings, KEY_LAST_TAB, 0);

    g_signal_connect(w->nb, "switch-page", G_CALLBACK(on_tab_switched), w);
    g_signal_connect(w->filter, "changed", G_CALLBACK(on_filter_changed), w);
    g_signal_connect(w->combo_limit, "changed", G_CALLBACK(on_limit_changed), w);
    g_signal_connect(w->combo_action, "changed", G_CALLBACK(on_action_changed), w);

    gtk_widget_show_all(vbox);
    for (int i = 0; i < NTABS; i++)
        set_detail(w, &w->tv[i], false, "");
    gtk_notebook_set_current_page(GTK_NOTEBOOK(w->nb), tab >= 0 && tab < NTABS ? tab : 0);
    gtk_widget_set_visible(w->combo_action, tab == 0 || tab >= NTABS);
    w->loading = false;
    ks_stats_win_status_changed(w);
    return w;
}

void ks_stats_win_free(struct ks_stats_win *w)
{
    if (w == NULL)
        return;
    ks_procdlg_free(w->proc);
    ks_ruleed_free(w->ruleed);
    gtk_widget_destroy(w->win);
    for (int i = 0; i < NTABS; i++) {
        g_object_unref(w->tv[i].store);
        g_free(w->tv[i].order_by);
        g_free(w->tv[i].det_order_by);
        g_free(w->tv[i].colsig);
    }
    g_free(w);
}

void ks_stats_win_show(struct ks_stats_win *w)
{
    gtk_window_present(GTK_WINDOW(w->win));
    gtk_widget_set_visible(w->combo_action, ks_sw_cur_tab(w)->tab == KS_TAB_MAIN);
    ks_sw_refresh(w);
}

/* _on_update_triggered() */
void ks_stats_win_update(struct ks_stats_win *w, const Protocol__Statistics *st, bool refresh)
{
    /* do not update any tab if the window is not visible */
    if (!gtk_widget_get_visible(w->win))
        return;
    if (st == NULL) {
        gtk_label_set_text(GTK_LABEL(w->l_ver), "");
        gtk_label_set_text(GTK_LABEL(w->l_uptime), "");
        gtk_label_set_text(GTK_LABEL(w->l_rules), "");
        gtk_label_set_text(GTK_LABEL(w->l_cons), "");
        gtk_label_set_text(GTK_LABEL(w->l_dropped), "");
    } else {
        gtk_label_set_text(GTK_LABEL(w->l_ver), nz(st->daemon_version));
        if (ks_nodes_count(ks_service_nodes(w->svc)) <= 1) {
            char b[64];
            ks_statsdb_timedelta(st->uptime, b, sizeof(b));
            gtk_label_set_text(GTK_LABEL(w->l_uptime), b);
            snprintf(b, sizeof(b), "%llu", (unsigned long long)st->rules);
            gtk_label_set_text(GTK_LABEL(w->l_rules), b);
            snprintf(b, sizeof(b), "%llu", (unsigned long long)st->connections);
            gtk_label_set_text(GTK_LABEL(w->l_cons), b);
            snprintf(b, sizeof(b), "%llu", (unsigned long long)st->dropped);
            gtk_label_set_text(GTK_LABEL(w->l_dropped), b);
        } else {
            gtk_label_set_text(GTK_LABEL(w->l_uptime), "");
            gtk_label_set_text(GTK_LABEL(w->l_rules), "");
            gtk_label_set_text(GTK_LABEL(w->l_cons), "");
            gtk_label_set_text(GTK_LABEL(w->l_dropped), "");
        }
    }
    if (refresh && !rows_selected(ks_sw_cur_tab(w)))
        ks_sw_refresh(w);
}

/* update_status() / _update_status_label() */
void ks_stats_win_status_changed(struct ks_stats_win *w)
{
    struct ks_service_state st = ks_service_state(w->svc);
    const char *text;
    const char *color;
    bool running;
    if (!st.connected) {
        text = "Not running";
        color = "red";
        running = false;
    } else if (st.fw_enabled) {
        text = "Running";
        color = "green";
        running = true;
    } else {
        text = "Disabled";
        color = "#ce5c00";
        running = false;
    }
    char *m = g_markup_printf_escaped("<span foreground=\"%s\">%12s</span>", color, text);
    gtk_label_set_markup(GTK_LABEL(w->status_label), m);
    g_free(m);
    w->loading = true;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->start_button), running);
    w->loading = false;
    gtk_widget_set_sensitive(w->start_button, st.connected);
}
