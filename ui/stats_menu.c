/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The context menus of the statistics window, Ctrl+C and Del, the export
 * of rules, and the small dialogs: port of _configure_events_contextual_menu,
 * _configure_rules_contextual_menu, _configure_alerts_contextual_menu,
 * _table_menu_* , _copy_selected_rows, _display_alert_info and
 * ConnDetails of upstream ui/opensnitch/dialogs/stats.py and conndetails.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/pycsv.h"
#include "ui/rulesops.h"
#include "ui/stats_win_priv.h"
#include "ui/statsdb.h"

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

/* ---- small dialogs -------------------------------------------------------- */

void ks_sw_message(struct ks_stats_win *w, GtkMessageType type, const char *primary,
                   const char *secondary)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(w->win), GTK_DIALOG_DESTROY_WITH_PARENT,
                                          type, GTK_BUTTONS_OK, "%s", primary);
    if (secondary != NULL && secondary[0] != '\0')
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", secondary);
    g_signal_connect_swapped(d, "response", G_CALLBACK(gtk_widget_destroy), d);
    gtk_widget_show(d);
}

bool ks_sw_confirm(struct ks_stats_win *w, const char *primary)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(w->win), GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_WARNING, GTK_BUTTONS_YES_NO, "%s", primary);
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", "Are you sure?");
    int r = gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return r == GTK_RESPONSE_YES;
}

char *ks_sw_choose_dir(struct ks_stats_win *w, const char *title)
{
    GtkWidget *d = gtk_file_chooser_dialog_new(
        title, GTK_WINDOW(w->win), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, GTK_STOCK_CANCEL,
        GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(d), g_get_home_dir());
    char *dir = NULL;
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT)
        dir = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
    gtk_widget_destroy(d);
    return dir;
}

/* the reply of a notification we sent: _cb_notification_callback() */
void ks_sw_ntf_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_stats_win *w = ud;
    (void)addr;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR)
        ks_sw_message(w, GTK_MESSAGE_WARNING, "Error:", nz(r->data));
    else
        ks_debug("notification %llu: reply %s", (unsigned long long)r->id, nz(r->data));
}

/* InfoWindow: a small window with a text */
static void show_info(struct ks_stats_win *w, const char *title, const char *markup)
{
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), title);
    gtk_window_set_transient_for(GTK_WINDOW(win), GTK_WINDOW(w->win));
    gtk_window_set_type_hint(GTK_WINDOW(win), GDK_WINDOW_TYPE_HINT_UTILITY);
    gtk_window_set_default_size(GTK_WINDOW(win), 420, 340);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_MOUSE);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    GtkWidget *l = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(l), markup);
    gtk_label_set_selectable(GTK_LABEL(l), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(l), TRUE);
    gtk_misc_set_alignment(GTK_MISC(l), 0.0f, 0.0f);
    gtk_misc_set_padding(GTK_MISC(l), 8, 8);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(sw), l);
    gtk_container_add(GTK_CONTAINER(win), sw);
    gtk_widget_show_all(win);
    /* a selectable label starts with everything selected */
    gtk_label_select_region(GTK_LABEL(l), 0, 0);
}

static sqlite3_stmt *prepare(struct ks_stats_win *w, const char *sql, const char *a, const char *b)
{
    sqlite3_stmt *st;
    sqlite3 *h = ks_db_handle(ks_service_db(w->svc));
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, a, -1, SQLITE_TRANSIENT);
    if (b != NULL)
        sqlite3_bind_text(st, 2, b, -1, SQLITE_TRANSIENT);
    return st;
}

static char *col(sqlite3_stmt *st, int i)
{
    const char *t = (const char *)sqlite3_column_text(st, i);
    return g_markup_escape_text(t != NULL ? t : "", -1);
}

/* ConnDetails.showByField("time", value): fields in ConnFields order */
void ks_sw_show_conn_details(struct ks_stats_win *w, const char *time)
{
    sqlite3_stmt *st = prepare(w, "SELECT * FROM connections WHERE time=?", time, NULL);
    if (st == NULL)
        return;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return;
    }
    char *tm = col(st, 0), *node = col(st, 1), *proto = col(st, 3), *sip = col(st, 4);
    char *sport = col(st, 5), *dip = col(st, 6), *dhost = col(st, 7), *dport = col(st, 8);
    char *pid = col(st, 10), *proc = col(st, 11), *cmd = col(st, 12), *cwd = col(st, 13);
    char *rule = col(st, 14);
    const char *action_raw = (const char *)sqlite3_column_text(st, 2);
    const char *node_raw = (const char *)sqlite3_column_text(st, 1);
    const char *uid_raw = (const char *)sqlite3_column_text(st, 9);
    char *action = g_markup_escape_text(action_raw ? action_raw : "", -1);
    char *up = g_ascii_strup(action, -1);
    char *proto_up = g_ascii_strup(proto, -1);
    char uidbuf[256];
    snprintf(uidbuf, sizeof(uidbuf), "%s", nz(uid_raw));
    if (node_raw != NULL && strncmp(node_raw, "unix", 4) == 0) /* Nodes.is_local() */
        ks_statsdb_user_id(nz(uid_raw), uidbuf, sizeof(uidbuf));
    char *uid = g_markup_escape_text(uidbuf, -1);
    char *text = g_strdup_printf(
        "<b>%s</b>\n\n<b>Time:</b> %s\n\n<b>Process:</b>\n%s\n<b>Cmdline:</b>\n%s\n"
        "<b>CWD:</b>\n%s\n\n<b>UID:</b> %s <b>PID:</b> %s\n\n<b>Node:</b> %s\n\n"
        "<b>%s</b> %s:%s -> %s (%s):%s\n\n<b>Rule:</b>\n%s",
        up, tm, proc, cmd, cwd, uid, pid, node, proto_up, sport, sip, dip, dhost, dport, rule);
    sqlite3_finalize(st);
    show_info(w, "Connection details", text);
    g_free(text);
    g_free(uid);
    g_free(proto_up);
    g_free(up);
    g_free(action);
    g_free(rule);
    g_free(cwd);
    g_free(cmd);
    g_free(proc);
    g_free(pid);
    g_free(dport);
    g_free(dhost);
    g_free(dip);
    g_free(sport);
    g_free(sip);
    g_free(proto);
    g_free(node);
    g_free(tm);
}

/* _display_alert_info(): AlertFields order */
void ks_sw_show_alert(struct ks_stats_win *w, const char *time, const char *node)
{
    sqlite3_stmt *st = prepare(w, "SELECT * FROM alerts WHERE time=? AND node=?", time, node);
    if (st == NULL)
        return;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return;
    }
    char *t = col(st, 0), *n = col(st, 1), *type = col(st, 2), *prio = col(st, 4);
    char *what = col(st, 5), *body = col(st, 6);
    char *text = g_strdup_printf("<b>%s</b>\n<b>Node:</b> %s\n<b>Type:</b> %s \xe2\x80\x93 "
                                 "<b>Severity:</b> %s\n\n<b>%s</b>\n\n%s\n\n---",
                                 t, n, type, prio, what, body);
    sqlite3_finalize(st);
    show_info(w, "Alert", text);
    g_free(text);
    g_free(body);
    g_free(what);
    g_free(prio);
    g_free(type);
    g_free(n);
    g_free(t);
}

/* ---- selection ------------------------------------------------------------ */

static void clear_selection(struct tabview *tv)
{
    gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(tv->tree)));
}

static bool alerts_shown(struct ks_stats_win *w, struct tabview *tv)
{
    return tv->tab == KS_TAB_RULES && !tv->detail &&
           gtk_combo_box_get_active(GTK_COMBO_BOX(w->combo_rules)) == 3;
}

/* ---- Ctrl+C --------------------------------------------------------------- */

/* _copy_selected_rows(): the selected rows as CSV */
void ks_sw_copy_selected(struct ks_stats_win *w)
{
    struct tabview *tv = ks_sw_cur_tab(w);
    GPtrArray *rows = ks_sw_selected_rows(tv);
    if (rows->len > 0) {
        GString *g = g_string_new(NULL);
        int n = ks_qmodel_cols(ks_qstore_model(tv->store));
        for (guint i = 0; i < rows->len; i++)
            ks_pycsv_row(g, (const char *const *)g_ptr_array_index(rows, i), n);
        gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), g->str, -1);
        g_string_free(g, TRUE);
    }
    g_ptr_array_free(rows, TRUE);
}

/* ---- the rules menu --------------------------------------------------------- */

struct mctx {
    struct ks_stats_win *w;
    struct tabview *tv;
    GPtrArray *rows; /* of char ** */
};

static void mctx_free(gpointer p)
{
    struct mctx *c = p;
    g_ptr_array_free(c->rows, TRUE);
    g_free(c);
}

static char **row_at(struct mctx *c, guint i)
{
    return g_ptr_array_index(c->rows, i);
}

static void after(struct mctx *c)
{
    /* the menu's `finally`: clear the selection and refresh */
    clear_selection(c->tv);
    ks_sw_refresh(c->w);
}

static void for_rows(struct mctx *c, bool (*fn)(struct mctx *, char **, const char *),
                     const char *arg)
{
    for (guint i = 0; i < c->rows->len; i++)
        fn(c, row_at(c, i), arg);
}

static bool op_change(struct mctx *c, char **row, const char *arg)
{
    /* arg: "action=deny" or "duration=5m" */
    enum ks_rule_field f = strncmp(arg, "action=", 7) == 0 ? KS_RF_ACTION : KS_RF_DURATION;
    const char *value = strchr(arg, '=') + 1;
    return ks_rops_change_field(ks_service_rules(c->w->svc), ks_service_nodes(c->w->svc),
                                row[COL_R_NODE], row[COL_R_NAME], f, value, ks_sw_ntf_reply,
                                c->w);
}

static bool op_duplicate(struct mctx *c, char **row, const char *arg)
{
    (void)arg;
    return ks_rops_duplicate(ks_service_rules(c->w->svc), ks_service_nodes(c->w->svc),
                             row[COL_R_NODE], row[COL_R_NAME], ks_sw_ntf_reply, c->w);
}

static bool op_apply(struct mctx *c, char **row, const char *arg)
{
    return ks_rops_apply_to_node(ks_service_rules(c->w->svc), ks_service_nodes(c->w->svc),
                                 row[COL_R_NAME], arg, ks_sw_ntf_reply, c->w);
}

static bool op_delete(struct mctx *c, char **row, const char *arg)
{
    (void)arg;
    return ks_rops_delete(ks_service_rules(c->w->svc), ks_service_nodes(c->w->svc),
                          row[COL_R_NAME], row[COL_R_NODE], ks_sw_ntf_reply, c->w);
}

static bool op_export_disk(struct mctx *c, char **row, const char *arg)
{
    return ks_rops_export(ks_service_rules(c->w->svc), row[COL_R_NODE], row[COL_R_NAME], arg);
}

static bool op_enable(struct mctx *c, char **row, const char *arg)
{
    return ks_rops_enable(ks_service_rules(c->w->svc), ks_service_nodes(c->w->svc),
                          row[COL_R_NODE], row[COL_R_NAME], arg, ks_sw_ntf_reply, c->w);
}

static struct mctx *item_ctx(GtkMenuItem *item)
{
    return g_object_get_data(G_OBJECT(item), "ctx");
}

static const char *item_arg(GtkMenuItem *item)
{
    return g_object_get_data(G_OBJECT(item), "arg");
}

static void m_change(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    for_rows(c, op_change, item_arg(item));
    after(c);
}

static void m_apply(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    char *q = g_strdup_printf("    Apply this rule to %s  ", item_arg(item));
    if (ks_sw_confirm(c->w, q))
        for_rows(c, op_apply, item_arg(item));
    g_free(q);
    after(c);
}

static void m_enable(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    /* every row is changed from the state of the first */
    const char *first = c->rows->len > 0 ? row_at(c, 0)[COL_R_ENABLED] : "True";
    for_rows(c, op_enable, first);
    after(c);
}

static void m_duplicate(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    for_rows(c, op_duplicate, NULL);
    after(c);
}

/* _table_menu_delete() for the rules and alerts tables */
static void delete_rows(struct mctx *c)
{
    struct ks_stats_win *w = c->w;
    bool alerts = alerts_shown(w, c->tv);
    if (!ks_sw_confirm(w, alerts ? "    You are about to delete this entry.    "
                                 : "    You are about to delete this rule.    "))
        return;
    if (alerts) {
        for (guint i = 0; i < c->rows->len; i++)
            ks_db_delete_alert(ks_service_db(w->svc), row_at(c, i)[COL_TIME], row_at(c, i)[COL_NODE]);
    } else {
        for_rows(c, op_delete, NULL);
    }
}

static void m_delete(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    delete_rows(c);
    after(c);
}

/* _table_menu_export_clipboard() */
static void m_export_clipboard(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    GString *g = g_string_new(NULL);
    if (alerts_shown(c->w, c->tv)) {
        for (guint i = 0; i < c->rows->len; i++) {
            char **r = row_at(c, i);
            /* indexes 2, 3, 4, 5 of the alerts table: it has only five
             * columns, the last one reads as None */
            g_string_append_printf(g, "\n%s,%s,%s,%s,%s,%s", r[0], r[1], r[2], r[3], r[4],
                                   "None");
        }
    } else {
        for (guint i = 0; i < c->rows->len; i++) {
            char *j = ks_rops_rule_json(ks_service_rules(c->w->svc), row_at(c, i)[COL_R_NODE],
                                        row_at(c, i)[COL_R_NAME]);
            if (j != NULL) {
                g_string_append_printf(g, "\n%s", j);
                free(j);
            } else {
                ks_warning("export to clipboard: ERROR converting \"%s\" to json",
                           row_at(c, i)[COL_R_NAME]);
            }
        }
    }
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), g->str, -1);
    g_string_free(g, TRUE);
    after(c);
}

/* _table_menu_export_disk() */
static void m_export_disk(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    if (alerts_shown(c->w, c->tv)) {
        after(c);
        return;
    }
    char *dir = ks_sw_choose_dir(c->w, "Select a directory to export rules");
    if (dir != NULL) {
        GString *errs = g_string_new(NULL);
        for (guint i = 0; i < c->rows->len; i++) {
            if (!op_export_disk(c, row_at(c, i), dir))
                g_string_append_printf(errs, "\n%s", row_at(c, i)[COL_R_NAME]);
        }
        if (errs->len == 0) {
            char *m = g_strdup_printf("Rules exported to %s", dir);
            ks_sw_message(c->w, GTK_MESSAGE_INFO, "Rules export", m);
            g_free(m);
        } else {
            ks_sw_message(c->w, GTK_MESSAGE_WARNING, "Rules export error",
                          g_strdup_printf("Error exporting the following rules:\n%s", errs->str));
        }
        g_string_free(errs, TRUE);
        g_free(dir);
    }
    after(c);
}

static void m_details(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    if (c->rows->len > 0)
        ks_sw_show_conn_details(c->w, row_at(c, 0)[COL_TIME]);
    clear_selection(c->tv);
}

static void m_view_alert(GtkMenuItem *item, gpointer ud)
{
    (void)ud;
    struct mctx *c = item_ctx(item);
    for (guint i = 0; i < c->rows->len; i++)
        ks_sw_show_alert(c->w, row_at(c, i)[COL_TIME], row_at(c, i)[COL_NODE]);
    clear_selection(c->tv);
}

static GtkWidget *add_item(GtkWidget *menu, struct mctx *c, const char *label,
                           GCallback cb, const char *arg, bool sensitive)
{
    GtkWidget *it = gtk_menu_item_new_with_label(label);
    g_object_set_data(G_OBJECT(it), "ctx", c);
    if (arg != NULL)
        g_object_set_data_full(G_OBJECT(it), "arg", g_strdup(arg), g_free);
    if (cb != NULL)
        g_signal_connect(it, "activate", cb, NULL);
    gtk_widget_set_sensitive(it, sensitive);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), it);
    return it;
}

static GtkWidget *add_submenu(GtkWidget *menu, const char *label)
{
    GtkWidget *it = gtk_menu_item_new_with_label(label);
    GtkWidget *sub = gtk_menu_new();
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(it), sub);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), it);
    return sub;
}

static gboolean destroy_menu_idle(gpointer menu)
{
    gtk_widget_destroy(GTK_WIDGET(menu));
    return G_SOURCE_REMOVE;
}

/* the item's "activate" comes after "selection-done": destroy the menu
 * (and with it the context) once that has run */
static void on_selection_done(GtkMenuShell *menu, gpointer ud)
{
    (void)ud;
    g_object_ref(menu);
    g_idle_add(destroy_menu_idle, menu);
}

static void popup(GtkWidget *menu, struct mctx *c, GdkEventButton *ev)
{
    g_object_ref_sink(menu);
    g_object_set_data_full(G_OBJECT(menu), "mctx", c, mctx_free);
    g_signal_connect(menu, "selection-done", G_CALLBACK(on_selection_done), NULL);
    gtk_widget_show_all(menu);
    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, ev ? ev->button : 0,
                   ev ? ev->time : gtk_get_current_event_time());
}

/* _configure_events_contextual_menu() */
static void events_menu(struct mctx *c, GdkEventButton *ev)
{
    GtkWidget *menu = gtk_menu_new();
    add_item(menu, c, "Details", G_CALLBACK(m_details), NULL, true);
    GtkWidget *rules = add_submenu(menu, "Rules");
    /* new rule from the event: the rules editor is the next step */
    GtkWidget *nw = add_item(rules, c, "New", NULL, NULL, false);
    gtk_widget_set_tooltip_text(nw, "The rules editor is not ported yet");
    popup(menu, c, ev);
}

/* _configure_alerts_contextual_menu() */
static void alerts_menu(struct mctx *c, GdkEventButton *ev)
{
    GtkWidget *menu = gtk_menu_new();
    add_item(menu, c, "View", G_CALLBACK(m_view_alert), NULL, true);
    add_item(menu, c, "Delete", G_CALLBACK(m_delete), NULL, true);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    GtkWidget *exp = add_submenu(menu, "Export");
    add_item(exp, c, "To clipboard", G_CALLBACK(m_export_clipboard), NULL, true);
    add_item(exp, c, "To disk", G_CALLBACK(m_export_disk), NULL, true);
    popup(menu, c, ev);
}

/* _configure_rules_contextual_menu() */
static void rules_menu(struct mctx *c, GdkEventButton *ev)
{
    struct ks_nodes *nodes = ks_service_nodes(c->w->svc);
    GtkWidget *menu = gtk_menu_new();
    if (nodes->len > 0) {
        GtkWidget *apply = add_submenu(menu, "Apply to");
        for (size_t i = 0; i < nodes->len; i++)
            add_item(apply, c, nodes->items[i]->addr, G_CALLBACK(m_apply), nodes->items[i]->addr,
                     true);
    }
    GtkWidget *act = add_submenu(menu, "Action");
    add_item(act, c, "Allow", G_CALLBACK(m_change), "action=allow", true);
    add_item(act, c, "Deny", G_CALLBACK(m_change), "action=deny", true);
    add_item(act, c, "Reject", G_CALLBACK(m_change), "action=reject", true);
    GtkWidget *dur = add_submenu(menu, "Duration");
    static const struct {
        const char *label, *value;
    } durs[] = {{"Always", KS_DUR_ALWAYS}, {"Until reboot", KS_DUR_UNTIL_RESTART},
                {"12h", "12h"},            {"1h", "1h"},
                {"30m", "30m"},            {"15m", "15m"},
                {"5m", "5m"}};
    for (size_t i = 0; i < sizeof(durs) / sizeof(durs[0]); i++) {
        char *arg = g_strdup_printf("duration=%s", durs[i].value);
        add_item(dur, c, durs[i].label, G_CALLBACK(m_change), arg, true);
        g_free(arg);
    }
    if (c->rows->len > 0) {
        /* the label comes from the first rule */
        bool on = strcmp(row_at(c, 0)[COL_R_ENABLED], "False") != 0;
        add_item(menu, c, on ? "Disable" : "Enable", G_CALLBACK(m_enable), NULL, true);
    }
    add_item(menu, c, "Duplicate", G_CALLBACK(m_duplicate), NULL, true);
    GtkWidget *ed = add_item(menu, c, "Edit", NULL, NULL, false);
    gtk_widget_set_tooltip_text(ed, "The rules editor is not ported yet");
    add_item(menu, c, "Delete", G_CALLBACK(m_delete), NULL, true);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    GtkWidget *exp = add_submenu(menu, "Export");
    add_item(exp, c, "To clipboard", G_CALLBACK(m_export_clipboard), NULL, true);
    add_item(exp, c, "To disk", G_CALLBACK(m_export_disk), NULL, true);
    popup(menu, c, ev);
}

/* _cb_table_context_menu() */
static void context_menu(struct ks_stats_win *w, struct tabview *tv, GdkEventButton *ev)
{
    /* only the events and rules tables have one; not in the rules' detail */
    if (tv->tab != KS_TAB_MAIN && tv->tab != KS_TAB_RULES)
        return;
    if (tv->tab == KS_TAB_RULES && tv->detail)
        return;
    GPtrArray *rows = ks_sw_selected_rows(tv);
    bool events = tv->tab == KS_TAB_MAIN;
    bool alerts = alerts_shown(w, tv);
    if ((events || alerts) && rows->len == 0) {
        g_ptr_array_free(rows, TRUE);
        return;
    }
    struct mctx *c = g_new0(struct mctx, 1);
    c->w = w;
    c->tv = tv;
    c->rows = rows;
    if (events)
        events_menu(c, ev);
    else if (alerts)
        alerts_menu(c, ev);
    else
        rules_menu(c, ev);
}

static gboolean on_button_press(GtkWidget *tree, GdkEventButton *ev, gpointer ud)
{
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tree), "win");
    if (ev->button != 3 || ev->type != GDK_BUTTON_PRESS)
        return FALSE;
    GtkTreePath *path = NULL;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tree), (gint)ev->x, (gint)ev->y, &path, NULL,
                                      NULL, NULL)) {
        /* a right click on a row outside the selection selects only it */
        if (!gtk_tree_selection_path_is_selected(sel, path)) {
            gtk_tree_selection_unselect_all(sel);
            gtk_tree_selection_select_path(sel, path);
        }
        gtk_tree_path_free(path);
    } else {
        gtk_tree_selection_unselect_all(sel);
    }
    context_menu(w, tv, ev);
    return TRUE;
}

static gboolean on_popup_menu(GtkWidget *tree, gpointer ud)
{
    struct tabview *tv = ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tree), "win");
    context_menu(w, tv, NULL);
    return TRUE;
}

/* eventFilter(): Ctrl+C and Del, on the events table */
static gboolean on_key_press(GtkWidget *tree, GdkEventKey *ev, gpointer ud)
{
    (void)ud;
    struct ks_stats_win *w = g_object_get_data(G_OBJECT(tree), "win");
    if ((ev->state & GDK_CONTROL_MASK) && (ev->keyval == GDK_c || ev->keyval == GDK_C)) {
        ks_sw_copy_selected(w);
        return TRUE;
    }
    if (ev->keyval == GDK_Delete) {
        ks_sw_delete_selected(w);
        return TRUE;
    }
    return FALSE;
}

/* _table_menu_delete() from the Del key: events and nodes have nothing to
 * delete this way, so on the events table (the only one with the key) it
 * does nothing, as upstream. */
void ks_sw_delete_selected(struct ks_stats_win *w)
{
    struct tabview *tv = ks_sw_cur_tab(w);
    if (tv->tab == KS_TAB_MAIN || tv->tab == KS_TAB_NODES || tv->detail)
        return;
}

void ks_sw_menu_attach(struct ks_stats_win *w, struct tabview *tv)
{
    (void)w;
    g_signal_connect(tv->tree, "button-press-event", G_CALLBACK(on_button_press), tv);
    g_signal_connect(tv->tree, "popup-menu", G_CALLBACK(on_popup_menu), tv);
    if (tv->tab == KS_TAB_MAIN)
        g_signal_connect(tv->tree, "key-press-event", G_CALLBACK(on_key_press), tv);
}
