/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The process details dialog: port of upstream
 * ui/opensnitch/dialogs/processdetails.py and res/process_details.ui.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/procinfo.h"
#include "ui/stats_win_priv.h"

enum { TAB_STATUS, TAB_DESCRIPTORS, TAB_IOSTATS, TAB_MAPS, TAB_STACK, TAB_ENVS, NPTABS };

struct ks_procdlg {
    struct ks_stats_win *w;
    GtkWidget *win, *icon, *name, *path, *args, *checksums, *parent, *cwd, *statm;
    GtkWidget *nb, *text[NPTABS], *check_files, *check_sockets;
    GtkWidget *combo, *action;
    char pid[32];     /* "" if not monitoring */
    GPtrArray *pids;  /* char *, the combo's items */
    GPtrArray *nodes; /* char *, their nodes */
    bool data_loaded;
    char *last; /* the last JSON received */
    bool loading;
};

static void set_text(GtkWidget *tv, const char *text)
{
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));
    gtk_text_buffer_set_text(b, text != NULL ? text : "", -1);
}

static void set_markup(GtkWidget *l, const char *m)
{
    gtk_label_set_markup(GTK_LABEL(l), m != NULL ? m : "");
}

static const char *node_of(struct ks_procdlg *d, const char *pid)
{
    for (guint i = 0; i < d->pids->len; i++) {
        if (strcmp(g_ptr_array_index(d->pids, i), pid) == 0)
            return g_ptr_array_index(d->nodes, i);
    }
    return "";
}

/* _reset() */
static void reset(struct ks_procdlg *d)
{
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo), -1);
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(d->combo));
    gtk_list_store_clear(GTK_LIST_STORE(m));
    set_markup(d->name, "loading...");
    set_markup(d->args, "loading...");
    set_markup(d->path, "loading...");
    gtk_image_clear(GTK_IMAGE(d->icon));
    set_markup(d->statm, "");
    set_markup(d->cwd, "");
    set_markup(d->checksums, "");
    set_markup(d->parent, "");
    for (int i = 0; i < NPTABS; i++)
        set_text(d->text[i], "");
}

static void set_running(struct ks_procdlg *d, bool yes)
{
    d->loading = true;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->action), yes);
    gtk_button_set_label(GTK_BUTTON(d->action), yes ? "Pause" : "Start");
    d->loading = false;
}

static char *task_data(const char *pid)
{
    return g_strdup_printf("{\"name\": \"pid-monitor\", \"data\": { \"interval\": \"5s\", "
                           "\"pid\": \"%s\" }}",
                           pid);
}

static void close_dialog(struct ks_procdlg *d);

/* the tab shown now, from the last data */
static void fill_tab(struct ks_procdlg *d, int tab)
{
    if (d->last == NULL)
        return;
    struct ks_procinfo p;
    if (!ks_procinfo_parse(&p, d->last))
        return;
    char *t = NULL;
    switch (tab) {
    case TAB_STATUS: t = ks_procinfo_status(&p); set_text(d->text[tab], t); break;
    case TAB_DESCRIPTORS:
        t = ks_procinfo_descriptors(
            &p, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->check_files)),
            gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->check_sockets)));
        set_text(d->text[tab], t);
        break;
    case TAB_IOSTATS: {
        t = ks_procinfo_iostats(&p);
        /* a plain text view: the bold of the labels is dropped */
        GString *g = g_string_new(t != NULL ? t : "");
        g_string_replace(g, "<b>", "", 0);
        g_string_replace(g, "</b>", "", 0);
        set_text(d->text[tab], g->str);
        g_string_free(g, TRUE);
        break;
    }
    case TAB_MAPS: t = ks_procinfo_maps(&p); set_text(d->text[tab], t); break;
    case TAB_STACK: t = ks_procinfo_stack(&p); set_text(d->text[tab], t); break;
    case TAB_ENVS: t = ks_procinfo_env(&p); set_text(d->text[tab], t); break;
    }
    g_free(t);
    ks_procinfo_free(&p);
}

/* _load_data() */
static void load_data(struct ks_procdlg *d, const char *json)
{
    struct ks_procinfo p;
    if (!ks_procinfo_parse(&p, json)) {
        ks_warning("[ProcessDetails]: exception loading data: %s", json);
        return;
    }
    g_free(d->last);
    d->last = g_strdup(json);
    /* _load_app_icon() */
    const cJSON *path = cJSON_GetObjectItemCaseSensitive(p.j, "Path");
    struct ks_app_info *info = d->w->desktop != NULL
                                   ? ks_desktop_info_by_path(d->w->desktop, path->valuestring,
                                                             KS_DESKTOP_TERMINAL_ICON)
                                   : NULL;
    const char *app = info != NULL && info->name != NULL && info->name[0] ? info->name
                                                                            : path->valuestring;
    char *e = g_markup_escape_text(app, -1);
    char *m = g_strdup_printf("<b>%s</b>", e);
    set_markup(d->name, m);
    gtk_widget_set_tooltip_markup(d->name, m);
    g_free(m);
    g_free(e);
    if (info != NULL && info->icon != NULL) {
        GdkPixbuf *pb = NULL;
        if (info->icon[0] == '/')
            pb = gdk_pixbuf_new_from_file_at_size(info->icon, 48, 48, NULL);
        else
            pb = gtk_icon_theme_load_icon(gtk_icon_theme_get_default(), info->icon, 48, 0, NULL);
        if (pb != NULL) {
            gtk_image_set_from_pixbuf(GTK_IMAGE(d->icon), pb);
            g_object_unref(pb);
        }
    }
    ks_app_info_free(info);

    char *s = ks_procinfo_parents(&p);
    set_markup(d->parent, s);
    g_free(s);
    s = ks_procinfo_path(&p);
    gtk_widget_set_visible(d->path, s != NULL);
    set_markup(d->path, s);
    g_free(s);
    s = ks_procinfo_checksums(&p);
    if (s != NULL)
        set_markup(d->checksums, s);
    g_free(s);
    s = ks_procinfo_args(&p);
    gtk_label_set_text(GTK_LABEL(d->args), s);
    gtk_widget_set_tooltip_text(d->args, s);
    g_free(s);
    s = ks_procinfo_cwd(&p);
    set_markup(d->cwd, s);
    g_free(s);
    s = ks_procinfo_mem(&p);
    set_markup(d->statm, s);
    g_free(s);
    ks_procinfo_free(&p);
    fill_tab(d, gtk_notebook_get_current_page(GTK_NOTEBOOK(d->nb)));
    d->data_loaded = true;
}

/* the replies of the pid-monitor task */
static void on_start_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_procdlg *d = ud;
    (void)addr;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR) {
        char *m = g_strdup_printf("Error loading process information:\n\n%s", r->data);
        ks_sw_message(d->w, GTK_MESSAGE_WARNING, m, "");
        g_free(m);
        d->pid[0] = '\0';
        set_running(d, false);
        /* if nothing was loaded yet and there's one pid, close the window */
        if (!d->data_loaded && d->pids->len <= 1)
            close_dialog(d);
        return;
    }
    if (r->data != NULL && r->data[0] != '\0')
        load_data(d, r->data);
}

static void on_stop_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_procdlg *d = ud;
    (void)addr;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR && r->data != NULL &&
        r->data[0] != '\0') {
        char *m = g_strdup_printf("Error stopping monitoring process:\n\n%s", r->data);
        ks_sw_message(d->w, GTK_MESSAGE_WARNING, m, "");
        g_free(m);
        set_running(d, false);
    }
}

static void send_task(struct ks_procdlg *d, const char *pid, Protocol__Action type,
                      ks_ntf_reply_cb cb)
{
    char *data = task_data(pid);
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.type = type;
    n.data = data;
    ks_nodes_send(ks_service_nodes(d->w->svc), node_of(d, pid), &n, cb, d);
    g_free(data);
}

/* _start_monitoring() */
static void start_monitoring(struct ks_procdlg *d)
{
    if (d->pid[0] != '\0')
        return;
    gchar *pid = gtk_combo_box_get_active_text(GTK_COMBO_BOX(d->combo));
    if (pid == NULL || pid[0] == '\0') {
        g_free(pid);
        return;
    }
    g_strlcpy(d->pid, pid, sizeof(d->pid));
    g_free(pid);
    set_running(d, true);
    send_task(d, d->pid, PROTOCOL__ACTION__TASK_START, on_start_reply);
}

/* _stop_monitoring() */
static void stop_monitoring(struct ks_procdlg *d)
{
    if (d->pid[0] == '\0')
        return;
    set_running(d, false);
    send_task(d, d->pid, PROTOCOL__ACTION__TASK_STOP, on_stop_reply);
    d->pid[0] = '\0';
}

static void close_dialog(struct ks_procdlg *d)
{
    stop_monitoring(d);
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(d->combo));
    gtk_list_store_clear(GTK_LIST_STORE(m));
    gtk_widget_hide(d->win);
}

static void on_close_clicked(GtkButton *b, gpointer ud)
{
    (void)b;
    close_dialog(ud);
}

static void on_action_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_procdlg *d = ud;
    if (d->loading)
        return;
    if (!gtk_toggle_button_get_active(b))
        stop_monitoring(d);
    else
        start_monitoring(d);
}

static void on_tab(GtkNotebook *nb, gpointer page, guint idx, gpointer ud)
{
    (void)nb;
    (void)page;
    fill_tab(ud, (int)idx);
}

static void on_filter(GtkToggleButton *b, gpointer ud)
{
    struct ks_procdlg *d = ud;
    (void)b;
    fill_tab(d, TAB_DESCRIPTORS);
}

static GtkWidget *scrolled_text(GtkWidget **tv, bool mono)
{
    *tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(*tv), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(*tv), FALSE);
    if (mono) {
        PangoFontDescription *f = pango_font_description_from_string("monospace 9");
        gtk_widget_modify_font(*tv, f);
        pango_font_description_free(f);
    }
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), *tv);
    return sw;
}

static GtkWidget *mlabel(void)
{
    GtkWidget *l = gtk_label_new("");
    gtk_misc_set_alignment(GTK_MISC(l), 0.0f, 0.5f);
    gtk_label_set_selectable(GTK_LABEL(l), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(l), TRUE);
    return l;
}

static gboolean on_delete(GtkWidget *win, GdkEvent *ev, gpointer ud)
{
    (void)win;
    (void)ev;
    close_dialog(ud);
    return TRUE;
}

struct ks_procdlg *ks_procdlg_new(struct ks_stats_win *w)
{
    struct ks_procdlg *d = g_new0(struct ks_procdlg, 1);
    d->w = w;
    d->pids = g_ptr_array_new_with_free_func(g_free);
    d->nodes = g_ptr_array_new_with_free_func(g_free);
    d->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(d->win), "Process details");
    gtk_window_set_default_size(GTK_WINDOW(d->win), 620, 560);
    g_signal_connect(d->win, "delete-event", G_CALLBACK(on_delete), d);
    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
    gtk_container_add(GTK_CONTAINER(d->win), vbox);

    GtkWidget *head = gtk_hbox_new(FALSE, 8);
    d->icon = gtk_image_new();
    gtk_widget_set_size_request(d->icon, 48, 48);
    gtk_box_pack_start(GTK_BOX(head), d->icon, FALSE, FALSE, 0);
    GtkWidget *col = gtk_vbox_new(FALSE, 2);
    d->name = mlabel();
    d->path = mlabel();
    d->args = mlabel();
    d->checksums = mlabel();
    d->parent = mlabel();
    d->cwd = mlabel();
    d->statm = mlabel();
    GtkWidget *ls[] = {d->name, d->path, d->args, d->checksums, d->parent, d->cwd, d->statm};
    for (size_t i = 0; i < sizeof(ls) / sizeof(ls[0]); i++)
        gtk_box_pack_start(GTK_BOX(col), ls[i], FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(head), col, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), head, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_hseparator_new(), FALSE, FALSE, 2);

    d->nb = gtk_notebook_new();
    static const char *const titles[NPTABS] = {"Status", "Open files", "I/O Statistics",
                                               "Memory mapped files", "Stack",
                                               "Environment variables"};
    for (int i = 0; i < NPTABS; i++) {
        GtkWidget *page;
        if (i == TAB_DESCRIPTORS) {
            page = gtk_vbox_new(FALSE, 2);
            GtkWidget *row = gtk_hbox_new(FALSE, 8);
            d->check_sockets = gtk_check_button_new_with_label("Filter sockets");
            d->check_files = gtk_check_button_new_with_label("Filter files");
            gtk_box_pack_start(GTK_BOX(row), d->check_sockets, FALSE, FALSE, 0);
            gtk_box_pack_start(GTK_BOX(row), d->check_files, FALSE, FALSE, 0);
            gtk_box_pack_start(GTK_BOX(page), row, FALSE, FALSE, 0);
            gtk_box_pack_start(GTK_BOX(page), scrolled_text(&d->text[i], true), TRUE, TRUE, 0);
            g_signal_connect(d->check_sockets, "toggled", G_CALLBACK(on_filter), d);
            g_signal_connect(d->check_files, "toggled", G_CALLBACK(on_filter), d);
        } else {
            page = scrolled_text(&d->text[i], false);
        }
        gtk_notebook_append_page(GTK_NOTEBOOK(d->nb), page, gtk_label_new(titles[i]));
    }
    gtk_box_pack_start(GTK_BOX(vbox), d->nb, TRUE, TRUE, 0);

    GtkWidget *bottom = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(bottom), gtk_label_new("Application pids"), FALSE, FALSE, 0);
    d->combo = gtk_combo_box_new_text();
    gtk_box_pack_start(GTK_BOX(bottom), d->combo, FALSE, FALSE, 0);
    d->action = gtk_toggle_button_new_with_label("Start");
    gtk_widget_set_tooltip_text(d->action, "Start or stop monitoring this process");
    gtk_box_pack_start(GTK_BOX(bottom), d->action, FALSE, FALSE, 0);
    GtkWidget *close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    gtk_box_pack_end(GTK_BOX(bottom), close, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), bottom, FALSE, FALSE, 0);

    g_signal_connect(close, "clicked", G_CALLBACK(on_close_clicked), d);
    g_signal_connect(d->action, "toggled", G_CALLBACK(on_action_toggled), d);
    g_signal_connect(d->nb, "switch-page", G_CALLBACK(on_tab), d);
    gtk_widget_show_all(vbox);
    return d;
}

void ks_procdlg_free(struct ks_procdlg *d)
{
    if (d == NULL)
        return;
    gtk_widget_destroy(d->win);
    g_ptr_array_free(d->pids, TRUE);
    g_ptr_array_free(d->nodes, TRUE);
    g_free(d->last);
    g_free(d);
}

/* monitor(pids) */
void ks_sw_proc_monitor(struct ks_stats_win *w, const char *const *pids, const char *const *nodes,
                        size_t n)
{
    if (w->proc == NULL)
        w->proc = ks_procdlg_new(w);
    struct ks_procdlg *d = w->proc;
    if (d->pid[0] != '\0')
        stop_monitoring(d);
    d->data_loaded = false;
    g_free(d->last);
    d->last = NULL;
    g_ptr_array_set_size(d->pids, 0);
    g_ptr_array_set_size(d->nodes, 0);
    reset(d);
    for (size_t i = 0; i < n; i++) {
        if (pids[i] == NULL)
            continue;
        g_ptr_array_add(d->pids, g_strdup(pids[i]));
        g_ptr_array_add(d->nodes, g_strdup(nodes[i]));
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->combo), pids[i]);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo), 0);
    gtk_window_present(GTK_WINDOW(d->win));
    start_monitoring(d);
}
