/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/prompt/__init__.py (PromptDialog)
 * and res/prompt.ui to GTK 2, built in code.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/prompt.h"

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/log.h"
#include "common/pb/ui.pb-c.h"

/* _constants.PAGE_* */
enum { PAGE_DETAILS = 0, PAGE_CHECKSUMS = 1, PAGE_MAIN = 2 };

#define ICON_SIZE 48
#define MAX_CHECKSUM_RULES 64

struct ks_prompt {
    struct ks_service *svc;
    struct ks_desktop *desktop;
    struct ks_settings *cfg;

    GtkWidget *win, *pages;
    /* main page */
    GtkWidget *icon, *app_name, *app_desc, *app_path, *args, *message;
    GtkWidget *cwd, *dst_ip, *dst_port, *dst_port_title, *uid, *checksum, *checksum_title;
    GtkWidget *check_dst_ip, *what_ip_combo, *check_dst_port, *check_uid, *check_sum;
    GtkWidget *what_combo, *duration_combo, *advanced;
    GtkWidget *action_button, *action_menu, *allow_button;
    /* details and checksums */
    GtkWidget *details;
    GtkWidget *checksum_rules, *checksum_note, *checksum_status;

    struct ks_combo what, what_ip;
    struct ks_ask *ask;
    int tick;
    bool stopped; /* the countdown */
    guint timer;
    bool timeout_triggered;
    int default_action;
    bool advanced_on;
    bool filling; /* setting widgets up: no user events */
    char *checksum_names[MAX_CHECKSUM_RULES];
    size_t nchecksum_names;
};

/* with mnemonics: Alt+D, Alt+A, Alt+R */
static const char *const action_text[] = {"_Deny", "_Allow", "_Reject"};

/* ---- countdown --------------------------------------------------------- */

static int cfg_timeout(struct ks_prompt *p)
{
    if (!ks_settings_has(p->cfg, KS_CFG_DEFAULT_TIMEOUT_KEY))
        return KS_PROMPT_DEFAULT_TIMEOUT;
    return ks_settings_get_int(p->cfg, KS_CFG_DEFAULT_TIMEOUT_KEY, KS_PROMPT_DEFAULT_TIMEOUT);
}

static int cfg_action(struct ks_prompt *p)
{
    return ks_settings_get_int(p->cfg, KS_CFG_DEFAULT_ACTION_KEY, 0);
}

/* _set_cmd_action_text() */
static void set_cmd_action_text(struct ks_prompt *p)
{
    char buf[64];
    int idx = cfg_action(p);
    if (idx < 0 || idx > 2)
        idx = 0;
    if (idx == KS_CFG_ACTION_ALLOW_IDX) {
        snprintf(buf, sizeof(buf), "%s (%d)", action_text[1], p->tick);
        gtk_button_set_label(GTK_BUTTON(p->allow_button), buf);
        gtk_button_set_label(GTK_BUTTON(p->action_button), action_text[0]);
    } else {
        gtk_button_set_label(GTK_BUTTON(p->allow_button), action_text[1]);
        snprintf(buf, sizeof(buf), "%s (%d)", action_text[idx], p->tick);
        gtk_button_set_label(GTK_BUTTON(p->action_button), buf);
    }
}

/* _stop_countdown() */
static void stop_countdown(struct ks_prompt *p)
{
    if (p->ask == NULL || p->stopped)
        return;
    int idx = cfg_action(p);
    if (idx < 0 || idx > 2)
        idx = 0;
    if (idx == KS_CFG_ACTION_ALLOW_IDX)
        gtk_button_set_label(GTK_BUTTON(p->allow_button), action_text[1]);
    else
        gtk_button_set_label(GTK_BUTTON(p->action_button), action_text[idx]);
    p->stopped = true;
}

static void send_rule(struct ks_prompt *p);

static gboolean on_tick(gpointer data)
{
    struct ks_prompt *p = data;
    if (p->ask == NULL) {
        p->timer = 0;
        return G_SOURCE_REMOVE;
    }
    if (p->stopped) {
        /* stop only stops the countdown */
        p->tick = cfg_timeout(p);
        return G_SOURCE_CONTINUE;
    }
    p->tick--;
    set_cmd_action_text(p);
    if (p->tick > 0)
        return G_SOURCE_CONTINUE;
    p->timer = 0;
    p->timeout_triggered = true;
    send_rule(p);
    return G_SOURCE_REMOVE;
}

static gboolean on_immediate_timeout(gpointer data)
{
    struct ks_prompt *p = data;
    if (p->ask != NULL) {
        p->timeout_triggered = true;
        send_rule(p);
    }
    return G_SOURCE_REMOVE;
}

/* ---- the answer -------------------------------------------------------- */

static int combo_index(GtkWidget *combo)
{
    return gtk_combo_box_get_active(GTK_COMBO_BOX(combo));
}

static void set_advanced(struct ks_prompt *p, bool on);

/* _send_rule() */
static void send_rule(struct ks_prompt *p)
{
    struct ks_ask *ask = p->ask;
    if (ask == NULL)
        return;
    if (p->timer) {
        g_source_remove(p->timer);
        p->timer = 0;
    }
    int what = combo_index(p->what_combo), what_ip = combo_index(p->what_ip_combo);
    struct ks_prompt_choice ch = {
        .action_idx = p->default_action,
        .duration_idx = combo_index(p->duration_combo),
        .what = (what >= 0 && (size_t)what < p->what.len) ? &p->what.items[what] : NULL,
        .what_ip = (what_ip >= 0 && (size_t)what_ip < p->what_ip.len)
                       ? &p->what_ip.items[what_ip] : NULL,
        .dst_ip = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(p->check_dst_ip)),
        .dst_port = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(p->check_dst_port)),
        .user_id = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(p->check_uid)),
        .checksum = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(p->check_sum)),
        .checksum_text = gtk_label_get_text(GTK_LABEL(p->checksum)),
    };
    struct ks_arena a = {0};
    Protocol__Rule *rule = NULL;
    if (ch.what != NULL)
        rule = ks_prompt_build_rule(&a, ask->con, &ch, ks_service_aliases(p->svc),
                                    ks_service_rules(p->svc), ask->node,
                                    (int64_t)time(NULL));
    if (rule == NULL)
        ks_info("popups: Invalid rule, discarding");

    gtk_widget_hide(p->win);
    if (p->advanced_on)
        set_advanced(p, false);
    p->ask = NULL;
    /* may show the next question right away */
    ks_service_answer(p->svc, ask, rule, p->timeout_triggered);
    ks_arena_free(&a);
}

static void on_allow(GtkButton *b, gpointer data)
{
    (void)b;
    struct ks_prompt *p = data;
    p->default_action = KS_CFG_ACTION_ALLOW_IDX;
    send_rule(p);
}

/* _on_deny_btn_clicked(): the default action, deny if that's allow */
static void on_action(GtkButton *b, gpointer data)
{
    (void)b;
    struct ks_prompt *p = data;
    p->default_action = cfg_action(p);
    if (p->default_action == KS_CFG_ACTION_ALLOW_IDX)
        p->default_action = KS_CFG_ACTION_DENY_IDX;
    send_rule(p);
}

static void on_menu_deny(GtkMenuItem *m, gpointer data)
{
    (void)m;
    struct ks_prompt *p = data;
    p->default_action = KS_CFG_ACTION_DENY_IDX;
    send_rule(p);
}

static void on_menu_reject(GtkMenuItem *m, gpointer data)
{
    (void)m;
    struct ks_prompt *p = data;
    p->default_action = KS_CFG_ACTION_REJECT_IDX;
    send_rule(p);
}

static void on_action_arrow(GtkButton *b, gpointer data)
{
    (void)b;
    struct ks_prompt *p = data;
    stop_countdown(p);
    gtk_menu_popup(GTK_MENU(p->action_menu), NULL, NULL, NULL, NULL, 0,
                   gtk_get_current_event_time());
}

/* closeEvent(): the window's X sends the rule */
static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer data)
{
    (void)w;
    (void)e;
    send_rule(data);
    return TRUE;
}

/* keyPressEvent(): Escape does nothing */
static gboolean on_key(GtkWidget *w, GdkEventKey *e, gpointer data)
{
    (void)w;
    (void)data;
    return e->keyval == GDK_KEY_Escape;
}

/* eventFilter(): a click on the dialog stops the countdown */
static gboolean on_button_press(GtkWidget *w, GdkEventButton *e, gpointer data)
{
    (void)w;
    (void)e;
    stop_countdown(data);
    return FALSE;
}

static void on_user_change(GtkWidget *w, gpointer data)
{
    (void)w;
    struct ks_prompt *p = data;
    if (!p->filling)
        stop_countdown(p);
}

/* ---- advanced, details, checksums -------------------------------------- */

static void show_if(GtkWidget *w, bool on)
{
    if (on)
        gtk_widget_show(w);
    else
        gtk_widget_hide(w);
}

/* _check_advanced_toggled() */
static void set_advanced(struct ks_prompt *p, bool on)
{
    p->advanced_on = on;
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(p->advanced)) != on) {
        p->filling = true;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(p->advanced), on);
        p->filling = false;
    }
    const Protocol__Connection *con = p->ask ? p->ask->con : NULL;
    bool md5 = con != NULL && ks_prompt_md5(con)[0] != '\0';
    show_if(p->check_dst_ip, on);
    show_if(p->what_ip_combo, on);
    show_if(p->dst_ip, !on);
    show_if(p->check_dst_port, on && con != NULL && con->dst_port != 0);
    show_if(p->check_uid, on);
    show_if(p->check_sum, md5 && on);
    show_if(p->checksum_title, md5 && on);
    show_if(p->checksum, md5 && on);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_MAIN);
}

static void on_advanced_toggled(GtkToggleButton *b, gpointer data)
{
    struct ks_prompt *p = data;
    if (p->filling)
        return;
    stop_countdown(p); /* checkAdvanced.clicked */
    set_advanced(p, gtk_toggle_button_get_active(b));
}

static void on_info(GtkButton *b, gpointer data)
{
    (void)b;
    struct ks_prompt *p = data;
    gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_DETAILS);
    stop_countdown(p);
}

static void on_back(GtkButton *b, gpointer data)
{
    (void)b;
    struct ks_prompt *p = data;
    gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_MAIN);
    stop_countdown(p);
}

static gboolean on_message_link(GtkLabel *l, gchar *uri, gpointer data)
{
    (void)l;
    struct ks_prompt *p = data;
    stop_countdown(p);
    if (strcmp(uri, "#warning-checksum") == 0)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_CHECKSUMS);
    return TRUE;
}

/* _cb_update_rule_clicked() */
static void update_rules(struct ks_prompt *p, bool all)
{
    gtk_label_set_text(GTK_LABEL(p->checksum_status), "");
    if (p->ask == NULL || p->nchecksum_names == 0 || combo_index(p->checksum_rules) < 0)
        return;
    /* upstream walks the list from the first entry either way: "Update
     * rule" updates the first one, not the selected one */
    for (size_t i = 0; i < p->nchecksum_names; i++) {
        struct ks_arena a = {0};
        Protocol__Rule *r = ks_prompt_checksum_update(&a, ks_service_rules(p->svc),
                                                      p->ask->node, p->checksum_names[i],
                                                      p->ask->con);
        if (r == NULL) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "<span foreground=\"red\">✘ Rule not updated, not found by name (%s)</span>",
                     p->checksum_names[i]);
            gtk_label_set_markup(GTK_LABEL(p->checksum_status), buf);
            ks_arena_free(&a);
            return;
        }
        Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
        Protocol__Rule *rules[1] = {r};
        ntf.type = PROTOCOL__ACTION__CHANGE_RULE;
        ntf.data = (char *)(uintptr_t) "";
        ntf.rules = rules;
        ntf.n_rules = 1;
        ks_nodes_send(ks_service_nodes(p->svc), p->ask->node, &ntf, NULL, NULL);
        ks_arena_free(&a);
        gtk_label_set_markup(GTK_LABEL(p->checksum_status),
                             "<span foreground=\"green\">✔Rule updated.</span>");
        if (!all)
            break;
    }
}

static void on_update_rule(GtkButton *b, gpointer data)
{
    (void)b;
    update_rules(data, false);
}

static void on_update_all(GtkButton *b, gpointer data)
{
    (void)b;
    update_rules(data, true);
}

static void clear_checksum_names(struct ks_prompt *p)
{
    for (size_t i = 0; i < p->nchecksum_names; i++)
        free(p->checksum_names[i]);
    p->nchecksum_names = 0;
}

/* _display_checksums_warning() */
static void display_checksums_warning(struct ks_prompt *p)
{
    const struct ks_ask *ask = p->ask;
    gtk_label_set_text(GTK_LABEL(p->checksum_status), "");
    clear_checksum_names(p);
    char *expected = NULL;
    bool bad = ks_prompt_checksum_mismatch(ks_service_rules(p->svc), ask->node, ask->con,
                                           p->checksum_names, MAX_CHECKSUM_RULES,
                                           &p->nchecksum_names, &expected);
    if (bad) {
        gtk_label_set_markup(
            GTK_LABEL(p->message),
            "<span foreground=\"red\">WARNING, bad checksum (<a href=\"#warning-checksum\">More "
            "info</a>)</span>");
        char *md5 = ks_markup_escape(ks_prompt_md5(ask->con));
        char *exp = ks_markup_escape(expected ? expected : "[]");
        char note[2048];
        snprintf(note, sizeof(note),
                 "<span foreground=\"red\">WARNING, checksums differ for at least one "
                 "rule.</span>\n\nCurrent process (%u):\n%s\n\nExpected from the rule:\n%s",
                 ask->con->process_id, md5 ? md5 : "", exp ? exp : "");
        gtk_label_set_markup(GTK_LABEL(p->checksum_note), note);
        free(md5);
        free(exp);
        GtkListStore *store =
            GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(p->checksum_rules)));
        gtk_list_store_clear(store);
        for (size_t i = 0; i < p->nchecksum_names; i++)
            gtk_combo_box_append_text(GTK_COMBO_BOX(p->checksum_rules), p->checksum_names[i]);
        gtk_combo_box_set_active(GTK_COMBO_BOX(p->checksum_rules), 0);
    }
    free(expected);
}

/* ---- rendering --------------------------------------------------------- */

static void fill_combo(GtkWidget *w, const struct ks_combo *c)
{
    GtkListStore *store = GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(w)));
    gtk_list_store_clear(store);
    for (size_t i = 0; i < c->len; i++) {
        GtkTreeIter it;
        gtk_list_store_append(store, &it);
        gtk_list_store_set(store, &it, 0, c->items[i].text, 1, !c->items[i].disabled, -1);
    }
    /* QComboBox selects the first entry after clear() + addItem() */
    gtk_combo_box_set_active(GTK_COMBO_BOX(w), c->len ? 0 : -1);
}

static GdkPixbuf *load_icon(const char *icon)
{
    GdkPixbuf *pb = NULL;
    if (icon != NULL && icon[0] == '/')
        pb = gdk_pixbuf_new_from_file_at_size(icon, ICON_SIZE, ICON_SIZE, NULL);
    else if (icon != NULL && icon[0] != '\0')
        pb = gtk_icon_theme_load_icon(gtk_icon_theme_get_default(), icon, ICON_SIZE,
                                      GTK_ICON_LOOKUP_FORCE_SIZE, NULL);
    if (pb == NULL)
        pb = gtk_icon_theme_load_icon(gtk_icon_theme_get_default(), KS_DESKTOP_TERMINAL_ICON,
                                      ICON_SIZE, GTK_ICON_LOOKUP_FORCE_SIZE, NULL);
    return pb;
}

static void set_label(GtkWidget *l, const char *text)
{
    gtk_label_set_text(GTK_LABEL(l), text ? text : "");
}

/* the position of the pop-up (move_popup) */
static void move_popup(struct ks_prompt *p)
{
    int pos = ks_settings_get_int(p->cfg, KS_CFG_DEFAULT_POPUP_POSITION, 0);
    GdkScreen *screen = gtk_window_get_screen(GTK_WINDOW(p->win));
    int px = 0, py = 0;
    gdk_display_get_pointer(gdk_screen_get_display(screen), NULL, &px, &py, NULL);
    int mon = gdk_screen_get_monitor_at_point(screen, px, py);
    GdkRectangle r;
    gdk_screen_get_monitor_geometry(screen, mon, &r);
    int w, h;
    gtk_window_get_size(GTK_WINDOW(p->win), &w, &h);
    switch (pos) {
    case KS_CFG_POPUP_TOP_RIGHT: gtk_window_move(GTK_WINDOW(p->win), r.x + r.width - w, r.y); break;
    case KS_CFG_POPUP_TOP_LEFT: gtk_window_move(GTK_WINDOW(p->win), r.x, r.y); break;
    case KS_CFG_POPUP_BOTTOM_RIGHT:
        gtk_window_move(GTK_WINDOW(p->win), r.x + r.width - w, r.y + r.height - h);
        break;
    case KS_CFG_POPUP_BOTTOM_LEFT:
        gtk_window_move(GTK_WINDOW(p->win), r.x, r.y + r.height - h);
        break;
    default:
        gtk_window_move(GTK_WINDOW(p->win), r.x + (r.width - w) / 2, r.y + (r.height - h) / 2);
    }
}

/* _render_connection() */
static void render(struct ks_prompt *p)
{
    const struct ks_ask *ask = p->ask;
    const Protocol__Connection *con = ask->con;
    p->filling = true;

    struct ks_app_info *info =
        ks_desktop_info_by_path(p->desktop, con->process_path ? con->process_path : "",
                                KS_DESKTOP_TERMINAL_ICON);
    const char *app_name = info ? info->name : "";
    GString *args = g_string_new("");
    for (size_t i = 0; i < con->n_process_args; i++)
        g_string_append_printf(args, "%s%s", i ? " " : "", con->process_args[i]);

    /* set_app_description() */
    if (info && info->description[0] != '\0') {
        char *d = ks_prompt_truncate(info->description, 64);
        ks_prompt_printable(d);
        set_label(p->app_desc, d);
        gtk_widget_set_tooltip_text(p->app_desc, info->description);
        gtk_widget_show(p->app_desc);
        free(d);
    } else {
        set_label(p->app_desc, "");
        gtk_widget_hide(p->app_desc);
    }
    char *path = ks_prompt_path_label(app_name, args->str, con);
    if (path != NULL) {
        char tip[4200];
        snprintf(tip, sizeof(tip), "Process path: %s", con->process_path);
        gtk_widget_set_tooltip_text(p->app_path, tip);
        set_label(p->app_path, path);
        gtk_widget_show(p->app_path);
    } else {
        set_label(p->app_path, "");
        gtk_widget_hide(p->app_path);
    }
    free(path);
    char *argl = ks_prompt_args_label(app_name, args->str);
    if (argl != NULL) {
        set_label(p->args, argl);
        gtk_widget_set_tooltip_text(p->args, args->str);
        gtk_widget_show(p->args);
    } else {
        set_label(p->args, "");
        gtk_widget_hide(p->args);
    }
    free(argl);

    set_label(p->checksum, ks_prompt_md5(con));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(p->check_sum), FALSE);

    char *display_name;
    if (app_name[0] == '\0') {
        gtk_widget_hide(p->app_path);
        gtk_widget_hide(p->args);
        set_label(p->args, "");
        display_name = g_strdup_printf("Unknown process %s", con->process_path);
        gtk_label_set_markup(GTK_LABEL(p->app_name), "<b><big>Outgoing connection</big></b>");
    } else {
        display_name = g_strdup(app_name);
        char *t = ks_prompt_truncate(app_name, 42);
        char *e = t ? ks_markup_escape(t) : NULL;
        char *m = g_strdup_printf("<b><big>%s</big></b>", e ? e : "");
        gtk_label_set_markup(GTK_LABEL(p->app_name), m);
        gtk_widget_set_tooltip_text(p->app_name, app_name);
        g_free(m);
        free(e);
        free(t);
    }

    char *cwd_tip = g_strdup_printf("Process launched from: %s", con->process_cwd);
    gtk_widget_set_tooltip_text(p->cwd, cwd_tip);
    g_free(cwd_tip);
    char *cwd = ks_prompt_truncate(con->process_cwd ? con->process_cwd : "", 32);
    set_label(p->cwd, cwd);
    free(cwd);

    GdkPixbuf *pb = load_icon(info ? info->icon : NULL);
    gtk_image_set_from_pixbuf(GTK_IMAGE(p->icon), pb);
    if (pb)
        g_object_unref(pb);

    char *msg = ks_prompt_message(ask->is_local, ask->node,
                                  ks_nodes_hostname(ks_service_nodes(p->svc), ask->node),
                                  display_name, con);
    gtk_label_set_markup(GTK_LABEL(p->message), msg ? msg : "");
    free(msg);
    g_free(display_name);

    set_label(p->dst_ip, con->dst_ip);
    char port[16] = "";
    if (con->dst_port != 0)
        snprintf(port, sizeof(port), "%u", con->dst_port);
    set_label(p->dst_port, port);
    show_if(p->dst_port, con->dst_port != 0);
    show_if(p->dst_port_title, con->dst_port != 0);
    bool md5 = ks_prompt_md5(con)[0] != '\0';
    show_if(p->check_sum, md5 && p->advanced_on);
    show_if(p->checksum, md5 && p->advanced_on);
    show_if(p->checksum_title, md5 && p->advanced_on);
    show_if(p->check_dst_port, con->dst_port != 0 && p->advanced_on);

    char *uid = ks_prompt_uid_text(con, ask->is_local);
    set_label(p->uid, uid);

    ks_combo_free(&p->what);
    ks_combo_free(&p->what_ip);
    ks_prompt_fill_combos(con, uid ? uid : "", ks_service_aliases(p->svc), &p->what,
                          &p->what_ip);
    free(uid);
    fill_combo(p->what_combo, &p->what);
    fill_combo(p->what_ip_combo, &p->what_ip);

    p->default_action = cfg_action(p);
    /* set_default_duration() */
    int dur = ks_settings_has(p->cfg, KS_CFG_DEFAULT_DURATION_KEY)
                  ? ks_settings_get_int(p->cfg, KS_CFG_DEFAULT_DURATION_KEY, 0)
                  : KS_CFG_DEFAULT_DURATION_IDX;
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->duration_combo),
                             (dur >= 0 && dur < KS_DURATION_COUNT) ? dur : -1);
    /* set_default_target() */
    int target = ks_prompt_default_target(
        &p->what, con, ks_settings_get_int(p->cfg, KS_CFG_DEFAULT_TARGET_KEY, 0),
        app_name, args->str);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->what_combo), target);

    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(p->check_dst_ip),
        ks_settings_get_bool(p->cfg, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTIP, false));
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(p->check_dst_port),
        ks_settings_get_bool(p->cfg, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTPORT, false));
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(p->check_uid),
        ks_settings_get_bool(p->cfg, KS_CFG_DEFAULT_POPUP_ADVANCED_UID, false));
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(p->check_sum),
        ks_settings_get_bool(p->cfg, KS_CFG_DEFAULT_POPUP_ADVANCED_CHECKSUM, false));
    if (ks_settings_get_bool(p->cfg, KS_CFG_DEFAULT_POPUP_ADVANCED, false))
        set_advanced(p, !p->advanced_on); /* checkAdvanced.toggle() */

    set_cmd_action_text(p);
    gtk_widget_grab_focus(p->advanced);
    g_string_free(args, TRUE);
    ks_app_info_free(info);
    p->filling = false;
}

void ks_prompt_ask(struct ks_prompt *p, struct ks_ask *ask)
{
    /* promptUser() */
    ks_settings_reload(p->cfg);
    p->tick = cfg_timeout(p);
    p->stopped = p->advanced_on;
    p->timeout_triggered = false;
    p->ask = ask;

    gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_MAIN);
    render(p);
    if (p->tick > 0) {
        gtk_widget_show(p->win);
        move_popup(p);
        gtk_window_present(GTK_WINDOW(p->win));
    }
    display_checksums_warning(p);
    char *details = ks_prompt_details(ask->con);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(p->details)),
                             details ? details : "", -1);
    free(details);

    /* _timeout_worker() */
    if (p->tick <= 0)
        g_idle_add(on_immediate_timeout, p);
    else
        p->timer = g_timeout_add_seconds(1, on_tick, p);
}

void ks_prompt_close(struct ks_prompt *p)
{
    struct ks_ask *ask = p->ask;
    if (ask == NULL)
        return;
    if (p->timer) {
        g_source_remove(p->timer);
        p->timer = 0;
    }
    p->ask = NULL;
    gtk_widget_hide(p->win);
    ks_service_answer(p->svc, ask, NULL, false);
}

/* ---- construction ------------------------------------------------------ */

static GtkWidget *label(const char *text, bool selectable)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_misc_set_alignment(GTK_MISC(l), 0, 0.5);
    gtk_label_set_selectable(GTK_LABEL(l), selectable);
    return l;
}

static GtkWidget *bold_label(const char *text)
{
    GtkWidget *l = gtk_label_new(NULL);
    char *m = g_strdup_printf("<b>%s</b>", text);
    gtk_label_set_markup(GTK_LABEL(l), m);
    g_free(m);
    gtk_misc_set_alignment(GTK_MISC(l), 0, 0.5);
    return l;
}

/* a combo whose entries can be disabled (column 1) */
static GtkWidget *new_combo(void)
{
    GtkListStore *store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_BOOLEAN);
    GtkWidget *c = gtk_combo_box_new_with_model(GTK_TREE_MODEL(store));
    g_object_unref(store);
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(c), r, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(c), r, "text", 0, "sensitive", 1, NULL);
    return c;
}

static GtkWidget *build_main_page(struct ks_prompt *p)
{
    GtkWidget *vbox = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

    /* the process */
    GtkWidget *top = gtk_hbox_new(FALSE, 8);
    p->icon = gtk_image_new();
    gtk_widget_set_size_request(p->icon, ICON_SIZE, ICON_SIZE);
    gtk_box_pack_start(GTK_BOX(top), p->icon, FALSE, FALSE, 0);
    GtkWidget *names = gtk_vbox_new(FALSE, 2);
    p->app_name = label("", true);
    p->app_desc = label("", true);
    gtk_label_set_line_wrap(GTK_LABEL(p->app_desc), TRUE);
    p->app_path = label("", true);
    p->args = label("", true);
    gtk_label_set_line_wrap(GTK_LABEL(p->args), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(p->args), PANGO_WRAP_WORD_CHAR);
    gtk_box_pack_start(GTK_BOX(names), p->app_name, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(names), p->app_desc, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(names), p->app_path, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(names), p->args, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), names, TRUE, TRUE, 0);
    GtkWidget *info = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(info),
                         gtk_image_new_from_stock(GTK_STOCK_INFO, GTK_ICON_SIZE_BUTTON));
    gtk_button_set_relief(GTK_BUTTON(info), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(info, "Details");
    g_signal_connect(info, "clicked", G_CALLBACK(on_info), p);
    gtk_box_pack_start(GTK_BOX(top), info, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), top, FALSE, FALSE, 0);

    p->message = label("", true);
    gtk_label_set_line_wrap(GTK_LABEL(p->message), TRUE);
    gtk_label_set_line_wrap_mode(GTK_LABEL(p->message), PANGO_WRAP_WORD_CHAR);
    gtk_widget_set_size_request(p->message, 460, -1);
    g_signal_connect(p->message, "activate-link", G_CALLBACK(on_message_link), p);
    gtk_box_pack_start(GTK_BOX(vbox), p->message, FALSE, FALSE, 4);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_hseparator_new(), FALSE, FALSE, 0);

    /* the details grid */
    GtkWidget *t = gtk_table_new(5, 3, FALSE);
    gtk_table_set_row_spacings(GTK_TABLE(t), 4);
    gtk_table_set_col_spacings(GTK_TABLE(t), 8);
    p->cwd = label("", true);
    p->dst_ip = label("", true);
    p->dst_port = label("", true);
    p->uid = label("", true);
    p->checksum = label("", true);
    p->dst_port_title = bold_label("Destination Port");
    p->checksum_title = bold_label("Checksum");
    p->check_dst_ip = gtk_check_button_new();
    p->check_dst_port = gtk_check_button_new();
    p->check_uid = gtk_check_button_new();
    p->check_sum = gtk_check_button_new();
    p->what_ip_combo = new_combo();
    GtkWidget *ipbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(ipbox), p->dst_ip, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ipbox), p->what_ip_combo, TRUE, TRUE, 0);
    GtkAttachOptions fill = GTK_FILL, grow = GTK_FILL | GTK_EXPAND;
    gtk_table_attach(GTK_TABLE(t), bold_label("Executed from"), 1, 2, 0, 1, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->cwd, 2, 3, 0, 1, grow, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->check_dst_ip, 0, 1, 1, 2, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), bold_label("Destination IP"), 1, 2, 1, 2, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), ipbox, 2, 3, 1, 2, grow, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->check_dst_port, 0, 1, 2, 3, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->dst_port_title, 1, 2, 2, 3, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->dst_port, 2, 3, 2, 3, grow, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->check_uid, 0, 1, 3, 4, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), bold_label("User ID"), 1, 2, 3, 4, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->uid, 2, 3, 3, 4, grow, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->check_sum, 0, 1, 4, 5, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->checksum_title, 1, 2, 4, 5, fill, fill, 0, 0);
    gtk_table_attach(GTK_TABLE(t), p->checksum, 2, 3, 4, 5, grow, fill, 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), t, FALSE, FALSE, 0);

    /* the choice */
    GtkWidget *row = gtk_hbox_new(FALSE, 4);
    p->what_combo = new_combo();
    p->duration_combo = gtk_combo_box_new_text();
    for (int i = 0; i < KS_DURATION_COUNT; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(p->duration_combo), ks_duration_labels[i]);
    p->advanced = gtk_toggle_button_new_with_label("+");
    gtk_widget_set_tooltip_text(p->advanced, "Advanced options");
    p->action_button = gtk_button_new_with_mnemonic(action_text[0]);
    gtk_button_set_use_underline(GTK_BUTTON(p->action_button), TRUE);
    gtk_button_set_image(GTK_BUTTON(p->action_button),
                         gtk_image_new_from_stock(GTK_STOCK_NO, GTK_ICON_SIZE_BUTTON));
    GtkWidget *arrow = gtk_button_new();
    gtk_container_add(GTK_CONTAINER(arrow), gtk_arrow_new(GTK_ARROW_DOWN, GTK_SHADOW_NONE));
    p->allow_button = gtk_button_new_with_mnemonic(action_text[1]);
    gtk_button_set_image(GTK_BUTTON(p->allow_button),
                         gtk_image_new_from_stock(GTK_STOCK_YES, GTK_ICON_SIZE_BUTTON));
    gtk_box_pack_start(GTK_BOX(row), p->what_combo, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(row), p->duration_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), p->advanced, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), row, FALSE, FALSE, 4);
    GtkWidget *buttons = gtk_hbox_new(FALSE, 4);
    GtkWidget *split = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(split), p->action_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(split), arrow, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(buttons), p->allow_button, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(buttons), split, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), buttons, FALSE, FALSE, 0);

    p->action_menu = gtk_menu_new();
    GtkWidget *deny = gtk_menu_item_new_with_mnemonic(action_text[0]);
    GtkWidget *reject = gtk_menu_item_new_with_mnemonic(action_text[2]);
    gtk_menu_shell_append(GTK_MENU_SHELL(p->action_menu), deny);
    gtk_menu_shell_append(GTK_MENU_SHELL(p->action_menu), reject);
    gtk_widget_show_all(p->action_menu);
    g_signal_connect(deny, "activate", G_CALLBACK(on_menu_deny), p);
    g_signal_connect(reject, "activate", G_CALLBACK(on_menu_reject), p);

    g_signal_connect(p->allow_button, "clicked", G_CALLBACK(on_allow), p);
    g_signal_connect(p->action_button, "clicked", G_CALLBACK(on_action), p);
    g_signal_connect(arrow, "clicked", G_CALLBACK(on_action_arrow), p);
    g_signal_connect(p->advanced, "toggled", G_CALLBACK(on_advanced_toggled), p);
    g_signal_connect(p->what_combo, "changed", G_CALLBACK(on_user_change), p);
    g_signal_connect(p->what_ip_combo, "changed", G_CALLBACK(on_user_change), p);
    g_signal_connect(p->duration_combo, "changed", G_CALLBACK(on_user_change), p);
    g_signal_connect(p->check_dst_ip, "toggled", G_CALLBACK(on_user_change), p);
    g_signal_connect(p->check_dst_port, "toggled", G_CALLBACK(on_user_change), p);
    g_signal_connect(p->check_uid, "toggled", G_CALLBACK(on_user_change), p);
    return vbox;
}

static GtkWidget *back_button(struct ks_prompt *p)
{
    GtkWidget *b = gtk_button_new_from_stock(GTK_STOCK_GO_BACK);
    gtk_button_set_relief(GTK_BUTTON(b), GTK_RELIEF_NONE);
    g_signal_connect(b, "clicked", G_CALLBACK(on_back), p);
    return b;
}

static GtkWidget *build_details_page(struct ks_prompt *p)
{
    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    GtkWidget *hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb), back_button(p), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hb, FALSE, FALSE, 0);
    p->details = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(p->details), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(p->details), GTK_WRAP_WORD_CHAR);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), p->details);
    gtk_widget_set_size_request(sw, -1, 220);
    gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 0);
    return vbox;
}

static GtkWidget *build_checksums_page(struct ks_prompt *p)
{
    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    GtkWidget *hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb), back_button(p), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hb, FALSE, FALSE, 0);
    p->checksum_note = label("", true);
    gtk_label_set_line_wrap(GTK_LABEL(p->checksum_note), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), p->checksum_note, FALSE, FALSE, 0);
    p->checksum_rules = gtk_combo_box_new_text();
    gtk_box_pack_start(GTK_BOX(vbox), p->checksum_rules, FALSE, FALSE, 0);
    p->checksum_status = label("", false);
    gtk_box_pack_start(GTK_BOX(vbox), p->checksum_status, FALSE, FALSE, 0);
    GtkWidget *bb = gtk_hbox_new(FALSE, 4);
    GtkWidget *upd = gtk_button_new_with_label("Update rule");
    GtkWidget *all = gtk_button_new_with_label("Update All");
    g_signal_connect(upd, "clicked", G_CALLBACK(on_update_rule), p);
    g_signal_connect(all, "clicked", G_CALLBACK(on_update_all), p);
    gtk_box_pack_start(GTK_BOX(bb), upd, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bb), all, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(vbox), bb, FALSE, FALSE, 0);
    return vbox;
}

struct ks_prompt *ks_prompt_new(struct ks_service *svc, struct ks_desktop *desktop)
{
    struct ks_prompt *p = calloc(1, sizeof(*p));
    if (p == NULL)
        return NULL;
    p->svc = svc;
    p->desktop = desktop;
    p->cfg = ks_service_settings(svc);

    p->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[64];
    snprintf(title, sizeof(title), "Kisnitch v%s", KS_VERSION);
    gtk_window_set_title(GTK_WINDOW(p->win), title);
    gtk_window_set_keep_above(GTK_WINDOW(p->win), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(p->win), FALSE);
    gtk_window_set_wmclass(GTK_WINDOW(p->win), "kisnitch-prompt", "Kisnitch");
    gtk_widget_add_events(p->win, GDK_BUTTON_PRESS_MASK);

    p->pages = gtk_notebook_new();
    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(p->pages), FALSE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(p->pages), FALSE);
    gtk_notebook_append_page(GTK_NOTEBOOK(p->pages), build_details_page(p), NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(p->pages), build_checksums_page(p), NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(p->pages), build_main_page(p), NULL);
    gtk_container_add(GTK_CONTAINER(p->win), p->pages);

    g_signal_connect(p->win, "delete-event", G_CALLBACK(on_delete), p);
    g_signal_connect(p->win, "key-press-event", G_CALLBACK(on_key), p);
    g_signal_connect(p->win, "button-press-event", G_CALLBACK(on_button_press), p);

    gtk_widget_show_all(p->pages);
    /* hidden until "advanced" (__init__) */
    gtk_widget_hide(p->what_ip_combo);
    gtk_widget_hide(p->check_dst_ip);
    gtk_widget_hide(p->check_dst_port);
    gtk_widget_hide(p->check_uid);
    gtk_widget_hide(p->check_sum);
    gtk_widget_hide(p->checksum);
    gtk_widget_hide(p->checksum_title);
    gtk_widget_hide(p->app_desc);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(p->pages), PAGE_MAIN);
    return p;
}

void ks_prompt_free(struct ks_prompt *p)
{
    if (p == NULL)
        return;
    ks_prompt_close(p);
    if (p->timer)
        g_source_remove(p->timer);
    gtk_widget_destroy(p->action_menu);
    gtk_widget_destroy(p->win);
    ks_combo_free(&p->what);
    ks_combo_free(&p->what_ip);
    clear_checksum_names(p);
    free(p);
}
