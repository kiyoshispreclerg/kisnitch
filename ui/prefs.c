/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/preferences.py (the dialog) and
 * res/preferences.ui. See prefs.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/prefs.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/log.h"
#include "ui/db.h"
#include "ui/prefs_node.h"
#include "ui/rulesdb.h"
#include "ui/tray.h"

#define HELP_URL "https://github.com/evilsocket/opensnitch/wiki/"
#define KEY_NOTIF_ENABLED "notifications/enabled"
#define KEY_NOTIF_TYPE "notifications/type"
#define KEY_REFRESH "statsDialog/refresh_interval"
#define KEY_SHOW_COLUMNS "statsDialog/show_columns"
#define KEY_MAX_MSG "global/server_max_message_length"
#define KEY_MAX_WORKERS "global/max_workers"
#define KEY_AUTH_CACERT "auth/cacert"
#define KEY_AUTH_CERT "auth/cert"
#define KEY_AUTH_CERTKEY "auth/certkey"
#define NOTIFICATION_TYPE_QT 0
#define NOTIFICATION_TYPE_SYSTEM 1
#define DEFAULT_DURATION_IDX 6
#define NCOLS 14

enum { TAB_POPUPS, TAB_UI, TAB_RULES, TAB_NODES, TAB_DB };

struct ks_prefs {
    struct ks_service *svc;
    struct ks_settings *cfg;
    void (*on_saved)(void *);
    void *ud;
    GtkWidget *win, *nb, *status;

    /* pop-ups */
    GtkWidget *spin_timeout, *popups_check, *c_action, *c_duration, *c_target, *c_pos;
    GtkWidget *adv_check, *uid_check, *dstport_check, *dstip_check, *sum_check;
    /* UI */
    GtkWidget *spin_refresh, *c_lang, *autostart, *srv_addr, *msg_size, *c_auth, *ca_line, *cert_line,
        *key_line, *spin_workers, *spin_clients, *notif_group, *radio_sys, *radio_qt,
        *cols[NCOLS];
    /* rules */
    GtkWidget *rules_check, *c_rules;
    /* nodes */
    GtkWidget *apply_all, *c_nodes, *l_version, *l_name, *n_action, *n_monitor, *n_intercept,
        *n_addr, *n_loglevel, *n_utc, *n_micro, *n_logfile, *n_auth, *n_ca, *n_srvcert, *n_cert,
        *n_key, *n_skip, *n_verify, *n_checksums, *n_rules_path, *n_rules_btn, *n_maxevents,
        *n_maxstats, *n_gc, *n_fwint, *n_flush, *n_block;
    /* database */
    GtkWidget *db_type, *db_label, *db_file_btn, *db_days_check, *db_days_spin, *db_interval_spin,
        *db_wal;

    struct ks_nform nf;
    GPtrArray *node_addrs;
    int db_type_loaded;
    bool loading;
    bool saved;
    char *restart; /* _changes_needs_restart */
};

/* ---- small helpers ---------------------------------------------------------------------- */

static const char *combo_entry_text(GtkWidget *c)
{
    return gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(c))));
}

static void set_combo_entry_text(GtkWidget *c, const char *t)
{
    gtk_entry_set_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(c))), t != NULL ? t : "");
}

static bool is_active(GtkWidget *w)
{
    return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
}

static void set_active(GtkWidget *w, bool on)
{
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), on);
}

static int spin_value(GtkWidget *w)
{
    return gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(w));
}

static void set_spin(GtkWidget *w, int v)
{
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), v);
}

static void set_status(struct ks_prefs *p, const char *msg, const char *color)
{
    char *m = g_markup_printf_escaped("<span foreground=\"%s\">%s</span>", color, msg);
    gtk_label_set_markup(GTK_LABEL(p->status), m);
    g_free(m);
    gtk_widget_show(p->status);
}

static void set_error(struct ks_prefs *p, const char *msg)
{
    set_status(p, msg, "red");
}

static void set_success(struct ks_prefs *p, const char *msg)
{
    set_status(p, msg, "green");
}

static void set_message(struct ks_prefs *p, const char *msg)
{
    set_status(p, msg, "darkorange");
}

static void reset_status(struct ks_prefs *p)
{
    gtk_label_set_text(GTK_LABEL(p->status), "");
    gtk_widget_hide(p->status);
}

static void need_restart(struct ks_prefs *p, const char *why)
{
    g_free(p->restart);
    p->restart = g_strdup(why);
}

static void message_dialog(struct ks_prefs *p, GtkMessageType type, const char *primary,
                           const char *secondary)
{
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(p->win), GTK_DIALOG_DESTROY_WITH_PARENT, type,
                                          GTK_BUTTONS_OK, "%s", primary);
    if (secondary != NULL && secondary[0] != '\0')
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d), "%s", secondary);
    g_signal_connect_swapped(d, "response", G_CALLBACK(gtk_widget_destroy), d);
    gtk_widget_show(d);
}

static GtkWidget *combo_with(const char *const *items, size_t n)
{
    GtkWidget *c = gtk_combo_box_new_text();
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(c), items[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), 0);
    return c;
}

static GtkWidget *entry_combo_with(const char *const *items, size_t n)
{
    GtkWidget *c = gtk_combo_box_entry_new_text();
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(c), items[i]);
    return c;
}

static GtkWidget *new_table(void)
{
    GtkWidget *t = gtk_table_new(1, 2, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(t), 8);
    return t;
}

/* a "Label | widget" row */
static void row(GtkWidget *table, int line, const char *label, GtkWidget *w, const char *tip)
{
    GtkWidget *l = gtk_label_new(label);
    gtk_misc_set_alignment(GTK_MISC(l), 0.0f, 0.5f);
    if (tip != NULL) {
        gtk_widget_set_tooltip_text(l, tip);
        gtk_widget_set_tooltip_text(w, tip);
    }
    gtk_table_attach(GTK_TABLE(table), l, 0, 1, (guint)line, (guint)line + 1, GTK_FILL, GTK_FILL, 6, 3);
    gtk_table_attach(GTK_TABLE(table), w, 1, 2, (guint)line, (guint)line + 1, GTK_EXPAND | GTK_FILL,
                     GTK_FILL, 6, 3);
}

static GtkWidget *spin(double min, double max, double val)
{
    GtkWidget *s = gtk_spin_button_new_with_range(min, max, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(s), val);
    return s;
}

/* a long page: tables in a scrolled window */
static GtkWidget *page(GtkWidget *content)
{
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(sw), content);
    gtk_viewport_set_shadow_type(GTK_VIEWPORT(gtk_bin_get_child(GTK_BIN(sw))), GTK_SHADOW_NONE);
    return sw;
}

/* ---- the node form <-> the widgets ----------------------------------------------------------- */

static const char *selected_node(struct ks_prefs *p)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_nodes));
    return i >= 0 && (guint)i < p->node_addrs->len ? g_ptr_array_index(p->node_addrs, (guint)i) : NULL;
}

static void read_nform(struct ks_prefs *p)
{
    struct ks_nform *f = &p->nf;
    f->action = gtk_combo_box_get_active(GTK_COMBO_BOX(p->n_action));
    f->monitor = gtk_combo_box_get_active(GTK_COMBO_BOX(p->n_monitor));
    f->intercept_unknown = is_active(p->n_intercept);
    f->log_level = gtk_combo_box_get_active(GTK_COMBO_BOX(p->n_loglevel));
    f->log_utc = is_active(p->n_utc);
    f->log_micro = is_active(p->n_micro);
    ks_nform_set(&f->address, combo_entry_text(p->n_addr));
    ks_nform_set(&f->log_file, combo_entry_text(p->n_logfile));
    f->auth_type = gtk_combo_box_get_active(GTK_COMBO_BOX(p->n_auth));
    ks_nform_set(&f->ca_cert, gtk_entry_get_text(GTK_ENTRY(p->n_ca)));
    ks_nform_set(&f->server_cert, gtk_entry_get_text(GTK_ENTRY(p->n_srvcert)));
    ks_nform_set(&f->client_cert, gtk_entry_get_text(GTK_ENTRY(p->n_cert)));
    ks_nform_set(&f->client_key, gtk_entry_get_text(GTK_ENTRY(p->n_key)));
    f->skip_verify = is_active(p->n_skip);
    f->verify_type = gtk_combo_box_get_active(GTK_COMBO_BOX(p->n_verify));
    f->checksums = is_active(p->n_checksums);
    ks_nform_set(&f->rules_path, gtk_entry_get_text(GTK_ENTRY(p->n_rules_path)));
    f->flush_conns = is_active(p->n_flush);
    f->gc = spin_value(p->n_gc);
    ks_nform_set(&f->fw_interval, gtk_entry_get_text(GTK_ENTRY(p->n_fwint)));
    f->block_on_fail = is_active(p->n_block);
    ks_nform_set(&f->max_events, gtk_entry_get_text(GTK_ENTRY(p->n_maxevents)));
    ks_nform_set(&f->max_stats, gtk_entry_get_text(GTK_ENTRY(p->n_maxstats)));
}

static void write_nform(struct ks_prefs *p)
{
    struct ks_nform *f = &p->nf;
    bool was = p->loading;
    p->loading = true;
    gtk_label_set_text(GTK_LABEL(p->l_version), f->version);
    gtk_label_set_text(GTK_LABEL(p->l_name), f->name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->n_action), f->action);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->n_monitor), f->monitor);
    set_active(p->n_intercept, f->intercept_unknown);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->n_loglevel), f->log_level);
    set_active(p->n_utc, f->log_utc);
    set_active(p->n_micro, f->log_micro);
    gtk_widget_set_sensitive(p->n_addr, f->server_enabled);
    gtk_widget_set_sensitive(p->n_logfile, f->server_enabled);
    set_combo_entry_text(p->n_addr, f->address);
    set_combo_entry_text(p->n_logfile, f->log_file);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->n_auth), f->auth_type);
    gtk_entry_set_text(GTK_ENTRY(p->n_ca), f->ca_cert);
    gtk_entry_set_text(GTK_ENTRY(p->n_srvcert), f->server_cert);
    gtk_entry_set_text(GTK_ENTRY(p->n_cert), f->client_cert);
    gtk_entry_set_text(GTK_ENTRY(p->n_key), f->client_key);
    set_active(p->n_skip, f->skip_verify);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->n_verify), f->verify_type);
    gtk_widget_set_sensitive(p->n_ca, f->ca_enabled);
    gtk_widget_set_sensitive(p->n_srvcert, f->certs_enabled);
    gtk_widget_set_sensitive(p->n_cert, f->certs_enabled);
    gtk_widget_set_sensitive(p->n_key, f->certs_enabled);
    gtk_widget_set_sensitive(p->n_skip, f->certs_enabled);
    gtk_widget_set_sensitive(p->n_verify, f->certs_enabled);
    set_active(p->n_checksums, f->checksums);
    gtk_entry_set_text(GTK_ENTRY(p->n_rules_path), f->rules_path);
    set_active(p->n_flush, f->flush_conns);
    set_spin(p->n_gc, f->gc);
    gtk_entry_set_text(GTK_ENTRY(p->n_fwint), f->fw_interval);
    set_active(p->n_block, f->block_on_fail);
    gtk_entry_set_text(GTK_ENTRY(p->n_maxevents), f->max_events);
    gtk_entry_set_text(GTK_ENTRY(p->n_maxstats), f->max_stats);
    p->loading = was;
}

/* _load_node_settings() */
static void load_node_settings(struct ks_prefs *p)
{
    const char *addr = selected_node(p);
    struct ks_node *n = addr != NULL ? ks_nodes_get(ks_service_nodes(p->svc), addr) : NULL;
    if (n == NULL || n->config == NULL)
        return;
    char *norm = NULL, err[300];
    bool ok = ks_prefs_load_node(&p->nf, n->config->version, n->config->name, n->config->loglevel,
                                 n->config->config, &norm, err, sizeof(err));
    write_nform(p);
    if (ok) {
        /* the node's configuration, as normalized, is the one it keeps */
        free(n->config->config);
        n->config->config = norm;
    } else {
        char *m = g_strdup_printf("Error loading config %s: %s", addr, err);
        set_error(p, m);
        g_free(m);
    }
}

/* _reset_node_settings() */
static void reset_node_settings(struct ks_prefs *p)
{
    ks_nform_reset(&p->nf);
    write_nform(p);
}

static void load_nodes(struct ks_prefs *p)
{
    struct ks_nodes *nodes = ks_service_nodes(p->svc);
    bool was = p->loading;
    p->loading = true;
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(p->c_nodes));
    gtk_list_store_clear(GTK_LIST_STORE(m));
    g_ptr_array_set_size(p->node_addrs, 0);
    for (size_t i = 0; i < nodes->len; i++) {
        const struct ks_node *n = nodes->items[i];
        char *lbl = g_strdup_printf("%s - %s", n->addr, ks_nodes_hostname(nodes, n->addr));
        gtk_combo_box_append_text(GTK_COMBO_BOX(p->c_nodes), lbl);
        g_free(lbl);
        g_ptr_array_add(p->node_addrs, g_strdup(n->addr));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_nodes), nodes->len > 0 ? 0 : -1);
    p->loading = was;
    if (nodes->len == 0) {
        reset_node_settings(p);
        set_message(p, "There're no nodes connected");
    }
    bool show = nodes->len > 1;
    gtk_widget_set_visible(p->c_nodes, show);
    gtk_widget_set_visible(p->apply_all, show);
}

/* ---- loading the settings -------------------------------------------------------------------- */

/* str(c) in cols: a list "0, 1" is its items; a lone value is a string and `in` looks for a
 * substring (as in the statistics window) */
static bool column_listed(const char *value, int c)
{
    char num[16];
    snprintf(num, sizeof(num), "%d", c);
    if (strchr(value, ',') == NULL)
        return strstr(value, num) != NULL;
    bool found = false;
    char **items = g_strsplit(value, ",", -1);
    for (char **it = items; *it != NULL; it++) {
        if (strcmp(g_strstrip(*it), num) == 0)
            found = true;
    }
    g_strfreev(items);
    return found;
}

static void db_cleaner_widgets(struct ks_prefs *p, bool enable)
{
    set_active(p->db_days_check, enable);
    gtk_widget_set_sensitive(p->db_days_spin, enable);
    gtk_widget_set_sensitive(p->db_interval_spin, enable);
}

static void load_settings(struct ks_prefs *p)
{
    struct ks_settings *c = p->cfg;
    p->loading = true;
    bool disable_popups = ks_settings_get_bool(c, KS_CFG_DEFAULT_DISABLE_POPUPS, false);
    int duration = ks_settings_has(c, KS_CFG_DEFAULT_DURATION_KEY)
                       ? ks_settings_get_int(c, KS_CFG_DEFAULT_DURATION_KEY, 0)
                       : DEFAULT_DURATION_IDX;
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_duration), duration);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_pos),
                             ks_settings_get_int(c, KS_CFG_DEFAULT_POPUP_POSITION, 0));
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_action),
                             ks_settings_get_int(c, KS_CFG_DEFAULT_ACTION_KEY, 0));
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_target),
                             ks_settings_get_int(c, KS_CFG_DEFAULT_TARGET_KEY, 0));
    set_spin(p->spin_timeout, ks_settings_get_int(c, KS_CFG_DEFAULT_TIMEOUT_KEY, KS_CFG_DEFAULT_TIMEOUT));
    gtk_widget_set_sensitive(p->spin_timeout, !disable_popups);
    set_active(p->popups_check, disable_popups);
    set_active(p->adv_check, ks_settings_get_bool(c, KS_CFG_DEFAULT_POPUP_ADVANCED, false));
    set_active(p->dstip_check, ks_settings_get_bool(c, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTIP, false));
    set_active(p->dstport_check, ks_settings_get_bool(c, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTPORT, false));
    set_active(p->uid_check, ks_settings_get_bool(c, KS_CFG_DEFAULT_POPUP_ADVANCED_UID, false));
    set_active(p->sum_check, ks_settings_get_bool(c, KS_CFG_DEFAULT_POPUP_ADVANCED_CHECKSUM, false));

    bool ignore = ks_settings_get_bool(c, KS_CFG_DEFAULT_IGNORE_RULES, false);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_rules),
                             ks_settings_get_int(c, KS_CFG_DEFAULT_IGNORE_TEMPORARY_RULES, 0));
    set_active(p->rules_check, ignore);
    gtk_widget_set_sensitive(p->c_rules, ignore);

    set_active(p->notif_group, ks_settings_get_bool(c, KEY_NOTIF_ENABLED, true));
    int ntype = ks_settings_get_int(c, KEY_NOTIF_TYPE, NOTIFICATION_TYPE_SYSTEM);
    set_active(p->radio_sys, ntype == NOTIFICATION_TYPE_SYSTEM);
    set_active(p->radio_qt, ntype != NOTIFICATION_TYPE_SYSTEM);

    /* database */
    p->db_type_loaded = ks_settings_get_int(c, KS_CFG_DEFAULT_DB_TYPE_KEY, 0);
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->db_type), p->db_type_loaded);
    bool file = p->db_type_loaded != KS_CFG_DB_TYPE_MEMORY;
    gtk_widget_set_visible(p->db_file_btn, file);
    gtk_widget_set_visible(p->db_label, file);
    if (file) {
        char *f = ks_settings_get_string(c, KS_CFG_DEFAULT_DB_FILE_KEY);
        gtk_label_set_text(GTK_LABEL(p->db_label), f != NULL ? f : "");
        free(f);
    }
    int days = ks_settings_get_int(c, KS_CFG_DB_MAX_DAYS, 1);
    bool purge = ks_settings_get_bool(c, KS_CFG_DB_PURGE_OLDEST, false);
    db_cleaner_widgets(p, purge);
    set_active(p->db_wal, ks_settings_get_bool(c, KS_CFG_DEFAULT_DB_JRNL_WAL, false));
    gtk_widget_set_sensitive(p->db_wal, purge);
    set_spin(p->db_days_spin, days);
    set_spin(p->db_interval_spin, ks_settings_get_int(c, KS_CFG_DB_PURGE_INTERVAL, 5));

    /* UI */
    set_spin(p->spin_refresh, ks_settings_get_int(c, KEY_REFRESH, 0));
    char *msg = ks_settings_get_string(c, KEY_MAX_MSG);
    if (msg != NULL && msg[0] != '\0')
        set_combo_entry_text(p->msg_size, msg);
    else
        set_combo_entry_text(p->msg_size, "4MiB");
    free(msg);
    char *addr = ks_settings_get_string(c, KS_CFG_DEFAULT_SERVER_ADDR);
    if (addr == NULL || addr[0] == '\0') {
        free(addr);
        addr = strdup("unix:///tmp/osui.sock");
    }
    set_combo_entry_text(p->srv_addr, addr);
    free(addr);
    set_spin(p->spin_workers, ks_settings_get_int(c, KEY_MAX_WORKERS, 20));
    set_spin(p->spin_clients, ks_settings_get_int(c, KS_CFG_DEFAULT_SERVER_MAX_CLIENTS, 0));
    char *t;
    t = ks_settings_get_string(c, KEY_AUTH_CACERT);
    gtk_entry_set_text(GTK_ENTRY(p->ca_line), t != NULL ? t : "");
    free(t);
    t = ks_settings_get_string(c, KEY_AUTH_CERT);
    gtk_entry_set_text(GTK_ENTRY(p->cert_line), t != NULL ? t : "");
    free(t);
    t = ks_settings_get_string(c, KEY_AUTH_CERTKEY);
    gtk_entry_set_text(GTK_ENTRY(p->key_line), t != NULL ? t : "");
    free(t);
    char *at = ks_settings_get_string(c, KS_CFG_AUTH_TYPE);
    int ai = at != NULL ? ks_node_auth_index(at) : 0;
    free(at);
    if (ai <= 0)
        ai = 0;
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_auth), ai);
    gtk_widget_set_sensitive(p->ca_line, ai == 2);
    gtk_widget_set_sensitive(p->cert_line, ai >= 1);
    gtk_widget_set_sensitive(p->key_line, ai >= 1);

    /* the columns of the events table: those listed are shown */
    char *cols = ks_settings_get_string(c, KEY_SHOW_COLUMNS);
    if (cols != NULL) {
        for (int i = 0; i < NCOLS; i++)
            set_active(p->cols[i], column_listed(cols, i));
    }
    free(cols);

    char *home_cfg = g_strdup(g_get_user_config_dir());
    set_active(p->autostart, ks_autostart_enabled(home_cfg));
    g_free(home_cfg);
    p->loading = false;
}

/* ---- saving ------------------------------------------------------------------------------------ */

static void set_int(struct ks_prefs *p, const char *key, int v)
{
    ks_settings_set_int(p->cfg, key, v);
}

static void set_bool(struct ks_prefs *p, const char *key, bool v)
{
    ks_settings_set_bool(p->cfg, key, v);
}

/* _save_db_config() */
static bool save_db_config(struct ks_prefs *p)
{
    int dbtype = gtk_combo_box_get_active(GTK_COMBO_BOX(p->db_type));
    char *db_name = ks_settings_get_string(p->cfg, KS_CFG_DEFAULT_DB_FILE_KEY);
    const char *label = gtk_label_get_text(GTK_LABEL(p->db_label));
    if (label[0] != '\0' && (dbtype != p->db_type_loaded || db_name == NULL || strcmp(db_name, label) != 0))
        need_restart(p, "DB type changed");
    char *name = NULL;
    if (dbtype != KS_CFG_DB_TYPE_MEMORY) {
        if (label[0] != '\0') {
            name = g_strdup(label);
        } else {
            message_dialog(p, GTK_MESSAGE_WARNING, "Warning",
                           "You must select a file for the database\nor choose \"In memory\" type.");
            free(db_name);
            return false;
        }
    } else {
        name = g_strdup(KS_CFG_DB_IN_MEMORY);
    }
    ks_settings_set_string(p->cfg, KS_CFG_DEFAULT_DB_FILE_KEY, name);
    set_int(p, KS_CFG_DEFAULT_DB_TYPE_KEY, dbtype);
    set_bool(p, KS_CFG_DB_PURGE_OLDEST, is_active(p->db_days_check));
    set_int(p, KS_CFG_DB_MAX_DAYS, spin_value(p->db_days_spin));
    set_int(p, KS_CFG_DB_PURGE_INTERVAL, spin_value(p->db_interval_spin));
    set_bool(p, KS_CFG_DEFAULT_DB_JRNL_WAL, is_active(p->db_wal));
    p->db_type_loaded = dbtype;
    g_free(name);
    free(db_name);
    return true;
}

/* _save_ui_columns_config(): the checked columns, as the list QSettings writes */
static void save_ui_columns(struct ks_prefs *p)
{
    GString *g = g_string_new(NULL);
    for (int i = 0; i < NCOLS; i++) {
        if (is_active(p->cols[i]))
            g_string_append_printf(g, "%s%d", g->len ? ", " : "", i);
    }
    /* an empty list is saved as a null value */
    ks_settings_set_raw(p->cfg, KEY_SHOW_COLUMNS, g->len ? g->str : "@Invalid()");
    ks_settings_sync(p->cfg);
    g_string_free(g, TRUE);
}

/* _save_ui_config() */
static bool save_ui_config(struct ks_prefs *p)
{
    struct ks_settings *c = p->cfg;
    save_ui_columns(p);

    const char *maxmsg = combo_entry_text(p->msg_size);
    char *saved = ks_settings_get_string(c, KEY_MAX_MSG);
    if (maxmsg[0] != '\0' && (saved == NULL || strcmp(saved, maxmsg) != 0)) {
        char *clean = g_strdelimit(g_strdup(maxmsg), " ", 'x');
        char *nospace = g_strdup(maxmsg);
        size_t o = 0;
        for (const char *s = clean; *s; s++) {
            if (*s != 'x')
                nospace[o++] = *s;
        }
        nospace[o] = '\0';
        ks_settings_set_string(c, KEY_MAX_MSG, nospace);
        need_restart(p, "Server options changed");
        g_free(clean);
        g_free(nospace);
    }
    free(saved);

    int ai = gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_auth));
    if (ai > 0) {
        /* TLS for the UI's server comes with phase 10: main refuses to start with it */
        set_error(p, "TLS is not supported yet (phase 10), the server stays on Simple");
        gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_auth), 0);
        ai = 0;
    }
    char *saved_auth = ks_settings_get_string(c, KS_CFG_AUTH_TYPE);
    if (saved_auth == NULL || strcmp(saved_auth, ks_node_auth_types[ai]) != 0)
        need_restart(p, "Certificates changed");
    free(saved_auth);
    ks_settings_set_string(c, KS_CFG_AUTH_TYPE, ks_node_auth_types[ai]);
    ks_settings_set_string(c, KEY_AUTH_CACERT, gtk_entry_get_text(GTK_ENTRY(p->ca_line)));
    ks_settings_set_string(c, KEY_AUTH_CERT, gtk_entry_get_text(GTK_ENTRY(p->cert_line)));
    ks_settings_set_string(c, KEY_AUTH_CERTKEY, gtk_entry_get_text(GTK_ENTRY(p->key_line)));

    char *srv = ks_settings_get_string(c, KS_CFG_DEFAULT_SERVER_ADDR);
    const char *new_srv = combo_entry_text(p->srv_addr);
    if (srv == NULL || strcmp(srv, new_srv) != 0) {
        ks_settings_set_string(c, KS_CFG_DEFAULT_SERVER_ADDR, new_srv);
        need_restart(p, "Server address changed");
    }
    free(srv);
    if (ks_settings_get_int(c, KEY_MAX_WORKERS, 20) != spin_value(p->spin_workers)) {
        set_int(p, KEY_MAX_WORKERS, spin_value(p->spin_workers));
        need_restart(p, "Server max workers changed");
    }
    if (ks_settings_get_int(c, KS_CFG_DEFAULT_SERVER_MAX_CLIENTS, 0) != spin_value(p->spin_clients)) {
        set_int(p, KS_CFG_DEFAULT_SERVER_MAX_CLIENTS, spin_value(p->spin_clients));
        need_restart(p, "Server max clients changed");
    }

    set_int(p, KS_CFG_DEFAULT_IGNORE_TEMPORARY_RULES, gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_rules)));
    set_bool(p, KS_CFG_DEFAULT_IGNORE_RULES, is_active(p->rules_check));
    struct ks_rulesdb *rules = ks_service_rules(p->svc);
    ks_rulesdb_set_duration_filter(rules, is_active(p->rules_check),
                                   gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_rules)));
    if (is_active(p->rules_check))
        ks_rulesdb_delete_filtered(rules);

    set_int(p, KEY_REFRESH, spin_value(p->spin_refresh));
    set_int(p, KS_CFG_DEFAULT_ACTION_KEY, gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_action)));
    set_int(p, KS_CFG_DEFAULT_DURATION_KEY, gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_duration)));
    set_int(p, KS_CFG_DEFAULT_TARGET_KEY, gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_target)));
    set_int(p, KS_CFG_DEFAULT_TIMEOUT_KEY, spin_value(p->spin_timeout));
    set_bool(p, KS_CFG_DEFAULT_DISABLE_POPUPS, is_active(p->popups_check));
    set_int(p, KS_CFG_DEFAULT_POPUP_POSITION, gtk_combo_box_get_active(GTK_COMBO_BOX(p->c_pos)));
    set_bool(p, KS_CFG_DEFAULT_POPUP_ADVANCED, is_active(p->adv_check));
    set_bool(p, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTIP, is_active(p->dstip_check));
    set_bool(p, KS_CFG_DEFAULT_POPUP_ADVANCED_DSTPORT, is_active(p->dstport_check));
    set_bool(p, KS_CFG_DEFAULT_POPUP_ADVANCED_UID, is_active(p->uid_check));
    set_bool(p, KS_CFG_DEFAULT_POPUP_ADVANCED_CHECKSUM, is_active(p->sum_check));
    set_bool(p, KEY_NOTIF_ENABLED, is_active(p->notif_group));
    set_int(p, KEY_NOTIF_TYPE, is_active(p->radio_sys) ? NOTIFICATION_TYPE_SYSTEM : NOTIFICATION_TYPE_QT);
    /* a workaround for not displaying pop-ups (upstream issue #79) */
    if (is_active(p->popups_check))
        set_int(p, KS_CFG_DEFAULT_TIMEOUT_KEY, 0);
    ks_autostart_enable(g_get_user_config_dir(), is_active(p->autostart));
    return true;
}

static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_prefs *p = ud;
    (void)addr;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__OK) {
        set_success(p, "Configuration applied.");
    } else {
        char *m = g_strdup_printf("Error applying configuration: %s", r->data != NULL ? r->data : "");
        set_error(p, m);
        g_free(m);
    }
}

/* _save_node_config() for one node; the error text, or NULL */
static char *save_node_config(struct ks_prefs *p, const char *addr)
{
    struct ks_nodes *nodes = ks_service_nodes(p->svc);
    struct ks_node *n = ks_nodes_get(nodes, addr);
    if (nodes->len == 0 || n == NULL || !n->online || n->config == NULL)
        return NULL;
    char *m = g_strdup_printf("Applying configuration on %s ...", addr);
    set_message(p, m);
    g_free(m);
    char *json = NULL, err[300];
    if (!ks_prefs_build_node(&p->nf, addr, n->config->config, &json, err, sizeof(err)))
        return g_strdup(err);
    /* a change of the node's address needs the GUI's address to follow */
    const char *cur = selected_node(p);
    const char *node_address = combo_entry_text(p->n_addr);
    const char *server_addr = combo_entry_text(p->srv_addr);
    if (g_str_has_prefix(server_addr, "unix:") &&
        ((cur != NULL && strcmp(cur, node_address) != 0) || strcmp(server_addr, node_address) != 0))
        need_restart(p, "Node address changed (update GUI address if needed)");
    if (g_str_has_prefix(node_address, "unix:") && !g_str_has_prefix(server_addr, "unix:"))
        need_restart(p, "Node address changed (update GUI address if needed)");

    /* Nodes.save_node_config() */
    free(n->config->config);
    n->config->config = json;
    Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
    ntf.clientname = (char *)(uintptr_t) "";
    ntf.servername = (char *)(uintptr_t) "";
    ntf.type = PROTOCOL__ACTION__CHANGE_CONFIG;
    ntf.data = json;
    ks_nodes_send(nodes, addr, &ntf, on_reply, p);
    return NULL;
}

/* _save_nodes_config() */
static bool save_nodes_config(struct ks_prefs *p)
{
    const char *addr = selected_node(p);
    if ((p->nf.needs_update || is_active(p->apply_all)) && addr != NULL) {
        set_message(p, "Saving configuration...");
        read_nform(p);
        if (is_active(p->apply_all)) {
            struct ks_nodes *nodes = ks_service_nodes(p->svc);
            for (size_t i = 0; i < nodes->len; i++) {
                char *e = save_node_config(p, nodes->items[i]->addr);
                if (e != NULL) {
                    set_error(p, e);
                    g_free(e);
                    return false;
                }
            }
        } else {
            char *e = save_node_config(p, addr);
            if (e != NULL) {
                set_error(p, e);
                g_free(e);
                return false;
            }
        }
    } else if (addr == NULL) {
        set_message(p, "There're no nodes connected");
        return false;
    }
    p->nf.needs_update = false;
    return true;
}

/* _save_settings() */
static void save_settings(struct ks_prefs *p)
{
    reset_status(p);
    bool ui = save_ui_config(p);
    bool db = save_db_config(p);
    bool nodes = save_nodes_config(p);
    if (ui && db && nodes)
        set_success(p, "Configuration applied.");
    ks_service_settings_saved(p->svc);
    if (p->on_saved)
        p->on_saved(p->ud);
    p->saved = true;
    if (p->restart != NULL) {
        message_dialog(p, GTK_MESSAGE_WARNING, p->restart,
                       "Restart the GUI in order changes to take effect");
        g_free(p->restart);
        p->restart = NULL;
    }
}

/* ---- callbacks --------------------------------------------------------------------------------- */

static void on_apply(GtkButton *b, gpointer ud)
{
    (void)b;
    save_settings(ud);
}

static void on_accept(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_prefs *p = ud;
    gtk_widget_hide(p->win);
    if (!p->saved)
        save_settings(p);
}

static void on_cancel(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_prefs *p = ud;
    gtk_widget_hide(p->win);
}

static void on_help(GtkButton *b, gpointer ud)
{
    (void)b;
    (void)ud;
    gchar *argv[] = {"xdg-open", (gchar *)HELP_URL, NULL};
    g_spawn_async(NULL, argv, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL |
                                        G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, NULL, NULL);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer ud)
{
    (void)e;
    (void)ud;
    gtk_widget_hide(w);
    return TRUE;
}

/* _cb_popups_check_toggled() */
static void on_popups_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_prefs *p = ud;
    if (p->loading)
        return;
    bool checked = gtk_toggle_button_get_active(b);
    gtk_widget_set_sensitive(p->spin_timeout, !checked);
    if (!checked)
        set_spin(p->spin_timeout, 20);
}

static void on_rules_check(GtkToggleButton *b, gpointer ud)
{
    struct ks_prefs *p = ud;
    gtk_widget_set_sensitive(p->c_rules, gtk_toggle_button_get_active(b));
}

/* _cb_db_type_changed() */
static void on_db_type(GtkComboBox *c, gpointer ud)
{
    struct ks_prefs *p = ud;
    if (p->loading)
        return;
    bool mem = gtk_combo_box_get_active(c) == KS_CFG_DB_TYPE_MEMORY;
    gtk_widget_set_visible(p->db_file_btn, !mem);
    gtk_widget_set_visible(p->db_label, !mem);
    db_cleaner_widgets(p, ks_settings_get_bool(p->cfg, KS_CFG_DB_PURGE_OLDEST, false));
    gtk_widget_set_sensitive(p->db_wal, !mem);
    set_active(p->db_wal, false);
}

static void on_db_days_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_prefs *p = ud;
    bool on = gtk_toggle_button_get_active(b);
    gtk_widget_set_sensitive(p->db_days_spin, on);
    gtk_widget_set_sensitive(p->db_interval_spin, on);
    gtk_widget_set_sensitive(p->db_wal, on);
}

static void on_db_wal_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_prefs *p = ud;
    (void)b;
    if (!p->loading)
        need_restart(p, "DB journal_mode changed");
}

/* _cb_file_db_clicked() */
static void on_db_file(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_prefs *p = ud;
    GtkWidget *d = gtk_file_chooser_dialog_new("", GTK_WINDOW(p->win), GTK_FILE_CHOOSER_ACTION_SAVE,
                                               GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE,
                                               GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
        if (f != NULL)
            gtk_label_set_text(GTK_LABEL(p->db_label), f);
        g_free(f);
    }
    gtk_widget_destroy(d);
}

/* _cb_cmd_node_rulespath_clicked() */
static void on_rules_path(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_prefs *p = ud;
    GtkWidget *d = gtk_file_chooser_dialog_new("", GTK_WINDOW(p->win), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                               GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN,
                                               GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(d), g_get_home_dir());
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *dir = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
        if (dir != NULL && dir[0] != '\0') {
            p->nf.needs_update = true;
            gtk_entry_set_text(GTK_ENTRY(p->n_rules_path), dir);
        }
        g_free(dir);
    }
    gtk_widget_destroy(d);
}

/* _cb_node_combo_changed() */
static void on_node_combo(GtkComboBox *c, gpointer ud)
{
    struct ks_prefs *p = ud;
    (void)c;
    if (!p->loading)
        load_node_settings(p);
}

/* any node option: _cb_node_needs_update() */
static void on_node_changed(GtkWidget *w, gpointer ud)
{
    struct ks_prefs *p = ud;
    (void)w;
    if (!p->loading)
        p->nf.needs_update = true;
}

/* _cb_combo_node_auth_type_changed() */
static void on_node_auth(GtkComboBox *c, gpointer ud)
{
    struct ks_prefs *p = ud;
    if (p->loading)
        return;
    int i = gtk_combo_box_get_active(c);
    gtk_widget_set_sensitive(p->n_ca, i == 2);
    gtk_widget_set_sensitive(p->n_srvcert, i >= 1);
    gtk_widget_set_sensitive(p->n_cert, i >= 1);
    gtk_widget_set_sensitive(p->n_key, i >= 1);
    gtk_widget_set_sensitive(p->n_skip, i >= 1);
    gtk_widget_set_sensitive(p->n_verify, i >= 1);
    p->nf.needs_update = true;
}

/* _cb_combo_auth_type_changed() */
static void on_auth(GtkComboBox *c, gpointer ud)
{
    struct ks_prefs *p = ud;
    if (p->loading)
        return;
    int i = gtk_combo_box_get_active(c);
    char *saved = ks_settings_get_string(p->cfg, KS_CFG_AUTH_TYPE);
    if (saved == NULL || i < 0 || i > 2 || strcmp(saved, ks_node_auth_types[i]) != 0)
        need_restart(p, "Auth type changed");
    free(saved);
    gtk_widget_set_sensitive(p->ca_line, i == 2);
    gtk_widget_set_sensitive(p->cert_line, i >= 1);
    gtk_widget_set_sensitive(p->key_line, i >= 1);
}

/* ---- construction -------------------------------------------------------------------------------- */

static GtkWidget *check(const char *label, const char *tip)
{
    GtkWidget *c = gtk_check_button_new_with_label(label);
    if (tip != NULL)
        gtk_widget_set_tooltip_text(c, tip);
    return c;
}

static GtkWidget *build_popups(struct ks_prefs *p)
{
    GtkWidget *t = new_table();
    int l = 0;
    p->spin_timeout = spin(0, 100, 30);
    row(t, l++, "Default timeout", p->spin_timeout,
        "This timeout is the countdown you see on the pop-up.");
    p->popups_check = check("Disable pop-ups, only display a notification", NULL);
    gtk_table_attach(GTK_TABLE(t), p->popups_check, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    static const char *const actions[] = {"deny", "allow", "reject"};
    static const char *const durations[] = {"once", "30s", "5m", "15m", "30m", "1h", "12h",
                                            "until reboot", "forever"};
    static const char *const targets[] = {"by executable", "by command line", "by destination port",
                                          "by destination ip", "by user id", "by PID"};
    static const char *const positions[] = {"center", "top right", "bottom right", "top left",
                                            "bottom left"};
    p->c_action = combo_with(actions, 3);
    row(t, l++, "Action", p->c_action, "Pop-up default action.");
    p->c_duration = combo_with(durations, 9);
    row(t, l++, "Duration", p->c_duration, "Pop-up default duration");
    p->c_target = combo_with(targets, 6);
    row(t, l++, "Default target", p->c_target, NULL);
    p->c_pos = combo_with(positions, 5);
    row(t, l++, "Default position on screen", p->c_pos, NULL);
    p->adv_check = check("Show advanced view by default",
                         "The advanced view allows you to easily select multiple fields.");
    gtk_table_attach(GTK_TABLE(t), p->adv_check, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    GtkWidget *lbl = gtk_label_new("Filter connections also by:");
    gtk_misc_set_alignment(GTK_MISC(lbl), 0.0f, 0.5f);
    gtk_table_attach(GTK_TABLE(t), lbl, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->uid_check = check("User ID", "If checked, this field will be selected when a pop-up is displayed.");
    p->dstport_check = check("Destination port", NULL);
    p->dstip_check = check("Destination IP", NULL);
    p->sum_check = check("checksum", NULL);
    GtkWidget *cs[] = {p->uid_check, p->dstport_check, p->dstip_check, p->sum_check};
    for (int i = 0; i < 4; i++)
        gtk_table_attach(GTK_TABLE(t), cs[i], 0, 2, (guint)l + (guint)i, (guint)l + (guint)i + 1,
                         GTK_FILL, GTK_FILL, 24, 1);
    g_signal_connect(p->popups_check, "toggled", G_CALLBACK(on_popups_toggled), p);
    return page(t);
}

static GtkWidget *build_ui(struct ks_prefs *p)
{
    GtkWidget *vbox = gtk_vbox_new(FALSE, 8);
    GtkWidget *f1 = gtk_frame_new("General");
    GtkWidget *t = new_table();
    int l = 0;
    p->spin_refresh = spin(0, 100, 1);
    row(t, l++, "Refresh interval (seconds)", p->spin_refresh, NULL);
    p->c_lang = gtk_combo_box_new_text();
    gtk_combo_box_append_text(GTK_COMBO_BOX(p->c_lang), "System default");
    gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_lang), 0);
    gtk_widget_set_sensitive(p->c_lang, FALSE);
    row(t, l++, "Language", p->c_lang, "Translations come with phase 10.");
    p->autostart = check("Autostart the GUI upon login", "By default the GUI is started when login");
    gtk_table_attach(GTK_TABLE(t), p->autostart, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    gtk_container_add(GTK_CONTAINER(f1), t);
    gtk_box_pack_start(GTK_BOX(vbox), f1, FALSE, FALSE, 0);

    GtkWidget *f2 = gtk_frame_new("Server");
    GtkWidget *t2 = new_table();
    l = 0;
    static const char *const addrs[] = {"unix:///tmp/osui.sock"};
    p->srv_addr = entry_combo_with(addrs, 1);
    char run_path[128], var_run[160];
    snprintf(run_path, sizeof(run_path), "/run/user/%u/opensnitch/", (unsigned)getuid());
    snprintf(var_run, sizeof(var_run), "/var%s", run_path);
    if (g_file_test(run_path, G_FILE_TEST_EXISTS)) {
        char *a = g_strdup_printf("unix://%s/osui.sock", run_path);
        gtk_combo_box_append_text(GTK_COMBO_BOX(p->srv_addr), a);
        g_free(a);
    }
    if (g_file_test(var_run, G_FILE_TEST_EXISTS)) {
        char *a = g_strdup_printf("unix://%s/osui.sock", var_run);
        gtk_combo_box_append_text(GTK_COMBO_BOX(p->srv_addr), a);
        g_free(a);
    }
    row(t2, l++, "Address", p->srv_addr, "The address where the GUI is listening for new nodes.");
    static const char *const sizes[] = {"4MiB", "8MiB", "16MiB", "32MiB"};
    p->msg_size = entry_combo_with(sizes, 4);
    row(t2, l++, "Max gRPC channel size", p->msg_size, "Maximum size of each message from nodes. Default 4MB");
    static const char *const auths[] = {"Simple", "Simple TLS", "Mutual TLS"};
    p->c_auth = combo_with(auths, 3);
    row(t2, l++, "Authentication type", p->c_auth,
        "Simple: no authentication. TLS comes with phase 10.");
    p->ca_line = gtk_entry_new();
    row(t2, l++, "CA cert file", p->ca_line, "Absolute path to the CA cert file");
    p->cert_line = gtk_entry_new();
    row(t2, l++, "Cert file", p->cert_line, "Absolute path to the cert file");
    p->key_line = gtk_entry_new();
    row(t2, l++, "Cert key file", p->key_line, "Absolute path to the cert key file");
    p->spin_workers = spin(0, 100000, 20);
    row(t2, l++, "Max server workers", p->spin_workers, NULL);
    p->spin_clients = spin(0, 100, 0);
    row(t2, l++, "Max server clients", p->spin_clients,
        "This option limits the number of nodes (incoming connections).");
    gtk_container_add(GTK_CONTAINER(f2), t2);
    gtk_box_pack_start(GTK_BOX(vbox), f2, FALSE, FALSE, 0);
    g_signal_connect(p->c_auth, "changed", G_CALLBACK(on_auth), p);

    GtkWidget *f3 = gtk_frame_new("Desktop notifications");
    GtkWidget *b3 = gtk_vbox_new(FALSE, 2);
    gtk_container_set_border_width(GTK_CONTAINER(b3), 8);
    p->notif_group = check("Enable", NULL);
    p->radio_sys = gtk_radio_button_new_with_label(NULL, "Use system notifications");
    p->radio_qt = gtk_radio_button_new_with_label(
        gtk_radio_button_get_group(GTK_RADIO_BUTTON(p->radio_sys)), "Use the tray icon's alert");
    GtkWidget *test = gtk_button_new_with_label("Test");
    gtk_widget_set_sensitive(test, FALSE);
    gtk_widget_set_tooltip_text(test, "Desktop notifications come with phase 10.");
    gtk_box_pack_start(GTK_BOX(b3), p->notif_group, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(b3), p->radio_sys, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(b3), p->radio_qt, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(b3), test, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(f3), b3);
    gtk_box_pack_start(GTK_BOX(vbox), f3, FALSE, FALSE, 0);

    GtkWidget *f4 = gtk_frame_new("Events tab columns");
    GtkWidget *b4 = gtk_table_new(5, 3, TRUE);
    gtk_container_set_border_width(GTK_CONTAINER(b4), 8);
    /* the order of the columns of the events table */
    static const char *const names[NCOLS] = {"Time", "Node", "Action", "Source port", "Source IP",
                                             "Dest IP", "Dest host", "Dest port", "Protocol", "UID",
                                             "PID", "Process", "Command line", "Rule"};
    for (int i = 0; i < NCOLS; i++) {
        p->cols[i] = check(names[i], NULL);
        set_active(p->cols[i], true);
        gtk_table_attach_defaults(GTK_TABLE(b4), p->cols[i], (guint)(i % 3), (guint)(i % 3) + 1,
                                  (guint)(i / 3), (guint)(i / 3) + 1);
    }
    gtk_container_add(GTK_CONTAINER(f4), b4);
    gtk_box_pack_start(GTK_BOX(vbox), f4, FALSE, FALSE, 0);
    return page(vbox);
}

static GtkWidget *build_rules(struct ks_prefs *p)
{
    GtkWidget *t = new_table();
    p->rules_check = check("Don't save/Delete rules of duration",
                           "When this option is selected, the rules of the selected duration are not "
                           "saved, and the ones already saved are deleted.");
    gtk_table_attach(GTK_TABLE(t), p->rules_check, 0, 1, 0, 1, GTK_FILL, GTK_FILL, 6, 3);
    static const char *const items[] = {"any temporary rules", "once", "30s or less", "5m or less",
                                        "15m or less", "30m or less", "1h or less"};
    p->c_rules = combo_with(items, 7);
    gtk_table_attach(GTK_TABLE(t), p->c_rules, 1, 2, 0, 1, GTK_FILL, GTK_FILL, 6, 3);
    g_signal_connect(p->rules_check, "toggled", G_CALLBACK(on_rules_check), p);
    return page(t);
}

/* a node option that marks the node as needing an update */
static void watch(struct ks_prefs *p, GtkWidget *w, const char *signal)
{
    g_signal_connect(w, signal, G_CALLBACK(on_node_changed), p);
}

static GtkWidget *build_nodes(struct ks_prefs *p)
{
    GtkWidget *vbox = gtk_vbox_new(FALSE, 6);
    GtkWidget *top = gtk_hbox_new(FALSE, 6);
    p->c_nodes = gtk_combo_box_new_text();
    gtk_widget_set_no_show_all(p->c_nodes, TRUE);
    p->apply_all = check("Apply configuration to all nodes", NULL);
    gtk_widget_set_no_show_all(p->apply_all, TRUE);
    gtk_box_pack_start(GTK_BOX(top), p->c_nodes, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), p->apply_all, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), top, FALSE, FALSE, 0);
    GtkWidget *info = gtk_hbox_new(FALSE, 6);
    p->l_name = gtk_label_new("");
    p->l_version = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(info), gtk_label_new("HostName"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(info), p->l_name, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(info), gtk_label_new("Version"), FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(info), p->l_version, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), info, FALSE, FALSE, 0);

    GtkWidget *nb = gtk_notebook_new();
    /* General */
    GtkWidget *t = new_table();
    int l = 0;
    p->n_action = combo_with(ks_node_actions, 3);
    row(t, l++, "Default action when the GUI is disconnected", p->n_action, NULL);
    p->n_addr = entry_combo_with((const char *const[]){"unix:///tmp/osui.sock"}, 1);
    row(t, l++, "Address", p->n_addr, "Address of the node.");
    p->n_intercept = check("Debug invalid connections", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_intercept, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->n_monitor = combo_with(ks_node_monitors, 3);
    row(t, l++, "Process monitor method", p->n_monitor, NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t, gtk_label_new("General"));
    /* Logging */
    t = new_table();
    l = 0;
    static const char *const levels[] = {"DEBUG", "INFO", "IMPORTANT", "WARNING", "ERROR", "FATAL"};
    p->n_loglevel = combo_with(levels, 6);
    row(t, l++, "Default log level", p->n_loglevel, NULL);
    p->n_utc = check("Log UTC timestamps", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_utc, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->n_micro = check("Log timestamp microseconds", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_micro, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    static const char *const logs[] = {"/var/log/opensnitchd.log", "/dev/stdout"};
    p->n_logfile = entry_combo_with(logs, 2);
    row(t, l++, "Log file", p->n_logfile, NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t, gtk_label_new("Logging"));
    /* Authentication */
    t = new_table();
    l = 0;
    p->n_auth = combo_with((const char *const[]){"Simple", "Simple TLS", "Mutual TLS"}, 3);
    row(t, l++, "Authentication type", p->n_auth, NULL);
    p->n_ca = gtk_entry_new();
    row(t, l++, "CA cert file", p->n_ca, "Absolute path to the CA cert file");
    p->n_srvcert = gtk_entry_new();
    row(t, l++, "Server cert file", p->n_srvcert, NULL);
    p->n_cert = gtk_entry_new();
    row(t, l++, "Cert file", p->n_cert, NULL);
    p->n_key = gtk_entry_new();
    row(t, l++, "Cert key file", p->n_key, NULL);
    p->n_skip = check("Don't verify certs", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_skip, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->n_verify = combo_with(ks_node_verify_types, 5);
    row(t, l++, "Client certificate verification", p->n_verify, NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t, gtk_label_new("Authentication"));
    /* Rules */
    t = new_table();
    l = 0;
    p->n_checksums = check("Enable checksums verification", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_checksums, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->n_rules_path = gtk_entry_new();
    p->n_rules_btn = gtk_button_new_with_label("Path");
    GtkWidget *hb = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hb), p->n_rules_path, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hb), p->n_rules_btn, FALSE, FALSE, 0);
    row(t, l++, "Rules path", hb, "If empty, default rules path will be /etc/opensnitchd/rules");
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t, gtk_label_new("Rules"));
    /* Internal */
    t = new_table();
    l = 0;
    p->n_maxevents = gtk_entry_new();
    row(t, l++, "Max events", p->n_maxevents, NULL);
    p->n_maxstats = gtk_entry_new();
    row(t, l++, "Max stats", p->n_maxstats, NULL);
    p->n_gc = spin(0, 100, 100);
    row(t, l++, "Garbage collector percentage", p->n_gc, NULL);
    p->n_fwint = gtk_entry_new();
    row(t, l++, "Firewall rules monitoring interval (seconds)", p->n_fwint,
        "Check every n seconds that the interception rules are present.");
    p->n_flush = check("Flush connections on start", "When this option is on, all the existing sockets will be killed.");
    gtk_table_attach(GTK_TABLE(t), p->n_flush, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->n_block = check("Block outbound network traffic if the daemon unexpectedly dies", NULL);
    gtk_table_attach(GTK_TABLE(t), p->n_block, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t, gtk_label_new("Internal"));
    gtk_box_pack_start(GTK_BOX(vbox), nb, TRUE, TRUE, 0);

    g_signal_connect(p->c_nodes, "changed", G_CALLBACK(on_node_combo), p);
    g_signal_connect(p->n_auth, "changed", G_CALLBACK(on_node_auth), p);
    g_signal_connect(p->n_rules_btn, "clicked", G_CALLBACK(on_rules_path), p);
    GtkWidget *combos[] = {p->n_action, p->n_monitor, p->n_loglevel, p->n_verify};
    for (size_t i = 0; i < sizeof(combos) / sizeof(combos[0]); i++)
        watch(p, combos[i], "changed");
    GtkWidget *entry_combos[] = {p->n_addr, p->n_logfile};
    for (size_t i = 0; i < 2; i++)
        watch(p, entry_combos[i], "changed");
    GtkWidget *checks[] = {p->n_intercept, p->n_utc, p->n_micro, p->n_skip, p->n_checksums,
                           p->n_flush, p->n_block, p->apply_all};
    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++)
        watch(p, checks[i], "toggled");
    GtkWidget *entries[] = {p->n_ca, p->n_srvcert, p->n_cert, p->n_key, p->n_rules_path,
                            p->n_maxevents, p->n_maxstats, p->n_fwint};
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++)
        watch(p, entries[i], "changed");
    watch(p, p->n_gc, "value-changed");
    return vbox;
}

static GtkWidget *build_db(struct ks_prefs *p)
{
    GtkWidget *t = new_table();
    int l = 0;
    static const char *const types[] = {"In memory", "File"};
    p->db_type = combo_with(types, 2);
    row(t, l++, "Database type", p->db_type, NULL);
    p->db_label = gtk_label_new("");
    p->db_file_btn = gtk_button_new_with_label("Select");
    GtkWidget *hb = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(hb), p->db_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hb), p->db_file_btn, FALSE, FALSE, 0);
    gtk_table_attach(GTK_TABLE(t), hb, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    gtk_widget_set_no_show_all(p->db_label, TRUE);
    gtk_widget_set_no_show_all(p->db_file_btn, TRUE);
    l++;
    p->db_days_check = check("Maximum days of events to keep", NULL);
    p->db_days_spin = spin(1, 99999, 1);
    GtkWidget *hb2 = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(hb2), p->db_days_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb2), p->db_days_spin, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb2), gtk_label_new("days"), FALSE, FALSE, 0);
    gtk_table_attach(GTK_TABLE(t), hb2, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->db_interval_spin = spin(5, 1440, 5);
    GtkWidget *hb3 = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(hb3), gtk_label_new("Minutes between events purges"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb3), p->db_interval_spin, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb3), gtk_label_new("minutes"), FALSE, FALSE, 0);
    gtk_table_attach(GTK_TABLE(t), hb3, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    l++;
    p->db_wal = check("Enable DB Write-Ahead Logging (WAL)", NULL);
    gtk_table_attach(GTK_TABLE(t), p->db_wal, 0, 2, (guint)l, (guint)l + 1, GTK_FILL, GTK_FILL, 6, 3);
    g_signal_connect(p->db_type, "changed", G_CALLBACK(on_db_type), p);
    g_signal_connect(p->db_file_btn, "clicked", G_CALLBACK(on_db_file), p);
    g_signal_connect(p->db_days_check, "toggled", G_CALLBACK(on_db_days_toggled), p);
    g_signal_connect(p->db_wal, "toggled", G_CALLBACK(on_db_wal_toggled), p);
    return page(t);
}

struct ks_prefs *ks_prefs_new(struct ks_service *svc, struct ks_settings *settings,
                              GtkWindow *parent, void (*on_saved)(void *), void *ud)
{
    struct ks_prefs *p = g_new0(struct ks_prefs, 1);
    p->svc = svc;
    p->cfg = settings;
    p->on_saved = on_saved;
    p->ud = ud;
    p->node_addrs = g_ptr_array_new_with_free_func(g_free);
    ks_nform_init(&p->nf);
    p->loading = true;

    p->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(p->win), "Preferences");
    gtk_window_set_default_size(GTK_WINDOW(p->win), 680, 560);
    if (parent != NULL)
        gtk_window_set_transient_for(GTK_WINDOW(p->win), parent);
    g_signal_connect(p->win, "delete-event", G_CALLBACK(on_delete), p);
    GtkWidget *vbox = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(p->win), vbox);

    p->nb = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(p->nb), build_popups(p), gtk_label_new("Pop-ups"));
    gtk_notebook_append_page(GTK_NOTEBOOK(p->nb), build_ui(p), gtk_label_new("UI"));
    gtk_notebook_append_page(GTK_NOTEBOOK(p->nb), build_rules(p), gtk_label_new("Rules"));
    gtk_notebook_append_page(GTK_NOTEBOOK(p->nb), build_nodes(p), gtk_label_new("Nodes"));
    gtk_notebook_append_page(GTK_NOTEBOOK(p->nb), build_db(p), gtk_label_new("Database"));
    gtk_box_pack_start(GTK_BOX(vbox), p->nb, TRUE, TRUE, 0);

    p->status = gtk_label_new("");
    gtk_misc_set_alignment(GTK_MISC(p->status), 0.0f, 0.5f);
    gtk_widget_set_no_show_all(p->status, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), p->status, FALSE, FALSE, 0);

    GtkWidget *bb = gtk_hbutton_box_new();
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bb), GTK_BUTTONBOX_END);
    gtk_box_set_spacing(GTK_BOX(bb), 6);
    GtkWidget *help = gtk_button_new_from_stock(GTK_STOCK_HELP);
    GtkWidget *close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    GtkWidget *apply = gtk_button_new_from_stock(GTK_STOCK_APPLY);
    GtkWidget *save = gtk_button_new_from_stock(GTK_STOCK_SAVE);
    g_signal_connect(help, "clicked", G_CALLBACK(on_help), p);
    g_signal_connect(close, "clicked", G_CALLBACK(on_cancel), p);
    g_signal_connect(apply, "clicked", G_CALLBACK(on_apply), p);
    g_signal_connect(save, "clicked", G_CALLBACK(on_accept), p);
    gtk_container_add(GTK_CONTAINER(bb), help);
    gtk_container_add(GTK_CONTAINER(bb), close);
    gtk_container_add(GTK_CONTAINER(bb), apply);
    gtk_container_add(GTK_CONTAINER(bb), save);
    gtk_box_pack_start(GTK_BOX(vbox), bb, FALSE, FALSE, 0);
    gtk_widget_show_all(vbox);
    gtk_widget_hide(p->status);
    p->loading = false;
    return p;
}

void ks_prefs_free(struct ks_prefs *p)
{
    if (p == NULL)
        return;
    gtk_widget_destroy(p->win);
    ks_nform_free(&p->nf);
    g_ptr_array_free(p->node_addrs, TRUE);
    g_free(p->restart);
    g_free(p);
}

/* showEvent() */
void ks_prefs_show(struct ks_prefs *p)
{
    g_free(p->restart);
    p->restart = NULL;
    p->saved = false;
    reset_status(p);
    load_nodes(p);
    load_settings(p);
    /* the node's form after the settings, as upstream (and the node-changed flag clear) */
    load_node_settings(p);
    p->nf.needs_update = false;
    gtk_window_present(GTK_WINDOW(p->win));
}

void ks_prefs_show_node(struct ks_prefs *p, const char *addr)
{
    ks_prefs_show(p);
    for (guint i = 0; i < p->node_addrs->len; i++) {
        if (strcmp(g_ptr_array_index(p->node_addrs, i), addr) == 0) {
            gtk_combo_box_set_active(GTK_COMBO_BOX(p->c_nodes), (gint)i);
            gtk_notebook_set_current_page(GTK_NOTEBOOK(p->nb), TAB_NODES);
        }
    }
}

GtkWidget *ks_prefs_window(struct ks_prefs *p)
{
    return p->win;
}
