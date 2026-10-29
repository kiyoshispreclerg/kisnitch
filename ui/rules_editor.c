/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/ruleseditor.py (the dialog) and
 * res/ruleseditor.ui. See rules_editor.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
/* setpwent() and friends are XSI, not POSIX base */
#define _DEFAULT_SOURCE 1
#include "ui/rules_editor.h"

#include <pwd.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/db.h"
#include "ui/rulegen.h"
#include "ui/rulesops.h"
#include "ui/statsdb.h"
#include "ui/i18n.h"

#define HELP_URL "https://github.com/evilsocket/opensnitch/wiki/"

/* the 16 checks, in the order of struct ks_rform */
enum {
    R_PROTO, R_PROC, R_CMDLINE, R_IFACE, R_SRCPORT, R_DSTPORT, R_SRCIP, R_DSTIP, R_DSTHOST, R_UID,
    R_PID, R_LISTS, R_LISTS_RE, R_LISTS_IPS, R_LISTS_NETS, R_MD5, NROWS
};

enum { MODE_ADD, MODE_EDIT };

struct row {
    GtkWidget *check, *input; /* the input is an entry or a combo with entry */
    GtkWidget *extra;         /* the regexp check of process and command line, or a "..." button */
    bool combo;
};

struct ks_ruleed {
    struct ks_service *svc;
    void (*on_saved)(void *);
    void *ud;
    GtkWidget *win, *name, *desc, *enable, *precedence, *nodes_combo, *apply_all;
    GtkWidget *radio[3], *duration;
    GtkWidget *sensitive, *nolog, *status;
    struct row rows[NROWS];
    struct ks_rform form;
    int mode;
    char *old_name;
    GArray *users; /* uid_t, the items of the user combo */
    GPtrArray *node_addrs;
    bool loading;
};

static struct ks_rcheck *check_of(struct ks_rform *f, int i)
{
    return &f->proto + i;
}

/* ---- widgets ------------------------------------------------------------------------- */

static const char *input_text(struct row *r)
{
    if (r->combo) {
        GtkWidget *e = gtk_bin_get_child(GTK_BIN(r->input));
        return gtk_entry_get_text(GTK_ENTRY(e));
    }
    return gtk_entry_get_text(GTK_ENTRY(r->input));
}

static void set_input_text(struct row *r, const char *t)
{
    GtkWidget *e = r->combo ? gtk_bin_get_child(GTK_BIN(r->input)) : r->input;
    gtk_entry_set_text(GTK_ENTRY(e), t != NULL ? t : "");
}

static int find_text(GtkWidget *combo, const char *t)
{
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
    GtkTreeIter it;
    int i = 0;
    if (!gtk_tree_model_get_iter_first(m, &it))
        return -1;
    do {
        gchar *s = NULL;
        gtk_tree_model_get(m, &it, 0, &s, -1);
        bool eq = s != NULL && strcmp(s, t) == 0;
        g_free(s);
        if (eq)
            return i;
        i++;
    } while (gtk_tree_model_iter_next(m, &it));
    return -1;
}

static void clear_combo(GtkWidget *combo)
{
    GtkTreeModel *m = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
    gtk_list_store_clear(GTK_LIST_STORE(m));
}

/* the status label: _set_status_error() red, _set_status_message() green */
static void set_status(struct ks_ruleed *d, const char *msg, bool error)
{
    char *m = g_markup_printf_escaped("<span foreground=\"%s\">%s</span>", error ? "red" : "green",
                                      msg);
    gtk_label_set_markup(GTK_LABEL(d->status), m);
    g_free(m);
}

static void message(struct ks_ruleed *d, GtkMessageType type, const char *primary,
                    const char *secondary)
{
    GtkWidget *w = gtk_message_dialog_new(GTK_WINDOW(d->win), GTK_DIALOG_DESTROY_WITH_PARENT, type,
                                          GTK_BUTTONS_OK, "%s", primary);
    if (secondary != NULL && secondary[0] != '\0')
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(w), "%s", secondary);
    g_signal_connect_swapped(w, "response", G_CALLBACK(gtk_widget_destroy), w);
    gtk_widget_show(w);
}

/* ---- the form <-> the widgets ------------------------------------------------------------ */

static const char *selected_node(struct ks_ruleed *d)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(d->nodes_combo));
    return i >= 0 && (guint)i < d->node_addrs->len ? g_ptr_array_index(d->node_addrs, (guint)i)
                                                    : NULL;
}

/* the widgets into d->form */
static void read_form(struct ks_ruleed *d)
{
    struct ks_rform *f = &d->form;
    ks_rform_set_name(f, gtk_entry_get_text(GTK_ENTRY(d->name)));
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(d->desc));
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(b, &s, &e);
    gchar *desc = gtk_text_buffer_get_text(b, &s, &e, FALSE);
    ks_rform_set_desc(f, desc);
    g_free(desc);
    f->enabled = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->enable));
    f->precedence = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->precedence));
    f->nolog = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->nolog));
    f->sensitive = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->sensitive));
    f->action = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->radio[KS_RACTION_ALLOW]))
                    ? KS_RACTION_ALLOW
                : gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->radio[KS_RACTION_REJECT]))
                    ? KS_RACTION_REJECT
                    : KS_RACTION_DENY;
    f->duration = gtk_combo_box_get_active(GTK_COMBO_BOX(d->duration));
    for (int i = 0; i < NROWS; i++) {
        struct ks_rcheck *c = check_of(f, i);
        c->on = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->rows[i].check));
        ks_rform_set(c, input_text(&d->rows[i]));
    }
    f->proc_regexp = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->rows[R_PROC].extra));
    f->cmdline_regexp = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->rows[R_CMDLINE].extra));
    const char *node = selected_node(d);
    f->node_is_local = node != NULL && ks_nodes_is_local(node);
    f->apply_all = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->apply_all));
}

/* d->form into the widgets */
static void write_form(struct ks_ruleed *d)
{
    struct ks_rform *f = &d->form;
    d->loading = true;
    gtk_entry_set_text(GTK_ENTRY(d->name), f->name);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(d->desc)), f->desc, -1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->enable), f->enabled);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->precedence), f->precedence);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->nolog), f->nolog);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->sensitive), f->sensitive);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->radio[f->action]), TRUE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->duration), f->duration);
    for (int i = 0; i < NROWS; i++) {
        struct ks_rcheck *c = check_of(f, i);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->rows[i].check), c->on);
        set_input_text(&d->rows[i], c->text);
    }
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->rows[R_PROC].extra), f->proc_regexp);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->rows[R_CMDLINE].extra), f->cmdline_regexp);
    d->loading = false;
    /* the enabled state of each input follows its check */
    for (int i = 0; i < NROWS; i++)
        g_signal_emit_by_name(d->rows[i].check, "toggled");
}

/* _cb_*_check_toggled() */
static void on_check_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_ruleed *d = ud;
    int i = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(b), "row"));
    bool on = gtk_toggle_button_get_active(b);
    struct row *r = &d->rows[i];
    gtk_widget_set_sensitive(r->input, on);
    if (i == R_PROC || i == R_CMDLINE) {
        /* the regexp checkbox is only there while the field is */
        gtk_widget_set_sensitive(r->extra, on);
        gtk_widget_set_visible(r->extra, on);
    } else if (r->extra != NULL) {
        gtk_widget_set_sensitive(r->extra, on);
    }
}

static void on_choose_dir(GtkButton *b, gpointer ud)
{
    struct ks_ruleed *d = ud;
    int i = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(b), "row"));
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "", GTK_WINDOW(d->win), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, GTK_STOCK_CANCEL,
        GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
    const char *cur = input_text(&d->rows[i]);
    if (cur[0] != '\0')
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dlg), cur);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *dir = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        if (dir != NULL && dir[0] != '\0')
            set_input_text(&d->rows[i], dir);
        g_free(dir);
    }
    gtk_widget_destroy(dlg);
}

/* _cb_uid_combo_changed(): choosing "user (uid)" puts the uid in the box */
static void on_uid_combo_changed(GtkComboBox *c, gpointer ud)
{
    struct ks_ruleed *d = ud;
    int idx = gtk_combo_box_get_active(c);
    if (d->loading || idx < 0 || (guint)idx >= d->users->len)
        return;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", (unsigned)g_array_index(d->users, uid_t, idx));
    set_input_text(&d->rows[R_UID], buf);
}

/* RestrictChars("/") on the name: the character is not inserted */
static void on_name_insert(GtkEditable *e, gchar *text, gint len, gint *pos, gpointer ud)
{
    struct ks_ruleed *d = ud;
    (void)pos;
    gchar *t = g_strndup(text, (gsize)len);
    bool bad = strpbrk(t, KS_RULE_INVALID_NAME_CHARS) != NULL;
    g_free(t);
    if (bad) {
        g_signal_stop_emission_by_name(e, "insert-text");
        char *m = g_strdup_printf(_("Invalid rule name (not allowed characters: '%s' )"),
                                  KS_RULE_INVALID_NAME_CHARS);
        set_status(d, m, true);
        g_free(m);
    } else {
        set_status(d, "", false);
    }
}

/* ---- the nodes ----------------------------------------------------------------------------- */

/* _load_nodes(): false if `addr` isn't connected */
static bool load_nodes(struct ks_ruleed *d, const char *addr)
{
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    if (addr != NULL && ks_nodes_get(nodes, addr) == NULL) {
        char *m = g_strdup_printf(_("node %s not connected"), addr);
        message(d, GTK_MESSAGE_WARNING, _("Error loading rule"), m);
        g_free(m);
        return false;
    }
    clear_combo(d->nodes_combo);
    g_ptr_array_set_size(d->node_addrs, 0);
    int sel = 0;
    for (size_t i = 0; i < nodes->len; i++) {
        const struct ks_node *n = nodes->items[i];
        const char *host = ks_nodes_hostname(nodes, n->addr);
        char *lbl = g_strdup_printf("%s - %s", n->addr, host);
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes_combo), lbl);
        g_free(lbl);
        g_ptr_array_add(d->node_addrs, g_strdup(n->addr));
        if (addr != NULL && strcmp(n->addr, addr) == 0)
            sel = (int)i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes_combo), nodes->len > 0 ? sel : -1);
    bool show = nodes->len > 1;
    gtk_widget_set_visible(d->nodes_combo, show);
    gtk_widget_set_visible(d->apply_all, show);
    return true;
}

/* showEvent(): the interfaces, their addresses and the users, if the node is local */
static void refresh_combos(struct ks_ruleed *d)
{
    char *old_iface = g_strdup(input_text(&d->rows[R_IFACE]));
    char *old_uid = g_strdup(input_text(&d->rows[R_UID]));
    clear_combo(d->rows[R_IFACE].input);
    clear_combo(d->rows[R_UID].input);
    g_array_set_size(d->users, 0);
    const char *addr = selected_node(d);
    if (addr != NULL && ks_nodes_is_local(addr)) {
        struct ks_iface ifs[64];
        size_t n = ks_net_ifaces(ifs, 64);
        for (size_t i = 0; i < n; i++) {
            gtk_combo_box_append_text(GTK_COMBO_BOX(d->rows[R_IFACE].input), ifs[i].name);
            if (find_text(d->rows[R_SRCIP].input, ifs[i].ip) == -1)
                gtk_combo_box_prepend_text(GTK_COMBO_BOX(d->rows[R_SRCIP].input), ifs[i].ip);
            if (find_text(d->rows[R_DSTIP].input, ifs[i].ip) == -1)
                gtk_combo_box_prepend_text(GTK_COMBO_BOX(d->rows[R_DSTIP].input), ifs[i].ip);
        }
        d->loading = true;
        setpwent();
        struct passwd *pw;
        while ((pw = getpwent()) != NULL) {
            char *lbl = g_strdup_printf("%s (%u)", pw->pw_name, (unsigned)pw->pw_uid);
            gtk_combo_box_append_text(GTK_COMBO_BOX(d->rows[R_UID].input), lbl);
            g_free(lbl);
            g_array_append_val(d->users, pw->pw_uid);
        }
        endpwent();
        d->loading = false;
    }
    set_input_text(&d->rows[R_IFACE], old_iface);
    set_input_text(&d->rows[R_UID], old_uid);
    g_free(old_iface);
    g_free(old_uid);
}

/* ---- saving ------------------------------------------------------------------------------------ */

static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_ruleed *d = ud;
    (void)addr;
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__OK) {
        set_status(d, _("Rule applied."), false);
    } else {
        char *m = g_strdup_printf(_("Error applying rule: %s"), r->data != NULL ? r->data : "");
        set_status(d, m, true);
        g_free(m);
    }
}

/* _add_rule() */
static void add_rule(struct ks_ruleed *d, Protocol__Rule *rule)
{
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    struct ks_rulesdb *db = ks_service_rules(d->svc);
    const char *addr = selected_node(d);
    Protocol__Rule *one[1] = {rule};
    if (d->form.apply_all) {
        for (size_t i = 0; i < nodes->len; i++)
            ks_rulesdb_add_pb(db, nodes->items[i]->addr, one, 1);
    } else {
        ks_rulesdb_add_pb(db, addr, one, 1);
    }
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.clientname = (char *)(uintptr_t) "";
    n.servername = (char *)(uintptr_t) "";
    n.data = (char *)(uintptr_t) "";
    n.type = PROTOCOL__ACTION__CHANGE_RULE;
    n.rules = one;
    n.n_rules = 1;
    if (d->form.apply_all)
        ks_nodes_send_all(nodes, &n, on_reply, d);
    else
        ks_nodes_send(nodes, addr, &n, on_reply, d);
}

/* _cb_save_clicked() */
static void on_save(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_ruleed *d = ud;
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    struct ks_rulesdb *db = ks_service_rules(d->svc);
    if (d->node_addrs->len == 0) {
        set_status(d, _("There're no nodes connected."), true);
        return;
    }
    read_form(d);
    const char *rule_name = d->form.name;
    if (rule_name[0] == '\0')
        return;
    const char *node = selected_node(d);
    /* avoid overwriting rules when adding, or when a rule is renamed to an existing name */
    bool exists = ks_rulesdb_get(db, rule_name, node) != NULL;
    if ((d->mode == MODE_ADD && exists) ||
        (d->mode == MODE_EDIT && (d->old_name == NULL || strcmp(rule_name, d->old_name) != 0) &&
         exists)) {
        set_status(d, _("There's already a rule with this name."), true);
        return;
    }
    if (d->form.md5.on && !d->form.proc.on) {
        set_status(d, _("Process path must be checked in order to verify checksums."), true);
        return;
    }
    struct ks_arena a = {0};
    Protocol__Rule *rule = NULL;
    char err[256];
    if (!ks_rform_to_rule(&d->form, ks_service_aliases(d->svc), &a, &rule, err, sizeof(err))) {
        set_status(d, err, true);
        ks_arena_free(&a);
        return;
    }
    add_rule(d, rule);
    /* a renamed rule: the old name goes */
    if (d->old_name != NULL && strcmp(d->old_name, rule->name) != 0) {
        ks_rops_delete(db, nodes, d->old_name, d->form.apply_all ? NULL : node, on_reply, d);
    }
    g_free(d->old_name);
    d->old_name = g_strdup(rule_name);
    /* after adding, the dialog is in edit mode: further changes without closing it */
    if (d->mode == MODE_ADD)
        d->mode = MODE_EDIT;
    ks_arena_free(&a);
    if (d->on_saved)
        d->on_saved(d->ud);
}

static void on_close(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_ruleed *d = ud;
    gtk_widget_hide(d->win);
}

static void reset_state(struct ks_ruleed *d)
{
    g_free(d->old_name);
    d->old_name = NULL;
    /* the checkboxes for enabled, priority, log and case keep their state */
    read_form(d);
    ks_rform_reset(&d->form);
    write_form(d);
    gtk_label_set_text(GTK_LABEL(d->status), "");
}

static void on_reset(GtkButton *b, gpointer ud)
{
    (void)b;
    reset_state(ud);
}

static void on_help(GtkButton *b, gpointer ud)
{
    (void)b;
    (void)ud;
    gchar *argv[] = {"xdg-open", (gchar *)HELP_URL, NULL};
    g_spawn_async(NULL, argv, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL |
                                        G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, NULL, NULL);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *ev, gpointer ud)
{
    (void)ev;
    (void)ud;
    gtk_widget_hide(w);
    return TRUE;
}

/* ---- construction ----------------------------------------------------------------------------------- */

static GtkWidget *entry_combo(const char *const *items, size_t n)
{
    GtkWidget *c = gtk_combo_box_entry_new_text();
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(c), items[i]);
    return c;
}

/* one row: check + input (+ extra) in a table */
static void add_row(struct ks_ruleed *d, GtkWidget *table, int line, int idx, const char *label,
                    GtkWidget *input, bool combo, const char *tip)
{
    struct row *r = &d->rows[idx];
    r->check = gtk_check_button_new_with_label(label);
    r->input = input;
    r->combo = combo;
    g_object_set_data(G_OBJECT(r->check), "row", GINT_TO_POINTER(idx));
    g_signal_connect(r->check, "toggled", G_CALLBACK(on_check_toggled), d);
    if (tip != NULL)
        gtk_widget_set_tooltip_text(input, tip);
    gtk_table_attach(GTK_TABLE(table), r->check, 0, 1, (guint)line, (guint)line + 1, GTK_FILL,
                     GTK_FILL, 4, 2);
    gtk_table_attach(GTK_TABLE(table), input, 1, 2, (guint)line, (guint)line + 1,
                     GTK_EXPAND | GTK_FILL, GTK_FILL, 4, 2);
}

static GtkWidget *new_table(void)
{
    GtkWidget *t = gtk_table_new(1, 3, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(t), 8);
    return t;
}

struct ks_ruleed *ks_ruleed_new(struct ks_service *svc, GtkWindow *parent,
                                void (*on_saved)(void *), void *ud)
{
    struct ks_ruleed *d = g_new0(struct ks_ruleed, 1);
    d->svc = svc;
    d->on_saved = on_saved;
    d->ud = ud;
    d->users = g_array_new(FALSE, FALSE, sizeof(uid_t));
    d->node_addrs = g_ptr_array_new_with_free_func(g_free);
    ks_rform_init(&d->form);

    d->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(d->win), _("Rule"));
    gtk_window_set_default_size(GTK_WINDOW(d->win), 640, 560);
    if (parent != NULL)
        gtk_window_set_transient_for(GTK_WINDOW(d->win), parent);
    g_signal_connect(d->win, "delete-event", G_CALLBACK(on_delete), d);
    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(d->win), vbox);

    /* name, enable, priority */
    GtkWidget *top = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(top), gtk_label_new(_("Name")), FALSE, FALSE, 0);
    d->name = gtk_entry_new();
    gtk_widget_set_tooltip_text(
        d->name, _("The rules are checked in alphabetical order, so you can name them accordingly "
                 "to control which ones are checked first."));
    g_signal_connect(d->name, "insert-text", G_CALLBACK(on_name_insert), d);
    gtk_box_pack_start(GTK_BOX(top), d->name, TRUE, TRUE, 0);
    d->enable = gtk_check_button_new_with_label(_("Enable"));
    d->precedence = gtk_check_button_new_with_label(_("Priority rule"));
    gtk_widget_set_tooltip_text(d->precedence,
                                _("If checked, this rule will take precedence over the rest of "
                                "the rules (except the ones with the same name or priority)."));
    gtk_box_pack_start(GTK_BOX(top), d->enable, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), d->precedence, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), top, FALSE, FALSE, 0);

    /* description */
    d->desc = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(d->desc), GTK_WRAP_WORD);
    GtkWidget *dsw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(dsw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(dsw), GTK_SHADOW_IN);
    gtk_widget_set_size_request(dsw, -1, 52);
    gtk_container_add(GTK_CONTAINER(dsw), d->desc);
    GtkWidget *dbox = gtk_hbox_new(FALSE, 6);
    gtk_box_pack_start(GTK_BOX(dbox), gtk_label_new(_("Description")), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(dbox), dsw, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), dbox, FALSE, FALSE, 0);

    /* nodes */
    GtkWidget *nbox = gtk_hbox_new(FALSE, 6);
    d->nodes_combo = gtk_combo_box_new_text();
    d->apply_all = gtk_check_button_new_with_label(_("Apply rule to all nodes"));
    gtk_widget_set_no_show_all(d->nodes_combo, TRUE);
    gtk_widget_set_no_show_all(d->apply_all, TRUE);
    gtk_box_pack_start(GTK_BOX(nbox), d->nodes_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(nbox), d->apply_all, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), nbox, FALSE, FALSE, 0);

    /* action and duration */
    GtkWidget *frame = gtk_frame_new(NULL);
    GtkWidget *abox = gtk_hbox_new(FALSE, 10);
    gtk_container_set_border_width(GTK_CONTAINER(abox), 6);
    gtk_box_pack_start(GTK_BOX(abox), gtk_label_new(_("Action")), FALSE, FALSE, 0);
    d->radio[KS_RACTION_DENY] = gtk_radio_button_new_with_label(NULL, _("Deny"));
    GSList *grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(d->radio[KS_RACTION_DENY]));
    d->radio[KS_RACTION_REJECT] = gtk_radio_button_new_with_label(grp, _("Reject"));
    grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(d->radio[KS_RACTION_REJECT]));
    d->radio[KS_RACTION_ALLOW] = gtk_radio_button_new_with_label(grp, _("Allow"));
    gtk_widget_set_tooltip_text(d->radio[KS_RACTION_DENY], _("Deny will just discard the connection"));
    gtk_widget_set_tooltip_text(d->radio[KS_RACTION_REJECT],
                                _("Reject will drop the connection, and kill the socket that "
                                "initiated it"));
    gtk_widget_set_tooltip_text(d->radio[KS_RACTION_ALLOW], _("Allow will allow the connection"));
    for (int i = 0; i < 3; i++)
        gtk_box_pack_start(GTK_BOX(abox), d->radio[i], FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(abox), gtk_label_new(_("Duration")), FALSE, FALSE, 8);
    d->duration = gtk_combo_box_new_text();
    static const char *const dur[] = {"once", "30s", "5m", "15m", "30m", "1h", "12h",
                                      "until reboot", "always"};
    for (size_t i = 0; i < sizeof(dur) / sizeof(dur[0]); i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->duration), dur[i]);
    gtk_box_pack_start(GTK_BOX(abox), d->duration, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(frame), abox);
    gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 0);

    /* the tabs */
    GtkWidget *nb = gtk_notebook_new();

    /* 1. process */
    GtkWidget *t1 = new_table();
    add_row(d, t1, 0, R_PROC, _("From this executable"), gtk_entry_new(), false,
            _("The value of this field is always the absolute path of the executable."));
    d->rows[R_PROC].extra = gtk_check_button_new_with_label(_("is regular expression"));
    gtk_table_attach(GTK_TABLE(t1), d->rows[R_PROC].extra, 2, 3, 0, 1, GTK_FILL, GTK_FILL, 4, 2);
    add_row(d, t1, 1, R_CMDLINE, _("From this command line"), gtk_entry_new(), false,
            _("This field will contain and match the command line of the process."));
    d->rows[R_CMDLINE].extra = gtk_check_button_new_with_label(_("Is regular expression"));
    gtk_table_attach(GTK_TABLE(t1), d->rows[R_CMDLINE].extra, 2, 3, 1, 2, GTK_FILL, GTK_FILL, 4, 2);
    add_row(d, t1, 2, R_UID, _("From this user ID"), gtk_combo_box_entry_new_text(), true, NULL);
    add_row(d, t1, 3, R_PID, _("From this PID"), gtk_entry_new(), false, NULL);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t1, gtk_label_new(_("Process")));

    /* 2. network */
    GtkWidget *t2 = new_table();
    static const char *const protos[] = {"TCP", "UDP", "UDPLITE", "TCP6", "UDP6", "UDPLITE6",
                                         "ICMP", "ICMP6", "SCTP", "SCTP6"};
    add_row(d, t2, 0, R_PROTO, _("Protocol"), entry_combo(protos, sizeof(protos) / sizeof(protos[0])),
            true, _("Only TCP, UDP or UDPLITE are allowed. You can also use a regular expression "
                  "or a list separated by commas."));
    add_row(d, t2, 1, R_IFACE, _("Network interface"), gtk_combo_box_entry_new_text(), true, NULL);
    add_row(d, t2, 2, R_SRCPORT, _("From this port"), gtk_entry_new(), false,
            _("You can specify multiple ports using regular expressions or a list separated by "
            "commas."));
    add_row(d, t2, 3, R_DSTPORT, _("To this port"), gtk_entry_new(), false,
            _("You can specify multiple ports using regular expressions or a list separated by "
            "commas."));
    static const char *const nets[] = {"LAN", "MULTICAST", "127.0.0.0/8", "192.168.0.0/24",
                                       "192.168.1.0/24", "192.168.2.0/24", "192.168.0.0/16",
                                       "169.254.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
                                       "::1/128", "fc00::/7", "ff00::/8", "fe80::/10", "fd00::/8"};
    const char *iptip = _("You can specify a single IP, a network range (192.168.1.0/24), a "
                        "regular expression, or a list separated by commas.");
    add_row(d, t2, 4, R_SRCIP, _("From this IP / Network"),
            entry_combo(nets, sizeof(nets) / sizeof(nets[0])), true, iptip);
    add_row(d, t2, 5, R_DSTIP, _("To this IP / Network"),
            entry_combo(nets, sizeof(nets) / sizeof(nets[0])), true, iptip);
    add_row(d, t2, 6, R_DSTHOST, _("To this host"), gtk_entry_new(), false,
            _("Domains separated by commas, or a regular expression (www.domain.org, "
            ".*\\.domain.org)."));
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t2, gtk_label_new(_("Network")));
    /* load_aliases_into_menu(): the network aliases at the top of the destination combo */
    const struct ks_py_aliases *al = ks_service_aliases(svc);
    for (size_t i = al != NULL ? al->len : 0; i > 0; i--) {
        if (find_text(d->rows[R_DSTIP].input, al->items[i - 1].name) == -1)
            gtk_combo_box_prepend_text(GTK_COMBO_BOX(d->rows[R_DSTIP].input), al->items[i - 1].name);
    }

    /* 3. lists */
    GtkWidget *t3 = new_table();
    static const struct {
        int row;
        const char *label, *tip;
    } lists[] = {
        {R_LISTS, N_("To this list of domains"), N_("Select a directory with lists of domains to block.")},
        {R_LISTS_RE, N_("To this list of domains (regular expressions)"),
         N_("Select a directory with files containing regular expressions.")},
        {R_LISTS_IPS, N_("To this list of IPs"), N_("Select a directory with files containing lists of IPs.")},
        {R_LISTS_NETS, N_("To this list of network ranges"),
         N_("Select a directory with files containing lists of network ranges.")},
    };
    for (int i = 0; i < 4; i++) {
        add_row(d, t3, i, lists[i].row, _(lists[i].label), gtk_entry_new(), false, _(lists[i].tip));
        GtkWidget *btn = gtk_button_new_from_stock(GTK_STOCK_OPEN);
        g_object_set_data(G_OBJECT(btn), "row", GINT_TO_POINTER(lists[i].row));
        g_signal_connect(btn, "clicked", G_CALLBACK(on_choose_dir), d);
        d->rows[lists[i].row].extra = btn;
        gtk_table_attach(GTK_TABLE(t3), btn, 2, 3, (guint)i, (guint)i + 1, GTK_FILL, GTK_FILL, 4, 2);
    }
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t3, gtk_label_new(_("Lists")));

    /* 4. advanced */
    GtkWidget *t4 = new_table();
    add_row(d, t4, 0, R_MD5, _("md5"), gtk_entry_new(), false, NULL);
    d->sensitive = gtk_check_button_new_with_label(_("Case-sensitive"));
    gtk_widget_set_tooltip_text(d->sensitive,
                                _("By default, the field of the rules are case-insensitive."));
    d->nolog = gtk_check_button_new_with_label(_("Don't log connections"));
    gtk_table_attach(GTK_TABLE(t4), d->sensitive, 0, 2, 1, 2, GTK_FILL, GTK_FILL, 4, 2);
    gtk_table_attach(GTK_TABLE(t4), d->nolog, 0, 2, 2, 3, GTK_FILL, GTK_FILL, 4, 2);
    gtk_table_attach(GTK_TABLE(t4), gtk_label_new(_("In development")), 0, 2, 3, 4, GTK_FILL,
                     GTK_FILL, 4, 8);
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), t4, gtk_label_new(_("Advanced")));
    gtk_box_pack_start(GTK_BOX(vbox), nb, TRUE, TRUE, 0);

    /* status and buttons */
    d->status = gtk_label_new("");
    gtk_misc_set_alignment(GTK_MISC(d->status), 0.0f, 0.5f);
    gtk_box_pack_start(GTK_BOX(vbox), d->status, FALSE, FALSE, 0);
    GtkWidget *bb = gtk_hbutton_box_new();
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bb), GTK_BUTTONBOX_END);
    gtk_box_set_spacing(GTK_BOX(bb), 6);
    GtkWidget *help = gtk_button_new_from_stock(GTK_STOCK_HELP);
    GtkWidget *reset = gtk_button_new_with_label(_("Reset"));
    GtkWidget *close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    GtkWidget *save = gtk_button_new_from_stock(GTK_STOCK_SAVE);
    g_signal_connect(help, "clicked", G_CALLBACK(on_help), d);
    g_signal_connect(reset, "clicked", G_CALLBACK(on_reset), d);
    g_signal_connect(close, "clicked", G_CALLBACK(on_close), d);
    g_signal_connect(save, "clicked", G_CALLBACK(on_save), d);
    gtk_container_add(GTK_CONTAINER(bb), help);
    gtk_container_add(GTK_CONTAINER(bb), reset);
    gtk_container_add(GTK_CONTAINER(bb), close);
    gtk_container_add(GTK_CONTAINER(bb), save);
    gtk_box_pack_start(GTK_BOX(vbox), bb, FALSE, FALSE, 0);

    g_signal_connect(d->rows[R_UID].input, "changed", G_CALLBACK(on_uid_combo_changed), d);
    gtk_widget_show_all(vbox);
    gtk_widget_set_no_show_all(d->nodes_combo, TRUE);
    return d;
}

void ks_ruleed_free(struct ks_ruleed *d)
{
    if (d == NULL)
        return;
    gtk_widget_destroy(d->win);
    ks_rform_free(&d->form);
    g_free(d->old_name);
    g_array_free(d->users, TRUE);
    g_ptr_array_free(d->node_addrs, TRUE);
    g_free(d);
}

GtkWidget *ks_ruleed_window(struct ks_ruleed *d)
{
    return d->win;
}

static void present(struct ks_ruleed *d)
{
    refresh_combos(d);
    gtk_window_set_modal(GTK_WINDOW(d->win), TRUE);
    gtk_window_present(GTK_WINDOW(d->win));
}

void ks_ruleed_new_rule(struct ks_ruleed *d)
{
    d->mode = MODE_ADD;
    reset_state(d);
    load_nodes(d, NULL);
    present(d);
}

bool ks_ruleed_new_rule_from_connection(struct ks_ruleed *d, const char *time)
{
    d->mode = MODE_ADD;
    reset_state(d);
    load_nodes(d, NULL);
    sqlite3_stmt *st = NULL;
    sqlite3 *h = ks_db_handle(ks_service_db(d->svc));
    if (sqlite3_prepare_v2(h, "SELECT * FROM connections WHERE time=?", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, time, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        ks_error("[rules editor] error loading connection fields by time: %s", time);
        return false;
    }
#define COL(i) ((const char *)sqlite3_column_text(st, (i)) ? (const char *)sqlite3_column_text(st, (i)) : "")
    /* ConnFields: Time 0, Node 1, Action 2, Protocol 3, SrcIP 4, SrcPort 5, DstIP 6, DstHost 7,
     * DstPort 8, UID 9, PID 10, Process 11, Cmdline 12 */
    char *node = g_strdup(COL(1));
    int idx = -1;
    for (guint i = 0; i < d->node_addrs->len; i++) {
        if (strcmp(g_ptr_array_index(d->node_addrs, i), node) == 0)
            idx = (int)i;
    }
    if (idx == -1) {
        char *m = g_strdup_printf(_("Unable to load connection, unknown node? (%d)"), idx);
        set_status(d, m, true);
        g_free(m);
        g_free(node);
        sqlite3_finalize(st);
        return false;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes_combo), idx);
    ks_rform_from_connection(&d->form, COL(3), COL(4), COL(5), COL(6), COL(7), COL(8), COL(9),
                             COL(10), COL(11), COL(12));
#undef COL
    g_free(node);
    sqlite3_finalize(st);
    write_form(d);
    present(d);
    /* the texts were set; refresh_combos() kept the iface and uid ones */
    return true;
}

void ks_ruleed_edit_rule(struct ks_ruleed *d, const char *node, const char *name)
{
    d->mode = MODE_EDIT;
    reset_state(d);
    const struct ks_ui_rule *row = ks_rulesdb_get(ks_service_rules(d->svc), name, node);
    if (row == NULL) {
        message(d, GTK_MESSAGE_WARNING, _("New rule error"), _("Rule not found by that name and node"));
        return;
    }
    struct ks_arena a = {0};
    Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
    if (r == NULL) {
        ks_arena_free(&a);
        return;
    }
    static const char *const types[] = {"list", "lists", "simple", "regexp", "network"};
    bool known = false;
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        known |= strcmp(r->operator_->type, types[i]) == 0;
    if (!known) {
        char *m = g_strdup_printf(_("This type of rule (%s) is not supported by version %s"),
                                  r->operator_->type, KS_UPSTREAM_VERSION);
        message(d, GTK_MESSAGE_WARNING, _("Rule not supported"), m);
        g_free(m);
        ks_arena_free(&a);
        return;
    }
    d->old_name = g_strdup(name);
    if (!load_nodes(d, node)) {
        ks_arena_free(&a);
        return;
    }
    char err[256];
    ks_rform_load_rule(&d->form, r, err, sizeof(err));
    ks_arena_free(&a);
    write_form(d);
    if (err[0] != '\0')
        set_status(d, err, true);
    present(d);
    if (err[0] != '\0')
        set_status(d, err, true);
}
