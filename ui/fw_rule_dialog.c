/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/firewall_rule.py and
 * res/firewall_rule.ui. See fw_rule_dialog.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/fw_rule_dialog.h"

#include <stdlib.h>
#include <string.h>

#include "ui/fwrules.h"
#include "ui/nodes.h"

#define ALL_NODES "all"

enum { OP_NEW, OP_SAVE, OP_DELETE };

/* the widgets of one condition (the dict of self.statements) */
struct stm {
    GtkWidget *expander, *what, *opts, *op, *value;
};

struct sent {
    uint64_t id;
    int op;
    char uuid[KS_UUID_STRLEN + 64];
};

struct ks_fwrule_dlg {
    struct ks_service *svc;
    void (*on_changed)(void *);
    void *ud;
    GtkWidget *win, *label_node, *nodes, *enable, *desc, *box, *tip, *advanced;
    GtkWidget *frame_dir, *direction, *verdict, *verdict_parms_combo, *verdict_parms;
    GtkWidget *status, *b_delete, *b_reset, *b_close, *b_save, *b_add;
    GPtrArray *stms; /* struct stm * */
    int current;
    GPtrArray *node_addrs;
    struct ks_fw_services services;
    int form_type;
    char uuid[KS_UUID_STRLEN + 64];
    char addr[KS_NODE_ADDR_MAX];
    GArray *sent; /* struct sent */
    bool loading;
};

/* ---- small helpers ------------------------------------------------------------ */

static GtkWidget *text_combo(void)
{
    return gtk_combo_box_new_text();
}

static void combo_clear(GtkWidget *c)
{
    gtk_list_store_clear(GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(c))));
}

static const char *entry_text(GtkWidget *combo_entry)
{
    return gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(combo_entry))));
}

static void set_entry_text(GtkWidget *combo_entry, const char *t)
{
    gtk_entry_set_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(combo_entry))), t);
}

static int active(GtkWidget *c)
{
    return gtk_combo_box_get_active(GTK_COMBO_BOX(c));
}

/* the status label: red errors, green success, orange messages */
static void status(struct ks_fwrule_dlg *d, const char *color, const char *msg)
{
    if (msg == NULL || msg[0] == '\0') {
        gtk_label_set_text(GTK_LABEL(d->status), "");
        gtk_widget_hide(d->status);
        return;
    }
    char *m = g_markup_printf_escaped("<span foreground=\"%s\">%s</span>", color, msg);
    gtk_label_set_markup(GTK_LABEL(d->status), m);
    g_free(m);
    gtk_widget_show(d->status);
}

#define set_status_error(d, m) status(d, "red", m)
#define set_status_successful(d, m) status(d, "green", m)
#define set_status_message(d, m) status(d, "darkorange", m)

static void enable_buttons(struct ks_fwrule_dlg *d, bool enable)
{
    gtk_widget_set_sensitive(d->b_save, enable);
    gtk_widget_set_sensitive(d->b_add, enable);
    gtk_widget_set_sensitive(d->b_delete, enable);
}

static void enable_save(struct ks_fwrule_dlg *d, bool enable)
{
    gtk_widget_set_sensitive(d->b_save, enable);
}

static void disable_controls(struct ks_fwrule_dlg *d)
{
    enable_buttons(d, false);
    gtk_widget_set_sensitive(d->box, FALSE);
}

static const char *selected_node(struct ks_fwrule_dlg *d)
{
    int i = active(d->nodes);
    return i >= 0 && (guint)i < d->node_addrs->len ? g_ptr_array_index(d->node_addrs, (guint)i)
                                                    : NULL;
}

static const char *nz_node(struct ks_fwrule_dlg *d)
{
    const char *n = selected_node(d);
    return n != NULL ? n : "";
}

/* ---- conditions --------------------------------------------------------------- */

static struct stm *stm_at(struct ks_fwrule_dlg *d, int i)
{
    return i >= 0 && (guint)i < d->stms->len ? g_ptr_array_index(d->stms, (guint)i) : NULL;
}

static void read_stm(struct stm *s, struct ks_fwf_statement *st)
{
    st->what = active(s->what) - 1; /* the first item is blank */
    st->opts = active(s->opts);
    st->op = active(s->op);
    snprintf(st->value, sizeof(st->value), "%s", entry_text(s->value));
}

/* _set_statement_title */
static void set_title(struct ks_fwrule_dlg *d, struct stm *s)
{
    struct ks_fwf_statement st;
    read_stm(s, &st);
    char t[KS_FWF_VALUE_MAX + 128];
    ks_fwf_title(&st, t, sizeof(t));
    set_status_message(d, NULL);
    gtk_expander_set_label(GTK_EXPANDER(s->expander), t[0] ? t : " ");
}

/* _configure_statem_value_opts */
static void configure_opts(struct ks_fwrule_dlg *d, struct stm *s)
{
    int what = active(s->what) - 1;
    if (what < 0)
        return;
    d->loading = true;
    char *old = g_strdup(entry_text(s->value));
    combo_clear(s->value);
    const char *vals[2048];
    size_t nv = ks_fwf_values(what, &d->services, vals, 2048);
    for (size_t i = 0; i < nv; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(s->value), vals[i]);
    if ((what == KS_FWF_IIFNAME || what == KS_FWF_OIFNAME) && ks_nodes_is_local(nz_node(d))) {
        struct ks_iface ifs[64];
        size_t n = ks_net_ifaces(ifs, 64);
        for (size_t i = 0; i < n; i++)
            gtk_combo_box_append_text(GTK_COMBO_BOX(s->value), ifs[i].name);
        g_free(old);
        old = g_strdup("");
    }
    set_entry_text(s->value, old);
    g_free(old);

    combo_clear(s->opts);
    const char *const *opts;
    bool show_opts, show_op;
    size_t n = ks_fwf_opts(what, &opts, &show_opts, &show_op);
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(s->opts), opts[i]);
    if (n > 0)
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->opts), ks_fwf_default_opts(what));
    gtk_widget_set_visible(s->opts, show_opts);
    gtk_widget_set_visible(s->op, show_op);
    gtk_widget_set_tooltip_text(s->value, ks_fwf_statm_tooltip(what));
    d->loading = false;
}

static int stm_index(struct ks_fwrule_dlg *d, struct stm *s)
{
    for (guint i = 0; i < d->stms->len; i++)
        if (g_ptr_array_index(d->stms, i) == s)
            return (int)i;
    return -1;
}

static void on_what_changed(GtkComboBox *c, gpointer ud);
static void on_part_changed(GtkComboBox *c, gpointer ud);

struct stm_cb {
    struct ks_fwrule_dlg *d;
    struct stm *s;
};

static void on_expanded(GObject *o, GParamSpec *p, gpointer ud)
{
    (void)p;
    struct stm_cb *cb = ud;
    if (!gtk_expander_get_expanded(GTK_EXPANDER(o)))
        return;
    cb->d->current = stm_index(cb->d, cb->s);
    /* one page open at a time */
    for (guint i = 0; i < cb->d->stms->len; i++) {
        struct stm *s = g_ptr_array_index(cb->d->stms, i);
        if (s != cb->s)
            gtk_expander_set_expanded(GTK_EXPANDER(s->expander), FALSE);
    }
}

static void free_stm_cb(gpointer data, GClosure *c)
{
    (void)c;
    g_free(data);
}

/* add_new_statement: after the current one */
static struct stm *add_statement(struct ks_fwrule_dlg *d)
{
    struct stm *s = g_new0(struct stm, 1);
    s->expander = gtk_expander_new(" ");
    GtkWidget *v = gtk_vbox_new(FALSE, 4), *h1 = gtk_hbox_new(FALSE, 4),
              *h2 = gtk_hbox_new(FALSE, 4);
    s->what = text_combo();
    for (int i = 0; i <= KS_FWF_NSTATM; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(s->what), ks_fwf_statm_labels[i]);
    s->opts = text_combo();
    gtk_combo_box_append_text(GTK_COMBO_BOX(s->opts), "TCP");
    gtk_combo_box_append_text(GTK_COMBO_BOX(s->opts), "UDP");
    gtk_combo_box_append_text(GTK_COMBO_BOX(s->opts), "ICMP");
    s->op = text_combo();
    static const char *const ops[] = {"Equal", "Not equal", "Greater or equal than",
                                      "Greater than", "Less or equal than", "Less than"};
    for (int i = 0; i < 6; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(s->op), ops[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(s->op), 0);
    s->value = gtk_combo_box_entry_new_text();
    gtk_box_pack_start(GTK_BOX(h1), s->what, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(h1), s->opts, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h2), s->op, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h2), s->value, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(v), h1, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h2, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(v), 6);
    gtk_container_add(GTK_CONTAINER(s->expander), v);

    int pos = d->current + 1;
    if (pos < 0 || (guint)pos > d->stms->len)
        pos = (int)d->stms->len;
    g_ptr_array_add(d->stms, NULL);
    memmove(&d->stms->pdata[pos + 1], &d->stms->pdata[pos],
            (d->stms->len - 1 - (guint)pos) * sizeof(gpointer));
    d->stms->pdata[pos] = s;
    gtk_box_pack_start(GTK_BOX(d->box), s->expander, FALSE, FALSE, 0);
    gtk_box_reorder_child(GTK_BOX(d->box), s->expander, pos);

    struct stm_cb *cb = g_new0(struct stm_cb, 1);
    cb->d = d;
    cb->s = s;
    g_signal_connect_data(s->expander, "notify::expanded", G_CALLBACK(on_expanded), cb,
                          free_stm_cb, 0);
    g_signal_connect(s->what, "changed", G_CALLBACK(on_what_changed), d);
    g_signal_connect(s->opts, "changed", G_CALLBACK(on_part_changed), d);
    g_signal_connect(s->op, "changed", G_CALLBACK(on_part_changed), d);
    g_signal_connect(s->value, "changed", G_CALLBACK(on_part_changed), d);
    gtk_widget_show_all(s->expander);
    gtk_expander_set_expanded(GTK_EXPANDER(s->expander), TRUE);
    d->current = pos;
    return s;
}

static struct stm *stm_of_widget(struct ks_fwrule_dlg *d, GtkWidget *w)
{
    for (guint i = 0; i < d->stms->len; i++) {
        struct stm *s = g_ptr_array_index(d->stms, i);
        if (s->what == w || s->opts == w || s->op == w || s->value == w)
            return s;
    }
    return NULL;
}

/* _cb_statem_combo_changed */
static void on_what_changed(GtkComboBox *c, gpointer ud)
{
    struct ks_fwrule_dlg *d = ud;
    if (d->loading)
        return;
    struct stm *s = stm_of_widget(d, GTK_WIDGET(c));
    if (s == NULL)
        return;
    enable_save(d, true);
    configure_opts(d, s);
    set_title(d, s);
}

/* _cb_statem_value_index_changed and the other parts' callbacks */
static void on_part_changed(GtkComboBox *c, gpointer ud)
{
    struct ks_fwrule_dlg *d = ud;
    if (d->loading)
        return;
    struct stm *s = stm_of_widget(d, GTK_WIDGET(c));
    if (s == NULL)
        return;
    enable_save(d, true);
    int what = active(s->what) - 1;
    if (GTK_WIDGET(c) == s->value && active(s->value) >= 0 &&
        (what == KS_FWF_SPORT || what == KS_FWF_DPORT)) {
        /* automagically choose the protocol of the selected service */
        char *val = g_ascii_strdown(entry_text(s->value), -1);
        int idx = -1;
        if (strstr(val, "tcp") != NULL)
            idx = 1;
        else if (strstr(val, "udp") != NULL)
            idx = 2;
        g_free(val);
        if (idx >= 0)
            gtk_combo_box_set_active(GTK_COMBO_BOX(s->opts), idx);
    }
    set_title(d, s);
}

/* _reset_widgets */
static void reset_statements(struct ks_fwrule_dlg *d)
{
    for (guint i = 0; i < d->stms->len; i++) {
        struct stm *s = g_ptr_array_index(d->stms, i);
        gtk_widget_destroy(s->expander);
        g_free(s);
    }
    g_ptr_array_set_size(d->stms, 0);
    d->current = -1;
}

static void on_add_statement(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    enable_save(d, true);
    struct stm *s = add_statement(d);
    gtk_expander_set_label(GTK_EXPANDER(s->expander), "<select a statement>");
}

static void on_del_statement(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    enable_save(d, true);
    struct stm *s = stm_at(d, d->current);
    if (s == NULL)
        return;
    g_ptr_array_remove_index(d->stms, (guint)d->current);
    gtk_widget_destroy(s->expander);
    g_free(s);
    if (d->current >= (int)d->stms->len)
        d->current = (int)d->stms->len - 1;
    struct stm *n = stm_at(d, d->current);
    if (n != NULL)
        gtk_expander_set_expanded(GTK_EXPANDER(n->expander), TRUE);
}

/* ---- verdicts and direction ------------------------------------------------------ */

static void configure_verdict_parms(struct ks_fwrule_dlg *d)
{
    int v = active(d->verdict);
    combo_clear(d->verdict_parms_combo);
    const char *const *items;
    size_t n = ks_fwf_verdict_parm_items(v, &items);
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->verdict_parms_combo), items[i]);
    if (n > 0)
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->verdict_parms_combo), 0);
    int dir = ks_fwf_verdict_direction(v, active(d->direction));
    if (dir >= 0)
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->direction), dir);
}

static void on_verdict_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fwrule_dlg *d = ud;
    if (d->loading)
        return;
    enable_save(d, true);
    bool show = ks_fwf_has_verdict_parms(active(d->verdict));
    gtk_widget_set_visible(d->verdict_parms, show);
    gtk_widget_set_visible(d->verdict_parms_combo, show);
    configure_verdict_parms(d);
}

/* _cb_direction_changed -> _is_valid_rule */
static void on_direction_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fwrule_dlg *d = ud;
    if (d->loading)
        return;
    enable_save(d, true);
    int dir = active(d->direction);
    const char *msg = ks_fwf_check_direction(active(d->verdict), &dir);
    set_status_message(d, msg);
    if (dir != active(d->direction))
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->direction), dir);
}

static void on_changed_enable_save(GtkWidget *w, gpointer ud)
{
    (void)w;
    struct ks_fwrule_dlg *d = ud;
    if (!d->loading)
        enable_save(d, true);
}

/* ---- the form ------------------------------------------------------------------- */

static void read_form(struct ks_fwrule_dlg *d, struct ks_fwf_form *f)
{
    memset(f, 0, sizeof(*f));
    f->form_type = d->form_type;
    f->direction = active(d->direction);
    f->verdict = active(d->verdict);
    f->verdict_parm = active(d->verdict_parms_combo);
    snprintf(f->verdict_parms, sizeof(f->verdict_parms), "%s",
             gtk_entry_get_text(GTK_ENTRY(d->verdict_parms)));
    f->enabled = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->enable));
    snprintf(f->description, sizeof(f->description), "%s",
             gtk_entry_get_text(GTK_ENTRY(d->desc)));
    snprintf(f->uuid, sizeof(f->uuid), "%s", d->uuid);
    for (guint i = 0; i < d->stms->len && i < KS_FWF_MAX_STATEMENTS; i++)
        read_stm(g_ptr_array_index(d->stms, i), &f->st[f->nst++]);
}

static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_fwrule_dlg *d = ud;
    (void)addr;
    enable_buttons(d, true);
    struct sent *rep = NULL;
    guint idx = 0;
    for (; idx < d->sent->len; idx++) {
        if (g_array_index(d->sent, struct sent, idx).id == r->id) {
            rep = &g_array_index(d->sent, struct sent, idx);
            break;
        }
    }
    if (rep == NULL)
        return;
    const char *data = r->data != NULL ? r->data : "";
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__OK) {
        if (rep->op == OP_DELETE) {
            gtk_widget_set_sensitive(d->box, FALSE);
            set_status_successful(d, "Rule deleted");
            disable_controls(d);
        } else if (rep->op == OP_SAVE) {
            set_status_successful(d, "Rule saved");
        } else {
            gtk_widget_set_visible(d->b_add, FALSE);
            gtk_widget_set_visible(d->b_save, TRUE);
            set_status_successful(d, "Rule added");
        }
    } else {
        char *msg = g_strdup_printf("Error adding rules:\n%s", data);
        bool shown = false;
        if (rep->op == OP_SAVE) {
            if (rep->uuid[0] != '\0' && strstr(data, rep->uuid) != NULL) {
                g_free(msg);
                msg = g_strdup("Error saving rule");
            } else {
                char *m = g_strdup_printf(
                    "Rule saved, but there're other rules with errors (REVIEW):\n%s", data);
                set_status_message(d, m);
                g_free(m);
                shown = true;
            }
        }
        if (!shown)
            set_status_error(d, msg);
        g_free(msg);
    }
    g_array_remove_index(d->sent, idx);
}

static void send_notification(struct ks_fwrule_dlg *d, const char *addr, int op,
                              const char *uuid)
{
    uint64_t id = ks_nodes_reload_fw(ks_service_nodes(d->svc), addr, on_reply, d);
    struct sent s = {id, op, ""};
    snprintf(s.uuid, sizeof(s.uuid), "%s", uuid != NULL ? uuid : "");
    g_array_append_val(d->sent, s);
    if (d->on_changed)
        d->on_changed(d->ud);
}

static struct ks_sysfw *node_fw(struct ks_fwrule_dlg *d, const char *addr)
{
    struct ks_node *n = ks_nodes_get(ks_service_nodes(d->svc), addr);
    return n != NULL ? n->fw : NULL;
}

/* add_rule / save_rule / delete_rule: NULL or the error to show */
static char *add_rule(struct ks_fwrule_dlg *d, const char *addr, const struct ks_fw_chain *c)
{
    const char *err = "this node doesn't have a firewall configuration, review it.";
    if (ks_fwr_insert(node_fw(d, addr), c, 0, &err) < 0)
        return g_strdup_printf("Error adding rule: %s", err);
    send_notification(d, addr, OP_NEW, KS_SYSFW_RULE(c, 0)->uuid);
    return NULL;
}

static char *save_rule(struct ks_fwrule_dlg *d, const char *addr, const struct ks_fw_chain *c)
{
    const char *err = "this node doesn't have a firewall configuration, review it.";
    if (ks_fwr_update(node_fw(d, addr), d->uuid, c, &err) < 0)
        return g_strdup_printf("Error saving rule %s", err);
    send_notification(d, addr, OP_SAVE, d->uuid);
    return NULL;
}

static char *delete_rule(struct ks_fwrule_dlg *d, const char *addr)
{
    if (ks_fwr_delete(node_fw(d, addr), d->uuid) < 0)
        return g_strdup_printf("Error deleting rule, %s", addr);
    send_notification(d, addr, OP_DELETE, d->uuid);
    return NULL;
}

/* form_to_protobuf, with upstream's message */
static bool form_rule(struct ks_fwrule_dlg *d, struct ks_fw_chain *c)
{
    struct ks_fwf_form f;
    read_form(d, &f);
    char err[512];
    if (ks_fwf_to_rule(&f, &d->services, c, err, sizeof(err)) < 0) {
        char *m = g_strdup_printf("Invalid rule: %s", err);
        set_status_error(d, m);
        g_free(m);
        return false;
    }
    return true;
}

typedef char *(*node_op)(struct ks_fwrule_dlg *d, const char *addr, const struct ks_fw_chain *c);

/* runs `op` on the selected node, or on all of them ("All") */
static void for_nodes(struct ks_fwrule_dlg *d, node_op op, const struct ks_fw_chain *c)
{
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    const char *addr = selected_node(d);
    if (active(d->nodes) == 0) {
        for (size_t i = 0; i < nodes->len; i++) {
            char *e = op(d, nodes->items[i]->addr, c);
            if (e != NULL)
                set_status_error(d, e);
            g_free(e);
        }
        return;
    }
    char *e = addr != NULL ? op(d, addr, c) : g_strdup("no node");
    if (e != NULL) {
        set_status_error(d, e);
        g_free(e);
        return;
    }
    enable_buttons(d, false);
}

static char *delete_op(struct ks_fwrule_dlg *d, const char *addr, const struct ks_fw_chain *c)
{
    (void)c;
    return delete_rule(d, addr);
}

static void on_add(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    if (d->stms->len == 0) {
        set_status_message(d, "Add at least one statement.");
        return;
    }
    struct ks_fw_chain c;
    if (!form_rule(d, &c))
        return;
    set_status_message(d, "Adding rule, wait");
    for_nodes(d, add_rule, &c);
    ks_fwr_free_chain(&c);
}

static void on_save(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    if (d->stms->len == 0) {
        set_status_message(d, "Add at least one statement.");
        return;
    }
    struct ks_fw_chain c;
    if (!form_rule(d, &c))
        return;
    set_status_message(d, "Saving rule, wait");
    for_nodes(d, save_rule, &c);
    ks_fwr_free_chain(&c);
}

static void on_delete(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    struct ks_fw_chain c;
    if (!form_rule(d, &c))
        return;
    set_status_message(d, "Deleting rule, wait");
    for_nodes(d, delete_op, &c);
    ks_fwr_free_chain(&c);
}

static void on_reset(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    reset_statements(d);
    struct stm *s = add_statement(d);
    gtk_expander_set_label(GTK_EXPANDER(s->expander), "<select a statement>");
}

static void on_help(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    GtkWidget *w = gtk_message_dialog_new_with_markup(
        GTK_WINDOW(d->win), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "You can use ',' or '-' to specify multiple ports/IPs or ranges/values:\n\n"
        "ports: 22 or 22,443 or 50000-60000\n"
        "IPs: 192.168.1.1 or 192.168.1.30-192.168.1.130\n"
        "Values: echo-reply,echo-request\n"
        "Values: new,established,related");
    g_signal_connect_swapped(w, "response", G_CALLBACK(gtk_widget_destroy), w);
    gtk_widget_show(w);
}

static void on_nodes_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fwrule_dlg *d = ud;
    if (d->loading)
        return;
    const char *n = selected_node(d);
    bool add = n == NULL || strcmp(n, d->addr) != 0;
    gtk_widget_set_visible(d->b_save, !add);
    gtk_widget_set_visible(d->b_add, add);
}

static gboolean on_delete_event(GtkWidget *w, GdkEvent *e, gpointer ud)
{
    (void)e;
    (void)ud;
    gtk_widget_hide(w);
    return TRUE;
}

static void on_close(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fwrule_dlg *d = ud;
    gtk_widget_hide(d->win);
}

/* ---- building ------------------------------------------------------------------ */

static GtkWidget *icon_button(const char *label, const char *stock)
{
    GtkWidget *b = label != NULL ? gtk_button_new_with_mnemonic(label) : gtk_button_new();
    if (stock != NULL)
        gtk_button_set_image(GTK_BUTTON(b), gtk_image_new_from_stock(stock, GTK_ICON_SIZE_BUTTON));
    return b;
}

static void icon_item(GtkWidget *combo, const char *label)
{
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), label);
}

struct ks_fwrule_dlg *ks_fwrule_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                        void (*on_changed)(void *), void *ud)
{
    struct ks_fwrule_dlg *d = g_new0(struct ks_fwrule_dlg, 1);
    d->svc = svc;
    d->on_changed = on_changed;
    d->ud = ud;
    d->stms = g_ptr_array_new();
    d->node_addrs = g_ptr_array_new_with_free_func(g_free);
    d->sent = g_array_new(FALSE, TRUE, sizeof(struct sent));
    d->current = -1;
    ks_fw_services_load(&d->services, NULL);

    d->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(d->win), "Firewall rule");
    gtk_window_set_default_size(GTK_WINDOW(d->win), 440, 460);
    if (parent != NULL)
        gtk_window_set_transient_for(GTK_WINDOW(d->win), parent);
    g_signal_connect(d->win, "delete-event", G_CALLBACK(on_delete_event), d);
    GtkWidget *v = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width(GTK_CONTAINER(v), 8);
    gtk_container_add(GTK_CONTAINER(d->win), v);

    /* labelNode, comboNodes */
    GtkWidget *h = gtk_hbox_new(FALSE, 6);
    d->label_node = gtk_label_new("Node");
    d->nodes = text_combo();
    gtk_box_pack_start(GTK_BOX(h), d->label_node, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->nodes, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    /* checkEnable, Description */
    d->enable = gtk_check_button_new_with_mnemonic("_Enable");
    gtk_box_pack_start(GTK_BOX(v), d->enable, FALSE, FALSE, 0);
    h = gtk_hbox_new(FALSE, 6);
    d->desc = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(h), gtk_label_new("Description"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->desc, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    /* the conditions (toolBoxSimple) and lblExcludeTip */
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER,
                                   GTK_POLICY_AUTOMATIC);
    d->box = gtk_vbox_new(FALSE, 2);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(sw), d->box);
    gtk_box_pack_start(GTK_BOX(v), sw, TRUE, TRUE, 0);
    d->tip = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(v), d->tip, FALSE, FALSE, 0);

    /* hboxAdvanced: add / remove condition */
    d->advanced = gtk_hbox_new(FALSE, 6);
    GtkWidget *add = icon_button(NULL, GTK_STOCK_ADD), *del = icon_button(NULL, GTK_STOCK_REMOVE);
    gtk_widget_set_tooltip_text(add, "Add new condition");
    gtk_widget_set_tooltip_text(del, "Remove selected condition");
    gtk_box_pack_end(GTK_BOX(d->advanced), del, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(d->advanced), add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), d->advanced, FALSE, FALSE, 0);
    g_signal_connect(add, "clicked", G_CALLBACK(on_add_statement), d);
    g_signal_connect(del, "clicked", G_CALLBACK(on_del_statement), d);

    /* frameDirection: Direction, Action and its parameters */
    d->frame_dir = gtk_table_new(2, 4, FALSE);
    gtk_table_set_col_spacings(GTK_TABLE(d->frame_dir), 6);
    gtk_table_set_row_spacings(GTK_TABLE(d->frame_dir), 4);
    d->direction = text_combo();
    static const char *const dirs[] = {"IN", "OUT", "FORWARD", "PREROUTING", "POSTROUTING"};
    for (int i = 0; i < 5; i++)
        icon_item(d->direction, dirs[i]);
    d->verdict = text_combo();
    static const char *const verdicts[] = {"ACCEPT", "DROP", "REJECT", "RETURN",
                                           "QUEUE",  "DNAT", "SNAT",   "REDIRECT"};
    for (int i = 0; i < KS_FWF_NVERDICT_ITEMS; i++)
        icon_item(d->verdict, verdicts[i]);
    d->verdict_parms_combo = text_combo();
    d->verdict_parms = gtk_entry_new();
    gtk_widget_set_tooltip_text(
        d->verdict_parms,
        "depending on the Action (i.e.: target), the syntaxis of the parameters will vary.\n"
        "Some examples:\n\n to 1.2.3.4 (snat, dnat)\n to :8080 (redirect, tproxy)\n to "
        "1.2.3.4:8080 (snat, dnat)\n num 1 (queue)\n to 1024-2048 (masquerade)");
    gtk_table_attach(GTK_TABLE(d->frame_dir), gtk_label_new("Direction"), 0, 1, 0, 1, GTK_FILL,
                     GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(d->frame_dir), d->direction, 1, 4, 0, 1,
                     GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(d->frame_dir), gtk_label_new("Action"), 0, 1, 1, 2, GTK_FILL,
                     GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(d->frame_dir), d->verdict, 1, 2, 1, 2, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(d->frame_dir), d->verdict_parms_combo, 2, 3, 1, 2, GTK_FILL,
                     GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(d->frame_dir), d->verdict_parms, 3, 4, 1, 2,
                     GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);
    gtk_box_pack_start(GTK_BOX(v), d->frame_dir, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), gtk_hseparator_new(), FALSE, FALSE, 0);

    d->status = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(d->status), TRUE);
    gtk_box_pack_start(GTK_BOX(v), d->status, FALSE, FALSE, 0);

    /* helpButton, Delete, Clear, Close, Save, Add */
    h = gtk_hbox_new(FALSE, 6);
    GtkWidget *help = icon_button(NULL, GTK_STOCK_HELP);
    d->b_delete = icon_button("_Delete", GTK_STOCK_DELETE);
    d->b_reset = icon_button("C_lear", NULL);
    d->b_close = icon_button("_Close", GTK_STOCK_CLOSE);
    d->b_save = icon_button("_Save", GTK_STOCK_SAVE);
    d->b_add = icon_button("_Add", GTK_STOCK_ADD);
    gtk_box_pack_start(GTK_BOX(h), help, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->b_delete, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->b_reset, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), d->b_add, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), d->b_save, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), d->b_close, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    g_signal_connect(help, "clicked", G_CALLBACK(on_help), d);
    g_signal_connect(d->b_delete, "clicked", G_CALLBACK(on_delete), d);
    g_signal_connect(d->b_reset, "clicked", G_CALLBACK(on_reset), d);
    g_signal_connect(d->b_close, "clicked", G_CALLBACK(on_close), d);
    g_signal_connect(d->b_save, "clicked", G_CALLBACK(on_save), d);
    g_signal_connect(d->b_add, "clicked", G_CALLBACK(on_add), d);
    g_signal_connect(d->verdict, "changed", G_CALLBACK(on_verdict_changed), d);
    g_signal_connect(d->direction, "changed", G_CALLBACK(on_direction_changed), d);
    g_signal_connect(d->nodes, "changed", G_CALLBACK(on_nodes_changed), d);
    g_signal_connect(d->enable, "toggled", G_CALLBACK(on_changed_enable_save), d);
    g_signal_connect(d->desc, "changed", G_CALLBACK(on_changed_enable_save), d);
    g_signal_connect(d->verdict_parms, "changed", G_CALLBACK(on_changed_enable_save), d);
    gtk_widget_show_all(v);
    return d;
}

void ks_fwrule_dlg_free(struct ks_fwrule_dlg *d)
{
    if (d == NULL)
        return;
    reset_statements(d);
    if (d->win != NULL)
        gtk_widget_destroy(d->win);
    g_ptr_array_free(d->stms, TRUE);
    g_ptr_array_free(d->node_addrs, TRUE);
    g_array_free(d->sent, TRUE);
    ks_fw_services_free(&d->services);
    g_free(d);
}

GtkWidget *ks_fwrule_dlg_window(struct ks_fwrule_dlg *d)
{
    return d->win;
}

/* _load_nodes */
static void load_nodes(struct ks_fwrule_dlg *d)
{
    d->loading = true;
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    combo_clear(d->nodes);
    g_ptr_array_set_size(d->node_addrs, 0);
    gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes), "All");
    g_ptr_array_add(d->node_addrs, g_strdup(ALL_NODES));
    for (size_t i = 0; i < nodes->len; i++) {
        const char *a = nodes->items[i]->addr;
        char *t = g_strdup_printf("%s - %s", a, ks_nodes_hostname(nodes, a));
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes), t);
        g_free(t);
        g_ptr_array_add(d->node_addrs, g_strdup(a));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes), nodes->len == 1 ? 1 : 0);
    if (nodes->len == 0)
        gtk_widget_set_sensitive(d->box, FALSE);
    bool show = nodes->len > 1;
    gtk_widget_set_visible(d->nodes, show);
    gtk_widget_set_visible(d->label_node, show);
    d->loading = false;
}

/* show() + _reset_fields() */
static void show_reset(struct ks_fwrule_dlg *d)
{
    d->loading = true;
    d->form_type = KS_FWF_SIMPLE;
    gtk_window_set_title(GTK_WINDOW(d->win), "Firewall rule");
    gtk_widget_set_visible(d->b_delete, FALSE);
    gtk_widget_set_visible(d->b_save, FALSE);
    gtk_widget_set_visible(d->b_add, TRUE);
    gtk_widget_set_visible(d->b_reset, TRUE);
    gtk_widget_set_visible(d->enable, TRUE);
    gtk_widget_set_sensitive(d->enable, TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->enable), TRUE);
    gtk_widget_set_visible(d->frame_dir, TRUE);
    gtk_widget_set_visible(d->tip, FALSE);
    gtk_label_set_text(GTK_LABEL(d->tip), "");
    status(d, NULL, NULL);
    enable_buttons(d, true);
    gtk_widget_set_sensitive(d->box, TRUE);
    gtk_entry_set_text(GTK_ENTRY(d->desc), "");
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->direction), KS_FWF_IN);
    gtk_widget_set_sensitive(d->direction, TRUE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->verdict), 0);
    gtk_widget_set_visible(d->verdict_parms, FALSE);
    gtk_widget_set_visible(d->verdict_parms_combo, FALSE);
    gtk_entry_set_text(GTK_ENTRY(d->verdict_parms), "");
    d->uuid[0] = '\0';
    d->addr[0] = '\0';
    d->loading = false;
    load_nodes(d);
    gtk_widget_show(d->win);
    gtk_window_present(GTK_WINDOW(d->win));
}

void ks_fwrule_dlg_new_rule(struct ks_fwrule_dlg *d)
{
    show_reset(d);
    reset_statements(d);
    gtk_widget_set_visible(d->advanced, TRUE);
    add_statement(d);
}

void ks_fwrule_dlg_exclude_service(struct ks_fwrule_dlg *d, int direction)
{
    show_reset(d);
    reset_statements(d);
    gtk_window_set_title(GTK_WINDOW(d->win), "Exclude service");
    gtk_widget_set_visible(d->b_reset, FALSE);
    gtk_widget_set_visible(d->enable, FALSE);
    gtk_widget_set_visible(d->advanced, FALSE);
    d->form_type = KS_FWF_ALLOW_IN_SERVICE;
    gtk_label_set_text(GTK_LABEL(d->tip), "Allow inbound connections to the selected port.");
    if (direction == KS_FWF_OUT) {
        gtk_label_set_text(GTK_LABEL(d->tip), "Allow outbound connections to the selected port.");
        d->form_type = KS_FWF_EXCLUDE_SERVICE;
    }
    struct stm *s = add_statement(d);
    gtk_combo_box_set_active(GTK_COMBO_BOX(s->what), KS_FWF_DPORT + 1);
    gtk_widget_set_visible(s->what, FALSE);
    gtk_widget_set_visible(s->op, FALSE);
    set_entry_text(s->value, "");
    gtk_widget_set_visible(d->frame_dir, FALSE);
    gtk_widget_set_visible(d->tip, TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->enable), TRUE);
}

void ks_fwrule_dlg_load(struct ks_fwrule_dlg *d, const char *addr, const char *uuid)
{
    show_reset(d);
    int ni = -1;
    for (guint i = 0; i < d->node_addrs->len; i++)
        if (strcmp(g_ptr_array_index(d->node_addrs, i), addr) == 0)
            ni = (int)i;
    if (ni < 0) {
        char *m = g_strdup_printf("node not found: %s", addr);
        set_status_message(d, m);
        g_free(m);
        return;
    }
    gtk_widget_set_visible(d->b_delete, TRUE);
    gtk_widget_set_visible(d->b_save, TRUE);
    gtk_widget_set_visible(d->b_add, FALSE);
    d->loading = true;
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes), ni);
    d->loading = false;
    snprintf(d->uuid, sizeof(d->uuid), "%s", uuid);
    snprintf(d->addr, sizeof(d->addr), "%s", addr);

    struct ks_fw_chain flat;
    struct ks_fwf_form f;
    char err[512];
    reset_statements(d);
    gtk_widget_set_visible(d->advanced, TRUE);
    struct ks_sysfw *fw = node_fw(d, addr);
    if (fw == NULL || ks_fwr_flat_by_uuid(fw, uuid, &flat) < 0) {
        set_status_error(d, "Rule hook (invalid) not supported yet");
        disable_controls(d);
        return;
    }
    int ret = ks_fwf_from_rule(&flat, &d->services, &f, err, sizeof(err));
    ks_fwr_free_chain(&flat);
    if (ret < 0) {
        set_status_error(d, err);
        disable_controls(d);
        return;
    }
    d->loading = true;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->enable), f.enabled);
    gtk_entry_set_text(GTK_ENTRY(d->desc), f.description);
    for (size_t i = 0; i < f.nst; i++) {
        struct stm *s = add_statement(d);
        const struct ks_fwf_statement *st = &f.st[i];
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->what), st->what + 1);
        d->loading = false;
        configure_opts(d, s);
        d->loading = true;
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->opts), st->opts);
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->op), st->op);
        set_entry_text(s->value, st->value);
        set_title(d, s);
    }
    struct stm *first = stm_at(d, 0);
    if (first != NULL)
        gtk_expander_set_expanded(GTK_EXPANDER(first->expander), TRUE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->direction), f.direction);
    /* changing the direction of an existing rule isn't supported upstream */
    gtk_widget_set_sensitive(d->direction, FALSE);
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->verdict), f.verdict);
    bool show = ks_fwf_has_verdict_parms(f.verdict);
    gtk_widget_set_visible(d->verdict_parms, show);
    gtk_widget_set_visible(d->verdict_parms_combo, show);
    configure_verdict_parms(d);
    gtk_entry_set_text(GTK_ENTRY(d->verdict_parms), f.verdict_parms);
    d->loading = false;
    enable_save(d, false);
}
