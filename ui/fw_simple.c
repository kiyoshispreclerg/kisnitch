/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The simplified system firewall panel. See fw_simple.h and fwsimple.h.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/fw_simple.h"

#include <net/if.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "ui/fwsimple.h"
#include "ui/nodes.h"

enum {
    COL_POS, COL_ENABLED, COL_ACTION, COL_DIR, COL_PORT, COL_FROM, COL_TO, COL_IFACE, COL_DESC,
    COL_UUID, COL_KIND, COL_STYLE, NCOLS
};

struct ks_fws_dlg {
    struct ks_service *svc;
    struct ks_fwrule_dlg *rule_dlg;
    void (*on_changed)(void *);
    void *ud;
    GtkWidget *win, *nodes, *warning, *combo_in, *combo_out, *view, *status;
    GtkWidget *b_add, *b_edit, *b_del, *b_up, *b_down, *b_adv;
    GtkListStore *store;
    GPtrArray *node_addrs;
    GArray *sent;
    struct ks_fws_apps apps;
    bool loading;
};

/* ---- helpers --------------------------------------------------------------- */

static void status(struct ks_fws_dlg *d, const char *color, const char *msg)
{
    if (msg == NULL) {
        gtk_label_set_text(GTK_LABEL(d->status), "");
        return;
    }
    char *m = g_markup_printf_escaped("<span foreground=\"%s\">%s</span>", color, msg);
    gtk_label_set_markup(GTK_LABEL(d->status), m);
    g_free(m);
}

static const char *node_addr(struct ks_fws_dlg *d)
{
    int i = gtk_combo_box_get_active(GTK_COMBO_BOX(d->nodes));
    return i >= 0 && (guint)i < d->node_addrs->len ? g_ptr_array_index(d->node_addrs, (guint)i)
                                                    : NULL;
}

static struct ks_node *node_of(struct ks_fws_dlg *d)
{
    const char *a = node_addr(d);
    return a != NULL ? ks_nodes_get(ks_service_nodes(d->svc), a) : NULL;
}

static struct ks_sysfw *fw_of(struct ks_fws_dlg *d)
{
    struct ks_node *n = node_of(d);
    return n != NULL ? n->fw : NULL;
}

/* the uuid and kind of the selected row; false if none */
static bool selected(struct ks_fws_dlg *d, char **uuid, int *kind)
{
    GtkTreeIter it;
    GtkTreeModel *m;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(d->view));
    if (!gtk_tree_selection_get_selected(sel, &m, &it))
        return false;
    gtk_tree_model_get(m, &it, COL_UUID, uuid, COL_KIND, kind, -1);
    return true;
}

static void update_buttons(struct ks_fws_dlg *d)
{
    char *uuid = NULL;
    int kind = -1;
    bool sel = selected(d, &uuid, &kind);
    bool fw = fw_of(d) != NULL;
    gtk_widget_set_sensitive(d->b_add, fw);
    gtk_widget_set_sensitive(d->b_edit, sel && kind == KS_FWS_ROW_SIMPLE);
    gtk_widget_set_sensitive(d->b_del, sel && kind != KS_FWS_ROW_POLICY);
    gtk_widget_set_sensitive(d->b_up, sel && kind != KS_FWS_ROW_POLICY);
    gtk_widget_set_sensitive(d->b_down, sel && kind != KS_FWS_ROW_POLICY);
    gtk_widget_set_sensitive(d->b_adv, sel);
    g_free(uuid);
}

/* ---- loading ----------------------------------------------------------------- */

static void load_rules(struct ks_fws_dlg *d, const char *keep_uuid)
{
    gtk_list_store_clear(d->store);
    struct ks_sysfw *fw = fw_of(d);
    struct ks_fws_rows rows;
    if (fw == NULL || ks_fws_rows(fw, &rows) < 0) {
        update_buttons(d);
        return;
    }
    GtkTreeIter keep;
    bool kept = false;
    for (size_t i = 0; i < rows.n; i++) {
        const struct ks_fws_row *r = &rows.v[i];
        GtkTreeIter it;
        gtk_list_store_append(d->store, &it);
        char pos[16], port[KS_FWS_TEXT_MAX + 16];
        snprintf(pos, sizeof(pos), "%zu", i + 1);
        if (r->kind == KS_FWS_ROW_SIMPLE) {
            const struct ks_fws_rule *s = &r->rule;
            ks_fws_port_text(s, port, sizeof(port));
            char from[KS_FWS_TEXT_MAX], to[KS_FWS_TEXT_MAX];
            ks_fws_addr_text(s->src, from, sizeof(from));
            ks_fws_addr_text(s->dst, to, sizeof(to));
            gtk_list_store_set(d->store, &it, COL_POS, pos, COL_ENABLED, r->enabled,
                               COL_ACTION, ks_fws_action_text(s->action), COL_DIR,
                               ks_fws_direction_text(s->direction), COL_PORT, port, COL_FROM,
                               from[0] ? from : "Any", COL_TO, to[0] ? to : "Any",
                               COL_IFACE, s->iface[0] ? s->iface : "Any", COL_DESC,
                               s->description, COL_UUID, r->uuid, COL_KIND, r->kind, COL_STYLE,
                               PANGO_STYLE_NORMAL, -1);
        } else {
            gtk_list_store_set(d->store, &it, COL_POS, pos, COL_ENABLED, r->enabled,
                               COL_ACTION, r->kind == KS_FWS_ROW_POLICY ? "Policy" : "Advanced",
                               COL_DIR, r->chain, COL_PORT, "", COL_FROM, "", COL_TO, "",
                               COL_IFACE, "", COL_DESC, r->summary, COL_UUID, r->uuid, COL_KIND,
                               r->kind, COL_STYLE, PANGO_STYLE_ITALIC, -1);
        }
        if (keep_uuid != NULL && strcmp(keep_uuid, r->uuid) == 0) {
            keep = it;
            kept = true;
        }
    }
    ks_fws_rows_free(&rows);
    if (kept)
        gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(d->view)),
                                       &keep);
    update_buttons(d);
}

static void load_policies(struct ks_fws_dlg *d)
{
    d->loading = true;
    struct ks_sysfw *fw = fw_of(d);
    bool din = false, dout = false;
    bool ok_in = fw != NULL && ks_fws_policy(fw, KS_FWS_IN, &din) == 0;
    bool ok_out = fw != NULL && ks_fws_policy(fw, KS_FWS_OUT, &dout) == 0;
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_in), din ? 1 : 0);
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_out), dout ? 1 : 0);
    gtk_widget_set_sensitive(d->combo_in, ok_in);
    gtk_widget_set_sensitive(d->combo_out, ok_out);
    const char *warn = NULL;
    if (fw == NULL)
        warn = "This node has no firewall configuration (it must use nftables).";
    else if (!fw->enabled)
        warn = "The system firewall is disabled: these rules apply once it's enabled in the "
               "Firewall window.";
    else if (!ok_in || !ok_out)
        warn = "The input or output chain is missing from this node's firewall.";
    else if (dout)
        warn = "Warning: Output policy configured to drop. If OpenSnitch dies, outbound "
               "network traffic will be blocked.";
    gtk_label_set_text(GTK_LABEL(d->warning), warn != NULL ? warn : "");
    gtk_widget_set_visible(d->warning, warn != NULL);
    d->loading = false;
}

void ks_fws_dlg_refresh(struct ks_fws_dlg *d)
{
    if (d == NULL || !gtk_widget_get_visible(d->win))
        return;
    char *uuid = NULL;
    int kind;
    selected(d, &uuid, &kind);
    load_policies(d);
    load_rules(d, uuid);
    g_free(uuid);
}

static void load_nodes(struct ks_fws_dlg *d)
{
    d->loading = true;
    struct ks_nodes *nodes = ks_service_nodes(d->svc);
    gtk_list_store_clear(GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(d->nodes))));
    g_ptr_array_set_size(d->node_addrs, 0);
    for (size_t i = 0; i < nodes->len; i++) {
        const char *a = nodes->items[i]->addr;
        char *t = g_strdup_printf("%s - %s", ks_nodes_hostname(nodes, a), a);
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes), t);
        g_free(t);
        g_ptr_array_add(d->node_addrs, g_strdup(a));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes), nodes->len > 0 ? 0 : -1);
    gtk_widget_set_visible(d->nodes, nodes->len > 1);
    d->loading = false;
}

/* ---- sending ------------------------------------------------------------------ */

static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    (void)addr;
    struct ks_fws_dlg *d = ud;
    for (guint i = 0; i < d->sent->len; i++) {
        if (g_array_index(d->sent, uint64_t, i) != r->id)
            continue;
        if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__OK) {
            status(d, "green", "Configuration applied.");
        } else {
            char *m = g_strdup_printf("There was an error: %s", r->data != NULL ? r->data : "");
            status(d, "red", m);
            g_free(m);
        }
        g_array_remove_index(d->sent, i);
        return;
    }
}

/* RELOAD_FW_RULES with the node's edited firewall */
static void apply(struct ks_fws_dlg *d, const char *keep_uuid)
{
    const char *addr = node_addr(d);
    if (addr == NULL)
        return;
    status(d, "darkorange", "Applying changes...");
    uint64_t id = ks_nodes_reload_fw(ks_service_nodes(d->svc), addr, on_reply, d);
    if (id != 0)
        g_array_append_val(d->sent, id);
    load_policies(d);
    load_rules(d, keep_uuid);
    if (d->on_changed != NULL)
        d->on_changed(d->ud);
}

/* ---- policies ------------------------------------------------------------------ */

static void on_policy(GtkComboBox *c, gpointer ud)
{
    struct ks_fws_dlg *d = ud;
    struct ks_sysfw *fw = fw_of(d);
    if (d->loading || fw == NULL)
        return;
    int dir = GTK_WIDGET(c) == d->combo_out ? KS_FWS_OUT : KS_FWS_IN;
    bool drop = gtk_combo_box_get_active(c) == 1;
    const char *err = NULL;
    if (ks_fws_set_policy(fw, dir, drop, &err) < 0) {
        char *m = g_strdup_printf("Policy not applied: %s", err ? err : "");
        status(d, "red", m);
        g_free(m);
        load_policies(d);
        return;
    }
    apply(d, NULL);
}

/* ---- the rule dialog ------------------------------------------------------------ */

struct edit {
    struct ks_fws_dlg *d;
    GtkWidget *dlg, *action, *dir, *app, *proto, *port, *src, *dst, *iface, *desc, *enabled, *err;
};

/* the protocol combo: Any, then ks_fw_port_protocols (tcp+udp shown so) */
static int proto_from_combo(GtkWidget *c)
{
    return gtk_combo_box_get_active(GTK_COMBO_BOX(c)) - 1;
}

static void on_app(GtkComboBox *c, gpointer ud)
{
    struct edit *e = ud;
    int i = gtk_combo_box_get_active(c) - 1;
    if (i < 0 || (size_t)i >= e->d->apps.n)
        return;
    const struct ks_fws_app *a = &e->d->apps.v[i];
    gtk_combo_box_set_active(GTK_COMBO_BOX(e->proto), a->proto + 1);
    gtk_entry_set_text(GTK_ENTRY(e->port), a->ports);
    if (gtk_entry_get_text(GTK_ENTRY(e->desc))[0] == '\0')
        gtk_entry_set_text(GTK_ENTRY(e->desc), a->name);
}

static GtkWidget *entry_row(GtkWidget *table, int row, const char *label, const char *text,
                            const char *tip)
{
    GtkWidget *l = gtk_label_new_with_mnemonic(label);
    gtk_misc_set_alignment(GTK_MISC(l), 0, 0.5);
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e), text);
    gtk_label_set_mnemonic_widget(GTK_LABEL(l), e);
    if (tip != NULL)
        gtk_widget_set_tooltip_text(e, tip);
    gtk_table_attach(GTK_TABLE(table), l, 0, 1, (guint)row, (guint)row + 1, GTK_FILL, GTK_FILL, 0,
                     0);
    gtk_table_attach(GTK_TABLE(table), e, 1, 2, (guint)row, (guint)row + 1, GTK_FILL | GTK_EXPAND,
                     GTK_FILL, 0, 0);
    return e;
}

static GtkWidget *combo_row(GtkWidget *table, int row, const char *label,
                            const char *const *items, size_t n, int active)
{
    GtkWidget *l = gtk_label_new_with_mnemonic(label);
    gtk_misc_set_alignment(GTK_MISC(l), 0, 0.5);
    GtkWidget *c = gtk_combo_box_new_text();
    for (size_t i = 0; i < n; i++)
        gtk_combo_box_append_text(GTK_COMBO_BOX(c), items[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), active);
    gtk_label_set_mnemonic_widget(GTK_LABEL(l), c);
    gtk_table_attach(GTK_TABLE(table), l, 0, 1, (guint)row, (guint)row + 1, GTK_FILL, GTK_FILL, 0,
                     0);
    gtk_table_attach(GTK_TABLE(table), c, 1, 2, (guint)row, (guint)row + 1, GTK_FILL | GTK_EXPAND,
                     GTK_FILL, 0, 0);
    return c;
}

/* Adds or edits a simple rule. Returns true if it was saved. */
static bool edit_rule(struct ks_fws_dlg *d, struct ks_fws_rule *r)
{
    struct edit e = {.d = d};
    bool is_new = r->uuid[0] == '\0';
    e.dlg = gtk_dialog_new_with_buttons(is_new ? "New rule" : "Edit rule", GTK_WINDOW(d->win),
                                        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE,
                                        GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(e.dlg), GTK_RESPONSE_OK);
    GtkWidget *t = gtk_table_new(11, 2, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(t), 10);
    gtk_table_set_row_spacings(GTK_TABLE(t), 6);
    gtk_table_set_col_spacings(GTK_TABLE(t), 10);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(e.dlg)->vbox), t, TRUE, TRUE, 0);

    static const char *const actions[] = {"Allow", "Deny", "Reject"};
    static const char *const dirs[] = {"In (incoming)", "Out (outgoing)"};
    static const char *const protos[] = {"Any", "TCP and UDP", "TCP",  "UDP",
                                         "UDP-Lite", "SCTP",   "DCCP"};
    e.action = combo_row(t, 0, "_Action", actions, 3, r->action);
    e.dir = combo_row(t, 1, "_Direction", dirs, 2, r->direction);
    /* the ufw application profiles, as shortcuts that fill the port */
    const char **apps = g_new0(const char *, d->apps.n + 1);
    apps[0] = "—";
    for (size_t i = 0; i < d->apps.n; i++)
        apps[i + 1] = d->apps.v[i].name;
    e.app = combo_row(t, 2, "A_pplication", apps, d->apps.n + 1, 0);
    g_free(apps);
    gtk_widget_set_sensitive(e.app, d->apps.n > 0);
    gtk_widget_set_tooltip_text(e.app, d->apps.n > 0
                                           ? "ufw application profiles (/etc/ufw/applications.d)"
                                           : "No ufw application profiles installed");
    e.proto = combo_row(t, 3, "P_rotocol", protos, 7, r->proto + 1);
    e.port = entry_row(t, 4, "P_ort", r->port, "A port (22), a list (80,443) or a range "
                                                "(6000-6007). Empty: any port");
    char src[KS_FWS_TEXT_MAX], dst[KS_FWS_TEXT_MAX];
    ks_fws_addr_text(r->src, src, sizeof(src));
    ks_fws_addr_text(r->dst, dst, sizeof(dst));
    e.src = entry_row(t, 5, "_From", src,
                      "Source address, network (192.168.1.0/24) or range. Empty: any. An IPv4 "
                      "address matches IPv4 only: add another rule for IPv6");
    e.dst = entry_row(t, 6, "_To", dst, "Destination address, network or range. Empty: any");
    e.iface = entry_row(t, 7, "_Interface", r->iface,
                        "Network interface (in: where it arrives, out: where it leaves). "
                        "Empty: any");
    /* the interfaces of this machine, as completion */
    GtkListStore *ifs = gtk_list_store_new(1, G_TYPE_STRING);
    struct if_nameindex *ni = if_nameindex();
    for (struct if_nameindex *p = ni; p != NULL && p->if_index != 0; p++) {
        GtkTreeIter it;
        gtk_list_store_append(ifs, &it);
        gtk_list_store_set(ifs, &it, 0, p->if_name, -1);
    }
    if (ni != NULL)
        if_freenameindex(ni);
    GtkEntryCompletion *comp = gtk_entry_completion_new();
    gtk_entry_completion_set_model(comp, GTK_TREE_MODEL(ifs));
    gtk_entry_completion_set_text_column(comp, 0);
    gtk_entry_completion_set_minimum_key_length(comp, 0);
    gtk_entry_set_completion(GTK_ENTRY(e.iface), comp);
    g_object_unref(comp);
    g_object_unref(ifs);
    e.desc = entry_row(t, 8, "D_escription", r->description, NULL);
    e.enabled = gtk_check_button_new_with_mnemonic("E_nabled");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(e.enabled), r->enabled);
    gtk_table_attach(GTK_TABLE(t), e.enabled, 1, 2, 9, 10, GTK_FILL, GTK_FILL, 0, 0);
    e.err = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(e.err), TRUE);
    gtk_table_attach(GTK_TABLE(t), e.err, 0, 2, 10, 11, GTK_FILL, GTK_FILL, 0, 0);
    g_signal_connect(e.app, "changed", G_CALLBACK(on_app), &e);
    gtk_widget_show_all(e.dlg);

    bool saved = false;
    while (gtk_dialog_run(GTK_DIALOG(e.dlg)) == GTK_RESPONSE_OK) {
        struct ks_fws_rule n = *r;
        n.action = gtk_combo_box_get_active(GTK_COMBO_BOX(e.action));
        n.direction = gtk_combo_box_get_active(GTK_COMBO_BOX(e.dir));
        n.proto = proto_from_combo(e.proto);
        n.enabled = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(e.enabled));
        snprintf(n.port, sizeof(n.port), "%s", gtk_entry_get_text(GTK_ENTRY(e.port)));
        snprintf(n.src, sizeof(n.src), "%s", gtk_entry_get_text(GTK_ENTRY(e.src)));
        snprintf(n.dst, sizeof(n.dst), "%s", gtk_entry_get_text(GTK_ENTRY(e.dst)));
        snprintf(n.iface, sizeof(n.iface), "%s", gtk_entry_get_text(GTK_ENTRY(e.iface)));
        snprintf(n.description, sizeof(n.description), "%s",
                 gtk_entry_get_text(GTK_ENTRY(e.desc)));
        g_strstrip(n.port);
        g_strstrip(n.src);
        g_strstrip(n.dst);
        g_strstrip(n.iface);
        char err[512];
        struct ks_sysfw *fw = fw_of(d);
        if (fw == NULL) {
            snprintf(err, sizeof(err), "This node has no firewall configuration.");
        } else if (ks_fws_save(fw, &n, err, sizeof(err)) == 0) {
            *r = n;
            saved = true;
            break;
        }
        char *m = g_markup_printf_escaped("<span foreground=\"red\">%s</span>", err);
        gtk_label_set_markup(GTK_LABEL(e.err), m);
        g_free(m);
    }
    gtk_widget_destroy(e.dlg);
    return saved;
}

/* ---- buttons ---------------------------------------------------------------------- */

static void on_add(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fws_dlg *d = ud;
    struct ks_fws_rule r;
    ks_fws_rule_init(&r);
    if (edit_rule(d, &r))
        apply(d, NULL);
}

static void edit_selected(struct ks_fws_dlg *d)
{
    char *uuid = NULL;
    int kind;
    struct ks_sysfw *fw = fw_of(d);
    if (fw == NULL || !selected(d, &uuid, &kind))
        return;
    if (kind != KS_FWS_ROW_SIMPLE) {
        /* advanced and policy rules: the full dialog */
        ks_fwrule_dlg_load(d->rule_dlg, node_addr(d), uuid);
        g_free(uuid);
        return;
    }
    struct ks_fw_chain flat;
    struct ks_fws_rule r;
    if (ks_fwr_flat_by_uuid(fw, uuid, &flat) == 0) {
        bool simple = ks_fws_from_flat(&flat, &r);
        ks_fwr_free_chain(&flat);
        if (simple) {
            snprintf(r.uuid, sizeof(r.uuid), "%s", uuid);
            if (edit_rule(d, &r))
                apply(d, uuid);
        }
    }
    g_free(uuid);
}

static void on_edit(GtkButton *b, gpointer ud)
{
    (void)b;
    edit_selected(ud);
}

static void on_row_activated(GtkTreeView *v, GtkTreePath *p, GtkTreeViewColumn *c, gpointer ud)
{
    (void)v;
    (void)p;
    (void)c;
    edit_selected(ud);
}

static void on_advanced(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fws_dlg *d = ud;
    char *uuid = NULL;
    int kind;
    if (selected(d, &uuid, &kind))
        ks_fwrule_dlg_load(d->rule_dlg, node_addr(d), uuid);
    g_free(uuid);
}

static void on_delete(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fws_dlg *d = ud;
    char *uuid = NULL;
    int kind;
    struct ks_sysfw *fw = fw_of(d);
    if (fw == NULL || !selected(d, &uuid, &kind))
        return;
    GtkWidget *q = gtk_message_dialog_new(GTK_WINDOW(d->win), GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
                                          "Delete this rule?");
    bool yes = gtk_dialog_run(GTK_DIALOG(q)) == GTK_RESPONSE_YES;
    gtk_widget_destroy(q);
    if (yes && ks_fwr_delete(fw, uuid) == 0)
        apply(d, NULL);
    g_free(uuid);
}

static void move(struct ks_fws_dlg *d, int delta)
{
    char *uuid = NULL;
    int kind;
    struct ks_sysfw *fw = fw_of(d);
    if (fw != NULL && selected(d, &uuid, &kind) && ks_fws_move(fw, uuid, delta))
        apply(d, uuid);
    g_free(uuid);
}

static void on_up(GtkButton *b, gpointer ud)
{
    (void)b;
    move(ud, -1);
}

static void on_down(GtkButton *b, gpointer ud)
{
    (void)b;
    move(ud, +1);
}

static void on_enabled_toggled(GtkCellRendererToggle *cell, gchar *path, gpointer ud)
{
    (void)cell;
    struct ks_fws_dlg *d = ud;
    struct ks_sysfw *fw = fw_of(d);
    GtkTreeIter it;
    if (fw == NULL || !gtk_tree_model_get_iter_from_string(GTK_TREE_MODEL(d->store), &it, path))
        return;
    char *uuid = NULL;
    gboolean on = FALSE;
    gtk_tree_model_get(GTK_TREE_MODEL(d->store), &it, COL_UUID, &uuid, COL_ENABLED, &on, -1);
    if (ks_fwr_enable(fw, uuid, !on) == 0)
        apply(d, uuid);
    g_free(uuid);
}

static void on_selection(GtkTreeSelection *s, gpointer ud)
{
    (void)s;
    update_buttons(ud);
}

static void on_node(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fws_dlg *d = ud;
    if (d->loading)
        return;
    load_policies(d);
    load_rules(d, NULL);
}

static void on_close(GtkButton *b, gpointer ud)
{
    (void)b;
    gtk_widget_hide(((struct ks_fws_dlg *)ud)->win);
}

/* ---- building ------------------------------------------------------------------- */

static GtkWidget *button(const char *label, const char *stock)
{
    GtkWidget *b = gtk_button_new_with_mnemonic(label);
    gtk_button_set_image(GTK_BUTTON(b), gtk_image_new_from_stock(stock, GTK_ICON_SIZE_BUTTON));
    return b;
}

static GtkWidget *policy_combo(void)
{
    GtkWidget *c = gtk_combo_box_new_text();
    gtk_combo_box_append_text(GTK_COMBO_BOX(c), "Allow");
    gtk_combo_box_append_text(GTK_COMBO_BOX(c), "Deny");
    return c;
}

static void text_column(struct ks_fws_dlg *d, const char *title, int col, bool expand)
{
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(title, r, "text", col,
                                                                    "style", COL_STYLE, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_column_set_expand(c, expand);
    gtk_tree_view_append_column(GTK_TREE_VIEW(d->view), c);
}

struct ks_fws_dlg *ks_fws_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                  struct ks_fwrule_dlg *rule_dlg, void (*on_changed)(void *),
                                  void *ud)
{
    struct ks_fws_dlg *d = g_new0(struct ks_fws_dlg, 1);
    d->svc = svc;
    d->rule_dlg = rule_dlg;
    d->on_changed = on_changed;
    d->ud = ud;
    d->node_addrs = g_ptr_array_new_with_free_func(g_free);
    d->sent = g_array_new(FALSE, TRUE, sizeof(uint64_t));
    ks_fws_apps_load(&d->apps, NULL);

    d->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(d->win), "Firewall rules");
    gtk_window_set_default_size(GTK_WINDOW(d->win), 820, 440);
    if (parent != NULL)
        gtk_window_set_transient_for(GTK_WINDOW(d->win), parent);
    g_signal_connect(d->win, "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), NULL);
    GtkWidget *v = gtk_vbox_new(FALSE, 8);
    gtk_container_set_border_width(GTK_CONTAINER(v), 10);
    gtk_container_add(GTK_CONTAINER(d->win), v);

    d->nodes = gtk_combo_box_new_text();
    gtk_box_pack_start(GTK_BOX(v), d->nodes, FALSE, FALSE, 0);
    d->warning = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(d->warning), TRUE);
    gtk_misc_set_alignment(GTK_MISC(d->warning), 0, 0.5);
    gtk_box_pack_start(GTK_BOX(v), d->warning, FALSE, FALSE, 0);

    /* the default policies */
    GtkWidget *h = gtk_hbox_new(FALSE, 8);
    d->combo_in = policy_combo();
    d->combo_out = policy_combo();
    gtk_box_pack_start(GTK_BOX(h), gtk_label_new("Incoming:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->combo_in, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), gtk_label_new("   Outgoing:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), d->combo_out, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(d->combo_in, "What happens to incoming connections that no "
                                             "rule allows. Deny keeps loopback and replies to "
                                             "your own connections working.");
    gtk_widget_set_tooltip_text(d->combo_out, "What happens to outgoing connections that no "
                                              "rule allows (before OpenSnitch asks).");
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    /* the rules */
    d->store = gtk_list_store_new(NCOLS, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_STRING,
                                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT,
                                  G_TYPE_INT);
    d->view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(d->store));
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(d->view), TRUE);
    text_column(d, "#", COL_POS, false);
    GtkCellRenderer *tog = gtk_cell_renderer_toggle_new();
    g_signal_connect(tog, "toggled", G_CALLBACK(on_enabled_toggled), d);
    gtk_tree_view_append_column(GTK_TREE_VIEW(d->view),
                                gtk_tree_view_column_new_with_attributes("On", tog, "active",
                                                                         COL_ENABLED, NULL));
    text_column(d, "Action", COL_ACTION, false);
    text_column(d, "Direction", COL_DIR, false);
    text_column(d, "Port", COL_PORT, false);
    text_column(d, "From", COL_FROM, false);
    text_column(d, "To", COL_TO, false);
    text_column(d, "Interface", COL_IFACE, false);
    text_column(d, "Description", COL_DESC, true);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), GTK_SHADOW_IN);
    gtk_container_add(GTK_CONTAINER(sw), d->view);
    gtk_box_pack_start(GTK_BOX(v), sw, TRUE, TRUE, 0);

    h = gtk_hbox_new(FALSE, 6);
    d->b_add = button("_Add", GTK_STOCK_ADD);
    d->b_edit = button("_Edit", GTK_STOCK_EDIT);
    d->b_del = button("_Delete", GTK_STOCK_DELETE);
    d->b_up = button("_Up", GTK_STOCK_GO_UP);
    d->b_down = button("Do_wn", GTK_STOCK_GO_DOWN);
    d->b_adv = button("Advanced _editor", GTK_STOCK_PROPERTIES);
    gtk_widget_set_tooltip_text(d->b_up, "Rules are checked in order: the first one that "
                                         "matches decides");
    gtk_widget_set_tooltip_text(d->b_adv, "Open the rule in the full firewall rule editor");
    GtkWidget *ws[] = {d->b_add, d->b_edit, d->b_del, d->b_up, d->b_down};
    for (size_t i = 0; i < sizeof(ws) / sizeof(ws[0]); i++)
        gtk_box_pack_start(GTK_BOX(h), ws[i], FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), d->b_adv, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    d->status = gtk_label_new("");
    gtk_misc_set_alignment(GTK_MISC(d->status), 0, 0.5);
    gtk_label_set_line_wrap(GTK_LABEL(d->status), TRUE);
    gtk_box_pack_start(GTK_BOX(v), d->status, FALSE, FALSE, 0);
    h = gtk_hbox_new(FALSE, 6);
    GtkWidget *close = button("_Close", GTK_STOCK_CLOSE);
    gtk_box_pack_end(GTK_BOX(h), close, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    g_signal_connect(d->nodes, "changed", G_CALLBACK(on_node), d);
    g_signal_connect(d->combo_in, "changed", G_CALLBACK(on_policy), d);
    g_signal_connect(d->combo_out, "changed", G_CALLBACK(on_policy), d);
    g_signal_connect(d->b_add, "clicked", G_CALLBACK(on_add), d);
    g_signal_connect(d->b_edit, "clicked", G_CALLBACK(on_edit), d);
    g_signal_connect(d->b_del, "clicked", G_CALLBACK(on_delete), d);
    g_signal_connect(d->b_up, "clicked", G_CALLBACK(on_up), d);
    g_signal_connect(d->b_down, "clicked", G_CALLBACK(on_down), d);
    g_signal_connect(d->b_adv, "clicked", G_CALLBACK(on_advanced), d);
    g_signal_connect(d->view, "row-activated", G_CALLBACK(on_row_activated), d);
    g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(d->view)), "changed",
                     G_CALLBACK(on_selection), d);
    g_signal_connect(close, "clicked", G_CALLBACK(on_close), d);
    gtk_widget_show_all(v);
    return d;
}

void ks_fws_dlg_free(struct ks_fws_dlg *d)
{
    if (d == NULL)
        return;
    gtk_widget_destroy(d->win);
    g_object_unref(d->store);
    g_ptr_array_free(d->node_addrs, TRUE);
    g_array_free(d->sent, TRUE);
    ks_fws_apps_free(&d->apps);
    g_free(d);
}

void ks_fws_dlg_show(struct ks_fws_dlg *d)
{
    status(d, NULL, NULL);
    gtk_widget_show(d->win);
    gtk_window_present(GTK_WINDOW(d->win));
    load_nodes(d);
    load_policies(d);
    load_rules(d, NULL);
}

GtkWidget *ks_fws_dlg_window(struct ks_fws_dlg *d)
{
    return d->win;
}
