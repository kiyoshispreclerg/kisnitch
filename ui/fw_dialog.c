/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/dialogs/firewall.py and res/firewall.ui.
 * See fw_dialog.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/fw_dialog.h"

#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "common/log.h"
#include "ui/fwrules.h"
#include "ui/nodes.h"

#define HELP_SYSFW_URL "https://github.com/evilsocket/opensnitch/wiki/System-rules"
#define HELP_SYS_RULES_URL \
    "https://github.com/evilsocket/opensnitch/wiki/System-rules#upgrading-from-previous-versions"
#define ALL_NODES "all"

enum { COMBO_IN, COMBO_OUT };
enum { POLICY_ACCEPT, POLICY_DROP };

struct ks_fw_dlg {
    struct ks_service *svc;
    void (*on_changed)(void *);
    void *ud;
    GtkWidget *win, *enable, *status_icon, *fw_status, *policies, *nodes, *combo_in, *combo_out;
    GtkWidget *profile, *lbl_profile, *b_in, *b_out, *b_new, *status;
    GPtrArray *node_addrs;
    GArray *sent; /* uint64_t ids */
    struct ks_fwrule_dlg *rule_dlg;
    bool loading;
    guint second_send; /* enable_fw()'s second notification */
    char second_addr[KS_NODE_ADDR_MAX];
    bool second_enable;
};

/* ---- helpers --------------------------------------------------------------- */

static void status(struct ks_fw_dlg *d, const char *color, const char *msg)
{
    if (msg == NULL) {
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

static int active(GtkWidget *c)
{
    return gtk_combo_box_get_active(GTK_COMBO_BOX(c));
}

static const char *selected_node(struct ks_fw_dlg *d)
{
    int i = active(d->nodes);
    return i >= 0 && (guint)i < d->node_addrs->len ? g_ptr_array_index(d->node_addrs, (guint)i)
                                                    : NULL;
}

static struct ks_nodes *nodes_of(struct ks_fw_dlg *d)
{
    return ks_service_nodes(d->svc);
}

/* _disable_widgets */
static void disable_widgets(struct ks_fw_dlg *d, bool disable)
{
    GtkWidget *ws[] = {d->combo_in, d->combo_out, d->b_new, d->b_out, d->b_in, d->nodes};
    for (size_t i = 0; i < sizeof(ws) / sizeof(ws[0]); i++)
        gtk_widget_set_sensitive(ws[i], !disable);
}

static void block(struct ks_fw_dlg *d, bool b)
{
    d->loading = b;
}

static void changed(struct ks_fw_dlg *d)
{
    if (d->on_changed != NULL)
        d->on_changed(d->ud);
}

/* ---- notifications ----------------------------------------------------------- */

static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    struct ks_fw_dlg *d = ud;
    (void)addr;
    gtk_widget_set_sensitive(d->combo_in, TRUE);
    gtk_widget_set_sensitive(d->combo_out, TRUE);
    for (guint i = 0; i < d->sent->len; i++) {
        if (g_array_index(d->sent, uint64_t, i) != r->id)
            continue;
        if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__OK) {
            set_status_successful(d, "Configuration applied.");
        } else {
            char *m = g_strdup_printf("There was an error: %s", r->data != NULL ? r->data : "");
            set_status_error(d, m);
            g_free(m);
        }
        g_array_remove_index(d->sent, i);
        return;
    }
    ks_debug("[fw dialog] unknown notification: %llu", (unsigned long long)r->id);
}

/* send_notification: to the selected node, or to all of them ("All"). */
static void send_notification(struct ks_fw_dlg *d)
{
    set_status_message(d, "Applying changes...");
    struct ks_nodes *nodes = nodes_of(d);
    const char *addr = selected_node(d);
    if (addr != NULL && strcmp(addr, ALL_NODES) == 0 && nodes->len > 1) {
        for (size_t i = 0; i < nodes->len; i++) {
            uint64_t id = ks_nodes_reload_fw(nodes, nodes->items[i]->addr, on_reply, d);
            g_array_append_val(d->sent, id);
        }
    } else if (addr != NULL) {
        uint64_t id = ks_nodes_reload_fw(nodes, addr, on_reply, d);
        g_array_append_val(d->sent, id);
    }
    changed(d);
}

/* ---- policies ------------------------------------------------------------------ */

static void apply_profile_all(struct ks_fw_dlg *d, enum ks_fw_profile p, bool notify)
{
    struct ks_nodes *nodes = nodes_of(d);
    struct ks_fw_chain prof;
    if (ks_fwr_profile(p, &prof) < 0)
        return;
    for (size_t i = 0; i < nodes->len; i++) {
        const char *err = NULL;
        if (ks_fwr_apply_profile(nodes->items[i]->fw, &prof, &err) == 0) {
            if (notify)
                send_notification(d);
        } else {
            char *m = g_strdup_printf("Policy not applied: %s", err);
            set_status_error(d, m);
            g_free(m);
        }
    }
    ks_fwr_free_chain(&prof);
}

static void delete_profile_all(struct ks_fw_dlg *d, enum ks_fw_profile p)
{
    struct ks_fw_chain prof;
    if (ks_fwr_profile(p, &prof) < 0)
        return;
    struct ks_nodes *nodes = nodes_of(d);
    for (size_t i = 0; i < nodes->len; i++)
        ks_fwr_delete_profile(nodes->items[i]->fw, &prof);
    ks_fwr_free_chain(&prof);
}

/* _cb_combo_policy_changed */
static void policy_changed(struct ks_fw_dlg *d, int combo)
{
    status(d, NULL, NULL);
    gtk_widget_set_sensitive(d->combo_in, FALSE);
    gtk_widget_set_sensitive(d->combo_out, FALSE);
    enum ks_fw_profile wanted = KS_FW_PROFILE_ACCEPT_INPUT;
    if (combo == COMBO_OUT)
        wanted = active(d->combo_out) == POLICY_DROP ? KS_FW_PROFILE_DROP_OUTPUT
                                                    : KS_FW_PROFILE_ACCEPT_OUTPUT;
    else if (active(d->combo_in) == POLICY_DROP)
        wanted = KS_FW_PROFILE_DROP_INPUT;

    if (combo == COMBO_IN && active(d->combo_in) == POLICY_ACCEPT) {
        delete_profile_all(d, KS_FW_PROFILE_DROP_INPUT);
    } else if (combo == COMBO_OUT && active(d->combo_out) == POLICY_ACCEPT) {
        set_status_message(d, "Warning: Output policy configured to drop. If OpenSnitch dies, "
                              "outbound network traffic will be blocked.");
        delete_profile_all(d, KS_FW_PROFILE_DROP_OUTPUT);
    }
    apply_profile_all(d, wanted, true);
}

static void on_in_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fw_dlg *d = ud;
    if (!d->loading)
        policy_changed(d, COMBO_IN);
}

static void on_out_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fw_dlg *d = ud;
    if (!d->loading)
        policy_changed(d, COMBO_OUT);
}

/* load_node_fw_policy */
static bool fw_is_incompatible(struct ks_fw_dlg *d, const char *addr, struct ks_node *node);

static bool load_node_fw_policy(struct ks_fw_dlg *d, const char *addr)
{
    struct ks_node *node = ks_nodes_get(nodes_of(d), addr);
    if (node == NULL || node->fw == NULL) {
        set_status_error(d, "Firewall status error (report on github please): no firewall "
                            "configuration");
        return false;
    }
    bool enable = node->fw->enabled;
    if (fw_is_incompatible(d, addr, node))
        return false;
    const char *pin = ks_fwr_get_policy(node->fw, "input", "filter", "inet");
    const char *pout = ks_fwr_get_policy(node->fw, "output", "mangle", "inet");
    if (pin != NULL) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_in),
                                 strcmp(pin, "drop") == 0 ? POLICY_DROP : POLICY_ACCEPT);
    } else {
        set_status_error(d, "Error getting INPUT chain policy");
        disable_widgets(d, true);
    }
    if (pout != NULL) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_out),
                                 strcmp(pout, "drop") == 0 ? POLICY_DROP : POLICY_ACCEPT);
    } else {
        set_status_error(d, "Error getting OUTPUT chain policy");
        disable_widgets(d, true);
    }
    return enable;
}

/* load_fw_policies */
static void load_fw_policies(struct ks_fw_dlg *d)
{
    gtk_label_set_text(GTK_LABEL(d->fw_status), "");
    block(d, true);
    disable_widgets(d, true);
    bool enable = false;
    struct ks_nodes *nodes = nodes_of(d);
    gtk_widget_set_sensitive(d->enable, nodes->len > 0);
    if (nodes->len > 0) {
        enable = nodes->len > 1;
        if (nodes->len == 1) {
            const char *addr = selected_node(d);
            enable = addr != NULL && load_node_fw_policy(d, addr);
        }
    }
    disable_widgets(d, !enable);
    gtk_widget_set_sensitive(d->status_icon, enable);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(d->enable), enable);
    block(d, false);
}

/* change_fw: asks to use nftables instead of iptables */
static bool change_fw(struct ks_fw_dlg *d, const char *addr)
{
    GtkWidget *w = gtk_message_dialog_new(
        GTK_WINDOW(d->win), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK_CANCEL,
        "In order to configure firewall rules from the GUI, we need to use 'nftables' "
        "instead of 'iptables'");
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(w), "Change default firewall to 'nftables' on node %s?", addr);
    int r = gtk_dialog_run(GTK_DIALOG(w));
    gtk_widget_destroy(w);
    return r != GTK_RESPONSE_CANCEL && r != GTK_RESPONSE_DELETE_EVENT;
}

static void enable_fw(struct ks_fw_dlg *d, const char *addr, bool enable);

/* _change_fw_backend: CHANGE_CONFIG with "Firewall": "nftables" */
static void change_fw_backend(struct ks_fw_dlg *d, struct ks_node *node, cJSON *cfg)
{
    cJSON_ReplaceItemInObject(cfg, "Firewall", cJSON_CreateString("nftables"));
    char *json = cJSON_PrintUnformatted(cfg);
    if (json == NULL)
        return;
    free(node->config->config);
    node->config->config = json;
    Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
    ntf.clientname = (char *)(uintptr_t) "";
    ntf.servername = (char *)(uintptr_t) "";
    ntf.type = PROTOCOL__ACTION__CHANGE_CONFIG;
    ntf.data = json;
    uint64_t id = ks_nodes_send(nodes_of(d), node->addr, &ntf, on_reply, d);
    g_array_append_val(d->sent, id);
}

static bool fw_is_incompatible(struct ks_fw_dlg *d, const char *addr, struct ks_node *node)
{
    bool incompatible = false;
    cJSON *cfg = node->config != NULL && node->config->config != NULL
                     ? cJSON_Parse(node->config->config)
                     : NULL;
    const cJSON *fwt = cfg != NULL ? cJSON_GetObjectItemCaseSensitive(cfg, "Firewall") : NULL;
    if (cJSON_IsString(fwt) && strcmp(fwt->valuestring, "iptables") == 0) {
        /* iptables isn't supported from the GUI */
        disable_widgets(d, true);
        gtk_widget_set_sensitive(d->enable, FALSE);
        if (gtk_widget_get_visible(d->win) && change_fw(d, addr)) {
            gtk_widget_set_sensitive(d->enable, TRUE);
            enable_fw(d, addr, true);
            change_fw_backend(d, node, cfg);
            cJSON_Delete(cfg);
            return false;
        }
        incompatible = true;
    }
    cJSON_Delete(cfg);
    if (node->config != NULL && node->config->systemfirewall != NULL &&
        node->config->systemfirewall->version == 0) {
        disable_widgets(d, true);
        gtk_widget_set_sensitive(d->enable, FALSE);
        char *m = g_markup_printf_escaped(
            "The firewall configuration is outdated,\nyou need to update it to the new format: "
            "<a href=\"%s\">learn more</a>",
            HELP_SYS_RULES_URL);
        gtk_label_set_markup(GTK_LABEL(d->fw_status), m);
        g_free(m);
        incompatible = true;
    }
    return incompatible;
}

static gboolean second_send(gpointer ud)
{
    struct ks_fw_dlg *d = ud;
    d->second_send = 0;
    struct ks_node *node = ks_nodes_get(nodes_of(d), d->second_addr);
    if (node != NULL && node->fw != NULL) {
        node->fw->enabled = d->second_enable;
        send_notification(d);
    }
    return FALSE;
}

/* enable_fw */
static void enable_fw(struct ks_fw_dlg *d, const char *addr, bool enable)
{
    disable_widgets(d, !enable);
    set_status_message(d, enable ? "Enabling firewall..." : "Disabling firewall...");
    /* disabling with a drop policy: the policy goes back to accept first */
    if (!enable && active(d->combo_in) == POLICY_DROP) {
        block(d, true);
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_in), POLICY_ACCEPT);
        block(d, false);
        apply_profile_all(d, KS_FW_PROFILE_ACCEPT_INPUT, false);
    }
    if (!enable && active(d->combo_out) == POLICY_DROP) {
        block(d, true);
        gtk_combo_box_set_active(GTK_COMBO_BOX(d->combo_out), POLICY_ACCEPT);
        block(d, false);
        apply_profile_all(d, KS_FW_PROFILE_ACCEPT_OUTPUT, false);
    }
    /* Upstream sends two changes half a second apart: one for the policy,
     * another one for enabling/disabling (the daemon ignores the policy of
     * a disabled firewall). */
    send_notification(d);
    snprintf(d->second_addr, sizeof(d->second_addr), "%s", addr != NULL ? addr : "");
    if (addr != NULL && strcmp(addr, ALL_NODES) == 0 && nodes_of(d)->len > 0)
        snprintf(d->second_addr, sizeof(d->second_addr), "%s", nodes_of(d)->items[0]->addr);
    d->second_enable = enable;
    if (d->second_send != 0)
        g_source_remove(d->second_send);
    d->second_send = g_timeout_add(500, second_send, d);
    gtk_widget_set_sensitive(d->status_icon, enable);
    gtk_widget_set_sensitive(d->policies, enable);
}

static void on_enable_toggled(GtkToggleButton *b, gpointer ud)
{
    struct ks_fw_dlg *d = ud;
    if (d->loading)
        return;
    if (nodes_of(d)->len == 0) {
        block(d, true);
        gtk_toggle_button_set_active(b, FALSE);
        block(d, false);
        return;
    }
    enable_fw(d, selected_node(d), gtk_toggle_button_get_active(b));
}

static void on_nodes_changed(GtkComboBox *c, gpointer ud)
{
    (void)c;
    struct ks_fw_dlg *d = ud;
    if (d->loading || active(d->nodes) < 1)
        return;
    block(d, true);
    load_node_fw_policy(d, selected_node(d));
    block(d, false);
}

static void on_new_rule(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fw_dlg *d = ud;
    ks_fwrule_dlg_new_rule(d->rule_dlg);
}

static void on_allow_in(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fw_dlg *d = ud;
    ks_fwrule_dlg_exclude_service(d->rule_dlg, KS_FWF_IN);
}

static void on_allow_out(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fw_dlg *d = ud;
    ks_fwrule_dlg_exclude_service(d->rule_dlg, KS_FWF_OUT);
}

static void on_help(GtkButton *b, gpointer ud)
{
    (void)b;
    (void)ud;
    GError *err = NULL;
    if (!gtk_show_uri(NULL, HELP_SYSFW_URL, GDK_CURRENT_TIME, &err)) {
        ks_warning("can't open %s: %s", HELP_SYSFW_URL, err ? err->message : "");
        g_clear_error(&err);
    }
}

static void on_close(GtkButton *b, gpointer ud)
{
    (void)b;
    struct ks_fw_dlg *d = ud;
    gtk_widget_hide(d->win);
}

/* ---- building ---------------------------------------------------------------- */

static GtkWidget *combo_allow_deny(void)
{
    GtkWidget *c = gtk_combo_box_new_text();
    gtk_combo_box_append_text(GTK_COMBO_BOX(c), "Allow");
    gtk_combo_box_append_text(GTK_COMBO_BOX(c), "Deny");
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), 0);
    return c;
}

static GtkWidget *stock_button(const char *label, const char *stock)
{
    GtkWidget *b = gtk_button_new_with_mnemonic(label);
    gtk_button_set_image(GTK_BUTTON(b), gtk_image_new_from_stock(stock, GTK_ICON_SIZE_BUTTON));
    return b;
}

static void on_rules_changed(void *ud)
{
    changed(ud);
}

struct ks_fw_dlg *ks_fw_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                void (*on_changed)(void *), void *ud)
{
    struct ks_fw_dlg *d = g_new0(struct ks_fw_dlg, 1);
    d->svc = svc;
    d->on_changed = on_changed;
    d->ud = ud;
    d->node_addrs = g_ptr_array_new_with_free_func(g_free);
    d->sent = g_array_new(FALSE, TRUE, sizeof(uint64_t));
    d->rule_dlg = ks_fwrule_dlg_new(svc, parent, on_rules_changed, d);

    d->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(d->win), "Firewall");
    if (parent != NULL)
        gtk_window_set_transient_for(GTK_WINDOW(d->win), parent);
    g_signal_connect(d->win, "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), NULL);
    GtkWidget *v = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width(GTK_CONTAINER(v), 10);
    gtk_container_add(GTK_CONTAINER(d->win), v);

    /* label_2, sliderFwEnable, lblStatusIcon */
    GtkWidget *h = gtk_hbox_new(FALSE, 8);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size=\"x-large\" weight=\"bold\">Firewall</span>");
    d->enable = gtk_check_button_new_with_mnemonic("_Enable");
    d->status_icon = gtk_image_new_from_icon_name("security-high", GTK_ICON_SIZE_DIALOG);
    gtk_box_pack_start(GTK_BOX(h), d->status_icon, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), title, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), d->enable, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), gtk_hseparator_new(), FALSE, FALSE, 0);
    d->fw_status = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(d->fw_status), TRUE);
    gtk_box_pack_start(GTK_BOX(v), d->fw_status, FALSE, FALSE, 0);

    /* policiesBox */
    d->policies = gtk_frame_new(NULL);
    GtkWidget *t = gtk_table_new(5, 3, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(t), 8);
    gtk_table_set_row_spacings(GTK_TABLE(t), 6);
    gtk_table_set_col_spacings(GTK_TABLE(t), 8);
    gtk_container_add(GTK_CONTAINER(d->policies), t);
    d->nodes = gtk_combo_box_new_text();
    gtk_table_attach(GTK_TABLE(t), d->nodes, 0, 3, 0, 1, GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);
    d->lbl_profile = gtk_label_new("Profile");
    d->profile = gtk_combo_box_new_text();
    gtk_table_attach(GTK_TABLE(t), d->lbl_profile, 0, 1, 1, 2, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(t), d->profile, 1, 3, 1, 2, GTK_FILL, GTK_FILL, 0, 0);
    d->combo_in = combo_allow_deny();
    d->combo_out = combo_allow_deny();
    gtk_table_attach(GTK_TABLE(t), gtk_label_new("Inbound"), 0, 1, 2, 3, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(t), d->combo_in, 1, 2, 2, 3, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(t), gtk_label_new("Outbound"), 0, 1, 3, 4, GTK_FILL, GTK_FILL, 0,
                     0);
    gtk_table_attach(GTK_TABLE(t), d->combo_out, 1, 2, 3, 4, GTK_FILL, GTK_FILL, 0, 0);
    d->b_in = stock_button("Allow service (_IN)", GTK_STOCK_GO_DOWN);
    d->b_out = stock_button("Allow service (_OUT)", GTK_STOCK_GO_UP);
    d->b_new = stock_button("_New rule", GTK_STOCK_NEW);
    gtk_widget_set_tooltip_text(d->b_in, "Allow inbound connections to a port");
    gtk_widget_set_tooltip_text(d->b_out,
                                "Exclude outbound connections to a port from being intercepted");
    gtk_table_attach(GTK_TABLE(t), d->b_in, 2, 3, 2, 3, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(t), d->b_out, 2, 3, 3, 4, GTK_FILL, GTK_FILL, 0, 0);
    gtk_table_attach(GTK_TABLE(t), gtk_hseparator_new(), 0, 3, 4, 5, GTK_FILL, GTK_FILL, 0, 0);
    GtkWidget *nb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_end(GTK_BOX(nb), d->b_new, FALSE, FALSE, 0);
    gtk_table_resize(GTK_TABLE(t), 6, 3);
    gtk_table_attach(GTK_TABLE(t), nb, 0, 3, 5, 6, GTK_FILL, GTK_FILL, 0, 0);
    gtk_box_pack_start(GTK_BOX(v), d->policies, FALSE, FALSE, 0);

    d->status = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(d->status), TRUE);
    gtk_box_pack_start(GTK_BOX(v), d->status, FALSE, FALSE, 0);
    h = gtk_hbox_new(FALSE, 6);
    GtkWidget *help = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(help), gtk_image_new_from_stock(GTK_STOCK_HELP,
                                                                    GTK_ICON_SIZE_BUTTON));
    GtkWidget *close = stock_button("_Close", GTK_STOCK_CLOSE);
    gtk_box_pack_start(GTK_BOX(h), help, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(h), close, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v), h, FALSE, FALSE, 0);

    g_signal_connect(d->enable, "toggled", G_CALLBACK(on_enable_toggled), d);
    g_signal_connect(d->combo_in, "changed", G_CALLBACK(on_in_changed), d);
    g_signal_connect(d->combo_out, "changed", G_CALLBACK(on_out_changed), d);
    g_signal_connect(d->nodes, "changed", G_CALLBACK(on_nodes_changed), d);
    g_signal_connect(d->b_new, "clicked", G_CALLBACK(on_new_rule), d);
    g_signal_connect(d->b_in, "clicked", G_CALLBACK(on_allow_in), d);
    g_signal_connect(d->b_out, "clicked", G_CALLBACK(on_allow_out), d);
    g_signal_connect(help, "clicked", G_CALLBACK(on_help), d);
    g_signal_connect(close, "clicked", G_CALLBACK(on_close), d);
    gtk_widget_show_all(v);
    /* profiles aren't offered yet upstream (TODO there) */
    gtk_widget_hide(d->profile);
    gtk_widget_hide(d->lbl_profile);
    return d;
}

void ks_fw_dlg_free(struct ks_fw_dlg *d)
{
    if (d == NULL)
        return;
    if (d->second_send != 0)
        g_source_remove(d->second_send);
    ks_fwrule_dlg_free(d->rule_dlg);
    gtk_widget_destroy(d->win);
    g_ptr_array_free(d->node_addrs, TRUE);
    g_array_free(d->sent, TRUE);
    g_free(d);
}

GtkWidget *ks_fw_dlg_window(struct ks_fw_dlg *d)
{
    return d->win;
}

struct ks_fwrule_dlg *ks_fw_dlg_rule_dialog(struct ks_fw_dlg *d)
{
    return d->rule_dlg;
}

/* _load_nodes */
static void load_nodes(struct ks_fw_dlg *d)
{
    block(d, true);
    struct ks_nodes *nodes = nodes_of(d);
    gtk_list_store_clear(GTK_LIST_STORE(gtk_combo_box_get_model(GTK_COMBO_BOX(d->nodes))));
    g_ptr_array_set_size(d->node_addrs, 0);
    gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes), "All");
    g_ptr_array_add(d->node_addrs, g_strdup(ALL_NODES));
    for (size_t i = 0; i < nodes->len; i++) {
        const char *a = nodes->items[i]->addr;
        char *t = g_strdup_printf("%s - %s", ks_nodes_hostname(nodes, a), a);
        gtk_combo_box_append_text(GTK_COMBO_BOX(d->nodes), t);
        g_free(t);
        g_ptr_array_add(d->node_addrs, g_strdup(a));
    }
    bool show = nodes->len > 1;
    gtk_combo_box_set_active(GTK_COMBO_BOX(d->nodes), show ? 0 : 1);
    gtk_widget_set_visible(d->nodes, show);
    block(d, false);
}

void ks_fw_dlg_show(struct ks_fw_dlg *d)
{
    status(d, NULL, NULL);
    gtk_widget_show(d->win);
    gtk_window_present(GTK_WINDOW(d->win));
    load_nodes(d);
    load_fw_policies(d);
}

void ks_fw_dlg_load_rule(struct ks_fw_dlg *d, const char *addr, const char *uuid)
{
    ks_fwrule_dlg_load(d->rule_dlg, addr, uuid);
}

void ks_fw_dlg_nodes_updated(struct ks_fw_dlg *d)
{
    if (nodes_of(d)->len <= 1 && gtk_widget_get_visible(d->win)) {
        load_nodes(d);
        load_fw_policies(d);
    }
}
