/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall rules of the statistics window: port of the
 * firewall parts of upstream ui/opensnitch/dialogs/stats.py (fwButton, the
 * "Firewall" entry of the rules tree/combo, the fwTable view with
 * customwidgets/firewalltableview.py's columns, its contextual menu,
 * double click to edit, reordering, filtering by text).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "ui/fw_dialog.h"
#include "ui/fwrules.h"
#include "ui/nodes.h"
#include "ui/pyjson.h"
#include "ui/stats_fw.h"

/* FirewallTableModel columns, after our 11 of ks_fwr_to_array() */
enum { FC_UUID, FC_ADDR, FC_NAME, FC_TABLE, FC_FAMILY, FC_HOOK, FC_ENABLED, FC_DESC, FC_PARMS,
       FC_ACTION, FC_ACTION_PARMS, FC_N };

static const char *const headers[FC_N] = {"",           "Node",    "Name",   "Table",
                                          "Family",     "Hook",    "Enabled", "Description",
                                          "Parameters", "Action",  "ActionParms"};

struct ks_sw_fw {
    struct ks_stats_win *w;
    GtkWidget *box, *tree, *up, *down;
    GtkListStore *store;
    struct ks_fw_dlg *dlg;
};

static struct ks_nodes *nodes_of(struct ks_sw_fw *f)
{
    return ks_service_nodes(f->w->svc);
}

/* ---- the table --------------------------------------------------------------- */

void ks_sw_fw_refresh(struct ks_sw_fw *f)
{
    if (f == NULL)
        return;
    const char *nail = gtk_entry_get_text(GTK_ENTRY(f->w->filter));
    gtk_list_store_clear(f->store);
    struct ks_nodes *nodes = nodes_of(f);
    size_t rows = 0;
    for (size_t n = 0; n < nodes->len; n++) {
        struct ks_sysfw *fw = nodes->items[n]->fw;
        if (fw == NULL)
            continue;
        for (size_t i = 0; i < fw->system_rules.len; i++) {
            struct ks_fw_chains_list *l = KS_SYSFW_RULES(fw, i);
            for (size_t j = 0; j < l->chains.len; j++) {
                struct ks_fw_chain *c = KS_SYSFW_CHAIN(l, j);
                for (size_t k = 0; k < c->rules.len; k++) {
                    struct ks_fw_rule *r = KS_SYSFW_RULE(c, k);
                    /* filterByQuery */
                    if (nail[0] != '\0' && !ks_fwr_matches(c, r, nail))
                        continue;
                    char *cols[KS_FWR_NCOLS];
                    if (ks_fwr_to_array(nodes->items[n]->addr, c, r, cols) < 0)
                        continue;
                    GtkTreeIter it;
                    gtk_list_store_append(f->store, &it);
                    for (int col = 0; col < FC_N; col++) {
                        gtk_list_store_set(f->store, &it, col, cols[col], -1);
                        free(cols[col]);
                    }
                    rows++;
                }
            }
        }
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%zu", rows);
    gtk_label_set_text(GTK_LABEL(f->w->rows_label), buf);
}

/* the selected rows: arrays of FC_N strings (g_strfreev each) */
static GPtrArray *selected(struct ks_sw_fw *f)
{
    GPtrArray *out = g_ptr_array_new_with_free_func((GDestroyNotify)g_strfreev);
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(f->tree));
    GtkTreeModel *m;
    GList *paths = gtk_tree_selection_get_selected_rows(sel, &m);
    for (GList *p = paths; p != NULL; p = p->next) {
        GtkTreeIter it;
        if (!gtk_tree_model_get_iter(m, &it, p->data))
            continue;
        char **row = g_new0(char *, FC_N + 1);
        for (int c = 0; c < FC_N; c++)
            gtk_tree_model_get(m, &it, c, &row[c], -1);
        g_ptr_array_add(out, row);
    }
    g_list_free_full(paths, (GDestroyNotify)gtk_tree_path_free);
    return out;
}

static struct ks_sysfw *fw_of(struct ks_sw_fw *f, const char *addr)
{
    struct ks_node *n = ks_nodes_get(nodes_of(f), addr);
    return n != NULL ? n->fw : NULL;
}

/* reload_fw() of each node in `addrs` (a set) */
static void reload_nodes(struct ks_sw_fw *f, GHashTable *addrs)
{
    GHashTableIter it;
    gpointer key;
    g_hash_table_iter_init(&it, addrs);
    while (g_hash_table_iter_next(&it, &key, NULL))
        ks_nodes_reload_fw(nodes_of(f), key, ks_sw_ntf_reply, f->w);
    ks_sw_fw_refresh(f);
}

/* ---- the contextual menu ---------------------------------------------------- */

enum { M_ACCEPT, M_DROP, M_REJECT, M_RETURN, M_ENABLE, M_DELETE, M_EDIT, M_CLIPBOARD };

struct mctx {
    struct ks_sw_fw *f;
    int what;
};

/* Rules.to_json: MessageToJson(flat chain) */
static cJSON *rule_json(const struct ks_fw_chain *c)
{
    cJSON *o = cJSON_CreateObject();
#define ADD_S(obj, k, v)                                   \
    if ((v) != NULL && (v)[0] != '\0')                      \
        cJSON_AddStringToObject(obj, k, v);
    ADD_S(o, "Name", c->name);
    ADD_S(o, "Table", c->table);
    ADD_S(o, "Family", c->family);
    ADD_S(o, "Priority", c->priority);
    ADD_S(o, "Type", c->type);
    ADD_S(o, "Hook", c->hook);
    ADD_S(o, "Policy", c->policy);
    if (c->rules.len > 0) {
        cJSON *rules = cJSON_AddArrayToObject(o, "Rules");
        for (size_t i = 0; i < c->rules.len; i++) {
            const struct ks_fw_rule *r = KS_SYSFW_RULE(c, i);
            cJSON *ro = cJSON_CreateObject();
            ADD_S(ro, "Table", r->table);
            ADD_S(ro, "Chain", r->chain);
            ADD_S(ro, "UUID", r->uuid);
            if (r->enabled)
                cJSON_AddTrueToObject(ro, "Enabled");
            if (r->position != 0) {
                char pos[24];
                snprintf(pos, sizeof(pos), "%llu", (unsigned long long)r->position);
                cJSON_AddStringToObject(ro, "Position", pos);
            }
            ADD_S(ro, "Description", r->description);
            ADD_S(ro, "Parameters", r->parameters);
            if (r->expressions.len > 0) {
                cJSON *ex = cJSON_AddArrayToObject(ro, "Expressions");
                for (size_t e = 0; e < r->expressions.len; e++) {
                    const struct ks_fw_statement *st = KS_SYSFW_EXPR(r, e)->statement;
                    cJSON *eo = cJSON_CreateObject();
                    if (st != NULL) {
                        cJSON *so = cJSON_AddObjectToObject(eo, "Statement");
                        ADD_S(so, "Op", st->op);
                        ADD_S(so, "Name", st->name);
                        if (st->values.len > 0) {
                            cJSON *va = cJSON_AddArrayToObject(so, "Values");
                            for (size_t v = 0; v < st->values.len; v++) {
                                cJSON *vo = cJSON_CreateObject();
                                ADD_S(vo, "Key", KS_SYSFW_VALUE(st, v)->key);
                                ADD_S(vo, "Value", KS_SYSFW_VALUE(st, v)->value);
                                cJSON_AddItemToArray(va, vo);
                            }
                        }
                    }
                    cJSON_AddItemToArray(ex, eo);
                }
            }
            ADD_S(ro, "Target", r->target);
            ADD_S(ro, "TargetParameters", r->target_parameters);
            cJSON_AddItemToArray(rules, ro);
        }
    }
#undef ADD_S
    return o;
}

static void on_menu(GtkMenuItem *item, gpointer ud)
{
    (void)item;
    struct mctx *m = ud;
    struct ks_sw_fw *f = m->f;
    GPtrArray *rows = selected(f);
    GHashTable *updated = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    static const char *const actions[] = {"accept", "drop", "reject", "return"};

    if (m->what == M_EDIT && rows->len > 0) {
        char **r = g_ptr_array_index(rows, 0);
        ks_fw_dlg_load_rule(ks_sw_fw_dialog(f), r[FC_ADDR], r[FC_UUID]);
    } else if (m->what == M_CLIPBOARD) {
        GString *g = g_string_new("");
        for (guint i = 0; i < rows->len; i++) {
            char **r = g_ptr_array_index(rows, i);
            struct ks_fw_chain flat;
            struct ks_sysfw *fw = fw_of(f, r[FC_ADDR]);
            if (fw == NULL || ks_fwr_flat_by_uuid(fw, r[FC_UUID], &flat) < 0)
                continue;
            cJSON *j = rule_json(&flat);
            char *s = ks_pyjson_dumps_indent(j, 2);
            if (s != NULL) {
                g_string_append(g, s);
                g_string_append(g, "\n");
            }
            free(s);
            cJSON_Delete(j);
            ks_fwr_free_chain(&flat);
        }
        gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), g->str, -1);
        g_string_free(g, TRUE);
    } else if (m->what == M_DELETE) {
        if (ks_sw_confirm(f->w, "    You are about to delete this rule.    ")) {
            for (guint i = 0; i < rows->len; i++) {
                char **r = g_ptr_array_index(rows, i);
                if (ks_fwr_delete(fw_of(f, r[FC_ADDR]), r[FC_UUID]) == 0)
                    g_hash_table_add(updated, g_strdup(r[FC_ADDR]));
            }
        }
    } else if (m->what == M_ENABLE && rows->len > 0) {
        /* the first row says whether they're enabled */
        bool enable = strcmp(((char **)g_ptr_array_index(rows, 0))[FC_ENABLED], "False") == 0;
        for (guint i = 0; i < rows->len; i++) {
            char **r = g_ptr_array_index(rows, i);
            if (ks_fwr_enable(fw_of(f, r[FC_ADDR]), r[FC_UUID], enable) == 0)
                g_hash_table_add(updated, g_strdup(r[FC_ADDR]));
        }
    } else if (m->what <= M_RETURN) {
        for (guint i = 0; i < rows->len; i++) {
            char **r = g_ptr_array_index(rows, i);
            if (ks_fwr_set_target(fw_of(f, r[FC_ADDR]), r[FC_UUID], actions[m->what]) == 0)
                g_hash_table_add(updated, g_strdup(r[FC_ADDR]));
        }
    }
    reload_nodes(f, updated);
    g_hash_table_destroy(updated);
    g_ptr_array_free(rows, TRUE);
}

static GtkWidget *menu_item(GtkWidget *menu, const char *label, struct mctx *ctx)
{
    GtkWidget *it = gtk_menu_item_new_with_label(label);
    g_signal_connect(it, "activate", G_CALLBACK(on_menu), ctx);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), it);
    return it;
}

static struct mctx ctxs[M_CLIPBOARD + 1];

/* _configure_fwrules_contextual_menu */
static void popup_menu(struct ks_sw_fw *f, GdkEventButton *ev)
{
    GPtrArray *rows = selected(f);
    if (rows->len == 0) {
        g_ptr_array_free(rows, TRUE);
        return;
    }
    char **first = g_ptr_array_index(rows, 0);
    char *action = g_ascii_strdown(first[FC_ACTION], -1);
    for (int i = 0; i <= M_CLIPBOARD; i++) {
        ctxs[i].f = f;
        ctxs[i].what = i;
    }
    GtkWidget *menu = gtk_menu_new();
    if (strcmp(action, "accept") == 0 || strcmp(action, "drop") == 0 ||
        strcmp(action, "return") == 0 || strcmp(action, "reject") == 0) {
        GtkWidget *sub = gtk_menu_new(), *it = gtk_menu_item_new_with_label("Action");
        menu_item(sub, "accept", &ctxs[M_ACCEPT]);
        menu_item(sub, "drop", &ctxs[M_DROP]);
        menu_item(sub, "reject", &ctxs[M_REJECT]);
        menu_item(sub, "return", &ctxs[M_RETURN]);
        gtk_menu_item_set_submenu(GTK_MENU_ITEM(it), sub);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), it);
    }
    menu_item(menu, strcmp(first[FC_ENABLED], "False") == 0 ? "Enable" : "Disable",
              &ctxs[M_ENABLE]);
    menu_item(menu, "Delete", &ctxs[M_DELETE]);
    menu_item(menu, "Edit", &ctxs[M_EDIT]);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    GtkWidget *exp = gtk_menu_new(), *expi = gtk_menu_item_new_with_label("Export");
    menu_item(exp, "To clipboard", &ctxs[M_CLIPBOARD]);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(expi), exp);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), expi);
    gtk_widget_show_all(menu);
    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, ev ? ev->button : 0,
                   ev ? ev->time : gtk_get_current_event_time());
    g_free(action);
    g_ptr_array_free(rows, TRUE);
}

static gboolean on_button(GtkWidget *tree, GdkEventButton *ev, gpointer ud)
{
    struct ks_sw_fw *f = ud;
    if (ev->type != GDK_BUTTON_PRESS || ev->button != 3)
        return FALSE;
    /* keep a multiple selection, else select the clicked row */
    GtkTreePath *path = NULL;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tree), (gint)ev->x, (gint)ev->y, &path, NULL,
                                      NULL, NULL)) {
        if (!gtk_tree_selection_path_is_selected(sel, path)) {
            gtk_tree_selection_unselect_all(sel);
            gtk_tree_selection_select_path(sel, path);
        }
        gtk_tree_path_free(path);
    }
    popup_menu(f, ev);
    return TRUE;
}

static void on_activated(GtkTreeView *t, GtkTreePath *p, GtkTreeViewColumn *c, gpointer ud)
{
    (void)c;
    struct ks_sw_fw *f = ud;
    GtkTreeIter it;
    GtkTreeModel *m = gtk_tree_view_get_model(t);
    if (!gtk_tree_model_get_iter(m, &it, p))
        return;
    char *uuid = NULL, *addr = NULL;
    gtk_tree_model_get(m, &it, FC_UUID, &uuid, FC_ADDR, &addr, -1);
    ks_fw_dlg_load_rule(ks_sw_fw_dialog(f), addr, uuid);
    g_free(uuid);
    g_free(addr);
}

/* the up/down buttons (UpDownButtonDelegate): Rules.swap() in the chain */
static void move(struct ks_sw_fw *f, int dir)
{
    GPtrArray *rows = selected(f);
    if (rows->len == 1) {
        char **r = g_ptr_array_index(rows, 0);
        struct ks_sysfw *fw = fw_of(f, r[FC_ADDR]);
        struct ks_fw_chain *c = NULL;
        struct ks_fw_rule *rule = fw != NULL ? ks_fwr_find(fw, r[FC_UUID], &c) : NULL;
        if (rule != NULL) {
            size_t pos = (size_t)(rule - (struct ks_fw_rule *)c->rules.items);
            if ((dir < 0 && pos > 0) || (dir > 0 && pos + 1 < c->rules.len)) {
                char *uuid = g_strdup(r[FC_UUID]), *addr = g_strdup(r[FC_ADDR]);
                if (ks_fwr_swap(fw, uuid, pos, dir < 0 ? pos - 1 : pos + 1)) {
                    ks_nodes_reload_fw(nodes_of(f), addr, ks_sw_ntf_reply, f->w);
                    ks_sw_fw_refresh(f);
                }
                g_free(uuid);
                g_free(addr);
            }
        }
    }
    g_ptr_array_free(rows, TRUE);
}

static void on_up(GtkButton *b, gpointer ud)
{
    (void)b;
    move(ud, -1);
}

static void on_down(GtkButton *b, gpointer ud)
{
    (void)b;
    move(ud, 1);
}

static void on_dialog_changed(void *ud)
{
    ks_sw_fw_refresh(ud);
}

struct ks_sw_fw *ks_sw_fw_new(struct ks_stats_win *w)
{
    struct ks_sw_fw *f = g_new0(struct ks_sw_fw, 1);
    f->w = w;
    GType types[FC_N];
    for (int i = 0; i < FC_N; i++)
        types[i] = G_TYPE_STRING;
    f->store = gtk_list_store_newv(FC_N, types);
    f->tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(f->store));
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(f->tree), TRUE);
    gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(f->tree)),
                                GTK_SELECTION_MULTIPLE);
    for (int i = FC_ADDR; i < FC_N; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *c =
            gtk_tree_view_column_new_with_attributes(headers[i], r, "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_sort_column_id(c, i);
        gtk_tree_view_append_column(GTK_TREE_VIEW(f->tree), c);
    }
    g_signal_connect(f->tree, "button-press-event", G_CALLBACK(on_button), f);
    g_signal_connect(f->tree, "row-activated", G_CALLBACK(on_activated), f);

    f->box = gtk_vbox_new(FALSE, 2);
    GtkWidget *h = gtk_hbox_new(FALSE, 2);
    f->up = gtk_button_new_from_stock(GTK_STOCK_GO_UP);
    f->down = gtk_button_new_from_stock(GTK_STOCK_GO_DOWN);
    gtk_box_pack_start(GTK_BOX(h), f->up, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(h), f->down, FALSE, FALSE, 0);
    g_signal_connect(f->up, "clicked", G_CALLBACK(on_up), f);
    g_signal_connect(f->down, "clicked", G_CALLBACK(on_down), f);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), f->tree);
    gtk_box_pack_start(GTK_BOX(f->box), h, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(f->box), sw, TRUE, TRUE, 0);
    gtk_widget_show_all(f->box);
    gtk_widget_set_no_show_all(f->box, TRUE);
    gtk_widget_hide(f->box);
    return f;
}

void ks_sw_fw_free(struct ks_sw_fw *f)
{
    if (f == NULL)
        return;
    ks_fw_dlg_free(f->dlg);
    g_object_unref(f->store);
    g_free(f);
}

GtkWidget *ks_sw_fw_widget(struct ks_sw_fw *f)
{
    return f->box;
}

struct ks_fw_dlg *ks_sw_fw_dialog(struct ks_sw_fw *f)
{
    if (f->dlg == NULL)
        f->dlg = ks_fw_dlg_new(f->w->svc, GTK_WINDOW(f->w->win), on_dialog_changed, f);
    return f->dlg;
}

bool ks_sw_fw_visible(struct ks_sw_fw *f)
{
    return f != NULL && gtk_widget_get_visible(f->box);
}

void ks_sw_fw_nodes_updated(struct ks_sw_fw *f)
{
    if (f == NULL)
        return;
    if (f->dlg != NULL)
        ks_fw_dlg_nodes_updated(f->dlg);
    if (ks_sw_fw_visible(f))
        ks_sw_fw_refresh(f);
}
