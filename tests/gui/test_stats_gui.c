/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The statistics window's dialogs and tasks, with the daemon's replies
 * injected: the process details dialog (pid-monitor), the Netstat tab
 * (sockets-monitor) and the node panel (node-monitor). Needs a display
 * (tests/integration/stats_gui.sh starts Xvfb); skips without one.
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "common/pb_util.h"
#include "ui/db.h"
#include "ui/rules_editor.h"
#include "ui/rulesdb.h"
#include "ui/stats_win_priv.h"
#include "tests/harness.h"

static struct ks_settings settings;
static struct ks_service *svc;
static struct ks_stats_win *w;

static Protocol__Notification *queued(const char *addr, size_t i)
{
    struct ks_node *n = ks_nodes_get(ks_service_nodes(svc), addr);
    if (n == NULL || i >= n->nqueue)
        return NULL;
    return (Protocol__Notification *)ks_pb_unpack(&protocol__notification__descriptor,
                                                    n->queue[i].buf, n->queue[i].len);
}

static void reply(const char *addr, uint64_t id, bool error, const char *data)
{
    Protocol__NotificationReply r = PROTOCOL__NOTIFICATION_REPLY__INIT;
    r.id = id;
    r.code = error ? PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR : PROTOCOL__NOTIFICATION_REPLY_CODE__OK;
    r.data = (char *)(uintptr_t)data;
    ks_nodes_reply(ks_service_nodes(svc), addr, &r);
}

static void spin(void)
{
    for (int i = 0; i < 50; i++) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        g_usleep(2000);
    }
}

/* the first widget under `wd` that is a button or label with this text */
static GtkWidget *find_labeled(GtkWidget *wd, const char *label)
{
    if (GTK_IS_BUTTON(wd) && strcmp(gtk_button_get_label(GTK_BUTTON(wd)), label) == 0)
        return wd;
    if (GTK_IS_CONTAINER(wd)) {
        GList *ch = gtk_container_get_children(GTK_CONTAINER(wd));
        for (GList *l = ch; l != NULL; l = l->next) {
            GtkWidget *r = find_labeled(l->data, label);
            if (r != NULL) {
                g_list_free(ch);
                return r;
            }
        }
        g_list_free(ch);
    }
    return NULL;
}

/* the entry in the cell next to a check button of a GtkTable (the dialog's rows) */
static GtkWidget *input_of(GtkWidget *check)
{
    GtkWidget *table = gtk_widget_get_parent(check);
    guint row = 0;
    gtk_container_child_get(GTK_CONTAINER(table), check, "top-attach", &row, NULL);
    GList *ch = gtk_container_get_children(GTK_CONTAINER(table));
    GtkWidget *found = NULL;
    for (GList *l = ch; l != NULL; l = l->next) {
        guint r = 0, left = 0;
        gtk_container_child_get(GTK_CONTAINER(table), l->data, "top-attach", &r, "left-attach", &left,
                                NULL);
        if (r == row && left == 1)
            found = l->data;
    }
    g_list_free(ch);
    if (found != NULL && GTK_IS_COMBO_BOX_ENTRY(found))
        found = gtk_bin_get_child(GTK_BIN(found));
    return found;
}

static void set_field(GtkWidget *win, const char *check_label, const char *text)
{
    GtkWidget *c = find_labeled(win, check_label);
    if (c == NULL) {
        fprintf(stderr, "no check \"%s\"\n", check_label);
        return;
    }
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(c), TRUE);
    gtk_entry_set_text(GTK_ENTRY(input_of(c)), text);
}

static GtkWidget *name_entry(GtkWidget *win)
{
    /* the first entry of the top row */
    GtkWidget *box = gtk_bin_get_child(GTK_BIN(win));
    GList *ch = gtk_container_get_children(GTK_CONTAINER(box));
    GtkWidget *top = ch->data;
    g_list_free(ch);
    ch = gtk_container_get_children(GTK_CONTAINER(top));
    GtkWidget *e = ch->next->data;
    g_list_free(ch);
    return e;
}

/* any label of any window whose text has `needle` */
static bool find_in(GtkWidget *wd, const char *needle)
{
    if (GTK_IS_LABEL(wd) && strstr(gtk_label_get_text(GTK_LABEL(wd)), needle) != NULL)
        return true;
    if (GTK_IS_ENTRY(wd) && strstr(gtk_entry_get_text(GTK_ENTRY(wd)), needle) != NULL)
        return true;
    if (GTK_IS_TEXT_VIEW(wd)) {
        GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(wd));
        GtkTextIter s, e;
        gtk_text_buffer_get_bounds(b, &s, &e);
        char *t = gtk_text_buffer_get_text(b, &s, &e, FALSE);
        bool hit = strstr(t, needle) != NULL;
        g_free(t);
        if (hit)
            return true;
    }
    if (GTK_IS_CONTAINER(wd)) {
        GList *ch = gtk_container_get_children(GTK_CONTAINER(wd));
        for (GList *l = ch; l != NULL; l = l->next) {
            if (find_in(l->data, needle)) {
                g_list_free(ch);
                return true;
            }
        }
        g_list_free(ch);
    }
    return false;
}

static bool on_screen(const char *needle)
{
    GList *tops = gtk_window_list_toplevels();
    bool hit = false;
    for (GList *l = tops; l != NULL && !hit; l = l->next)
        hit = find_in(l->data, needle);
    g_list_free(tops);
    return hit;
}

static const char *proc_json =
    "{\"Path\": \"/usr/bin/curl\", \"Args\": [\"curl\", \"-s\", \"https://x.example\"], "
    "\"CWD\": \"/home/u\", \"Statm\": {\"Size\": 123456789, \"Resident\": 1048575, \"Lib\": 0, "
    "\"Data\": 52428800, \"Text\": 2097152}, \"Status\": \"Name:\\tcurl\\nState:\\tS (sleeping)\\n\", "
    "\"Env\": {\"HOME\": \"/root\"}, \"Tree\": [{\"key\": \"/usr/bin/curl\", \"value\": 1}, "
    "{\"key\": \"/bin/bash\", \"value\": 2}], \"Descriptors\": [], \"IOStats\": {}, \"Maps\": \"\", "
    "\"Stack\": \"\"}";

TEST(process_dialog)
{
    const char *pids[] = {"4242"}, *nodes[] = {"unix:/local"};
    ks_sw_proc_monitor(w, pids, nodes, 1);
    spin();
    CHECK(on_screen("loading..."));
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__TASK_START);
    CHECK_STR_HAS(n->data, "\"name\": \"pid-monitor\"");
    CHECK_STR_HAS(n->data, "\"pid\": \"4242\"");
    uint64_t id = n->id;
    protobuf_c_message_free_unpacked(&n->base, NULL);

    reply("unix:/local", id, false, proc_json);
    spin();
    CHECK(on_screen("curl -s https://x.example"));
    CHECK(on_screen("(/usr/bin/curl)"));
    CHECK(on_screen("VIRT: 117MB"));
    CHECK(on_screen("Parent(s): /bin/bash"));
    CHECK(on_screen("State:\tS (sleeping)")); /* the Status tab, the current one */
    /* the data keeps coming with the same id (the task runs every 5 s) */
    reply("unix:/local", id, false, proc_json);
    spin();
    CHECK(on_screen("CWD: /home/u"));

    /* a second monitor() stops the first one: TASK_STOP, then TASK_START */
    ks_sw_proc_monitor(w, pids, nodes, 1);
    n = queued("unix:/local", 1);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__TASK_STOP);
    protobuf_c_message_free_unpacked(&n->base, NULL);
    n = queued("unix:/local", 2);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__TASK_START);
    id = n->id;
    protobuf_c_message_free_unpacked(&n->base, NULL);
    /* the daemon cannot: a message, and the dialog (nothing loaded) closes */
    reply("unix:/local", id, true, "task pid-monitor is not supported yet");
    spin();
    CHECK(on_screen("Error loading process information"));
}

TEST(netstat_tab)
{
    /* an interval of 5s on the Netstat tab starts the task */
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_interval), 1);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_proto), 1); /* TCP */
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->ns_state), 10); /* LISTEN */
    ks_sw_netstat_enter(w);
    spin();
    size_t i = 0;
    Protocol__Notification *n = NULL, *found = NULL;
    while ((n = queued("unix:/local", i++)) != NULL) {
        if (n->type == PROTOCOL__ACTION__TASK_START && strstr(n->data, "sockets-monitor") != NULL) {
            if (found != NULL)
                protobuf_c_message_free_unpacked(&found->base, NULL);
            found = n;
        } else {
            protobuf_c_message_free_unpacked(&n->base, NULL);
        }
    }
    CHECK(found != NULL);
    if (found == NULL)
        return;
    CHECK_STR_HAS(found->data, "\"interval\": \"5s\"");
    CHECK_STR_HAS(found->data, "\"state\": 10");
    CHECK_STR_HAS(found->data, "\"proto\": 6");
    CHECK_STR_HAS(found->data, "\"family\": 0");
    uint64_t id = found->id;
    protobuf_c_message_free_unpacked(&found->base, NULL);

    reply("unix:/local", id,  false,
          "{\"Table\": [{\"Socket\": {\"ID\": {\"Source\": \"127.0.0.1\", \"Destination\": \"0.0.0.0\", "
          "\"Cookie\": [1, 2], \"Interface\": 0, \"SourcePort\": 631, \"DestinationPort\": 0}, "
          "\"Expires\": 0, \"RQueue\": 0, \"WQueue\": 0, \"UID\": 0, \"INode\": 7, \"Family\": 2, "
          "\"State\": 10, \"Timer\": 0, \"Retrans\": 0}, \"Iface\": \"\", \"PID\": 77, \"Mark\": 0, "
          "\"Proto\": 6}], \"Processes\": {\"77\": {\"Path\": \"/usr/sbin/cupsd\", \"Comm\": \"cupsd\"}}}");
    spin();
    CHECK_INT_EQ((int)ks_db_count(ks_service_db(svc), "sockets"), 1);

    /* an error reply goes to the label */
    reply("unix:/local", id, true, "boom");
    spin();
    CHECK(on_screen("error starting netstat table: boom"));
    /* leaving the tab stops the task */
    ks_sw_netstat_leave(w);
    n = NULL;
    size_t cnt = 0;
    bool stop = false;
    while ((n = queued("unix:/local", cnt++)) != NULL) {
        if (n->type == PROTOCOL__ACTION__TASK_STOP && strstr(n->data, "sockets-monitor"))
            stop = true;
        protobuf_c_message_free_unpacked(&n->base, NULL);
    }
    CHECK(stop);
}

TEST(node_panel)
{
    /* a node row in the table, then the click that starts node-monitor */
    ks_db_exec(ks_service_db(svc), "INSERT INTO nodes (addr,status,hostname,daemon_version,daemon_uptime,"
                                   "daemon_rules,cons,cons_dropped,version,last_connection) VALUES "
                                   "('unix:/local','on','host','1.8.0','0:00:05','0','0','0','5.15','t')");
    struct tabview *tv = ks_sw_tab(w, KS_TAB_NODES);
    ks_sw_run_query(w, tv, false);
    ks_sw_node_clicked(w, tv, 0);
    spin();
    size_t i = 0;
    uint64_t id = 0;
    Protocol__Notification *n;
    while ((n = queued("unix:/local", i++)) != NULL) {
        if (n->type == PROTOCOL__ACTION__TASK_START && strstr(n->data, "node-monitor")) {
            id = n->id;
            CHECK_STR_HAS(n->data, "\"node\": \"unix:/local\"");
        }
        protobuf_c_message_free_unpacked(&n->base, NULL);
    }
    CHECK(id != 0);
    CHECK(on_screen("daemon uptime: 0:00:05"));
    CHECK(on_screen("Kernel: 5.15"));
    reply("unix:/local", id, false,
          "{\"Uptime\": 360000, \"Loads\": [12345, 54321, 100000], \"Totalram\": 16651239424, "
          "\"Freeram\": 8000000000, \"Totalswap\": 2147479552, \"Freeswap\": 2147479552, \"Procs\": 512}");
    spin();
    CHECK(on_screen("RAM: 16 GB Free: 7 GB"));
    CHECK(on_screen("Load avg:"));
    CHECK(on_screen("0.12, 0.54, 1.00"));
    CHECK(on_screen("Processes: 512"));
    /* an error: the panel says why */
    reply("unix:/local", id, true, "task node-monitor is not supported yet");
    spin();
    CHECK(on_screen("task node-monitor is not supported yet"));
    /* a second click on the same node stops it */
    ks_sw_node_clicked(w, tv, 0);
    CHECK_INT_EQ((int)w->monitored[0], 0);
}

static void clear_queue(void)
{
    struct ks_node *n = ks_nodes_get(ks_service_nodes(svc), "unix:/local");
    for (size_t i = 0; n != NULL && i < n->nqueue; i++)
        free(n->queue[i].buf);
    if (n != NULL)
        n->nqueue = 0;
}

TEST(rules_editor_new_and_save)
{
    clear_queue();
    struct ks_ruleed *ed = ks_sw_ruleed(w);
    ks_ruleed_new_rule(ed);
    spin();
    GtkWidget *win = ks_ruleed_window(ed);
    CHECK(gtk_widget_get_visible(win));
    GtkWidget *save = find_labeled(win, "gtk-save");
    CHECK(save != NULL);
    if (save == NULL)
        return;

    /* a name, but no field: nothing to build */
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "t1");
    gtk_button_clicked(GTK_BUTTON(save));
    CHECK(on_screen("Select at least one field."));

    /* a field, checked: an allow rule for port 443 and 80, from a list */
    set_field(win, "To this port", "443, 80");
    GtkWidget *allow = find_labeled(win, "Allow");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(allow), TRUE);
    gtk_button_clicked(GTK_BUTTON(save));
    spin();
    const struct ks_ui_rule *row = ks_rulesdb_get(ks_service_rules(svc), "t1", "unix:/local");
    CHECK(row != NULL);
    if (row != NULL) {
        CHECK_STR_EQ(row->f[KS_RF_ACTION], "allow");
        CHECK_STR_EQ(row->f[KS_RF_OP_OPERAND], "dest.port");
        CHECK_STR_EQ(row->f[KS_RF_OP_DATA], "^(443|80)$");
        CHECK_STR_EQ(row->f[KS_RF_OP_TYPE], "regexp");
        CHECK_STR_EQ(row->f[KS_RF_ENABLED], "False"); /* the Enable box was not checked */
    }
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK(n != NULL);
    if (n != NULL) {
        CHECK_INT_EQ(n->type, PROTOCOL__ACTION__CHANGE_RULE);
        CHECK_STR_EQ(n->rules[0]->name, "t1");
        uint64_t id = n->id;
        protobuf_c_message_free_unpacked(&n->base, NULL);
        reply("unix:/local", id, false, "");
        CHECK(on_screen("Rule applied."));
    }

    /* now in edit mode: saving again under the same name is fine; a rename deletes the old */
    gtk_button_clicked(GTK_BUTTON(save));
    CHECK(!on_screen("There's already a rule with this name."));
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "t2");
    gtk_button_clicked(GTK_BUTTON(save));
    spin();
    CHECK(ks_rulesdb_get(ks_service_rules(svc), "t2", "unix:/local") != NULL);
    CHECK(ks_rulesdb_get(ks_service_rules(svc), "t1", "unix:/local") == NULL);
    bool del = false;
    size_t i = 0;
    while ((n = queued("unix:/local", i++)) != NULL) {
        if (n->type == PROTOCOL__ACTION__DELETE_RULE && strcmp(n->rules[0]->name, "t1") == 0)
            del = true;
        protobuf_c_message_free_unpacked(&n->base, NULL);
    }
    CHECK(del);

    /* a name in use, in add mode */
    ks_ruleed_new_rule(ed);
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "t2");
    set_field(win, "To this port", "1");
    gtk_button_clicked(GTK_BUTTON(save));
    CHECK(on_screen("There's already a rule with this name."));

    /* bad input: the message of _save_rule */
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "t3");
    set_field(win, "To this port", "80,x");
    gtk_button_clicked(GTK_BUTTON(save));
    CHECK(on_screen("Invalid text"));
    /* md5 without the process path */
    set_field(win, "To this port", "80");
    set_field(win, "md5", "abc");
    gtk_button_clicked(GTK_BUTTON(save));
    CHECK(on_screen("Process path must be checked in order to verify checksums."));
    /* "/" is not allowed in a name: the character is dropped */
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "");
    gtk_editable_insert_text(GTK_EDITABLE(name_entry(win)), "a/b", 3, &(gint){0});
    CHECK_STR_EQ(gtk_entry_get_text(GTK_ENTRY(name_entry(win))), "");
    CHECK(on_screen("Invalid rule name (not allowed characters: '/' )"));
}

TEST(rules_editor_from_event_and_edit)
{
    clear_queue();
    struct ks_ruleed *ed = ks_sw_ruleed(w);
    ks_db_exec(ks_service_db(svc),
               "INSERT INTO connections (time,node,action,protocol,src_ip,src_port,dst_ip,dst_host,"
               "dst_port,uid,pid,process,process_args,process_cwd,rule) VALUES "
               "('2026-02-02 10:00:00.000001','unix:/local','deny','tcp','10.0.0.2','40000','1.1.1.1',"
               "'one.example','443','1000','77','/usr/bin/curl','curl x','/','')");
    CHECK(!ks_ruleed_new_rule_from_connection(ed, "no such time"));
    CHECK(ks_ruleed_new_rule_from_connection(ed, "2026-02-02 10:00:00.000001"));
    spin();
    GtkWidget *win = ks_ruleed_window(ed);
    CHECK(on_screen("one.example"));
    CHECK(on_screen("/usr/bin/curl"));
    CHECK(on_screen("TCP"));
    /* the texts are there; no check is toggled, so nothing is built until one is */
    gtk_entry_set_text(GTK_ENTRY(name_entry(win)), "ev1");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(find_labeled(win, "To this host")), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(find_labeled(win, "From this executable")), TRUE);
    gtk_button_clicked(GTK_BUTTON(find_labeled(win, "gtk-save")));
    spin();
    const struct ks_ui_rule *row = ks_rulesdb_get(ks_service_rules(svc), "ev1", "unix:/local");
    CHECK(row != NULL);
    if (row != NULL) {
        CHECK_STR_EQ(row->f[KS_RF_OP_TYPE], "list");
        CHECK_STR_HAS(row->f[KS_RF_OP_DATA], "\"operand\": \"dest.host\"");
        CHECK_STR_HAS(row->f[KS_RF_OP_DATA], "\"data\": \"one.example\"");
        CHECK_STR_HAS(row->f[KS_RF_OP_DATA], "\"operand\": \"process.path\"");
    }

    /* edit it: the form gets the operators of the list */
    ks_ruleed_edit_rule(ed, "unix:/local", "ev1");
    spin();
    CHECK(gtk_widget_get_visible(win));
    CHECK(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(find_labeled(win, "To this host"))));
    CHECK(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(find_labeled(win, "From this executable"))));
    CHECK(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(find_labeled(win, "To this port"))));
    CHECK(on_screen("one.example"));
    /* a rule type this version does not know */
    const char *v[KS_RF_COUNT] = {"t", "unix:/local", "odd", "True", "False", "allow", "always",
                                  "future", "False", "x", "y", "", "False", ""};
    ks_rulesdb_add_row(ks_service_rules(svc), v);
    gtk_widget_hide(win);
    ks_ruleed_edit_rule(ed, "unix:/local", "nope");
    spin();
    CHECK(on_screen("Rule not found by that name and node"));
}

int main(int argc, char **argv)
{
    if (!gtk_init_check(&argc, &argv)) {
        printf("SKIP (stats gui): no display\n");
        return 0;
    }
    ks_settings_parse(&settings, "[database]\ntype=0\n", 18);
    svc = ks_service_new(&settings, NULL, NULL);
    if (svc == NULL)
        return 1;
    Protocol__ClientConfig c = PROTOCOL__CLIENT_CONFIG__INIT;
    c.name = (char *)(uintptr_t) "host";
    c.version = (char *)(uintptr_t) "5.15";
    size_t len;
    uint8_t *buf = ks_pb_pack(&c.base, &len);
    Protocol__ClientConfig *cfg =
        (Protocol__ClientConfig *)ks_pb_unpack(&protocol__client_config__descriptor, buf, len);
    free(buf);
    ks_nodes_add(ks_service_nodes(svc), "unix:", cfg);
    w = ks_stats_win_new(svc, &settings, NULL);
    gtk_widget_show_all(w->win);
    spin();

    RUN(process_dialog);
    RUN(netstat_tab);
    RUN(node_panel);
    RUN(rules_editor_new_and_save);
    RUN(rules_editor_from_event_and_edit);

    ks_stats_win_free(w);
    ks_service_free(svc);
    ks_settings_close(&settings);
    return harness_report();
}
