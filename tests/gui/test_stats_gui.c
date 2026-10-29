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
#include <unistd.h>

#include "common/pb_util.h"
#include "common/json_util.h"
#include "common/sysfw.h"
#include "ui/db.h"
#include "ui/fw_dialog.h"
#include "ui/fwrules.h"
#include "ui/stats_fw.h"
#include "ui/prefs.h"
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
    if (GTK_IS_BUTTON(wd) && gtk_button_get_label(GTK_BUTTON(wd)) != NULL &&
        strcmp(gtk_button_get_label(GTK_BUTTON(wd)), label) == 0)
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

/* the label under `wd` with exactly this text */
static GtkWidget *find_in_label(GtkWidget *wd, const char *text)
{
    if (GTK_IS_LABEL(wd) && strcmp(gtk_label_get_text(GTK_LABEL(wd)), text) == 0)
        return wd;
    if (GTK_IS_CONTAINER(wd)) {
        GList *ch = gtk_container_get_children(GTK_CONTAINER(wd));
        for (GList *l = ch; l != NULL; l = l->next) {
            GtkWidget *r = find_in_label(l->data, text);
            if (r != NULL) {
                g_list_free(ch);
                return r;
            }
        }
        g_list_free(ch);
    }
    return NULL;
}

/* any label of any window whose text has `needle` */
static bool find_in(GtkWidget *wd, const char *needle)
{
    if (GTK_IS_EXPANDER(wd) && gtk_expander_get_label(GTK_EXPANDER(wd)) != NULL &&
        strstr(gtk_expander_get_label(GTK_EXPANDER(wd)), needle) != NULL)
        return true;
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

TEST(preferences_save)
{
    clear_queue();
    struct ks_node *n = ks_nodes_get(ks_service_nodes(svc), "unix:/local");
    CHECK(n != NULL);
    if (n->config->config[0] != '\0')
        free(n->config->config);
    n->config->config = strdup(
        "{\"Server\":{\"Address\":\"unix:///tmp/osui.sock\",\"LogFile\":\"/var/log/opensnitchd.log\"},"
        "\"DefaultAction\":\"allow\",\"DefaultDuration\":\"once\",\"InterceptUnknown\":false,"
        "\"ProcMonitorMethod\":\"proc\",\"LogLevel\":1,\"Firewall\":\"nftables\","
        "\"Stats\":{\"MaxEvents\":150,\"MaxStats\":25}}");
    struct ks_prefs *p = ks_sw_prefs(w);
    ks_prefs_show(p);
    spin();
    GtkWidget *win = ks_prefs_window(p);
    CHECK(gtk_widget_get_visible(win));
    CHECK(on_screen("Default timeout"));
    GtkWidget *adv = find_labeled(win, "Show advanced view by default");
    CHECK(adv != NULL);
    CHECK(!ks_settings_get_bool(&settings, KS_CFG_DEFAULT_POPUP_ADVANCED, false));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(adv), TRUE);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(find_labeled(win, "Disable pop-ups, only display a notification")), TRUE);
    GtkWidget *dbg = find_labeled(win, "Debug invalid connections");
    CHECK(dbg != NULL);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dbg), TRUE);
    gtk_button_clicked(GTK_BUTTON(find_labeled(win, "gtk-apply")));
    spin();
    CHECK(ks_settings_get_bool(&settings, KS_CFG_DEFAULT_POPUP_ADVANCED, false));
    CHECK(ks_settings_get_bool(&settings, KS_CFG_DEFAULT_DISABLE_POPUPS, false));
    CHECK_INT_EQ(ks_settings_get_int(&settings, KS_CFG_DEFAULT_TIMEOUT_KEY, -1), 0);
    /* the node got its new configuration */
    uint64_t id = 0;
    for (size_t i = 0;; i++) {
        Protocol__Notification *m = queued("unix:/local", i);
        if (m == NULL)
            break;
        if (m->type == PROTOCOL__ACTION__CHANGE_CONFIG) {
            id = m->id;
            CHECK_STR_HAS(m->data, "\"InterceptUnknown\": true");
        }
        protobuf_c_message_free_unpacked(&m->base, NULL);
    }
    CHECK(id != 0);
    reply("unix:/local", id, false, "");
    spin();
    CHECK(on_screen("Configuration applied."));
    gtk_widget_hide(win);
}

TEST(export_csv)
{
    struct tabview *tv = ks_sw_tab(w, KS_TAB_MAIN);
    ks_sw_run_query(w, tv, false);
    char *path = g_build_filename(g_get_tmp_dir(), "ks-events-test.csv", NULL);
    CHECK(ks_sw_write_csv(w, tv, path));
    char *txt = NULL;
    CHECK(g_file_get_contents(path, &txt, NULL, NULL));
    if (txt != NULL) {
        CHECK_STR_HAS(txt, "Time,node,action");
        CHECK_STR_HAS(txt, "one.example");
        CHECK_STR_HAS(txt, "\r\n");
    }
    g_free(txt);
    unlink(path);
    g_free(path);
}

/* the last notification queued for a node */
static Protocol__Notification *last_queued(const char *addr)
{
    struct ks_node *n = ks_nodes_get(ks_service_nodes(svc), addr);
    return n != NULL && n->nqueue > 0 ? queued(addr, n->nqueue - 1) : NULL;
}

static GtkWidget *window_titled(const char *title)
{
    GList *tops = gtk_window_list_toplevels();
    GtkWidget *found = NULL;
    for (GList *l = tops; l != NULL; l = l->next) {
        const char *t = gtk_window_get_title(GTK_WINDOW(l->data));
        if (t != NULL && strcmp(t, title) == 0 && gtk_widget_get_visible(l->data))
            found = l->data;
    }
    g_list_free(tops);
    return found;
}

/* the first visible widget of type `t` under `wd` */
static GtkWidget *find_type(GtkWidget *wd, GType t)
{
    if (G_TYPE_CHECK_INSTANCE_TYPE(wd, t) && gtk_widget_get_visible(wd))
        return wd;
    if (GTK_IS_CONTAINER(wd)) {
        GList *ch = gtk_container_get_children(GTK_CONTAINER(wd));
        for (GList *l = ch; l != NULL; l = l->next) {
            GtkWidget *r = find_type(l->data, t);
            if (r != NULL) {
                g_list_free(ch);
                return r;
            }
        }
        g_list_free(ch);
    }
    return NULL;
}

static const Protocol__FwChain *pb_chain(const Protocol__SysFirewall *fw, const char *name)
{
    for (size_t i = 0; i < fw->n_systemrules; i++)
        for (size_t j = 0; j < fw->systemrules[i]->n_chains; j++)
            if (strcmp(fw->systemrules[i]->chains[j]->name, name) == 0)
                return fw->systemrules[i]->chains[j];
    return NULL;
}

TEST(firewall_dialogs)
{
    struct ks_node *node = ks_nodes_get(ks_service_nodes(svc), "unix:/local");
    char err[256];
    size_t len;
    char *raw = ks_read_file(KS_FIXTURES_DIR "/../../upstream/daemon/data/system-fw.json",
                             1 << 20, &len, err, sizeof(err));
    CHECK(raw != NULL);
    node->fw = calloc(1, sizeof(*node->fw));
    CHECK(ks_sysfw_parse(raw, len, node->fw, err, sizeof(err)) == 0);
    free(raw);
    free(node->config->config);
    node->config->config = strdup("{\"Firewall\": \"nftables\"}");

    /* fwButton: the policies of the node */
    struct ks_fw_dlg *d = ks_sw_fw_dialog(w->fw);
    ks_fw_dlg_show(d);
    spin();
    GtkWidget *fwwin = window_titled("Firewall");
    CHECK(fwwin != NULL);
    GtkWidget *inbound = input_of(find_in_label(fwwin, "Inbound"));
    CHECK(inbound != NULL && GTK_IS_COMBO_BOX(inbound));
    CHECK_INT_EQ(gtk_combo_box_get_active(GTK_COMBO_BOX(inbound)), 0);

    /* inbound: deny -> the drop profile goes to the daemon */
    gtk_combo_box_set_active(GTK_COMBO_BOX(inbound), 1);
    spin();
    Protocol__Notification *n = last_queued("unix:/local");
    CHECK(n != NULL && n->type == PROTOCOL__ACTION__RELOAD_FW_RULES && n->sysfirewall != NULL);
    const Protocol__FwChain *in = pb_chain(n->sysfirewall, "filter_input");
    CHECK(in != NULL);
    CHECK_STR_EQ(in->policy, "drop");
    CHECK_INT_EQ(in->n_rules, 3);
    reply("unix:/local", n->id, false, "");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    spin();
    CHECK(on_screen("Configuration applied."));

    /* Allow service (OUT): port 22 */
    ks_fwrule_dlg_exclude_service(ks_fw_dlg_rule_dialog(d), KS_FWF_OUT);
    spin();
    GtkWidget *rwin = window_titled("Exclude service");
    CHECK(rwin != NULL);
    GtkWidget *value = find_type(rwin, GTK_TYPE_COMBO_BOX_ENTRY);
    CHECK(value != NULL);
    gtk_entry_set_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(value))), "22");
    gtk_button_clicked(GTK_BUTTON(find_labeled(rwin, "_Add")));
    spin();
    n = last_queued("unix:/local");
    CHECK(n != NULL && n->type == PROTOCOL__ACTION__RELOAD_FW_RULES);
    const Protocol__FwChain *out = pb_chain(n->sysfirewall, "mangle_output");
    CHECK(out != NULL && out->n_rules == 5);
    const Protocol__FwRule *r = out->rules[0];
    /* the protocol combo starts at "tcp,udp", as upstream's */
    CHECK_STR_EQ(r->expressions[0]->statement->name, "meta");
    CHECK_STR_EQ(r->expressions[0]->statement->values[0]->key, "l4proto");
    CHECK_STR_EQ(r->expressions[0]->statement->values[0]->value, "tcp,udp");
    CHECK_STR_EQ(r->expressions[0]->statement->values[1]->key, "dport");
    CHECK_STR_EQ(r->expressions[0]->statement->values[1]->value, "22");
    CHECK_STR_EQ(r->target, "accept");
    char uuid[64];
    snprintf(uuid, sizeof(uuid), "%s", r->uuid);
    reply("unix:/local", n->id, false, "");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    spin();
    CHECK(on_screen("Rule added"));

    /* the "Firewall" entry of the rules combo: every rule of the node */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(w->nb), 2);
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_rules), 4);
    ks_sw_run_query(w, ks_sw_tab(w, KS_TAB_RULES), false);
    spin();
    CHECK(ks_sw_fw_visible(w->fw));
    CHECK(!gtk_widget_get_visible(w->rules_sw));
    CHECK_STR_EQ(gtk_label_get_text(GTK_LABEL(w->rows_label)), "9"); /* 6 + 2 of the profile + 1 */
    gtk_entry_set_text(GTK_ENTRY(w->filter), "dport 22");
    spin();
    CHECK_STR_EQ(gtk_label_get_text(GTK_LABEL(w->rows_label)), "2");
    gtk_entry_set_text(GTK_ENTRY(w->filter), "");
    gtk_combo_box_set_active(GTK_COMBO_BOX(w->combo_rules), 0);
    spin();
    CHECK(!ks_sw_fw_visible(w->fw));
    gtk_notebook_set_current_page(GTK_NOTEBOOK(w->nb), 0);

    /* editing it: the rule dialog loads it; an error naming it is shown */
    ks_fw_dlg_load_rule(d, "unix:/local", uuid);
    spin();
    rwin = window_titled("Firewall rule");
    CHECK(rwin != NULL);
    /* KS_SHOT_DIR: screenshots of the dialogs */
    const char *shots = getenv("KS_SHOT_DIR");
    if (shots != NULL) {
        char cmd[512];
        gtk_window_move(GTK_WINDOW(fwwin), 0, 0);
        gtk_window_move(GTK_WINDOW(rwin), 420, 0);
        spin();
        snprintf(cmd, sizeof(cmd), "import -window root '%s/firewall-dialogs.png'", shots);
        if (system(cmd) != 0)
            fprintf(stderr, "screenshot failed\n");
    }
    CHECK(on_screen("tcp,udp dport == ssh/22") || on_screen("tcp,udp dport == 22")); /* the service of the port, if /etc/services has it */
    gtk_button_clicked(GTK_BUTTON(find_labeled(rwin, "_Save")));
    spin();
    n = last_queued("unix:/local");
    CHECK(n != NULL);
    char data[256];
    snprintf(data, sizeof(data), "%s invalid rule parameters (%s),", uuid, uuid);
    reply("unix:/local", n->id, true, data);
    protobuf_c_message_free_unpacked(&n->base, NULL);
    spin();
    CHECK(on_screen("Error saving rule"));
    gtk_widget_hide(rwin);
    gtk_widget_hide(fwwin);
}

/* ---- the simplified firewall panel ---------------------------------------------- */

static int fill_step;

static gboolean fill_new_rule(gpointer ud)
{
    (void)ud;
    GtkWidget *win = window_titled("New rule");
    if (win == NULL)
        return TRUE; /* not open yet */
    GtkWidget *port = input_of(find_in_label(win, "Port"));
    if (fill_step == 0) {
        /* an invalid port first: the dialog stays, with the form's message */
        gtk_combo_box_set_active(GTK_COMBO_BOX(input_of(find_in_label(win, "Protocol"))), 2);
        gtk_entry_set_text(GTK_ENTRY(port), "abc");
        gtk_entry_set_text(GTK_ENTRY(input_of(find_in_label(win, "From"))), "10.0.0.0/8");
        gtk_entry_set_text(GTK_ENTRY(input_of(find_in_label(win, "Description"))), "web");
        fill_step = 1;
        gtk_dialog_response(GTK_DIALOG(win), GTK_RESPONSE_OK);
        return TRUE;
    }
    if (fill_step == 1) {
        if (!on_screen("port not valid."))
            return TRUE;
        gtk_entry_set_text(GTK_ENTRY(port), "8080");
        fill_step = 2;
        gtk_dialog_response(GTK_DIALOG(win), GTK_RESPONSE_OK);
    }
    return FALSE;
}

static bool store_has(GtkTreeModel *m, int col, const char *text)
{
    GtkTreeIter it;
    for (bool ok = gtk_tree_model_get_iter_first(m, &it); ok; ok = gtk_tree_model_iter_next(m, &it)) {
        char *v = NULL;
        gtk_tree_model_get(m, &it, col, &v, -1);
        bool hit = v != NULL && strcmp(v, text) == 0;
        g_free(v);
        if (hit)
            return true;
    }
    return false;
}

TEST(firewall_simple_panel)
{
    struct ks_fw_dlg *d = ks_sw_fw_dialog(w->fw);
    ks_fw_dlg_show(d);
    spin();
    GtkWidget *fwwin = window_titled("Firewall");
    CHECK(fwwin != NULL);
    gtk_button_clicked(GTK_BUTTON(find_labeled(fwwin, "_Rules (simple)")));
    spin();
    GtkWidget *win = window_titled("Firewall rules");
    CHECK(win != NULL);
    GtkWidget *view = find_type(win, GTK_TYPE_TREE_VIEW);
    CHECK(view != NULL);
    GtkTreeModel *m = gtk_tree_view_get_model(GTK_TREE_VIEW(view));
    /* the inbound drop policy of the previous test: its rules, as "Policy" */
    CHECK(store_has(m, 2, "Policy"));
    /* the "Allow service (OUT)" rule: tcp,udp dport 22, accept, output */
    CHECK(store_has(m, 4, "tcp+udp 22"));
    GtkWidget *incoming =
        find_type(gtk_widget_get_parent(find_in_label(win, "Incoming:")), GTK_TYPE_COMBO_BOX);
    CHECK(incoming != NULL);
    CHECK_INT_EQ(gtk_combo_box_get_active(GTK_COMBO_BOX(incoming)), 1);

    /* a new rule through the dialog */
    fill_step = 0;
    g_timeout_add(50, fill_new_rule, NULL);
    gtk_button_clicked(GTK_BUTTON(find_labeled(win, "_Add")));
    spin();
    CHECK_INT_EQ(fill_step, 2);
    Protocol__Notification *n = last_queued("unix:/local");
    CHECK(n != NULL && n->type == PROTOCOL__ACTION__RELOAD_FW_RULES);
    const Protocol__FwChain *in = pb_chain(n->sysfirewall, "filter_input");
    CHECK(in != NULL && in->n_rules >= 1);
    const Protocol__FwRule *r = in->rules[in->n_rules - 1];
    CHECK_STR_EQ(r->description, "web");
    CHECK_STR_EQ(r->target, "accept");
    CHECK_STR_EQ(r->expressions[0]->statement->name, "tcp");
    CHECK_STR_EQ(r->expressions[0]->statement->values[0]->value, "8080");
    CHECK_STR_EQ(r->expressions[1]->statement->name, "ip");
    CHECK_STR_EQ(r->expressions[1]->statement->values[0]->key, "saddr");
    CHECK_STR_EQ(r->expressions[1]->statement->values[0]->value, "10.0.0.0-10.255.255.255");
    reply("unix:/local", n->id, false, "");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    spin();
    CHECK(on_screen("Configuration applied."));
    CHECK(store_has(m, 4, "tcp 8080"));
    CHECK(store_has(m, 5, "10.0.0.0/8"));

    /* outgoing: deny */
    GtkWidget *box = gtk_widget_get_parent(find_in_label(win, "   Outgoing:"));
    GList *ch = gtk_container_get_children(GTK_CONTAINER(box));
    GtkWidget *combo_out = g_list_nth_data(ch, 3);
    g_list_free(ch);
    CHECK(combo_out != NULL && GTK_IS_COMBO_BOX(combo_out));
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_out), 1);
    spin();
    n = last_queued("unix:/local");
    CHECK(n != NULL);
    const Protocol__FwChain *out = pb_chain(n->sysfirewall, "mangle_output");
    CHECK(out != NULL);
    CHECK_STR_EQ(out->policy, "drop");
    reply("unix:/local", n->id, false, "");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    spin();
    CHECK(on_screen("Output policy configured to drop"));

    const char *shots = getenv("KS_SHOT_DIR");
    if (shots != NULL) {
        char cmd[512];
        gtk_window_move(GTK_WINDOW(win), 0, 0);
        spin();
        snprintf(cmd, sizeof(cmd), "import -window root '%s/firewall-simple.png'", shots);
        if (system(cmd) != 0)
            fprintf(stderr, "screenshot failed\n");
    }
    gtk_widget_hide(win);
    gtk_widget_hide(fwwin);
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
    RUN(preferences_save);
    RUN(export_csv);
    RUN(firewall_dialogs);
    RUN(firewall_simple_panel);

    ks_stats_win_free(w);
    ks_service_free(svc);
    ks_settings_close(&settings);
    return harness_report();
}
