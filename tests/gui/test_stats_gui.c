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

/* any label of any window whose text has `needle` */
static bool find_in(GtkWidget *wd, const char *needle)
{
    if (GTK_IS_LABEL(wd) && strstr(gtk_label_get_text(GTK_LABEL(wd)), needle) != NULL)
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

    ks_stats_win_free(w);
    ks_service_free(svc);
    ks_settings_close(&settings);
    return harness_report();
}
