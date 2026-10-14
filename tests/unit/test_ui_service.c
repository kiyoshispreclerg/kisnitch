/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI's gRPC server and service (ui/server.c, ui/service.c) on a GLib
 * main loop, against a fake daemon: a client made with common/grpc/ on a
 * unix socket, calling the RPCs of proto/ui.proto the way the daemon does.
 */
#include "ui/server.h"

#include <fcntl.h>
#include <glib-unix.h>
#include <glib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/grpc/grpc.h"
#include "common/log.h"
#include "common/pb_util.h"
#include "ui/service.h"
#include "tests/harness.h"

static char dir[64], sock_path[96], address[128];
static struct ks_settings settings;
static struct ks_service *svc;
static struct ks_ui_server *srv;

/* ---- what the service asks of the GTK side ----------------------------- */

static struct {
    struct ks_ask *asks[8];
    int nasks;
    int status_changes;
    char last_title[256], last_body[1024];
    int messages;
    char daemon_version[32];
    int version_warnings;
} gui;

static void gui_prompt(void *ud, struct ks_ask *ask)
{
    (void)ud;
    if (gui.nasks < 8)
        gui.asks[gui.nasks++] = ask;
}

static void gui_status(void *ud)
{
    (void)ud;
    gui.status_changes++;
}

static void gui_message(void *ud, const char *title, const char *body)
{
    (void)ud;
    gui.messages++;
    snprintf(gui.last_title, sizeof(gui.last_title), "%s", title);
    snprintf(gui.last_body, sizeof(gui.last_body), "%s", body);
}

static void gui_version(void *ud, const char *d, const char *u)
{
    (void)ud;
    (void)u;
    gui.version_warnings++;
    snprintf(gui.daemon_version, sizeof(gui.daemon_version), "%s", d);
}

/* ---- the fake daemon --------------------------------------------------- */

static struct {
    struct ks_grpc_conn *conn;
    guint in_id, out_id, timer_id;
    bool closed;
} cli;

struct result {
    bool done;
    int status;
    char message[256];
    uint8_t *msg; /* last message */
    size_t len;
    int nmsgs;
};

static void res_reset(struct result *r)
{
    free(r->msg);
    memset(r, 0, sizeof(*r));
}

static void on_res_message(struct ks_grpc_call *c, const uint8_t *m, size_t len, void *data)
{
    (void)c;
    struct result *r = data;
    free(r->msg);
    r->msg = malloc(len ? len : 1);
    memcpy(r->msg, m, len);
    r->len = len;
    r->nmsgs++;
}

static void on_res_close(struct ks_grpc_call *c, int status, const char *msg, void *data)
{
    (void)c;
    struct result *r = data;
    r->done = true;
    r->status = status;
    snprintf(r->message, sizeof(r->message), "%s", msg);
}

static const struct ks_grpc_call_cbs res_cbs = {.on_message = on_res_message,
                                                .on_close = on_res_close};

static gboolean cli_in(gint fd, GIOCondition cond, gpointer data)
{
    (void)fd;
    (void)data;
    ks_grpc_conn_on_io(cli.conn, (cond & (G_IO_IN | G_IO_HUP | G_IO_ERR)) != 0, false);
    if (ks_grpc_conn_closed(cli.conn)) {
        cli.closed = true;
        cli.in_id = 0;
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static gboolean cli_out(gint fd, GIOCondition cond, gpointer data)
{
    (void)fd;
    (void)cond;
    (void)data;
    ks_grpc_conn_on_io(cli.conn, false, true);
    return G_SOURCE_CONTINUE;
}

static void cli_want_write(struct ks_grpc_conn *c, bool on, void *data)
{
    (void)data;
    if (on && cli.out_id == 0)
        cli.out_id = g_unix_fd_add(ks_grpc_conn_fd(c), G_IO_OUT, cli_out, NULL);
    else if (!on && cli.out_id != 0) {
        g_source_remove(cli.out_id);
        cli.out_id = 0;
    }
}

static gboolean cli_tick(gpointer data)
{
    (void)data;
    if (cli.conn && !cli.closed)
        ks_grpc_conn_tick(cli.conn);
    return G_SOURCE_CONTINUE;
}

static void cli_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_un un = {.sun_family = AF_UNIX};
    snprintf(un.sun_path, sizeof(un.sun_path), "%s", sock_path);
    connect(fd, (struct sockaddr *)&un, sizeof(un));
    static const struct ks_grpc_conn_cbs cbs = {.want_write = cli_want_write};
    struct ks_grpc_conn_opts opts = {.server = false, .authority = "///weird/path"};
    cli.closed = false;
    cli.conn = ks_grpc_conn_new(fd, &opts, &cbs, NULL);
    cli.in_id = g_unix_fd_add(fd, G_IO_IN | G_IO_HUP | G_IO_ERR, cli_in, NULL);
    cli_want_write(cli.conn, true, NULL);
    cli.timer_id = g_timeout_add(20, cli_tick, NULL);
}

static void cli_disconnect(void)
{
    if (cli.in_id)
        g_source_remove(cli.in_id);
    if (cli.out_id)
        g_source_remove(cli.out_id);
    if (cli.timer_id)
        g_source_remove(cli.timer_id);
    ks_grpc_conn_free(cli.conn);
    memset(&cli, 0, sizeof(cli));
}

/* Runs the loop until *flag or ~3 s. */
static bool spin_until(const bool *flag)
{
    for (int i = 0; i < 3000 && !*flag; i++) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        if (!*flag)
            g_usleep(1000);
    }
    return *flag;
}

static void spin(int ms)
{
    for (int i = 0; i < ms; i++) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        g_usleep(1000);
    }
}

static struct ks_grpc_call *unary(const char *method, const ProtobufCMessage *m,
                                  struct result *r, int64_t timeout_ns)
{
    char path[64];
    snprintf(path, sizeof(path), "/protocol.UI/%s", method);
    size_t len;
    uint8_t *buf = ks_pb_pack(m, &len);
    struct ks_grpc_call *c = ks_grpc_unary(cli.conn, path, timeout_ns, buf, len, &res_cbs, r);
    free(buf);
    return c;
}

static int subscribe(const char *config, bool fw_running, struct result *r)
{
    Protocol__ClientConfig cc = PROTOCOL__CLIENT_CONFIG__INIT;
    cc.name = (char *)(uintptr_t) "testhost";
    cc.version = (char *)(uintptr_t) "5.15";
    cc.isfirewallrunning = fw_running;
    cc.config = (char *)(uintptr_t)config;
    Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
    op.type = (char *)(uintptr_t) "simple";
    op.operand = (char *)(uintptr_t) "process.path";
    op.data = (char *)(uintptr_t) "/usr/bin/curl";
    Protocol__Rule rule = PROTOCOL__RULE__INIT;
    rule.name = (char *)(uintptr_t) "existing";
    rule.action = (char *)(uintptr_t) "allow";
    rule.duration = (char *)(uintptr_t) "always";
    rule.enabled = 1;
    rule.operator_ = &op;
    Protocol__Rule *rules[1] = {&rule};
    cc.rules = rules;
    cc.n_rules = 1;
    res_reset(r);
    unary("Subscribe", &cc.base, r, 10000000000LL);
    return spin_until(&r->done) ? 0 : -1;
}

/* ---- tests ------------------------------------------------------------- */

TEST(subscribe_and_ping)
{
    struct result r = {0};
    cli_connect();
    ks_settings_set_raw(&settings, KS_CFG_DEFAULT_ACTION_KEY, "1");
    CHECK(subscribe("{\"Server\": {\"Address\": \"unix:///x\"}, \"DefaultAction\": \"deny\","
                    " \"LogLevel\": 2, \"Stats\": {\"MaxEvents\": 150}}",
                    true, &r) == 0);
    CHECK_INT_EQ(r.status, KS_GRPC_OK);
    Protocol__ClientConfig *reply = (Protocol__ClientConfig *)ks_pb_unpack(
        &protocol__client_config__descriptor, r.msg, r.len);
    CHECK(reply != NULL);
    /* _overwrite_nodes_config(): json.dumps with our DefaultAction */
    CHECK_STR_EQ(reply->config, "{\"Server\": {\"Address\": \"unix:///x\"}, \"DefaultAction\": "
                                "\"allow\", \"LogLevel\": 2, \"Stats\": {\"MaxEvents\": 150}}");
    CHECK_STR_EQ(reply->name, "testhost");
    CHECK_INT_EQ(reply->n_rules, 1);
    protobuf_c_message_free_unpacked(&reply->base, NULL);

    struct ks_service_state st = ks_service_state(svc);
    CHECK(st.connected);
    CHECK(st.fw_enabled);
    CHECK(st.fw_menu_enabled);
    CHECK_INT_EQ(ks_nodes_count(ks_service_nodes(svc)), 1);
    CHECK_STR_EQ(ks_nodes_hostname(ks_service_nodes(svc), "unix:/local"), "testhost");
    /* the node's rules are in the table */
    CHECK(ks_rulesdb_get(ks_service_rules(svc), "existing", "unix:/local") != NULL);

    /* Ping: the same id back; a 1.6.5 daemon gets the version warning, once */
    Protocol__Statistics stats = PROTOCOL__STATISTICS__INIT;
    stats.daemon_version = (char *)(uintptr_t) "1.6.5";
    Protocol__PingRequest ping = PROTOCOL__PING_REQUEST__INIT;
    ping.id = 777;
    ping.stats = &stats;
    for (int i = 0; i < 2; i++) {
        res_reset(&r);
        unary("Ping", &ping.base, &r, 1000000000LL);
        CHECK(spin_until(&r.done));
        CHECK_INT_EQ(r.status, KS_GRPC_OK);
        Protocol__PingReply *pr =
            (Protocol__PingReply *)ks_pb_unpack(&protocol__ping_reply__descriptor, r.msg, r.len);
        CHECK(pr != NULL);
        CHECK_INT_EQ(pr->id, 777);
        protobuf_c_message_free_unpacked(&pr->base, NULL);
    }
    CHECK_INT_EQ(gui.version_warnings, 1);
    CHECK_STR_EQ(gui.daemon_version, "1.6.5");

    /* PostAlert */
    Protocol__Alert alert = PROTOCOL__ALERT__INIT;
    alert.type = PROTOCOL__ALERT__TYPE__WARNING;
    alert.action = PROTOCOL__ALERT__ACTION__SHOW_ALERT;
    alert.data_case = PROTOCOL__ALERT__DATA_TEXT;
    alert.text = (char *)(uintptr_t) "something happened";
    res_reset(&r);
    unary("PostAlert", &alert.base, &r, 1000000000LL);
    CHECK(spin_until(&r.done));
    CHECK_INT_EQ(r.status, KS_GRPC_OK);
    CHECK_STR_EQ(gui.last_title, "Warning");
    CHECK_STR_EQ(gui.last_body, "something happened");

    /* unknown method */
    res_reset(&r);
    unary("Nope", &alert.base, &r, 1000000000LL);
    CHECK(spin_until(&r.done));
    CHECK_INT_EQ(r.status, KS_GRPC_UNIMPLEMENTED);
    res_reset(&r);
    cli_disconnect();
    spin(50);
}

static struct result ntf_res;
static uint8_t ntf_last[512];
static size_t ntf_last_len;
static int ntf_count;

static void on_ntf_msg(struct ks_grpc_call *c, const uint8_t *m, size_t len, void *data)
{
    (void)c;
    (void)data;
    if (len <= sizeof(ntf_last)) {
        memcpy(ntf_last, m, len);
        ntf_last_len = len;
    }
    ntf_count++;
}

static const struct ks_grpc_call_cbs ntf_cbs = {.on_message = on_ntf_msg,
                                                .on_close = on_res_close};

TEST(notifications)
{
    struct result r = {0};
    cli_connect();
    CHECK(subscribe("{\"DefaultAction\": \"deny\"}", false, &r) == 0);
    struct ks_service_state st = ks_service_state(svc);
    CHECK(st.connected);
    CHECK(!st.fw_enabled);

    res_reset(&ntf_res);
    ntf_count = 0;
    struct ks_grpc_call *stream =
        ks_grpc_call_start(cli.conn, "/protocol.UI/Notifications", 0, &ntf_cbs, &ntf_res);
    CHECK(stream != NULL);
    /* the daemon's first reply (id 0) */
    Protocol__NotificationReply first = PROTOCOL__NOTIFICATION_REPLY__INIT;
    size_t len;
    uint8_t *buf = ks_pb_pack(&first.base, &len);
    ks_grpc_call_send(stream, buf, len);
    free(buf);
    spin(50);

    /* the tray's Enable: ENABLE_INTERCEPTION goes out on the stream */
    ks_service_toggle_interception(svc);
    CHECK(ks_service_state(svc).fw_enabled);
    for (int i = 0; i < 300 && ntf_count == 0; i++)
        spin(1);
    CHECK_INT_EQ(ntf_count, 1);
    Protocol__Notification *n = (Protocol__Notification *)ks_pb_unpack(
        &protocol__notification__descriptor, ntf_last, ntf_last_len);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__ENABLE_INTERCEPTION);
    CHECK(n->id > 1000000000000000ULL); /* time.time() without the dot */
    /* the reply is matched by id */
    Protocol__NotificationReply rep = PROTOCOL__NOTIFICATION_REPLY__INIT;
    rep.id = n->id;
    protobuf_c_message_free_unpacked(&n->base, NULL);
    buf = ks_pb_pack(&rep.base, &len);
    ks_grpc_call_send(stream, buf, len);
    free(buf);
    spin(50);
    CHECK_INT_EQ(ks_service_nodes(svc)->nsent, 0);

    /* the stream ends: the node goes, and we're disconnected */
    ks_grpc_call_cancel(stream);
    spin(100);
    CHECK_INT_EQ(ks_nodes_count(ks_service_nodes(svc)), 0);
    st = ks_service_state(svc);
    CHECK(!st.connected);
    CHECK(!st.fw_enabled);
    CHECK(!st.fw_menu_enabled);
    res_reset(&r);
    cli_disconnect();
    spin(50);
}

static Protocol__Rule *answer_rule(struct ks_arena *a, const char *action, const char *duration)
{
    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    Protocol__Operator *op = ks_arena_alloc(a, sizeof(*op));
    protocol__rule__init(r);
    protocol__operator__init(op);
    r->name = ks_arena_printf(a, "%s-%s-simple-usr-bin-curl", action, duration);
    r->action = ks_arena_strdup(a, action);
    r->duration = ks_arena_strdup(a, duration);
    r->enabled = 1;
    r->created = 1700000000;
    op->type = ks_arena_strdup(a, "simple");
    op->operand = ks_arena_strdup(a, "process.path");
    op->data = ks_arena_strdup(a, "/usr/bin/curl");
    r->operator_ = op;
    return r;
}

TEST(ask_rule)
{
    struct result r1 = {0}, r2 = {0}, r3 = {0}, sub = {0};
    gui.nasks = 0;
    cli_connect();
    CHECK(subscribe("{}", true, &sub) == 0);

    Protocol__Connection con = PROTOCOL__CONNECTION__INIT;
    con.protocol = (char *)(uintptr_t) "tcp";
    con.dst_ip = (char *)(uintptr_t) "1.2.3.4";
    con.dst_port = 443;
    con.process_path = (char *)(uintptr_t) "/usr/bin/curl";
    unary("AskRule", &con.base, &r1, 120000000000LL);
    unary("AskRule", &con.base, &r2, 120000000000LL);
    /* the third gives up while waiting: never shown */
    unary("AskRule", &con.base, &r3, 300000000LL);
    spin(100);
    CHECK_INT_EQ(gui.nasks, 1); /* one at a time */
    CHECK_STR_EQ(gui.asks[0]->con->process_path, "/usr/bin/curl");
    CHECK_STR_EQ(gui.asks[0]->node, "unix:/local");
    CHECK_STR_EQ(gui.asks[0]->peer, "unix:");
    CHECK(gui.asks[0]->is_local);
    CHECK(spin_until(&r3.done));
    /* the server enforces the deadline too: whichever side is first */
    CHECK(r3.status == KS_GRPC_DEADLINE_EXCEEDED || r3.status == KS_GRPC_CANCELLED);

    /* the answer goes back and into the table; the next question shows */
    struct ks_arena a = {0};
    ks_service_answer(svc, gui.asks[0], answer_rule(&a, "allow", "always"), true);
    ks_arena_free(&a);
    CHECK(spin_until(&r1.done));
    CHECK_INT_EQ(r1.status, KS_GRPC_OK);
    Protocol__Rule *got =
        (Protocol__Rule *)ks_pb_unpack(&protocol__rule__descriptor, r1.msg, r1.len);
    CHECK(got != NULL);
    CHECK_STR_EQ(got->name, "allow-always-simple-usr-bin-curl");
    protobuf_c_message_free_unpacked(&got->base, NULL);
    CHECK(ks_rulesdb_get(ks_service_rules(svc), "allow-always-simple-usr-bin-curl",
                         "unix:/local") != NULL);
    /* the timeout message */
    CHECK_STR_EQ(gui.last_title, "/usr/bin/curl");
    CHECK_STR_HAS(gui.last_body, "allow action applied");

    CHECK_INT_EQ(gui.nasks, 2);
    /* no rule: the daemon gets an error and applies its default */
    ks_service_answer(svc, gui.asks[1], NULL, false);
    CHECK(spin_until(&r2.done));
    CHECK_INT_EQ(r2.status, KS_GRPC_UNKNOWN);
    CHECK_INT_EQ(gui.nasks, 2);

    /* a question whose daemon goes away stays on screen; answering it is
     * harmless */
    struct result r4 = {0};
    unary("AskRule", &con.base, &r4, 120000000000LL);
    spin(50);
    CHECK_INT_EQ(gui.nasks, 3);
    struct ks_ask *last = gui.asks[2];
    cli_disconnect();
    spin(100);
    CHECK(last->call == NULL);
    struct ks_arena b = {0};
    ks_service_answer(svc, last, answer_rule(&b, "deny", "once"), false);
    ks_arena_free(&b);
    res_reset(&r1);
    res_reset(&r2);
    res_reset(&r3);
    res_reset(&r4);
    res_reset(&sub);
    spin(50);
}

TEST(tcp_peer)
{
    /* a TCP server and its peer names */
    char err[256];
    struct ks_ui_server_opts o = {.address = "127.0.0.1:0"};
    struct ks_ui_server *t = ks_ui_server_new(&o, svc, err, sizeof(err));
    CHECK(t != NULL);
    ks_ui_server_free(t);
    o.address = "not-an-address";
    CHECK(ks_ui_server_new(&o, svc, err, sizeof(err)) == NULL);
    o.address = "unix:///nonexistent-dir/x.sock";
    CHECK(ks_ui_server_new(&o, svc, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "Failed to bind");

    char addr[64];
    ks_nodes_peer_addr("unix:", addr, sizeof(addr));
    CHECK_STR_EQ(addr, "unix:/local");
    ks_nodes_peer_addr("ipv4:192.168.1.2:4567", addr, sizeof(addr));
    CHECK_STR_EQ(addr, "ipv4:192.168.1.2");
    ks_nodes_peer_addr("ipv6:[::1]:4567", addr, sizeof(addr));
    CHECK_STR_EQ(addr, "ipv6:["); /* as upstream's split(":") */
    CHECK_INT_EQ(ks_ui_max_msg_length("16MiB"), 16777216);
    CHECK_INT_EQ(ks_ui_max_msg_length(NULL), 4194304);
}

int main(void)
{
    ks_log_set_level(KS_LOG_ERROR);
    snprintf(dir, sizeof(dir), "/tmp/ks-uisvc-XXXXXX");
    if (mkdtemp(dir) == NULL)
        return 1;
    snprintf(sock_path, sizeof(sock_path), "%s/ui.sock", dir);
    snprintf(address, sizeof(address), "unix://%s", sock_path);

    static const struct ks_service_ops ops = {.prompt = gui_prompt,
                                              .status_changed = gui_status,
                                              .message = gui_message,
                                              .version_warning = gui_version};
    ks_settings_parse(&settings, "", 0);
    svc = ks_service_new(&settings, &ops, NULL);
    char err[256];
    struct ks_ui_server_opts opts = {.address = address};
    srv = ks_ui_server_new(&opts, svc, err, sizeof(err));
    if (srv == NULL) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }

    RUN(subscribe_and_ping);
    RUN(notifications);
    RUN(ask_rule);
    RUN(tcp_peer);

    ks_ui_server_free(srv);
    ks_service_free(svc);
    ks_settings_close(&settings);
    unlink(sock_path);
    rmdir(dir);
    return harness_report();
}
