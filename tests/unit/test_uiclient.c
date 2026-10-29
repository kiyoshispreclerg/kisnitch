/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI client (daemon/uiclient.c) against a fake UI: our own gRPC server
 * on a unix socket, served by the same event loop.
 */
#include "daemon/uiclient.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/grpc/grpc.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/procmon/process.h"
#include "daemon/procmon/procmon.h"
#include "daemon/protocol.h"
#include "daemon/rules/loader.h"
#include "daemon/rules/rule.h"
#include "daemon/stats.h"
#include "tests/harness.h"

static struct ks_evloop *loop;
static char dir[64], sock_path[100], config_path[256], rules_dir[256];

/* ---- the fake UI -------------------------------------------------------- */

static struct {
    int lfd;
    struct ks_grpc_conn *conn;
    struct ks_grpc_call *ntf; /* the daemon's Notifications stream */
    int subscribes, pings, alerts, ntf_replies;
    char hostname[256];
    char sub_config[4096];
    size_t sub_rules;
    uint64_t last_reply_id;
    int last_reply_code;
    char last_reply_data[512];
    uint64_t ping_connections;
    size_t ping_events;
    char alert_text[256];
    /* AskRule: answer with this rule, or fail if NULL */
    const char *ask_action;
    int asks;
    char ask_path[256];
    const char *ui_default_action;
} ui;

static void srv_io(int fd, uint32_t events, void *data)
{
    (void)fd;
    (void)data;
    if (ui.conn)
        ks_grpc_conn_on_io(ui.conn, (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0,
                           (events & EPOLLOUT) != 0);
}

static void srv_want_write(struct ks_grpc_conn *conn, bool on, void *data)
{
    (void)data;
    ks_evloop_mod_fd(loop, ks_grpc_conn_fd(conn), EPOLLIN | (on ? EPOLLOUT : 0));
}

static void srv_closed(struct ks_grpc_conn *conn, const char *reason, void *data)
{
    (void)reason;
    (void)data;
    ks_evloop_del_fd(loop, ks_grpc_conn_fd(conn));
    ui.ntf = NULL;
    /* freed by the test (or the next accept) */
}

static void reply_msg(struct ks_grpc_call *call, const ProtobufCMessage *m)
{
    size_t len;
    uint8_t *buf = ks_pb_pack(m, &len);
    ks_grpc_call_send(call, buf, len);
    free(buf);
    ks_grpc_call_finish(call, KS_GRPC_OK, NULL);
}

static void on_unary(struct ks_grpc_call *call, const uint8_t *msg, size_t len, void *data)
{
    const char *method = data;
    if (strcmp(method, "Subscribe") == 0) {
        Protocol__ClientConfig *cc = (Protocol__ClientConfig *)ks_pb_unpack(
            &protocol__client_config__descriptor, msg, len);
        if (cc == NULL)
            return;
        ui.subscribes++;
        snprintf(ui.hostname, sizeof(ui.hostname), "%s", cc->name);
        snprintf(ui.sub_config, sizeof(ui.sub_config), "%s", cc->config);
        ui.sub_rules = cc->n_rules;
        protobuf_c_message_free_unpacked(&cc->base, NULL);
        char cfg[256];
        snprintf(cfg, sizeof(cfg), "{\"DefaultAction\": \"%s\"}", ui.ui_default_action);
        Protocol__ClientConfig r = PROTOCOL__CLIENT_CONFIG__INIT;
        r.config = cfg;
        reply_msg(call, &r.base);
    } else if (strcmp(method, "Ping") == 0) {
        Protocol__PingRequest *p = (Protocol__PingRequest *)ks_pb_unpack(
            &protocol__ping_request__descriptor, msg, len);
        if (p == NULL)
            return;
        ui.pings++;
        ui.ping_connections = p->stats ? p->stats->connections : 0;
        ui.ping_events = p->stats ? p->stats->n_events : 0;
        Protocol__PingReply r = PROTOCOL__PING_REPLY__INIT;
        r.id = p->id;
        protobuf_c_message_free_unpacked(&p->base, NULL);
        reply_msg(call, &r.base);
    } else if (strcmp(method, "PostAlert") == 0) {
        Protocol__Alert *a = (Protocol__Alert *)ks_pb_unpack(&protocol__alert__descriptor,
                                                             msg, len);
        if (a == NULL)
            return;
        ui.alerts++;
        if (a->data_case == PROTOCOL__ALERT__DATA_TEXT)
            snprintf(ui.alert_text, sizeof(ui.alert_text), "%s", a->text);
        protobuf_c_message_free_unpacked(&a->base, NULL);
        Protocol__MsgResponse r = PROTOCOL__MSG_RESPONSE__INIT;
        reply_msg(call, &r.base);
    } else if (strcmp(method, "AskRule") == 0) {
        Protocol__Connection *c = (Protocol__Connection *)ks_pb_unpack(
            &protocol__connection__descriptor, msg, len);
        if (c == NULL)
            return;
        ui.asks++;
        snprintf(ui.ask_path, sizeof(ui.ask_path), "%s", c->process_path);
        protobuf_c_message_free_unpacked(&c->base, NULL);
        if (ui.ask_action == NULL) {
            /* like the Python UI returning None */
            ks_grpc_call_finish(call, KS_GRPC_UNKNOWN, "Exception serializing response!");
            return;
        }
        if (strcmp(ui.ask_action, "hang") == 0)
            return;
        Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
        op.type = "simple";
        op.operand = "process.path";
        op.data = ui.ask_path;
        Protocol__Rule r = PROTOCOL__RULE__INIT;
        r.name = "allow-from-ui";
        r.action = (char *)ui.ask_action;
        r.duration = "until restart";
        r.enabled = true;
        r.operator_ = &op;
        reply_msg(call, &r.base);
    }
}

static void on_ntf_reply(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                         void *data)
{
    (void)call;
    (void)data;
    Protocol__NotificationReply *r = (Protocol__NotificationReply *)ks_pb_unpack(
        &protocol__notification_reply__descriptor, msg, len);
    if (r == NULL)
        return;
    ui.ntf_replies++;
    ui.last_reply_id = r->id;
    ui.last_reply_code = r->code;
    snprintf(ui.last_reply_data, sizeof(ui.last_reply_data), "%s", r->data);
    protobuf_c_message_free_unpacked(&r->base, NULL);
}

static void on_ntf_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    (void)status;
    (void)message;
    (void)data;
    if (call == ui.ntf)
        ui.ntf = NULL;
}

static int srv_on_call(struct ks_grpc_conn *conn, struct ks_grpc_call *call,
                       const char *path, void *data)
{
    (void)conn;
    (void)data;
    static const struct ks_grpc_call_cbs unary = {on_unary, NULL, NULL};
    static const struct ks_grpc_call_cbs stream = {on_ntf_reply, NULL, on_ntf_close};
    static const char *const methods[] = {"Subscribe", "Ping", "PostAlert", "AskRule"};
    for (size_t i = 0; i < 4; i++) {
        char p[64];
        snprintf(p, sizeof(p), "/protocol.UI/%s", methods[i]);
        if (strcmp(path, p) == 0) {
            ks_grpc_call_set_cbs(call, &unary, (void *)methods[i]);
            return KS_GRPC_OK;
        }
    }
    if (strcmp(path, "/protocol.UI/Notifications") == 0) {
        ks_grpc_call_set_cbs(call, &stream, NULL);
        ui.ntf = call;
        return KS_GRPC_OK;
    }
    return KS_GRPC_UNIMPLEMENTED;
}

static void srv_accept(int fd, uint32_t events, void *data)
{
    (void)events;
    (void)data;
    int c = accept(fd, NULL, NULL);
    if (c < 0)
        return;
    fcntl(c, F_SETFL, O_NONBLOCK);
    if (ui.conn) {
        ks_evloop_del_fd(loop, ks_grpc_conn_fd(ui.conn));
        ks_grpc_conn_free(ui.conn);
    }
    struct ks_grpc_conn_opts o = {.server = true};
    struct ks_grpc_conn_cbs cbs = {.on_call = srv_on_call, .on_closed = srv_closed,
                                   .want_write = srv_want_write};
    ui.conn = ks_grpc_conn_new(c, &o, &cbs, NULL);
    ks_evloop_add_fd(loop, c, EPOLLIN | EPOLLOUT, srv_io, NULL);
}

static int ui_start(void)
{
    ui.lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock_path);
    unlink(sock_path);
    if (ui.lfd < 0 || bind(ui.lfd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
        listen(ui.lfd, 4) < 0)
        return -1;
    return ks_evloop_add_fd(loop, ui.lfd, EPOLLIN, srv_accept, NULL);
}

static void ui_stop(void)
{
    if (ui.conn) {
        ks_evloop_del_fd(loop, ks_grpc_conn_fd(ui.conn));
        ks_grpc_conn_free(ui.conn);
        ui.conn = NULL;
    }
    ui.ntf = NULL;
    if (ui.lfd >= 0) {
        ks_evloop_del_fd(loop, ui.lfd);
        close(ui.lfd);
        ui.lfd = -1;
    }
    unlink(sock_path);
}

static void send_notification(Protocol__Notification *n)
{
    size_t len;
    uint8_t *buf = ks_pb_pack(&n->base, &len);
    if (ui.ntf)
        ks_grpc_call_send(ui.ntf, buf, len);
    free(buf);
}

/* ---- helpers ------------------------------------------------------------ */

static bool run_until(bool (*cond)(void), int ms)
{
    int64_t until = ks_grpc_now() + (int64_t)ms * 1000000;
    while (ks_grpc_now() < until) {
        if (cond())
            return true;
        ks_evloop_run_once(loop, 20);
    }
    return cond();
}

static struct ks_uiclient *client;

static bool has_ntf(void) { return ui.ntf != NULL && ui.ntf_replies >= 1; }
static int want_replies;
static bool replies_reached(void) { return ui.ntf_replies >= want_replies; }
static bool has_ping(void) { return ui.pings > 0; }
static bool has_alert(void) { return ui.alerts > 0; }
static bool no_tasks(void) { return ks_uiclient_task_count(client) == 0; }
static bool is_disconnected(void) { return !ks_uiclient_connected(client); }

static void write_file(const char *path, const char *s)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(s, f);
        fclose(f);
    }
}

static void write_config(const char *default_action)
{
    char cfg[1024];
    snprintf(cfg, sizeof(cfg),
             "{\n  \"Server\": {\"Address\": \"unix://%s\", \"LogFile\": \"\"},\n"
             "  \"DefaultAction\": \"%s\",\n  \"DefaultDuration\": \"once\",\n"
             "  \"InterceptUnknown\": false,\n  \"ProcMonitorMethod\": \"proc\",\n"
             "  \"LogLevel\": 4,\n  \"Firewall\": \"nftables\",\n"
             "  \"Rules\": {\"Path\": \"%s\"},\n"
             "  \"Stats\": {\"MaxEvents\": 150, \"MaxStats\": 25, \"Workers\": 6}\n}\n",
             sock_path, default_action, rules_dir);
    write_file(config_path, cfg);
}

static struct ks_loader *rules;
static struct ks_stats stats;

static int setup(void)
{
    snprintf(dir, sizeof(dir), "/tmp/ks-uiclient-XXXXXX");
    if (mkdtemp(dir) == NULL)
        return -1;
    snprintf(sock_path, sizeof(sock_path), "%s/ui.sock", dir);
    snprintf(config_path, sizeof(config_path), "%s/default-config.json", dir);
    snprintf(rules_dir, sizeof(rules_dir), "%s/rules", dir);
    mkdir(rules_dir, 0700);
    write_config("allow");
    loop = ks_evloop_new();
    rules = ks_loader_new(loop, NULL, true);
    ks_stats_init(&stats, rules);
    memset(&ui, 0, sizeof(ui));
    ui.lfd = -1;
    ui.ask_action = "allow";
    ui.ui_default_action = "reject";
    if (ui_start() < 0)
        return -1;
    struct ks_uiclient_deps deps = {.loop = loop, .rules = rules, .stats = &stats};
    client = ks_uiclient_new(&deps, NULL, config_path);
    return client ? 0 : -1;
}

static void teardown(void)
{
    ks_uiclient_free(client);
    client = NULL;
    ui_stop();
    ks_stats_free(&stats);
    ks_loader_free(rules);
    ks_procmon_end();
    ks_evloop_free(loop);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "could not remove %s\n", dir);
    ks_log_set_level(KS_LOG_INFO);
}

/* ---- tests ---------------------------------------------------------------- */

TEST(subscribe_and_notifications)
{
    CHECK(setup() == 0);
    /* the configuration was applied */
    CHECK_STR_EQ(ks_uiclient_config(client)->default_action, "allow");
    CHECK_STR_EQ(ks_loader_path(rules), rules_dir);
    CHECK_STR_EQ(ks_procmon_get_method(), "proc");
    CHECK_STR_EQ(ks_uiclient_default_action(client), "allow"); /* not connected */

    CHECK(run_until(has_ntf, 3000));
    CHECK_INT_EQ(ui.subscribes, 1);
    CHECK(strchr(ui.sub_config, '\n') == NULL); /* sent without newlines */
    CHECK(strstr(ui.sub_config, "\"DefaultAction\": \"allow\"") != NULL);
    CHECK(ui.hostname[0] != '\0');
    CHECK_INT_EQ(ui.last_reply_id, 0); /* the hello */
    /* while connected, DefaultAction is the UI's */
    CHECK_STR_EQ(ks_uiclient_default_action(client), "reject");

    /* CHANGE_RULE: a new "always" rule is saved */
    Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
    op.type = "simple";
    op.operand = "dest.host";
    op.data = "example.com";
    Protocol__Rule r = PROTOCOL__RULE__INIT;
    r.name = "deny-example";
    r.action = "deny";
    r.duration = "always";
    r.enabled = true;
    r.operator_ = &op;
    Protocol__Rule *rl[] = {&r};
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.id = 1001;
    n.type = PROTOCOL__ACTION__CHANGE_RULE;
    n.rules = rl;
    n.n_rules = 1;
    want_replies = 2;
    send_notification(&n);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_id, 1001);
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    const struct ks_rule *got = ks_loader_get(rules, "deny-example");
    CHECK(got != NULL && got->enabled);
    char file[300];
    snprintf(file, sizeof(file), "%s/deny-example.json", rules_dir);
    CHECK(access(file, F_OK) == 0);

    /* DISABLE_RULE */
    n.id = 1002;
    n.type = PROTOCOL__ACTION__DISABLE_RULE;
    want_replies = 3;
    send_notification(&n);
    CHECK(run_until(replies_reached, 2000));
    got = ks_loader_get(rules, "deny-example");
    CHECK(got != NULL && !got->enabled);

    /* DELETE_RULE */
    n.id = 1003;
    n.type = PROTOCOL__ACTION__DELETE_RULE;
    want_replies = 4;
    send_notification(&n);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    CHECK(ks_loader_get(rules, "deny-example") == NULL);
    CHECK(access(file, F_OK) != 0);

    /* TASK_START: the UI's notification IDs are timestamps, and the task's
     * results come back as replies to that ID */
    Protocol__Notification t = PROTOCOL__NOTIFICATION__INIT;
    char tdata[256];
    snprintf(tdata, sizeof(tdata),
             "{\"Name\": \"pid-monitor\", \"Data\": {\"pid\": \"%d\", \"interval\": \"5s\"}}",
             (int)getpid());
    t.id = 1700000000001ull;
    t.type = PROTOCOL__ACTION__TASK_START;
    t.data = tdata;
    want_replies = 5;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_id, 1700000000001ull);
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    CHECK(strncmp(ui.last_reply_data, "{\"Statm\":{\"Size\":", 17) == 0);
    CHECK_INT_EQ(ks_uiclient_task_count(client), 1);

    /* the same PID again */
    t.id = 1700000000002ull;
    want_replies = 6;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_id, 1700000000002ull);
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR);
    char want[128];
    snprintf(want, sizeof(want), "task with name pid-monitor-%d already exists", (int)getpid());
    CHECK_STR_EQ(ui.last_reply_data, want);

    /* TASK_STOP: no reply */
    t.type = PROTOCOL__ACTION__TASK_STOP;
    send_notification(&t);
    CHECK(run_until(no_tasks, 2000));

    /* strconv.Atoi's error; a PID that isn't running */
    t.id = 1700000000003ull;
    t.type = PROTOCOL__ACTION__TASK_START;
    t.data = "{\"name\": \"pid-monitor\", \"data\": {\"pid\": \"abc\"}}";
    want_replies = 7;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_STR_EQ(ui.last_reply_data, "strconv.Atoi: parsing \"abc\": invalid syntax");
    t.data = "{\"name\": \"pid-monitor\", \"data\": {\"pid\": \"-5\"}}";
    want_replies = 8;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_STR_EQ(ui.last_reply_data, "The process is no longer running");
    /* conf["pid"].(string) panics upstream: its message */
    t.data = "{\"name\": \"pid-monitor\", \"data\": {\"pid\": 12}}";
    want_replies = 9;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_STR_EQ(ui.last_reply_data, "interface conversion: interface {} is float64, not string");

    /* lower case keys, as the UI sends them (Go's decoder ignores case) */
    t.id = 1700000000004ull;
    t.data = "{\"name\": \"node-monitor\", \"data\": {\"node\": \"unix:/local\", "
             "\"interval\": \"5s\"}}";
    want_replies = 10;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_id, 1700000000004ull);
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    CHECK(strncmp(ui.last_reply_data, "{\"Uptime\":", 10) == 0);

    t.id = 1700000000005ull;
    t.data = "{\"name\": \"sockets-monitor\", \"data\": {\"interval\": \"5s\", \"state\": 0, "
             "\"proto\": 0, \"family\": 0}}";
    want_replies = 11;
    send_notification(&t);
    /* the dump looks up the owner of every socket in /proc */
    CHECK(run_until(replies_reached, 20000));
    CHECK_INT_EQ(ui.last_reply_id, 1700000000005ull);
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    CHECK(strncmp(ui.last_reply_data, "{\"Table\":[", 10) == 0);
    CHECK_INT_EQ(ks_uiclient_task_count(client), 2);

    t.type = PROTOCOL__ACTION__TASK_STOP;
    t.data = "{\"name\": \"sockets-monitor\", \"data\": {}}";
    send_notification(&t);
    t.data = "{\"name\": \"node-monitor\", \"data\": {\"node\": \"unix:/local\", "
             "\"interval\": \"5s\"}}";
    send_notification(&t);
    CHECK(run_until(no_tasks, 2000));

    /* RELOAD_FW_RULES: phase 8 -> ERROR */
    t.id = 1005;
    t.type = PROTOCOL__ACTION__RELOAD_FW_RULES;
    t.data = "";
    want_replies = 12;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR);

    /* CHANGE_CONFIG: applied, saved verbatim, then reloaded from disk */
    char newcfg[1024];
    snprintf(newcfg, sizeof(newcfg),
             "{\"Server\": {\"Address\": \"unix://%s\"}, \"DefaultAction\": \"deny\", "
             "\"ProcMonitorMethod\": \"proc\", \"LogLevel\": 4, \"Firewall\": \"nftables\", "
             "\"Rules\": {\"Path\": \"%s\"}, \"InterceptUnknown\": true}",
             sock_path, rules_dir);
    t.id = 1006;
    t.type = PROTOCOL__ACTION__CHANGE_CONFIG;
    t.data = newcfg;
    want_replies = 13;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__OK);
    FILE *f = fopen(config_path, "r");
    CHECK(f != NULL);
    char saved[1024] = "";
    size_t sn = fread(saved, 1, sizeof(saved) - 1, f);
    fclose(f);
    saved[sn] = '\0';
    CHECK_STR_EQ(saved, newcfg);
    ks_uiclient_reload_from_disk(client); /* as the inotify event would */
    CHECK(ks_uiclient_intercept_unknown(client));
    CHECK_STR_EQ(ks_uiclient_config(client)->default_action, "deny");

    /* An invalid configuration is refused */
    t.id = 1007;
    t.data = "{not json";
    want_replies = 14;
    send_notification(&t);
    CHECK(run_until(replies_reached, 2000));
    CHECK_INT_EQ(ui.last_reply_code, PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR);
    teardown();
}

static bool ask_done;
static char ask_got_action[32];

static void on_answer(struct ks_rule *r, void *data)
{
    (void)data;
    ask_done = true;
    snprintf(ask_got_action, sizeof(ask_got_action), "%s", r ? r->action : "(nil)");
    ks_rule_free(r);
}

static bool asked(void) { return ask_done; }

static struct ks_proc *mkproc(void)
{
    struct ks_proc *p = ks_proc_new_empty(4321, "curl");
    free(p->path);
    p->path = strdup("/usr/bin/curl");
    ks_proc_sync(p);
    return p;
}

TEST(ask_rule)
{
    CHECK(setup() == 0);
    CHECK(run_until(has_ntf, 3000));
    struct ks_proc *p = mkproc();
    struct ks_conn c;
    memset(&c, 0, sizeof(c));
    c.protocol = "tcp";
    ks_ip_parse("10.0.0.1", &c.src_ip);
    ks_ip_parse("10.0.0.2", &c.dst_ip);
    c.dst_port = 443;
    c.dst_host = "";
    c.process = &p->view;

    ask_done = false;
    CHECK(ks_uiclient_ask(client, &c, p, on_answer, NULL) == 0);
    CHECK(ks_uiclient_is_asking(client));
    CHECK(ks_uiclient_ask(client, &c, p, on_answer, NULL) < 0); /* one at a time */
    CHECK(run_until(asked, 2000));
    CHECK_STR_EQ(ask_got_action, "allow");
    CHECK_STR_EQ(ui.ask_path, "/usr/bin/curl");
    CHECK(!ks_uiclient_is_asking(client));

    /* the UI fails the call: NULL rule */
    ui.ask_action = NULL;
    ask_done = false;
    ks_log_set_level(KS_LOG_ERROR); /* the warning is expected */
    CHECK(ks_uiclient_ask(client, &c, p, on_answer, NULL) == 0);
    CHECK(run_until(asked, 2000));
    CHECK_STR_EQ(ask_got_action, "(nil)");

    /* the UI goes away while asking: NULL rule, and back to our default */
    ui.ask_action = "hang";
    ask_done = false;
    CHECK(ks_uiclient_ask(client, &c, p, on_answer, NULL) == 0);
    run_until(asked, 200);
    CHECK(!ask_done);
    ks_log_set_level(KS_LOG_FATAL); /* "Connection to the UI service lost." */
    ui_stop();
    CHECK(run_until(asked, 3000));
    CHECK_STR_EQ(ask_got_action, "(nil)");
    CHECK(run_until(is_disconnected, 3000));
    CHECK_STR_EQ(ks_uiclient_default_action(client), "allow");
    CHECK(ks_uiclient_ask(client, &c, p, on_answer, NULL) < 0);
    ks_proc_unref(p);
    teardown();
}

TEST(ping_alerts_and_reconnect)
{
    CHECK(setup() == 0);
    /* an alert before connecting is queued, then delivered */
    ks_uiclient_send_warning_alert(client, "queued before connecting");
    CHECK(run_until(has_alert, 3000));
    CHECK_STR_EQ(ui.alert_text, "queued before connecting");
    CHECK(run_until(has_ntf, 3000));

    /* no new events: no ping */
    run_until(has_ping, 1500);
    CHECK_INT_EQ(ui.pings, 0);

    struct ks_proc *p = mkproc();
    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = "simple";
    op.operand = "true";
    op.data = "";
    struct ks_rule *r = ks_rule_create("allow-all", "", true, false, false, "allow",
                                       "always", &op);
    struct ks_conn c;
    memset(&c, 0, sizeof(c));
    c.protocol = "udp";
    ks_ip_parse("10.0.0.2", &c.dst_ip);
    c.dst_port = 53;
    c.dst_host = "";
    c.process = &p->view;
    ks_stats_on_connection(&stats, &c, p, r, false);
    ks_rule_free(r);
    ks_proc_unref(p);
    CHECK(run_until(has_ping, 2500));
    CHECK_INT_EQ(ui.ping_connections, 1);
    CHECK_INT_EQ(ui.ping_events, 1);
    CHECK_INT_EQ(stats.nevents, 0);

    /* the UI restarts: the daemon reconnects and subscribes again */
    ks_log_set_level(KS_LOG_FATAL);
    ui_stop();
    CHECK(run_until(is_disconnected, 3000));
    CHECK(ui_start() == 0);
    ui.ntf_replies = 0;
    CHECK(run_until(has_ntf, 4000));
    CHECK_INT_EQ(ui.subscribes, 2);

    /* "Server ordered to close notifications" (type NONE) */
    Protocol__Notification n = PROTOCOL__NOTIFICATION__INIT;
    n.id = 7;
    send_notification(&n);
    CHECK(run_until(is_disconnected, 2000));
    ui.ntf_replies = 0;
    CHECK(run_until(has_ntf, 4000));
    CHECK_INT_EQ(ui.subscribes, 3);
    teardown();
}

int main(void)
{
    RUN(subscribe_and_notifications);
    RUN(ask_rule);
    RUN(ping_alerts_and_reconnect);
    return harness_report();
}
