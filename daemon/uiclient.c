/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/ui/client.go, notifications.go, alerts.go and
 * config_utils.go. See uiclient.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/uiclient.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/arena.h"
#include "common/grpc/grpc.h"
#include "common/log.h"
#include "common/vendor/cjson/cJSON.h"
#include "daemon/evloop.h"
#include "daemon/fw/fw.h"
#include "daemon/procmon/procmon.h"
#include "daemon/protocol.h"
#include "daemon/rules/loader.h"
#include "daemon/rules/rule.h"
#include "daemon/sockdiag.h"
#include "daemon/stats.h"

/* Method paths of service protocol.UI. */
#define RPC_PING          "/protocol.UI/Ping"
#define RPC_ASK_RULE      "/protocol.UI/AskRule"
#define RPC_SUBSCRIBE     "/protocol.UI/Subscribe"
#define RPC_NOTIFICATIONS "/protocol.UI/Notifications"
#define RPC_POST_ALERT    "/protocol.UI/PostAlert"

/* Task names (Name in each package of daemon/tasks/), handled from phase 10 on. */
#define TASK_PID_MONITOR     "pid-monitor"
#define TASK_NODE_MONITOR    "node-monitor"
#define TASK_SOCKETS_MONITOR "sockets-monitor"

/* uint64(time.Time{}.UnixNano()): the Id getClientConfig() sends, from a
 * zero time.Time (the multiplication overflows int64 in Go). */
#define ZERO_TIME_UNIX_NANO 11651379494838206464ull

struct alert {
    uint8_t *buf;
    size_t len;
};

/* Name resolution for TCP addresses runs on a thread: our own DNS queries
 * go through the queue this loop serves. */
struct resolve {
    pthread_t thread;
    int pipe[2];
    char host[256], port[64];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int gai_err;
};

struct ks_uiclient {
    struct ks_uiclient_deps d;
    char *config_file;
    struct ks_config config; /* c.config */

    /* c.socketPath, isUnixSocket, unixSockPrefix */
    char *socket_path;
    bool is_unix;
    bool is_abstract;

    struct ks_grpc_conn *conn;
    struct ks_grpc_conn *zombies[4]; /* closed, freed from reap_timer */
    struct ks_timer *reap_timer;
    struct ks_timer *tick_timer;
    int64_t tick_at;
    struct resolve *resolving;

    struct ks_timer *poll_timer; /* isPolling */
    bool was_connected;

    struct ks_grpc_call *subscribe;
    Protocol__ClientConfig *subscribe_reply;
    struct ks_grpc_call *notifications;
    struct ks_grpc_call *ping;
    uint64_t ping_id;
    bool pong_ok;

    struct ks_grpc_call *ask;
    Protocol__Rule *ask_reply;
    ks_ask_cb ask_cb;
    void *ask_data;
    char ask_desc[512];
    bool asking; /* isAsking */

    /* clientConnectedRule, clientDisconnectedRule, clientErrorRule */
    char connected_action[32];
    char disconnected_action[32];
    char error_action[32];
    char disconnected_duration[32];

    bool alerts_connected; /* the dispatcher's `connected` */
    struct alert queued[KS_UI_MAX_QUEUED_ALERTS];
    size_t nqueued;

    int inotify_fd;
};

static void disconnect(struct ks_uiclient *c);
static void poller_tick(void *data);
static void rearm_tick(struct ks_uiclient *c);
static int reload_configuration(struct ks_uiclient *c, bool reload, struct ks_config *n,
                                char *err, size_t errlen);

static bool seq(const char *a, const char *b)
{
    return strcmp(a ? a : "", b ? b : "") == 0;
}

static const char *nz(const char *s)
{
    return s ? s : "";
}

static void set_str(char *dst, size_t len, const char *src)
{
    snprintf(dst, len, "%s", nz(src));
}

/* The error string grpc-go gives for a failed call. */
static void rpc_error(int status, const char *msg, char *buf, size_t len)
{
    snprintf(buf, len, "rpc error: code = %s desc = %s", ks_grpc_status_name(status),
             msg);
}

/* ---- the connection on the loop -------------------------------------------- */

static void on_conn_io(int fd, uint32_t events, void *data)
{
    (void)fd;
    struct ks_uiclient *c = data;
    if (c->conn == NULL)
        return;
    ks_grpc_conn_on_io(c->conn, (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0,
                       (events & EPOLLOUT) != 0);
    rearm_tick(c);
}

static void on_reap(void *data)
{
    struct ks_uiclient *c = data;
    c->reap_timer = NULL;
    for (size_t i = 0; i < sizeof(c->zombies) / sizeof(c->zombies[0]); i++) {
        struct ks_grpc_conn *z = c->zombies[i];
        c->zombies[i] = NULL;
        ks_grpc_conn_free(z); /* pending calls get their on_close here */
    }
}

/* Drops the current connection. It's freed from a timer: we may be inside
 * one of its callbacks. */
static void drop_conn(struct ks_uiclient *c)
{
    struct ks_grpc_conn *conn = c->conn;
    if (conn == NULL)
        return;
    c->conn = NULL;
    ks_evloop_del_fd(c->d.loop, ks_grpc_conn_fd(conn));
    if (c->tick_timer) {
        ks_evloop_cancel_timer(c->d.loop, c->tick_timer);
        c->tick_timer = NULL;
    }
    c->subscribe = NULL;
    c->notifications = NULL;
    c->ping = NULL;
    size_t n = sizeof(c->zombies) / sizeof(c->zombies[0]);
    size_t i;
    for (i = 0; i < n && c->zombies[i] != NULL; i++)
        ;
    if (i == n) { /* too many at once: free the oldest now */
        ks_grpc_conn_free(c->zombies[0]);
        memmove(&c->zombies[0], &c->zombies[1], (n - 1) * sizeof(c->zombies[0]));
        i = n - 1;
    }
    c->zombies[i] = conn;
    if (c->reap_timer == NULL)
        c->reap_timer = ks_evloop_add_timer(c->d.loop, 0, 0, on_reap, c);
}

static void on_tick(void *data)
{
    struct ks_uiclient *c = data;
    c->tick_timer = NULL;
    c->tick_at = 0;
    if (c->conn == NULL)
        return;
    ks_grpc_conn_tick(c->conn);
    rearm_tick(c);
}

/* Keeps a timer for the connection's deadlines and keepalive. */
static void rearm_tick(struct ks_uiclient *c)
{
    if (c->conn == NULL || ks_grpc_conn_closed(c->conn))
        return;
    int64_t next = ks_grpc_conn_tick(c->conn);
    if (c->conn == NULL)
        return;
    if (next < 0) {
        if (c->tick_timer) {
            ks_evloop_cancel_timer(c->d.loop, c->tick_timer);
            c->tick_timer = NULL;
        }
        return;
    }
    if (c->tick_timer != NULL && c->tick_at == next)
        return;
    if (c->tick_timer)
        ks_evloop_cancel_timer(c->d.loop, c->tick_timer);
    int64_t delay = next - ks_grpc_now();
    c->tick_at = next;
    c->tick_timer = ks_evloop_add_timer(c->d.loop, delay > 0 ? delay : 0, 0, on_tick, c);
}

static void on_want_write(struct ks_grpc_conn *conn, bool on, void *data)
{
    struct ks_uiclient *c = data;
    if (conn != c->conn)
        return;
    ks_evloop_mod_fd(c->d.loop, ks_grpc_conn_fd(conn), EPOLLIN | (on ? EPOLLOUT : 0));
}

static void on_conn_closed(struct ks_grpc_conn *conn, const char *reason, void *data)
{
    struct ks_uiclient *c = data;
    if (conn != c->conn)
        return;
    ks_debug("UI connection closed: %s", reason);
    /* The poller notices (Connected() is false) and reconnects. */
    drop_conn(c);
}

static int start_conn(struct ks_uiclient *c, int fd, const char *authority)
{
    struct ks_grpc_conn_opts o = {.authority = authority};
    if (!c->is_unix) {
        o.keepalive_time_ns = KS_UI_KEEPALIVE_TIME_NS;
        o.keepalive_timeout_ns = KS_UI_KEEPALIVE_TIMEOUT_NS;
    }
    struct ks_grpc_conn_cbs cbs = {.on_closed = on_conn_closed, .want_write = on_want_write};
    c->conn = ks_grpc_conn_new(fd, &o, &cbs, c); /* owns fd */
    if (c->conn == NULL)
        return -1;
    if (ks_evloop_add_fd(c->d.loop, fd, EPOLLIN | EPOLLOUT, on_conn_io, c) < 0) {
        ks_grpc_conn_free(c->conn);
        c->conn = NULL;
        return -1;
    }
    rearm_tick(c);
    return 0;
}

static int connect_fd(const struct sockaddr *sa, socklen_t len, char *err, size_t errlen)
{
    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }
    if (connect(fd, sa, len) < 0 && errno != EINPROGRESS) {
        snprintf(err, errlen, "dial: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int open_unix(struct ks_uiclient *c, char *err, size_t errlen)
{
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    const char *path = c->socket_path;
    size_t plen = strlen(path);
    size_t off = 0;
    /* Go: a leading '@' is an abstract socket; so is unix-abstract:. */
    if (c->is_abstract || (plen > 0 && path[0] == '@')) {
        if (path[0] == '@') {
            path++;
            plen--;
        }
        off = 1; /* sun_path[0] = '\0' */
    }
    if (plen + off >= sizeof(sun.sun_path)) {
        snprintf(err, errlen, "dial unix %s: socket path too long", c->socket_path);
        return -1;
    }
    memcpy(sun.sun_path + off, path, plen);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + off + plen +
                                (off ? 0 : 1));
    int fd = connect_fd((struct sockaddr *)&sun, len, err, errlen);
    if (fd < 0)
        return -1;
    return start_conn(c, fd, "localhost");
}

/* net.SplitHostPort() */
static int split_host_port(const char *addr, char *host, size_t hlen, char *port,
                           size_t plen)
{
    const char *colon = strrchr(addr, ':');
    if (colon == NULL)
        return -1;
    const char *h = addr;
    size_t n = (size_t)(colon - addr);
    if (addr[0] == '[') {
        const char *end = strchr(addr, ']');
        if (end == NULL || end + 1 != colon)
            return -1;
        h = addr + 1;
        n = (size_t)(end - h);
    } else if (memchr(addr, ':', n) != NULL) {
        return -1; /* too many colons */
    }
    if (n >= hlen || strlen(colon + 1) >= plen)
        return -1;
    memcpy(host, h, n);
    host[n] = '\0';
    snprintf(port, plen, "%s", colon + 1);
    return 0;
}

static void *resolve_thread(void *arg)
{
    struct resolve *r = arg;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    r->gai_err = getaddrinfo(r->host[0] ? r->host : NULL, r->port, &hints, &res);
    if (r->gai_err == 0 && res != NULL && res->ai_addrlen <= sizeof(r->addr)) {
        memcpy(&r->addr, res->ai_addr, res->ai_addrlen);
        r->addrlen = res->ai_addrlen;
    } else if (r->gai_err == 0) {
        r->gai_err = EAI_FAIL;
    }
    if (res)
        freeaddrinfo(res);
    char b = 1;
    ssize_t w = write(r->pipe[1], &b, 1);
    (void)w;
    return NULL;
}

static void resolve_free(struct ks_uiclient *c)
{
    struct resolve *r = c->resolving;
    if (r == NULL)
        return;
    c->resolving = NULL;
    ks_evloop_del_fd(c->d.loop, r->pipe[0]);
    pthread_join(r->thread, NULL);
    close(r->pipe[0]);
    close(r->pipe[1]);
    free(r);
}

static void on_resolved(int fd, uint32_t events, void *data)
{
    (void)fd;
    (void)events;
    struct ks_uiclient *c = data;
    struct resolve *r = c->resolving;
    pthread_join(r->thread, NULL);
    ks_evloop_del_fd(c->d.loop, r->pipe[0]);
    close(r->pipe[0]);
    close(r->pipe[1]);
    c->resolving = NULL;
    char err[256];
    if (r->gai_err != 0) {
        ks_debug("connect() dial tcp %s:%s: %s", r->host, r->port, gai_strerror(r->gai_err));
    } else {
        int s = connect_fd((struct sockaddr *)&r->addr, r->addrlen, err, sizeof(err));
        char authority[512];
        snprintf(authority, sizeof(authority), "%s", c->socket_path);
        if (s < 0 || start_conn(c, s, authority) < 0)
            ks_debug("connect() %s", s < 0 ? err : "out of memory");
    }
    free(r);
}

static int open_tcp(struct ks_uiclient *c, char *err, size_t errlen)
{
    char host[256], port[64];
    if (split_host_port(c->socket_path, host, sizeof(host), port, sizeof(port)) < 0) {
        snprintf(err, errlen, "dial tcp %s: missing or invalid port in address",
                 c->socket_path);
        return -1;
    }
    /* Numeric addresses connect right away. */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host[0] ? host : NULL, port, &hints, &res) == 0 && res != NULL) {
        int fd = connect_fd(res->ai_addr, res->ai_addrlen, err, errlen);
        freeaddrinfo(res);
        if (fd < 0)
            return -1;
        return start_conn(c, fd, c->socket_path);
    }
    struct resolve *r = calloc(1, sizeof(*r));
    if (r == NULL || pipe(r->pipe) < 0) {
        free(r);
        snprintf(err, errlen, "out of resources");
        return -1;
    }
    fcntl(r->pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(r->pipe[1], F_SETFD, FD_CLOEXEC);
    snprintf(r->host, sizeof(r->host), "%s", host);
    snprintf(r->port, sizeof(r->port), "%s", port);
    if (pthread_create(&r->thread, NULL, resolve_thread, r) != 0) {
        close(r->pipe[0]);
        close(r->pipe[1]);
        free(r);
        snprintf(err, errlen, "pthread_create failed");
        return -1;
    }
    c->resolving = r;
    ks_evloop_add_fd(c->d.loop, r->pipe[0], EPOLLIN, on_resolved, c);
    return 0;
}

/* openSocket(): auth.New() first. Returns -1 for invalid options (what
 * grpc.Dial reports), -2 if dialing failed: grpc-go dials in the
 * background, so for upstream that's no error, just a connection that
 * isn't ready; the poller tries again a second later. */
static int open_socket(struct ks_uiclient *c, char *err, size_t errlen)
{
    const char *auth = nz(c->config.server.auth.type);
    if (auth[0] != '\0' && strcmp(auth, "simple") != 0) {
        snprintf(err, errlen, "Invalid client auth options: %s authentication is not "
                              "supported yet (TLS=1, phase 10)", auth);
        return -1;
    }
    int rv = c->is_unix ? open_unix(c, err, errlen) : open_tcp(c, err, errlen);
    return rv < 0 ? -2 : 0;
}

bool ks_uiclient_connected(const struct ks_uiclient *c)
{
    return c->conn != NULL && ks_grpc_conn_ready(c->conn);
}

/* connect() */
static int do_connect(struct ks_uiclient *c, char *err, size_t errlen)
{
    if (ks_uiclient_connected(c))
        return 0;
    if (c->conn != NULL) {
        if (!ks_grpc_conn_closed(c->conn))
            return 0; /* still connecting */
        disconnect(c);
    }
    if (c->resolving != NULL)
        return 0;
    int rv = open_socket(c, err, errlen);
    if (rv < 0) {
        ks_debug("connect() %s", err);
        disconnect(c);
        return rv == -1 ? -1 : 0;
    }
    return 0;
}

/* ---- alerts ----------------------------------------------------------------- */

static void dispatch_alert(struct ks_uiclient *c, const struct alert *a)
{
    if (c->conn == NULL)
        return;
    static const struct ks_grpc_call_cbs none = {0};
    ks_grpc_unary(c->conn, RPC_POST_ALERT, KS_UI_ALERT_TIMEOUT_NS, a->buf, a->len, &none,
                  NULL);
    rearm_tick(c);
}

static void set_alerts_connected(struct ks_uiclient *c, bool ready)
{
    c->alerts_connected = ready;
    if (!ready)
        return;
    ks_important("UI connected, dispathing queued alerts: %d", 0);
    for (size_t i = 0; i < c->nqueued; i++) {
        dispatch_alert(c, &c->queued[i]);
        free(c->queued[i].buf);
    }
    c->nqueued = 0;
}

void ks_uiclient_post_alert(struct ks_uiclient *c, Protocol__Alert__Type type,
                            Protocol__Alert__What what, Protocol__Alert__Action action,
                            Protocol__Alert__Priority prio, const char *text)
{
    struct ks_arena a = {0};
    struct alert al = {0};
    Protocol__Alert *pa = ks_pb_alert_text(&a, type, what, action, prio, text);
    if (pa != NULL)
        al.buf = ks_pb_pack(&pa->base, &al.len);
    ks_arena_free(&a);
    if (al.buf == NULL)
        return;
    if (!ks_uiclient_connected(c))
        ks_debug("UI not connected, queueing alert: %zu", c->nqueued);
    if (c->alerts_connected) {
        dispatch_alert(c, &al);
        free(al.buf);
        return;
    }
    if (c->nqueued >= KS_UI_MAX_QUEUED_ALERTS - 1) {
        /* empty queue before adding a new one */
        free(c->queued[0].buf);
        memmove(&c->queued[0], &c->queued[1], (c->nqueued - 1) * sizeof(c->queued[0]));
        c->nqueued--;
        ks_debug("Discarding queued alert (%zu)", c->nqueued);
    }
    c->queued[c->nqueued++] = al;
}

void ks_uiclient_send_info_alert(struct ks_uiclient *c, const char *text)
{
    ks_uiclient_post_alert(c, PROTOCOL__ALERT__TYPE__INFO, PROTOCOL__ALERT__WHAT__GENERIC,
                           PROTOCOL__ALERT__ACTION__SHOW_ALERT,
                           PROTOCOL__ALERT__PRIORITY__LOW, text);
}

void ks_uiclient_send_warning_alert(struct ks_uiclient *c, const char *text)
{
    ks_uiclient_post_alert(c, PROTOCOL__ALERT__TYPE__WARNING,
                           PROTOCOL__ALERT__WHAT__GENERIC,
                           PROTOCOL__ALERT__ACTION__SHOW_ALERT,
                           PROTOCOL__ALERT__PRIORITY__MEDIUM, text);
}

void ks_uiclient_send_error_alert(struct ks_uiclient *c, const char *text)
{
    ks_uiclient_post_alert(c, PROTOCOL__ALERT__TYPE__ERROR, PROTOCOL__ALERT__WHAT__GENERIC,
                           PROTOCOL__ALERT__ACTION__SHOW_ALERT,
                           PROTOCOL__ALERT__PRIORITY__HIGH, text);
}

/* ---- disconnect / status ------------------------------------------------------ */

static void disconnect(struct ks_uiclient *c)
{
    c->alerts_connected = false; /* isConnected <- false */
    resolve_free(c);
    if (c->conn != NULL) {
        drop_conn(c);
        ks_debug("client.disconnect()");
    }
}

static void subscribe(struct ks_uiclient *c);

static void on_status_change(struct ks_uiclient *c, bool connected)
{
    if (connected) {
        ks_info("Connected to the UI service on %s", c->socket_path);
        subscribe(c);
        set_alerts_connected(c, true);
    } else {
        ks_error("Connection to the UI service lost.");
        disconnect(c);
    }
}

/* ---- Ping ------------------------------------------------------------------- */

static void ping_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                            void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->ping)
        return;
    Protocol__PingReply *r = (Protocol__PingReply *)ks_pb_unpack(
        &protocol__ping_reply__descriptor, msg, len);
    if (r == NULL)
        return;
    c->pong_ok = r->id == c->ping_id;
    if (!c->pong_ok)
        ks_debug("Error while pinging UI service: Expected pong with id 0x%llx, got 0x%llx",
                 (unsigned long long)c->ping_id, (unsigned long long)r->id);
    protobuf_c_message_free_unpacked(&r->base, NULL);
}

static void ping_on_close(struct ks_grpc_call *call, int status, const char *message,
                          void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->ping)
        return;
    c->ping = NULL;
    if (status != KS_GRPC_OK) {
        char e[512];
        rpc_error(status, message, e, sizeof(e));
        ks_debug("Error while pinging UI service: %s", e);
    }
}

/* ping(): only sent when there are new stats. */
static void ping(struct ks_uiclient *c)
{
    if (!ks_uiclient_connected(c) || c->ping != NULL || c->d.stats == NULL)
        return;
    struct ks_arena a = {0};
    Protocol__Statistics *st = ks_stats_serialize(c->d.stats, &a);
    if (st == NULL) {
        ks_trace("client, no stats");
        ks_arena_free(&a);
        return;
    }
    Protocol__PingRequest req = PROTOCOL__PING_REQUEST__INIT;
    req.id = ks_unix_nano();
    req.stats = st;
    size_t len = 0;
    uint8_t *buf = ks_pb_pack(&req.base, &len);
    ks_arena_free(&a);
    ks_stats_empty(c->d.stats);
    if (buf == NULL) {
        ks_debug("Error while pinging UI service: grpc: error while marshaling");
        return;
    }
    static const struct ks_grpc_call_cbs cbs = {ping_on_message, NULL, ping_on_close};
    c->ping_id = req.id;
    c->pong_ok = false;
    c->ping = ks_grpc_unary(c->conn, RPC_PING, KS_UI_PING_TIMEOUT_NS, buf, len, &cbs, c);
    free(buf);
    rearm_tick(c);
}

/* ---- the poller --------------------------------------------------------------- */

static void stop_poller(struct ks_uiclient *c)
{
    if (c->poll_timer) {
        ks_evloop_cancel_timer(c->d.loop, c->poll_timer);
        c->poll_timer = NULL;
    }
}

static void poller_tick(void *data)
{
    struct ks_uiclient *c = data;
    if (c->socket_path == NULL || c->socket_path[0] == '\0') {
        ks_error("client.Server address not set, exiting");
        stop_poller(c);
        ks_info("uiClient exit");
        return;
    }
    bool is = ks_uiclient_connected(c);
    if (c->was_connected != is) {
        on_status_change(c, is);
        c->was_connected = is;
    }
    if (!ks_uiclient_connected(c)) {
        char err[512];
        if (do_connect(c, err, sizeof(err)) < 0)
            ks_warning("Error while connecting to UI service: %s", err);
    }
    if (ks_uiclient_connected(c))
        ping(c);
}

void ks_uiclient_connect(struct ks_uiclient *c)
{
    if (c->poll_timer != NULL)
        return;
    ks_debug("UI service poller started for socket %s", nz(c->socket_path));
    c->poll_timer = ks_evloop_add_timer(c->d.loop, 0, KS_UI_POLL_INTERVAL_NS, poller_tick,
                                        c);
}

/* ---- AskRule ------------------------------------------------------------------ */

bool ks_uiclient_is_asking(const struct ks_uiclient *c)
{
    return c->asking;
}

static void ask_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->ask || c->ask_reply != NULL)
        return;
    c->ask_reply = (Protocol__Rule *)ks_pb_unpack(&protocol__rule__descriptor, msg, len);
}

static void ask_on_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->ask)
        return;
    c->ask = NULL;
    struct ks_rule *r = NULL;
    if (status != KS_GRPC_OK || c->ask_reply == NULL) {
        char e[512];
        if (status == KS_GRPC_OK)
            snprintf(e, sizeof(e), "rpc error: code = Internal desc = grpc: failed to "
                                   "unmarshal the received message");
        else
            rpc_error(status, message, e, sizeof(e));
        ks_warning("Error while asking for rule: %s - %s", e, c->ask_desc);
    } else {
        char err[128];
        r = ks_rule_from_pb(c->ask_reply, err, sizeof(err));
    }
    if (c->ask_reply)
        protobuf_c_message_free_unpacked(&c->ask_reply->base, NULL);
    c->ask_reply = NULL;
    ks_ask_cb cb = c->ask_cb;
    void *cbdata = c->ask_data;
    c->ask_cb = NULL;
    cb(r, cbdata);
    c->asking = false; /* SetIsAsking(false), deferred in acceptOrDeny */
}

int ks_uiclient_ask(struct ks_uiclient *c, const struct ks_conn *con,
                    const struct ks_proc *proc, ks_ask_cb cb, void *data)
{
    if (c->conn == NULL || c->asking)
        return -1;
    ks_conn_string(con, c->ask_desc, sizeof(c->ask_desc));
    struct ks_arena a = {0};
    Protocol__Connection *pc = ks_pb_connection(&a, con, proc);
    size_t len = 0;
    uint8_t *buf = pc ? ks_pb_pack(&pc->base, &len) : NULL;
    ks_arena_free(&a);
    if (buf == NULL) {
        ks_warning("Error while asking for rule: rpc error: code = Internal desc = grpc: "
                   "error while marshaling: string field contains invalid UTF-8 - %s",
                   c->ask_desc);
        return -1;
    }
    static const struct ks_grpc_call_cbs cbs = {ask_on_message, NULL, ask_on_close};
    c->ask_cb = cb;
    c->ask_data = data;
    c->asking = true;
    c->ask = ks_grpc_unary(c->conn, RPC_ASK_RULE, KS_UI_ASK_TIMEOUT_NS, buf, len, &cbs, c);
    free(buf);
    if (c->ask == NULL) {
        c->asking = false;
        c->ask_cb = NULL;
        return -1;
    }
    rearm_tick(c);
    return 0;
}

const char *ks_uiclient_default_action(const struct ks_uiclient *c)
{
    return ks_uiclient_connected(c) ? c->connected_action : c->disconnected_action;
}

bool ks_uiclient_intercept_unknown(const struct ks_uiclient *c)
{
    return c->config.intercept_unknown;
}

const struct ks_config *ks_uiclient_config(const struct ks_uiclient *c)
{
    return &c->config;
}

/* ---- Notifications ------------------------------------------------------------ */

/* sendNotificationReply(): `err` NULL means OK. */
static void send_reply(struct ks_uiclient *c, const Protocol__Notification *ntf,
                       const char *data, const char *err)
{
    if (c->notifications == NULL)
        return;
    Protocol__NotificationReply r = PROTOCOL__NOTIFICATION_REPLY__INIT;
    r.id = ntf->id;
    r.code = err ? PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR
                 : PROTOCOL__NOTIFICATION_REPLY_CODE__OK;
    r.data = (char *)(uintptr_t)(err ? err : nz(data));
    size_t len;
    uint8_t *buf = ks_pb_pack(&r.base, &len);
    if (buf == NULL || ks_grpc_call_send(c->notifications, buf, len) < 0)
        ks_error("Error replying to notification, type: %d, id: %llu, err: %s",
                 (int)ntf->type, (unsigned long long)ntf->id,
                 buf ? "the stream is closed" : "marshaling");
    free(buf);
}

static void handle_change_config(struct ks_uiclient *c, const Protocol__Notification *ntf)
{
    ks_info("[notification] Reloading configuration, type: %d, id: %llu", (int)ntf->type,
            (unsigned long long)ntf->id);
    struct ks_config n;
    char err[1024];
    if (ks_config_parse(ntf->data, strlen(ntf->data), &n, err, sizeof(err)) < 0) {
        ks_warning("[notification] error parsing received config: %s", ntf->data);
        send_reply(c, ntf, "", err);
        return;
    }
    char rerr[512] = "";
    if (reload_configuration(c, true, &n, rerr, sizeof(rerr)) > KS_MONITOR_NO_ERROR) {
        ks_config_free(&n);
        send_reply(c, ntf, "", rerr);
        return;
    }
    ks_config_free(&n);
    /* this save operation triggers a regular re-loadConfiguration() */
    int rv = ks_config_save_raw(c->config_file, ntf->data, strlen(ntf->data), err,
                                sizeof(err));
    if (rv < 0)
        ks_warning("[notification] CHANGE_CONFIG not applied %s", err);
    send_reply(c, ntf, "", rv < 0 ? err : NULL);
}

/* ENABLE_RULE, DISABLE_RULE and CHANGE_RULE: Replace(), saved to disk if
 * the duration is "always". `enabled` < 0 keeps the rule's flag. */
static void handle_replace_rules(struct ks_uiclient *c, const Protocol__Notification *ntf,
                                 int enabled)
{
    char err[640] = "";
    bool failed = false;
    for (size_t i = 0; i < ntf->n_rules; i++) {
        char e[512];
        struct ks_rule *r = ks_rule_from_pb(ntf->rules[i], e, sizeof(e));
        if (r == NULL) {
            /* upstream dereferences the nil rule (a panic) for enable/disable */
            snprintf(err, sizeof(err), "Invalid rule, %s", e);
            failed = true;
            continue;
        }
        if (enabled >= 0) {
            ks_info("[notification] %s rule: %s", enabled ? "enable" : "disable", r->name);
            r->enabled = enabled != 0;
        } else {
            char desc[1024];
            ks_rule_describe(r, desc, sizeof(desc));
            ks_info("[notification] change rule: %s %llu", desc,
                    (unsigned long long)ntf->id);
        }
        bool save = strcmp(r->duration, "always") == 0;
        char name[256];
        set_str(name, sizeof(name), r->name);
        if (ks_loader_replace(c->d.rules, r, save, e, sizeof(e)) < 0) {
            if (enabled < 0)
                ks_warning("[notification] Error changing rule: %s %s", e, name);
            snprintf(err, sizeof(err), "%s", e);
            failed = true;
        } else if (enabled >= 0) {
            /* enable/disable keep only the last rule's result */
            failed = false;
            err[0] = '\0';
        }
    }
    send_reply(c, ntf, "", failed ? err : NULL);
}

static void handle_delete_rules(struct ks_uiclient *c, const Protocol__Notification *ntf)
{
    char err[512] = "";
    bool failed = false;
    for (size_t i = 0; i < ntf->n_rules; i++) {
        const char *name = ntf->rules[i]->name;
        ks_info("[notification] delete rule: %s %llu", name, (unsigned long long)ntf->id);
        failed = ks_loader_delete(c->d.rules, name, err, sizeof(err)) < 0;
        if (failed)
            ks_error("[notification] Error deleting rule: %s %s", err, name);
    }
    send_reply(c, ntf, "", failed ? err : NULL);
}

/* TASK_START / TASK_STOP: the JSON is parsed as upstream does; the tasks
 * themselves arrive with phase 10. */
static void handle_task(struct ks_uiclient *c, const Protocol__Notification *ntf, bool start)
{
    cJSON *j = cJSON_Parse(ntf->data);
    const cJSON *name = j ? cJSON_GetObjectItemCaseSensitive(j, "Name") : NULL;
    if (j == NULL || (name != NULL && !cJSON_IsString(name) && !cJSON_IsNull(name))) {
        if (start) {
            ks_error("parsing TaskStart, err: invalid JSON, %s", ntf->data);
            send_reply(c, ntf, "", "invalid task notification");
        } else {
            ks_error("parsing TaskStop, err: invalid JSON, %s", ntf->data);
            char e[600];
            snprintf(e, sizeof(e), "Error stopping task: %s", ntf->data);
            send_reply(c, ntf, "", e);
        }
        cJSON_Delete(j);
        return;
    }
    const char *n = cJSON_IsString(name) ? name->valuestring : "";
    bool known = strcmp(n, TASK_PID_MONITOR) == 0 || strcmp(n, TASK_NODE_MONITOR) == 0 ||
                 strcmp(n, TASK_SOCKETS_MONITOR) == 0;
    if (!known) {
        ks_debug("%s, unknown task: %s", start ? "TaskStart" : "TaskStop", ntf->data);
    } else if (start) {
        char e[300];
        snprintf(e, sizeof(e), "task %s is not supported yet", n);
        ks_warning("[tasks] %s", e);
        send_reply(c, ntf, "", e);
    } else {
        ks_debug("[tasks] TaskStop %s: no such task running", n);
    }
    cJSON_Delete(j);
}

static void handle_enable_interception(struct ks_uiclient *c,
                                       const Protocol__Notification *ntf)
{
    ks_info("[notification] starting interception");
    char err[256];
    if (ks_procmon_reconfigure(c->d.loop, nz(c->config.proc_monitor_method), err,
                               sizeof(err)) > KS_MONITOR_NO_ERROR) {
        ks_warning("[notification] error enabling monitor (%s): %s",
                   nz(c->config.proc_monitor_method), err);
        send_reply(c, ntf, "", err);
        return;
    }
    if (c->d.fw != NULL && ks_fw_enable_interception(c->d.fw) < 0) {
        ks_warning("[notification] firewall.EnableInterception() error");
        send_reply(c, ntf, "", "error enabling interception");
        return;
    }
    send_reply(c, ntf, "", NULL);
}

static void handle_disable_interception(struct ks_uiclient *c,
                                        const Protocol__Notification *ntf)
{
    ks_info("[notification] stopping interception");
    ks_procmon_monitor_end();
    if (c->d.fw != NULL && ks_fw_disable_interception(c->d.fw) < 0) {
        ks_warning("firewall.DisableInterception() error");
        send_reply(c, ntf, "", "error disabling interception");
        return;
    }
    send_reply(c, ntf, "", NULL);
}

static void handle_reload_fw(struct ks_uiclient *c, const Protocol__Notification *ntf)
{
    ks_info("[notification] reloading firewall");
    /* firewall.Deserialize() + SaveConfiguration(): phase 8. */
    ks_warning("[notification] system firewall rules are not supported yet");
    send_reply(c, ntf, "", "Error reloading firewall: system firewall rules are not "
                           "supported yet");
}

static void handle_notification(struct ks_uiclient *c, const Protocol__Notification *ntf)
{
    switch (ntf->type) {
    case PROTOCOL__ACTION__TASK_START:
        handle_task(c, ntf, true);
        break;
    case PROTOCOL__ACTION__TASK_STOP:
        handle_task(c, ntf, false);
        break;
    case PROTOCOL__ACTION__CHANGE_CONFIG:
        handle_change_config(c, ntf);
        break;
    case PROTOCOL__ACTION__ENABLE_INTERCEPTION:
        handle_enable_interception(c, ntf);
        break;
    case PROTOCOL__ACTION__DISABLE_INTERCEPTION:
        handle_disable_interception(c, ntf);
        break;
    case PROTOCOL__ACTION__RELOAD_FW_RULES:
        handle_reload_fw(c, ntf);
        break;
    case PROTOCOL__ACTION__ENABLE_RULE:
        handle_replace_rules(c, ntf, 1);
        break;
    case PROTOCOL__ACTION__DISABLE_RULE:
        handle_replace_rules(c, ntf, 0);
        break;
    case PROTOCOL__ACTION__DELETE_RULE:
        handle_delete_rules(c, ntf);
        break;
    case PROTOCOL__ACTION__CHANGE_RULE:
        handle_replace_rules(c, ntf, -1);
        break;
    default: /* LOG_LEVEL, STOP and unknown values: ignored, as upstream */
        break;
    }
}

/* The Exit: label of listenForNotifications(). */
static void stop_notifications(struct ks_uiclient *c)
{
    struct ks_grpc_call *call = c->notifications;
    c->notifications = NULL;
    if (call != NULL)
        ks_grpc_call_close_send(call);
    ks_info("Stop receiving notifications");
    disconnect(c);
    /* TaskMgr.StopTempTasks(): no tasks yet (phase 10) */
}

static void ntf_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->notifications)
        return;
    Protocol__Notification *ntf = (Protocol__Notification *)ks_pb_unpack(
        &protocol__notification__descriptor, msg, len);
    if (ntf == NULL) {
        ks_error("getting notifications: grpc: failed to unmarshal the received message");
        stop_notifications(c);
        return;
    }
    if ((int)ntf->type <= PROTOCOL__ACTION__NONE) {
        ks_debug("Server ordered to close notifications");
        protobuf_c_message_free_unpacked(&ntf->base, NULL);
        stop_notifications(c);
        return;
    }
    handle_notification(c, ntf);
    protobuf_c_message_free_unpacked(&ntf->base, NULL);
    rearm_tick(c);
}

static void ntf_on_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->notifications)
        return;
    if (status == KS_GRPC_OK) {
        ks_warning("notification channel closed by the server");
    } else {
        char e[512];
        rpc_error(status, message, e, sizeof(e));
        ks_error("getting notifications: %s <nil>", e);
    }
    c->notifications = NULL;
    stop_notifications(c);
}

/* listenForNotifications() */
static void listen_for_notifications(struct ks_uiclient *c)
{
    static const struct ks_grpc_call_cbs cbs = {ntf_on_message, NULL, ntf_on_close};
    if (c->conn == NULL ||
        (c->notifications = ks_grpc_call_start(c->conn, RPC_NOTIFICATIONS, 0, &cbs, c)) ==
            NULL) {
        ks_error("establishing notifications channel %s", "the connection is closed");
        return;
    }
    Protocol__NotificationReply hello = PROTOCOL__NOTIFICATION_REPLY__INIT;
    size_t len;
    uint8_t *buf = ks_pb_pack(&hello.base, &len);
    if (buf == NULL || ks_grpc_call_send(c->notifications, buf, len) < 0) {
        ks_error("sending notification HELLO %s", "error");
        free(buf);
        return;
    }
    free(buf);
    ks_info("Start receiving notifications");
}

/* ---- Subscribe ---------------------------------------------------------------- */

static char *read_text_file(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    char *buf = malloc(max + 1);
    size_t n = 0;
    if (buf != NULL) {
        n = fread(buf, 1, max, f);
        buf[n] = '\0';
    }
    fclose(f);
    if (len)
        *len = n;
    return buf;
}

/* strings.Replace(s, "\n", "", -1), in place. */
static void strip_newlines(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++)
        if (*r != '\n')
            *w++ = *r;
    *w = '\0';
}

static char *read_proc_value(const char *path)
{
    char *s = read_text_file(path, 4096, NULL);
    if (s == NULL)
        return strdup("");
    strip_newlines(s);
    return s;
}

/* getClientConfig() */
static uint8_t *client_config(struct ks_uiclient *c, size_t *len)
{
    struct ks_arena a = {0};
    char *raw = read_text_file(c->config_file, KS_CONFIG_MAX_SIZE, NULL);
    char *name = read_proc_value("/proc/sys/kernel/hostname");
    char *version = read_proc_value("/proc/sys/kernel/osrelease");
    if (raw != NULL)
        strip_newlines(raw);

    Protocol__ClientConfig cc = PROTOCOL__CLIENT_CONFIG__INIT;
    cc.id = ZERO_TIME_UNIX_NANO;
    cc.name = name ? name : (char *)"";
    cc.version = version ? version : (char *)"";
    cc.isfirewallrunning = c->d.fw != NULL && ks_fw_is_running(c->d.fw);
    cc.config = raw ? raw : (char *)"";
    cc.loglevel = (uint32_t)ks_log_get_level();
    size_t n = ks_loader_num_rules(c->d.rules);
    uint8_t *buf = NULL;
    if (n > 0) {
        cc.rules = ks_arena_calloc(&a, n, sizeof(*cc.rules));
        if (cc.rules == NULL)
            goto out;
        for (size_t i = 0; i < n; i++)
            if ((cc.rules[i] = ks_pb_rule(&a, ks_loader_rule_at(c->d.rules, i))) == NULL)
                goto out;
        cc.n_rules = n;
    }
    /* SystemFirewall: firewall.Serialize() of system-fw.json, phase 8. */
    buf = ks_pb_pack(&cc.base, len);
out:
    ks_arena_free(&a);
    free(raw);
    free(name);
    free(version);
    return buf;
}

static void sub_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->subscribe || c->subscribe_reply != NULL)
        return;
    c->subscribe_reply = (Protocol__ClientConfig *)ks_pb_unpack(
        &protocol__client_config__descriptor, msg, len);
}

static void sub_on_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    struct ks_uiclient *c = data;
    if (call != c->subscribe) {
        return;
    }
    c->subscribe = NULL;
    Protocol__ClientConfig *reply = c->subscribe_reply;
    c->subscribe_reply = NULL;
    if (status != KS_GRPC_OK || reply == NULL) {
        char e[512];
        if (status == KS_GRPC_OK)
            snprintf(e, sizeof(e), "rpc error: code = Internal desc = grpc: failed to "
                                   "unmarshal the received message");
        else
            rpc_error(status, message, e, sizeof(e));
        ks_error("Subscribing to GUI %s", e);
        if (reply)
            protobuf_c_message_free_unpacked(&reply->base, NULL);
        /* When connecting to the GUI via TCP, sometimes the notifications
         * channel is not established: disconnect and try again. */
        disconnect(c);
        return;
    }
    struct ks_config tmp;
    char err[256];
    if (ks_config_parse(reply->config, strlen(reply->config), &tmp, err, sizeof(err)) ==
        0) {
        set_str(c->connected_action, sizeof(c->connected_action), tmp.default_action);
        ks_config_free(&tmp);
    }
    protobuf_c_message_free_unpacked(&reply->base, NULL);
    listen_for_notifications(c);
}

/* Subscribe() */
static void subscribe(struct ks_uiclient *c)
{
    if (c->conn == NULL || c->subscribe != NULL)
        return;
    size_t len = 0;
    uint8_t *buf = client_config(c, &len);
    if (buf == NULL) {
        ks_error("Subscribing to GUI %s", "grpc: error while marshaling");
        disconnect(c);
        return;
    }
    static const struct ks_grpc_call_cbs cbs = {sub_on_message, NULL, sub_on_close};
    c->subscribe = ks_grpc_unary(c->conn, RPC_SUBSCRIBE, KS_UI_SUBSCRIBE_TIMEOUT_NS, buf,
                                 len, &cbs, c);
    free(buf);
    rearm_tick(c);
}

/* ---- configuration (config_utils.go) ----------------------------------------- */

/* getSocketPath(): strips the scheme and sets isUnixSocket. */
static const char *get_socket_path(struct ks_uiclient *c, const char *addr)
{
    if (strncmp(addr, "unix:", 5) == 0) {
        c->is_unix = true;
        c->is_abstract = false;
        return addr + 5;
    }
    if (strncmp(addr, "unix-abstract:", 14) == 0) {
        c->is_unix = true;
        c->is_abstract = true;
        return addr + 14;
    }
    c->is_unix = false;
    c->is_abstract = false;
    return addr;
}

static void set_socket_path(struct ks_uiclient *c, const char *path)
{
    char *p = strdup(path);
    if (p == NULL)
        return;
    free(c->socket_path);
    c->socket_path = p;
}

static bool stats_equal(const struct ks_stats_config *a, const struct ks_stats_config *b)
{
    return a->max_events == b->max_events && a->max_stats == b->max_stats &&
           a->workers == b->workers;
}

static bool tls_equal(const struct ks_tls_options *a, const struct ks_tls_options *b)
{
    return seq(a->ca_cert, b->ca_cert) && seq(a->server_cert, b->server_cert) &&
           seq(a->server_key, b->server_key) && seq(a->client_cert, b->client_cert) &&
           seq(a->client_key, b->client_key) &&
           seq(a->client_auth_type, b->client_auth_type) && a->skip_verify == b->skip_verify;
}

static bool loggers_equal(const struct ks_array *a, const struct ks_array *b)
{
    if (a->len != b->len || a->non_nil != b->non_nil)
        return false;
    for (size_t i = 0; i < a->len; i++) {
        const struct ks_logger_config *x = KS_ARRAY_ITEM(*a, struct ks_logger_config, i);
        const struct ks_logger_config *y = KS_ARRAY_ITEM(*b, struct ks_logger_config, i);
        if (!seq(x->name, y->name) || !seq(x->format, y->format) ||
            !seq(x->protocol, y->protocol) || !seq(x->server, y->server) ||
            !seq(x->write_timeout, y->write_timeout) ||
            !seq(x->connect_timeout, y->connect_timeout) || !seq(x->tag, y->tag) ||
            x->workers != y->workers || x->max_connect_attempts != y->max_connect_attempts)
            return false;
    }
    return true;
}

/* GetFirewallType() */
static const char *firewall_type(const struct ks_uiclient *c)
{
    return c->config.firewall && c->config.firewall[0] ? c->config.firewall
                                                       : KS_FW_IPTABLES;
}

/* reloadConfiguration(). Returns the monitor error kind (with its message
 * in `err`). `n` may be changed (ProcMonitorMethod after a fallback). */
static int reload_configuration(struct ks_uiclient *c, bool reload, struct ks_config *n,
                                char *err, size_t errlen)
{
    struct ks_config *o = &c->config;
    int what = KS_MONITOR_NO_ERROR;

    /* firstly load config level, to detect further errors if any */
    if (n->log_level.set)
        ks_log_set_level(n->log_level.value);
    ks_log_set_utc(n->log_utc);
    ks_log_set_micro(n->log_micro);
    if (nz(n->server.log_file)[0] != '\0') {
        ks_debug("[config] using config.server.logfile: %s", n->server.log_file);
        ks_log_close();
        ks_log_open_file(n->server.log_file);
    }
    if (!loggers_equal(&o->server.loggers, &n->server.loggers))
        ks_debug("[config] reloading config.server.loggers (not supported yet)");
    else
        ks_debug("[config] config.server.loggers not changed");

    if (!stats_equal(&n->stats, &o->stats)) {
        ks_debug("[config] reloading config.stats");
        if (c->d.stats)
            ks_stats_set_limits(c->d.stats, &n->stats);
    } else {
        ks_debug("[config] config.stats not changed");
    }

    /* 1. disconnect from the server (GUI) if the new server addr is empty.
     * 2. connect to the server (GUI) if the new server addr is not empty,
     *    and previous addr was empty.
     * 3. reconnect if auth options changed, or the address did. */
    bool reconnect = !seq(n->server.auth.type, o->server.auth.type) ||
                     !tls_equal(&n->server.auth.tls, &o->server.auth.tls);
    bool connect = false;
    if (nz(n->server.address)[0] == '\0') {
        ks_debug("[config] config.server.address changed, disconnecting from %s",
                 nz(c->socket_path));
        set_socket_path(c, "");
    }
    if (nz(n->server.address)[0] != '\0' && !seq(n->server.address, o->server.address)) {
        const char *tmp = get_socket_path(c, n->server.address);
        ks_debug("[config] using new config.server.address: %s -> %s",
                 nz(o->server.address), n->server.address);
        if (!seq(tmp, c->socket_path))
            reconnect = true; /* the poller reconnects to the new address */
        set_socket_path(c, tmp);
        if (nz(o->server.address)[0] == '\0') {
            ks_debug("[config] previous address was empty, connected: %d, connecting "
                     "to %s", ks_uiclient_connected(c), c->socket_path);
            char *a = strdup(n->server.address);
            if (a != NULL) {
                free(o->server.address);
                o->server.address = a;
            }
            connect = true;
        }
    }
    ks_debug("[config] server.address old: %s, new: %s, reconnect: %d, connect: %d",
             nz(o->server.address), nz(n->server.address), reconnect, connect);
    if (reconnect) {
        ks_debug("[config] config.server.address.* changed, disconnecting from %s",
                 nz(o->server.address));
        disconnect(c);
    }
    if (connect) {
        ks_debug("[config] config.server. changed, connecting to %s", nz(c->socket_path));
        ks_uiclient_connect(c);
    }

    if (nz(n->default_action)[0] != '\0') {
        set_str(c->disconnected_action, sizeof(c->disconnected_action), n->default_action);
        set_str(c->error_action, sizeof(c->error_action), n->default_action);
    }
    if (nz(n->default_duration)[0] != '\0')
        set_str(c->disconnected_duration, sizeof(c->disconnected_duration),
                n->default_duration);
    ks_debug("[config] config.internal.gcpercent not changed");

    /* 1. load rules */
    ks_loader_enable_checksums(c->d.rules, n->rules.enable_checksums);
    if (nz(n->rules.path)[0] == '\0' || !seq(o->rules.path, n->rules.path)) {
        char e[512];
        if (ks_loader_reload(c->d.rules, nz(n->rules.path), e, sizeof(e)) < 0)
            ks_warning("%s", e);
        ks_debug("[config] reloading config.rules.path, old: <%s> new: <%s>",
                 nz(o->rules.path), nz(n->rules.path));
    } else {
        ks_debug("[config] config.rules.path not changed");
    }

    /* 2. load proc mon method */
    bool reload_proc = nz(o->proc_monitor_method)[0] == '\0' ||
                       !seq(n->proc_monitor_method, o->proc_monitor_method);
    if (reload_proc)
        ks_debug("[config] reloading config.ProcMonMethod, old: %s -> new: %s",
                 nz(o->proc_monitor_method), nz(n->proc_monitor_method));
    else
        ks_debug("[config] config.ProcMonMethod not changed");
    (void)reload; /* only matters for the ebpf and audit options (phases 9, 10) */

    /* 3. load fw */
    const struct ks_fw_options *nf = &n->fw_options, *of = &o->fw_options;
    bool reload_fw = !seq(firewall_type(c), n->firewall) ||
                     !seq(nf->config_path, of->config_path) ||
                     nf->queue_num != of->queue_num ||
                     !seq(nf->monitor_interval, of->monitor_interval) ||
                     nf->queue_bypass != of->queue_bypass;
    if (reload_fw) {
        ks_debug("[config] reloading config.firewall");
        if (c->d.fw != NULL &&
            ks_fw_reload(c->d.fw, nz(n->firewall), nz(nf->config_path),
                         nz(nf->monitor_interval), nf->queue_bypass, nf->queue_num) < 0)
            ks_error("[config] firewall reload error");
    } else {
        ks_debug("[config] config.firewall not changed");
    }

    /* 4. reload procmon if needed */
    if (reload_proc) {
        what = ks_procmon_reconfigure(c->d.loop, nz(n->proc_monitor_method), err, errlen);
        /* fall back to the last known good method */
        if (what == KS_MONITOR_EBPF_ERR || what == KS_MONITOR_AUDITD_ERR) {
            char *m = strdup(ks_procmon_get_method());
            if (m != NULL) {
                free(n->proc_monitor_method);
                n->proc_monitor_method = m;
            }
        }
    } else {
        ks_debug("[config] config.procmon not changed");
    }

    if ((reload_proc || reload_fw) && n->internal.flush_conns_on_start) {
        ks_debug("[config] flushing established connections");
        ks_flush_connections();
    } else {
        ks_debug("[config] not flushing established connections");
    }
    if (!seq(n->tasks.config_path, o->tasks.config_path))
        ks_debug("[config] reloading TasksOptions.ConfigFile from %s (tasks are not "
                 "supported yet)", nz(n->tasks.config_path));
    else
        ks_debug("[config] config.TasksOptions not changed");
    return what;
}

/* loadConfiguration(): parse, apply, and keep the new configuration even
 * if some option failed. */
static int load_configuration(struct ks_uiclient *c, bool reload, const char *raw,
                              size_t len, char *err, size_t errlen)
{
    struct ks_config n;
    char perr[1024];
    if (ks_config_parse(raw, len, &n, perr, sizeof(perr)) < 0) {
        snprintf(err, errlen, "parsing configuration %s: %s", c->config_file, perr);
        return -1;
    }
    int what = reload_configuration(c, reload, &n, err, errlen);
    ks_config_free(&c->config);
    c->config = n;
    return what > KS_MONITOR_NO_ERROR ? -1 : 0;
}

static void watch_config(struct ks_uiclient *c)
{
    if (c->inotify_fd < 0)
        return;
    if (inotify_add_watch(c->inotify_fd, c->config_file, IN_MODIFY | IN_DELETE_SELF) < 0)
        ks_error("[config] Could not watch path: %s", strerror(errno));
}

/* loadDiskConfiguration() */
static void load_disk_configuration(struct ks_uiclient *c, bool reload)
{
    /* Add the file every time, to survive its removal and rewrites. */
    watch_config(c);
    size_t len = 0;
    char *raw = read_text_file(c->config_file, KS_CONFIG_MAX_SIZE, &len);
    if (raw == NULL || len == 0) {
        ks_warning("[config] Error loading configuration from disk %s: %s",
                   c->config_file, raw == NULL ? strerror(errno) : "empty file");
        free(raw);
        return;
    }
    char err[1200];
    if (load_configuration(c, reload, raw, len, err, sizeof(err)) < 0) {
        ks_error("[client] error loading config file: %s", err);
        ks_uiclient_send_warning_alert(c, err);
    }
    free(raw);
}

void ks_uiclient_reload_from_disk(struct ks_uiclient *c)
{
    load_disk_configuration(c, true);
}

/* monitorConfigWorker(): writes and removals reload the file. */
static void on_config_event(int fd, uint32_t events, void *data)
{
    (void)events;
    struct ks_uiclient *c = data;
    alignas(struct inotify_event) char buf[4096];
    bool reload = false;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (ssize_t off = 0; off < n;) {
            const struct inotify_event *ev = (const struct inotify_event *)(buf + off);
            if (ev->mask & (IN_MODIFY | IN_DELETE_SELF))
                reload = true;
            off += (ssize_t)(sizeof(*ev) + ev->len);
        }
    }
    if (reload)
        load_disk_configuration(c, true);
}

struct ks_uiclient *ks_uiclient_new(const struct ks_uiclient_deps *deps,
                                    const char *socket_path, const char *config_file)
{
    struct ks_uiclient *c = calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    c->d = *deps;
    c->config_file = strdup(config_file && config_file[0] ? config_file
                                                          : KS_CONFIG_DEFAULT_FILE);
    c->socket_path = strdup("");
    if (c->config_file == NULL || c->socket_path == NULL) {
        free(c->config_file);
        free(c->socket_path);
        free(c);
        return NULL;
    }
    set_str(c->connected_action, sizeof(c->connected_action), KS_ACTION_DENY);
    set_str(c->disconnected_action, sizeof(c->disconnected_action), KS_ACTION_ALLOW);
    set_str(c->error_action, sizeof(c->error_action), KS_ACTION_ALLOW);
    set_str(c->disconnected_duration, sizeof(c->disconnected_duration), "once");
    /* c.config.Rules.Path = rules.Path */
    c->config.rules.path = strdup(ks_loader_path(deps->rules));

    c->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (c->inotify_fd >= 0 &&
        ks_evloop_add_fd(deps->loop, c->inotify_fd, EPOLLIN, on_config_event, c) < 0) {
        close(c->inotify_fd);
        c->inotify_fd = -1;
    }
    load_disk_configuration(c, false);
    if (socket_path != NULL && socket_path[0] != '\0')
        set_socket_path(c, get_socket_path(c, socket_path));
    /* procmon.EventsCache.SetComputeChecksums() and rules.EnableChecksums()
     * already ran in reloadConfiguration(). TaskMgr: phase 10. */
    return c;
}

void ks_uiclient_free(struct ks_uiclient *c)
{
    if (c == NULL)
        return;
    stop_poller(c);
    resolve_free(c);
    if (c->conn) {
        ks_evloop_del_fd(c->d.loop, ks_grpc_conn_fd(c->conn));
        struct ks_grpc_conn *conn = c->conn;
        c->conn = NULL;
        c->subscribe = c->notifications = c->ping = NULL;
        ks_grpc_conn_free(conn); /* a pending question gets NULL */
    }
    if (c->tick_timer)
        ks_evloop_cancel_timer(c->d.loop, c->tick_timer);
    if (c->reap_timer)
        ks_evloop_cancel_timer(c->d.loop, c->reap_timer);
    c->reap_timer = NULL;
    on_reap(c);
    if (c->inotify_fd >= 0) {
        ks_evloop_del_fd(c->d.loop, c->inotify_fd);
        close(c->inotify_fd);
    }
    for (size_t i = 0; i < c->nqueued; i++)
        free(c->queued[i].buf);
    if (c->subscribe_reply)
        protobuf_c_message_free_unpacked(&c->subscribe_reply->base, NULL);
    if (c->ask_reply)
        protobuf_c_message_free_unpacked(&c->ask_reply->base, NULL);
    ks_config_free(&c->config);
    free(c->config_file);
    free(c->socket_path);
    free(c);
}
