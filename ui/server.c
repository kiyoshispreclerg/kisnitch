/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * gRPC server of the UI over common/grpc/ on the GLib main loop. Port of
 * the server set up in upstream ui/bin/opensnitch-ui.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <glib-unix.h>
#include <glib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/grpc/grpc.h"
#include "common/log.h"

#define MAX_LISTENERS 8
#define KEEPALIVE_TIME_NS (5 * 1000000000LL)     /* grpc.keepalive_time_ms */
#define KEEPALIVE_TIMEOUT_NS (20 * 1000000000LL) /* grpc.keepalive_timeout_ms */

struct sconn {
    struct ks_ui_server *srv;
    struct ks_grpc_conn *g;
    guint in_id, out_id;
    int64_t next_tick;
    bool closing;
    char peer[KS_NODE_ADDR_MAX];
    struct sconn *next;
};

struct ks_ui_server {
    struct ks_service *svc;
    int lfd[MAX_LISTENERS];
    guint lid[MAX_LISTENERS];
    size_t nl;
    struct sconn *conns;
    size_t nconns;
    guint timer_id;
    int64_t timer_at;
    size_t max_msg;
    int max_clients;
    struct ks_tls_ctx *tls;
};

size_t ks_ui_max_msg_length(const char *s)
{
    if (s != NULL && strcmp(s, "8MiB") == 0)
        return 8388608;
    if (s != NULL && strcmp(s, "16MiB") == 0)
        return 16777216;
    return 4194304;
}

size_t ks_ui_server_conns(const struct ks_ui_server *srv)
{
    return srv->nconns;
}

/* ---- connections ------------------------------------------------------- */

static void rearm(struct ks_ui_server *srv);

static void conn_free(struct sconn *c)
{
    struct ks_ui_server *srv = c->srv;
    for (struct sconn **pp = &srv->conns; *pp; pp = &(*pp)->next) {
        if (*pp == c) {
            *pp = c->next;
            srv->nconns--;
            break;
        }
    }
    c->closing = true;
    if (c->in_id)
        g_source_remove(c->in_id);
    if (c->out_id)
        g_source_remove(c->out_id);
    c->in_id = c->out_id = 0;
    ks_grpc_conn_free(c->g);
    free(c);
}

/* After driving a connection: its next timer, or freeing it once closed. */
static bool conn_after(struct sconn *c)
{
    if (ks_grpc_conn_closed(c->g)) {
        conn_free(c);
        return false;
    }
    c->next_tick = ks_grpc_conn_tick(c->g);
    if (ks_grpc_conn_closed(c->g)) {
        conn_free(c);
        return false;
    }
    return true;
}

static gboolean on_conn_in(gint fd, GIOCondition cond, gpointer data)
{
    (void)fd;
    struct sconn *c = data;
    struct ks_ui_server *srv = c->srv;
    ks_grpc_conn_on_io(c->g, (cond & (G_IO_IN | G_IO_HUP | G_IO_ERR)) != 0, false);
    bool alive = conn_after(c);
    rearm(srv);
    return alive ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static gboolean on_conn_out(gint fd, GIOCondition cond, gpointer data)
{
    (void)fd;
    (void)cond;
    struct sconn *c = data;
    struct ks_ui_server *srv = c->srv;
    ks_grpc_conn_on_io(c->g, false, true);
    bool alive = conn_after(c);
    rearm(srv);
    return alive ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static void conn_want_write(struct ks_grpc_conn *g, bool on, void *data)
{
    (void)g;
    struct sconn *c = data;
    if (c->closing)
        return;
    if (on && c->out_id == 0) {
        c->out_id = g_unix_fd_add(ks_grpc_conn_fd(c->g), G_IO_OUT, on_conn_out, c);
    } else if (!on && c->out_id != 0) {
        g_source_remove(c->out_id);
        c->out_id = 0;
    }
}

static int conn_on_call(struct ks_grpc_conn *g, struct ks_grpc_call *call, const char *path,
                        void *data)
{
    (void)g;
    struct sconn *c = data;
    return ks_service_on_call(c->srv->svc, call, path, c->peer);
}

static void conn_on_closed(struct ks_grpc_conn *g, const char *reason, void *data)
{
    (void)g;
    struct sconn *c = data;
    ks_debug("[server] connection from %s closed: %s", c->peer, reason);
}

/* context.peer() as grpc core writes it. */
static void peer_string(const struct sockaddr_storage *ss, socklen_t len, char *out,
                        size_t outlen)
{
    char ip[INET6_ADDRSTRLEN];
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        snprintf(out, outlen, "ipv4:%s:%u", ip, ntohs(in->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
        /* v4-mapped addresses are reported as IPv4 */
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            inet_ntop(AF_INET, &in6->sin6_addr.s6_addr[12], ip, sizeof(ip));
            snprintf(out, outlen, "ipv4:%s:%u", ip, ntohs(in6->sin6_port));
        } else {
            inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
            snprintf(out, outlen, "ipv6:[%s]:%u", ip, ntohs(in6->sin6_port));
        }
    } else {
        /* the daemon's end of a unix socket has no name */
        (void)len;
        snprintf(out, outlen, "unix:");
    }
}

static gboolean on_accept(gint lfd, GIOCondition cond, gpointer data)
{
    (void)cond;
    struct ks_ui_server *srv = data;
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int fd = accept(lfd, (struct sockaddr *)&ss, &sl);
        if (fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                ks_warning("[server] accept: %s", strerror(errno));
            break;
        }
        if (srv->max_clients > 0 && srv->nconns >= (size_t)srv->max_clients) {
            ks_warning("[server] too many connections, refusing one");
            close(fd);
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        struct sconn *c = calloc(1, sizeof(*c));
        if (c == NULL) {
            close(fd);
            continue;
        }
        c->srv = srv;
        peer_string(&ss, sl, c->peer, sizeof(c->peer));
        struct ks_grpc_conn_opts opts = {
            .server = true,
            .max_recv = srv->max_msg,
            .keepalive_time_ns = KEEPALIVE_TIME_NS,
            .keepalive_timeout_ns = KEEPALIVE_TIMEOUT_NS,
            .tls = srv->tls,
        };
        static const struct ks_grpc_conn_cbs cbs = {
            .on_call = conn_on_call,
            .on_closed = conn_on_closed,
            .want_write = conn_want_write,
        };
        c->g = ks_grpc_conn_new(fd, &opts, &cbs, c);
        if (c->g == NULL) {
            free(c);
            continue;
        }
        c->next = srv->conns;
        srv->conns = c;
        srv->nconns++;
        c->in_id = g_unix_fd_add(fd, G_IO_IN | G_IO_HUP | G_IO_ERR, on_conn_in, c);
        /* the preface and SETTINGS go out when writable */
        conn_want_write(c->g, true, c);
        ks_debug("[server] new connection from %s", c->peer);
    }
    rearm(srv);
    return G_SOURCE_CONTINUE;
}

/* ---- timers ------------------------------------------------------------ */

static gboolean on_timer(gpointer data)
{
    struct ks_ui_server *srv = data;
    srv->timer_id = 0;
    int64_t now = ks_grpc_now();
    for (struct sconn *c = srv->conns, *nx; c != NULL; c = nx) {
        nx = c->next;
        if (c->next_tick >= 0 && c->next_tick <= now)
            conn_after(c);
    }
    rearm(srv);
    return G_SOURCE_REMOVE;
}

static void rearm(struct ks_ui_server *srv)
{
    int64_t next = -1;
    for (const struct sconn *c = srv->conns; c != NULL; c = c->next) {
        if (c->next_tick >= 0 && (next < 0 || c->next_tick < next))
            next = c->next_tick;
    }
    if (srv->timer_id != 0 && srv->timer_at == next)
        return;
    if (srv->timer_id != 0) {
        g_source_remove(srv->timer_id);
        srv->timer_id = 0;
    }
    if (next < 0)
        return;
    int64_t ms = (next - ks_grpc_now() + 999999) / 1000000;
    if (ms < 0)
        ms = 0;
    srv->timer_at = next;
    srv->timer_id = g_timeout_add((guint)(ms > 3600000 ? 3600000 : ms), on_timer, srv);
}

/* ---- listening --------------------------------------------------------- */

static int add_listener(struct ks_ui_server *srv, int fd)
{
    if (srv->nl >= MAX_LISTENERS) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    srv->lfd[srv->nl] = fd;
    srv->lid[srv->nl] = g_unix_fd_add(fd, G_IO_IN, on_accept, srv);
    srv->nl++;
    return 0;
}

static int listen_unix(struct ks_ui_server *srv, const char *path, bool abstract, char *err,
                       size_t errlen)
{
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    size_t pl = strlen(path);
    size_t off = abstract ? 1 : 0;
    if (pl + off >= sizeof(un.sun_path)) {
        snprintf(err, errlen, "unix socket path too long: %s", path);
        return -1;
    }
    memcpy(un.sun_path + off, path, pl);
    socklen_t sl = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + off + pl + (abstract ? 0 : 1));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }
    if (!abstract) {
        /* grpc removes a stale socket file before binding */
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode))
            unlink(path);
    }
    if (bind(fd, (struct sockaddr *)&un, sl) < 0 || listen(fd, 64) < 0) {
        snprintf(err, errlen, "Failed to bind to address %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    return add_listener(srv, fd);
}

static int listen_tcp(struct ks_ui_server *srv, const char *addr, char *err, size_t errlen)
{
    char host[256], port[16];
    const char *colon;
    if (addr[0] == '[') {
        const char *close = strchr(addr, ']');
        if (close == NULL || close[1] != ':')
            goto bad;
        snprintf(host, sizeof(host), "%.*s", (int)(close - addr - 1), addr + 1);
        colon = close + 1;
    } else {
        colon = strrchr(addr, ':');
        if (colon == NULL)
            goto bad;
        snprintf(host, sizeof(host), "%.*s", (int)(colon - addr), addr);
    }
    snprintf(port, sizeof(port), "%s", colon + 1);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                             .ai_flags = AI_PASSIVE}, *res = NULL;
    int rc = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "%s: %s", addr, gai_strerror(rc));
        return -1;
    }
    int bound = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0 || listen(fd, 64) < 0) {
            /* "[::]" is dual stack: 0.0.0.0 on the same port fails */
            if (bound == 0)
                snprintf(err, errlen, "Failed to bind to address %s: %s", addr, strerror(errno));
            close(fd);
            continue;
        }
        if (add_listener(srv, fd) == 0)
            bound++;
    }
    freeaddrinfo(res);
    return bound > 0 ? 0 : -1;
bad:
    snprintf(err, errlen, "invalid address: %s", addr);
    return -1;
}

struct ks_ui_server *ks_ui_server_new(const struct ks_ui_server_opts *opts,
                                      struct ks_service *svc, char *err, size_t errlen)
{
    struct ks_ui_server *srv = calloc(1, sizeof(*srv));
    if (srv == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    srv->svc = svc;
    srv->max_msg = opts->max_msg ? opts->max_msg : KS_GRPC_MAX_RECV_DEFAULT;
    srv->max_clients = opts->max_clients;
    srv->tls = opts->tls;
    const char *a = opts->address;
    int rc;
    if (strncmp(a, "unix-abstract:", 14) == 0) {
        rc = listen_unix(srv, a + 14, true, err, errlen);
    } else if (strncmp(a, "unix:@", 6) == 0) {
        rc = listen_unix(srv, a + 6, true, err, errlen);
    } else if (strncmp(a, "unix:", 5) == 0) {
        const char *path = a + 5;
        /* unix://abs -> /abs; "unix:///tmp/x" keeps one slash */
        if (strncmp(path, "//", 2) == 0)
            path += 2;
        rc = listen_unix(srv, path, false, err, errlen);
        /* restrict_socket_perms(): only for unix:// addresses */
        if (rc == 0 && strncmp(a, "unix://", 7) == 0)
            chmod(path, 0640);
    } else {
        rc = listen_tcp(srv, a, err, errlen);
    }
    if (rc < 0) {
        ks_ui_server_free(srv);
        return NULL;
    }
    ks_info("[server] using address: %s", a);
    return srv;
}

void ks_ui_server_free(struct ks_ui_server *srv)
{
    if (srv == NULL)
        return;
    while (srv->conns)
        conn_free(srv->conns);
    for (size_t i = 0; i < srv->nl; i++) {
        g_source_remove(srv->lid[i]);
        close(srv->lfd[i]);
    }
    if (srv->timer_id)
        g_source_remove(srv->timer_id);
    free(srv);
}
