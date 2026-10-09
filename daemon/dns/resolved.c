/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/dns/systemd/monitor.go (ResolvedMonitor),
 * initSystemdResolvedMonitor() in daemon/main.go, and the parts of
 * github.com/varlink/go v0.4.0 (Connection.Send and its receive callback)
 * they use.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/dns/resolved.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/unicode.h"
#include "daemon/dns/cache.h"
#include "daemon/dns/parse.h"
#include "daemon/evloop.h"

/* Success state and the answer types upstream tracks. */
#define SUCCESS_STATE "success"

/* Send(ctx, resolvedSubscribeMethod, &emptyT{}, Continues|More): the call
 * as json.Marshal writes it, plus the NUL. */
static const char subscribe_msg[] =
    "{\"method\":\"io.systemd.Resolve.Monitor.SubscribeQueryResults\","
    "\"parameters\":{},\"more\":true}";

struct ks_resolved {
    struct ks_evloop *loop;
    char *path;
    int fd;
    bool connected;
    char *buf;
    size_t len, cap;
    struct ks_timer *retry;
};

/* ---- lenient decoding, as encoding/json into MonitorResponse ---------- */
/* Upstream ignores json.Unmarshal's error for the parameters: fields of
 * the wrong type keep their zero value and the rest still decodes. Keys
 * match without case (ASCII, divergence 2); with repeated keys the last
 * one wins, and repeated objects merge, as in Go. */

static bool key_is(const cJSON *item, const char *key)
{
    return item->string != NULL && strcasecmp(item->string, key) == 0;
}

/* Go int from a JSON number (divergence 1 for literals like 1.0). */
static void dec_int(const cJSON *v, int64_t *out)
{
    if (!cJSON_IsNumber(v))
        return;
    double d = v->valuedouble;
    /* Range first: converting an out-of-range double is undefined. */
    if (d >= -9223372036854775808.0 && d < 9223372036854775808.0 && d == (double)(int64_t)d)
        *out = (int64_t)d;
}

static void dec_string(const cJSON *v, const char **out)
{
    if (cJSON_IsString(v))
        *out = v->valuestring;
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* base64.StdEncoding.Decode: '\r' and '\n' are skipped, padding is
 * required and only at the end, trailing bits are ignored. Returns a
 * malloc'd buffer (possibly empty) or NULL on error. */
static uint8_t *b64_decode(const char *s, size_t *out_len)
{
    size_t n = strlen(s);
    char *t = malloc(n + 1);
    uint8_t *out = malloc(n / 4 * 3 + 1);
    size_t m = 0, o = 0;
    if (t == NULL || out == NULL)
        goto fail;
    for (size_t i = 0; i < n; i++)
        if (s[i] != '\r' && s[i] != '\n')
            t[m++] = s[i];
    if (m % 4 != 0)
        goto fail;
    for (size_t i = 0; i < m; i += 4) {
        int v[4], k;
        for (k = 0; k < 4; k++) {
            if (t[i + k] == '=')
                break;
            if ((v[k] = b64_value(t[i + k])) < 0)
                goto fail;
        }
        if (k < 4) { /* padding: "xx==" or "xxx=", in the last quantum */
            if (k < 2 || i + 4 != m || (k == 2 && t[i + 3] != '='))
                goto fail;
        }
        uint32_t q = 0;
        for (int j = 0; j < k; j++)
            q |= (uint32_t)v[j] << (18 - 6 * j);
        out[o++] = (uint8_t)(q >> 16);
        if (k > 2)
            out[o++] = (uint8_t)(q >> 8);
        if (k > 3)
            out[o++] = (uint8_t)q;
    }
    free(t);
    *out_len = o;
    return out;
fail:
    free(t);
    free(out);
    return NULL;
}

/* RRType: name, address, key. */
struct rr {
    const char *name;
    uint8_t *address; /* owned; NULL is Go's nil */
    size_t address_len;
    const char *key_name;
    int64_t key_type;
};

static void dec_address(const cJSON *v, struct rr *rr)
{
    if (cJSON_IsNull(v)) {
        free(rr->address);
        rr->address = NULL;
        rr->address_len = 0;
        return;
    }
    uint8_t *b = NULL;
    size_t n = 0;
    if (cJSON_IsArray(v)) {
        n = (size_t)cJSON_GetArraySize(v);
        b = calloc(n + 1, 1);
        if (b == NULL)
            return;
        size_t i = 0;
        const cJSON *e;
        cJSON_ArrayForEach(e, v) {
            int64_t x = 0;
            dec_int(e, &x);
            b[i++] = x >= 0 && x <= 255 ? (uint8_t)x : 0; /* out of range: error, 0 */
        }
    } else if (cJSON_IsString(v)) {
        if ((b = b64_decode(v->valuestring, &n)) == NULL)
            return; /* CorruptInputError: field unchanged */
    } else {
        return;
    }
    free(rr->address);
    rr->address = b;
    rr->address_len = n;
}

static void dec_key(const cJSON *obj, struct rr *rr)
{
    const cJSON *m;
    cJSON_ArrayForEach(m, obj) {
        if (key_is(m, "name"))
            dec_string(m, &rr->key_name);
        else if (key_is(m, "type"))
            dec_int(m, &rr->key_type);
    }
}

static void dec_rr(const cJSON *obj, struct rr *rr)
{
    const cJSON *m;
    cJSON_ArrayForEach(m, obj) {
        if (key_is(m, "name"))
            dec_string(m, &rr->name);
        else if (key_is(m, "address"))
            dec_address(m, rr);
        else if (key_is(m, "key") && cJSON_IsObject(m))
            dec_key(m, rr);
    }
}

/* AnswerMonitorResponse: only "rr" is used. */
static void dec_answer(const cJSON *obj, struct rr *rr)
{
    const cJSON *m;
    cJSON_ArrayForEach(m, obj)
        if (key_is(m, "rr") && cJSON_IsObject(m))
            dec_rr(m, rr);
}

struct response {
    const char *state;
    struct rr *answer;
    size_t nanswer;
};

static void free_answers(struct response *r)
{
    for (size_t i = 0; i < r->nanswer; i++)
        free(r->answer[i].address);
    free(r->answer);
    r->answer = NULL;
    r->nanswer = 0;
}

static void dec_response(const cJSON *obj, struct response *r)
{
    const cJSON *m;
    cJSON_ArrayForEach(m, obj) {
        if (key_is(m, "state")) {
            dec_string(m, &r->state);
        } else if (key_is(m, "answer")) {
            if (cJSON_IsNull(m)) {
                free_answers(r);
            } else if (cJSON_IsArray(m)) {
                size_t n = (size_t)cJSON_GetArraySize(m);
                struct rr *a = calloc(n + 1, sizeof(*a));
                if (a == NULL)
                    continue;
                free_answers(r);
                r->answer = a;
                r->nanswer = n;
                size_t i = 0;
                const cJSON *e;
                cJSON_ArrayForEach(e, m) {
                    a[i].name = a[i].key_name = "";
                    if (cJSON_IsObject(e))
                        dec_answer(e, &a[i]);
                    i++;
                }
            }
        }
    }
}

/* ---- the response handler in initSystemdResolvedMonitor() ------------- */

/* Go converts invalid UTF-8 in JSON strings to U+FFFD. */
static void track(const char *resolved, const char *hostname)
{
    size_t n;
    char *r = ks_utf8_sanitize(resolved, strlen(resolved), &n);
    char *h = ks_utf8_sanitize(hostname, strlen(hostname), &n);
    if (r != NULL && h != NULL)
        ks_dns_track(r, h);
    free(r);
    free(h);
}

static void handle_response(const struct response *resp)
{
    if (strcmp(resp->state, SUCCESS_STATE) != 0) {
        ks_debug("[DNS] systemd-resolved monitor response error: state=%s answers=%zu",
                 resp->state, resp->nanswer);
        return;
    }
    for (size_t i = 0; i < resp->nanswer; i++) {
        const struct rr *a = &resp->answer[i];
        if (a->key_type != KS_DNS_TYPE_A && a->key_type != KS_DNS_TYPE_AAAA &&
            a->key_type != KS_DNS_TYPE_CNAME) {
            ks_trace("systemd-resolved, excluding answer: type %lld %s", (long long)a->key_type,
                     a->key_name);
            continue;
        }
        if (a->key_type == KS_DNS_TYPE_CNAME) {
            ks_debug("systemd-resolved CNAME >> %s -> %s", a->name, a->key_name);
            track(a->name, a->key_name);
        } else {
            char *ip = ks_dns_ip_string(a->address, a->address_len);
            if (ip == NULL)
                continue;
            ks_debug("%zu systemd-resolved monitor response: %s -> %s", i, a->key_name, ip);
            track(ip, a->key_name);
            free(ip);
        }
    }
}

enum ks_resolved_reply ks_resolved_handle_reply(const char *msg, size_t len)
{
    char err[128];
    cJSON *root = ks_json_parse(msg, len, err, sizeof(err));
    if (root == NULL) {
        ks_debug("[DNS] systemd-resolved: invalid reply: %s", err);
        return KS_RESOLVED_ERROR;
    }

    /* varlink's reply struct. null leaves it zeroed: not continued. */
    enum ks_resolved_reply ret = KS_RESOLVED_END;
    const cJSON *params = NULL, *m;
    bool continues = false, type_error = !cJSON_IsObject(root) && !cJSON_IsNull(root);
    const char *error = "";
    if (cJSON_IsObject(root)) {
        cJSON_ArrayForEach(m, root) {
            if (key_is(m, "parameters")) {
                params = cJSON_IsNull(m) ? NULL : m;
            } else if (key_is(m, "continues")) {
                if (cJSON_IsBool(m))
                    continues = cJSON_IsTrue(m);
                else if (!cJSON_IsNull(m))
                    type_error = true;
            } else if (key_is(m, "error")) {
                if (cJSON_IsString(m))
                    error = m->valuestring;
                else if (!cJSON_IsNull(m))
                    type_error = true;
            }
        }
    }
    if (type_error) {
        ks_debug("[DNS] systemd-resolved: invalid reply");
        ret = KS_RESOLVED_ERROR;
    } else if (error[0] != '\0') {
        ks_debug("[DNS] systemd-resolved: %s", error);
        ret = KS_RESOLVED_ERROR;
    } else if (continues) {
        /* monitor() only passes on replies that continue. */
        struct response resp = {.state = ""};
        if (params != NULL && cJSON_IsObject(params))
            dec_response(params, &resp);
        ks_trace("ResolvedMonitor >> new response: state=%s answers=%zu", resp.state,
                 resp.nanswer);
        handle_response(&resp);
        free_answers(&resp);
        ret = KS_RESOLVED_CONTINUE;
    }
    cJSON_Delete(root);
    return ret;
}

/* ---- connection --------------------------------------------------------- */

static void on_readable(int fd, uint32_t events, void *data);
static void on_retry(void *data);

static void disconnect(struct ks_resolved *r)
{
    if (r->fd >= 0) {
        ks_evloop_del_fd(r->loop, r->fd);
        close(r->fd);
        r->fd = -1;
    }
    r->connected = false;
    r->len = 0;
}

/* Connect() + Subscribe(). Returns 0 or -1 with `err` filled. */
static int connect_subscribe(struct ks_resolved *r, const char **what, char *err, size_t errlen)
{
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    size_t plen = strlen(r->path);
    *what = "Connecting to";
    if (plen >= sizeof(sa.sun_path)) {
        snprintf(err, errlen, "dial unix %s: path too long", r->path);
        return -1;
    }
    memcpy(sa.sun_path, r->path, plen + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errlen, "dial unix %s: connect: %s", r->path, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    *what = "Subscribing to";
    /* The message is far smaller than any socket buffer: a fresh socket
     * takes it whole. */
    ssize_t n = send(fd, subscribe_msg, sizeof(subscribe_msg), MSG_NOSIGNAL);
    if (n != (ssize_t)sizeof(subscribe_msg)) {
        snprintf(err, errlen, "%s", n < 0 ? strerror(errno) : "short write");
        close(fd);
        return -1;
    }
    if (ks_evloop_add_fd(r->loop, fd, EPOLLIN, on_readable, r) < 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        close(fd);
        return -1;
    }
    r->fd = fd;
    r->connected = true;
    r->len = 0;
    return 0;
}

/* monitor() exited: connPoller reconnects within 5 s. Upstream tries only
 * once (and only subscribes if that works); here it keeps trying every
 * 5 s (docs/UPSTREAM.md, divergences). */
static void schedule_retry(struct ks_resolved *r)
{
    if (r->retry == NULL)
        r->retry = ks_evloop_add_timer(r->loop, KS_RESOLVED_RECONNECT_NS, 0, on_retry, r);
}

static void on_retry(void *data)
{
    struct ks_resolved *r = data;
    r->retry = NULL;
    ks_debug("ResolvedMonitor not connected");
    char err[256];
    const char *what;
    if (connect_subscribe(r, &what, err, sizeof(err)) < 0) {
        ks_debug("[DNS] %s systemd-resolved: %s", what, err);
        schedule_retry(r);
    }
}

static void lost(struct ks_resolved *r, bool error)
{
    if (error)
        ks_debug("[DNS] systemd-resolved monitor disconnected. Reconnecting...");
    ks_debug("ResolvedMonitor.monitor() exit.");
    disconnect(r);
    schedule_retry(r);
}

static void on_readable(int fd, uint32_t events, void *data)
{
    struct ks_resolved *r = data;
    (void)events;
    for (;;) {
        if (r->cap - r->len < 4096) {
            size_t ncap = r->cap ? r->cap * 2 : 8192;
            if (ncap > KS_RESOLVED_MSG_MAX + 4096)
                ncap = KS_RESOLVED_MSG_MAX + 4096;
            if (ncap <= r->cap) {
                ks_debug("[DNS] systemd-resolved: message too long");
                lost(r, true);
                return;
            }
            char *b = realloc(r->buf, ncap);
            if (b == NULL) {
                lost(r, true);
                return;
            }
            r->buf = b;
            r->cap = ncap;
        }
        ssize_t n = read(fd, r->buf + r->len, r->cap - r->len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (n <= 0) { /* io.ErrUnexpectedEOF, or a read error */
            lost(r, true);
            return;
        }
        r->len += (size_t)n;

        /* Hand out every complete message. */
        size_t start = 0;
        char *nul;
        while ((nul = memchr(r->buf + start, '\0', r->len - start)) != NULL) {
            size_t mlen = (size_t)(nul - (r->buf + start));
            enum ks_resolved_reply rep = ks_resolved_handle_reply(r->buf + start, mlen);
            if (rep != KS_RESOLVED_CONTINUE) {
                lost(r, rep == KS_RESOLVED_ERROR);
                return;
            }
            start += mlen + 1;
        }
        memmove(r->buf, r->buf + start, r->len - start);
        r->len -= start;
    }
}

struct ks_resolved *ks_resolved_start(struct ks_evloop *loop, const char *socket_path)
{
    /* NewResolvedMonitor */
    struct stat st;
    if (stat(socket_path, &st) < 0) {
        ks_debug("[DNS] Unable to use systemd-resolved monitor: %s doesn't exist", socket_path);
        return NULL;
    }
    struct ks_resolved *r = calloc(1, sizeof(*r));
    if (r == NULL || (r->path = strdup(socket_path)) == NULL) {
        free(r);
        return NULL;
    }
    r->loop = loop;
    r->fd = -1;
    char err[256];
    const char *what;
    if (connect_subscribe(r, &what, err, sizeof(err)) < 0) {
        ks_debug("[DNS] %s systemd-resolved%s: %s", what,
                 strcmp(what, "Subscribing to") == 0 ? " DNS events" : "", err);
        ks_resolved_stop(r);
        return NULL;
    }
    return r;
}

void ks_resolved_stop(struct ks_resolved *r)
{
    if (r == NULL)
        return;
    disconnect(r);
    if (r->retry != NULL)
        ks_evloop_cancel_timer(r->loop, r->retry);
    free(r->buf);
    free(r->path);
    free(r);
}

bool ks_resolved_connected(const struct ks_resolved *r)
{
    return r != NULL && r->connected;
}
