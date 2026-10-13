/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal gRPC over nghttp2. See grpc.h and docs/PROTOCOL.md.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/grpc/grpc.h"

#include <errno.h>
#include <limits.h>
#include <nghttp2/nghttp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* A growable byte buffer with a read offset. */
struct buf {
    uint8_t *data;
    size_t off, len, cap;
};

static int buf_append(struct buf *b, const void *p, size_t n)
{
    if (n == 0)
        return 0;
    if (b->off > 0 && b->off == b->len)
        b->off = b->len = 0;
    if (b->len + n > b->cap) {
        if (b->off > 0) {
            memmove(b->data, b->data + b->off, b->len - b->off);
            b->len -= b->off;
            b->off = 0;
        }
        if (b->len + n > b->cap) {
            size_t cap = b->cap ? b->cap : 256;
            while (cap < b->len + n) {
                if (cap > SIZE_MAX / 2)
                    return -1;
                cap *= 2;
            }
            uint8_t *d = realloc(b->data, cap);
            if (d == NULL)
                return -1;
            b->data = d;
            b->cap = cap;
        }
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

static size_t buf_avail(const struct buf *b)
{
    return b->len - b->off;
}

static void buf_free(struct buf *b)
{
    free(b->data);
    memset(b, 0, sizeof(*b));
}

struct ks_grpc_call {
    struct ks_grpc_conn *conn;
    struct ks_grpc_call *prev, *next;
    int32_t stream_id;
    struct ks_grpc_call_cbs cbs;
    void *data;
    int64_t deadline; /* 0: none */

    struct buf rx; /* received, not yet deframed */
    struct buf tx; /* framed messages waiting for the data provider */
    bool provider;  /* a data provider is attached to the stream */
    bool deferred;  /* the provider returned NGHTTP2_ERR_DEFERRED */
    bool tx_eof;    /* client: close_send; server: finish */

    /* server */
    char *path;
    bool headers_sent;
    int finish_status;
    char *finish_message;

    /* client: response state */
    int http_status;
    bool grpc_content_type;
    bool have_status;
    int status;
    char *message;

    bool reported; /* on_close ran: no more callbacks */
};

struct ks_grpc_conn {
    int fd;
    nghttp2_session *session;
    struct ks_grpc_conn_opts opts;
    char *authority;
    struct ks_grpc_conn_cbs cbs;
    void *data;
    struct ks_grpc_call *calls;

    bool ready;
    bool closed;     /* on_closed ran (or is about to) */
    bool failing;    /* closing: finish_close() pending */
    char reason[128];
    bool blocked;    /* the last write hit EAGAIN */
    bool want_write; /* what we last told the driver */
    int depth;       /* > 0 while inside nghttp2 or a user callback */

    int64_t last_rx;
    int64_t ping_sent; /* 0: no keepalive ping outstanding */
};

int64_t ks_grpc_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

const char *ks_grpc_status_name(int status)
{
    static const char *const names[] = {
        "OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded",
        "NotFound", "AlreadyExists", "PermissionDenied", "ResourceExhausted",
        "FailedPrecondition", "Aborted", "OutOfRange", "Unimplemented",
        "Internal", "Unavailable", "DataLoss", "Unauthenticated",
    };
    unsigned u = (unsigned)status; /* negative values wrap around */
    if (u < sizeof(names) / sizeof(names[0]))
        return names[u];
    return "Unknown";
}

/* grpc-go encodeTimeout(). */
void ks_grpc_format_timeout(int64_t ns, char *buf, size_t len)
{
    static const struct { int64_t unit; char c; } units[] = {
        {1, 'n'}, {1000, 'u'}, {1000000, 'm'}, {1000000000, 'S'},
        {60LL * 1000000000, 'M'}, {3600LL * 1000000000, 'H'},
    };
    if (ns <= 0) {
        snprintf(buf, len, "0n");
        return;
    }
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
        int64_t d = ns / units[i].unit + (ns % units[i].unit != 0);
        if (d <= 99999999) {
            snprintf(buf, len, "%lld%c", (long long)d, units[i].c);
            return;
        }
    }
    snprintf(buf, len, "99999999H");
}

int64_t ks_grpc_parse_timeout(const char *s, size_t len)
{
    if (len < 2 || len > 9)
        return -1;
    int64_t v = 0;
    for (size_t i = 0; i + 1 < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (s[i] - '0');
    }
    int64_t unit;
    switch (s[len - 1]) {
    case 'n': unit = 1; break;
    case 'u': unit = 1000; break;
    case 'm': unit = 1000000; break;
    case 'S': unit = 1000000000; break;
    case 'M': unit = 60LL * 1000000000; break;
    case 'H': unit = 3600LL * 1000000000; break;
    default: return -1;
    }
    if (v > INT64_MAX / unit)
        return INT64_MAX;
    return v * unit;
}

void ks_grpc_percent_encode(const char *in, char *out, size_t outlen)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    if (outlen == 0)
        return;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (*p >= 0x20 && *p <= 0x7e && *p != '%') {
            if (o + 1 >= outlen)
                break;
            out[o++] = (char)*p;
        } else {
            if (o + 3 >= outlen)
                break;
            out[o++] = '%';
            out[o++] = hex[*p >> 4];
            out[o++] = hex[*p & 15];
        }
    }
    out[o] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void ks_grpc_percent_decode(const char *in, size_t inlen, char *out, size_t outlen)
{
    size_t o = 0;
    if (outlen == 0)
        return;
    for (size_t i = 0; i < inlen && o + 1 < outlen; i++) {
        int h, l;
        if (in[i] == '%' && i + 2 < inlen && (h = hexval(in[i + 1])) >= 0 &&
            (l = hexval(in[i + 2])) >= 0) {
            out[o++] = (char)(h << 4 | l);
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
}

/* ---- connection plumbing ------------------------------------------------ */

static void conn_fail(struct ks_grpc_conn *c, const char *reason)
{
    if (c->failing || c->closed)
        return;
    c->failing = true;
    snprintf(c->reason, sizeof(c->reason), "%s", reason);
}

static void call_unlink_free(struct ks_grpc_call *call)
{
    struct ks_grpc_conn *c = call->conn;
    if (call->prev)
        call->prev->next = call->next;
    else if (c->calls == call)
        c->calls = call->next;
    if (call->next)
        call->next->prev = call->prev;
    if (call->stream_id > 0 && c->session != NULL)
        nghttp2_session_set_stream_user_data(c->session, call->stream_id, NULL);
    buf_free(&call->rx);
    buf_free(&call->tx);
    free(call->path);
    free(call->finish_message);
    free(call->message);
    free(call);
}

/* Runs on_close once. The struct stays until its stream is gone. */
static void call_report(struct ks_grpc_call *call, int status, const char *message)
{
    if (call->reported)
        return;
    call->reported = true;
    if (call->cbs.on_close) {
        call->conn->depth++;
        call->cbs.on_close(call, status, message ? message : "", call->data);
        call->conn->depth--;
    }
}

static struct ks_grpc_call *call_new(struct ks_grpc_conn *c)
{
    struct ks_grpc_call *call = calloc(1, sizeof(*call));
    if (call == NULL)
        return NULL;
    call->conn = c;
    call->next = c->calls;
    if (c->calls)
        c->calls->prev = call;
    c->calls = call;
    return call;
}

static void set_want_write(struct ks_grpc_conn *c, bool on)
{
    if (c->want_write == on)
        return;
    c->want_write = on;
    if (c->cbs.want_write)
        c->cbs.want_write(c, on, c->data);
}

/* Sends what nghttp2 has queued, unless we're inside a callback (the
 * outermost caller flushes). */
static void flush(struct ks_grpc_conn *c)
{
    if (c->depth > 0 || c->closed || c->failing || c->session == NULL)
        return;
    c->depth++;
    int rv = nghttp2_session_send(c->session);
    c->depth--;
    if (rv != 0) {
        conn_fail(c, nghttp2_strerror(rv));
        return;
    }
    set_want_write(c, c->blocked && nghttp2_session_want_write(c->session));
}

/* After the session is over: every call is told, then the owner. */
static void finish_close(struct ks_grpc_conn *c)
{
    if (c->closed || c->depth > 0)
        return;
    if (!c->failing && c->session != NULL && (nghttp2_session_want_read(c->session) ||
                                              nghttp2_session_want_write(c->session)))
        return;
    if (!c->failing)
        snprintf(c->reason, sizeof(c->reason), "connection closed");
    c->closed = true;
    set_want_write(c, false);
    int status = c->opts.server ? KS_GRPC_CANCELLED : KS_GRPC_UNAVAILABLE;
    while (c->calls != NULL) {
        struct ks_grpc_call *call = c->calls;
        call_report(call, status, c->reason);
        call_unlink_free(call);
    }
    if (c->cbs.on_closed)
        c->cbs.on_closed(c, c->reason, c->data); /* may free c */
}

/* ---- data provider -------------------------------------------------------- */

static void make_nv(nghttp2_nv *nv, const char *name, const char *value)
{
    nv->name = (uint8_t *)(uintptr_t)name;
    nv->namelen = strlen(name);
    nv->value = (uint8_t *)(uintptr_t)value;
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP2_NV_FLAG_NONE;
}

static int submit_trailers(struct ks_grpc_call *call)
{
    char status[16], message[512];
    snprintf(status, sizeof(status), "%d", call->finish_status);
    nghttp2_nv nv[2];
    size_t n = 0;
    make_nv(&nv[n++], "grpc-status", status);
    if (call->finish_message && call->finish_message[0]) {
        ks_grpc_percent_encode(call->finish_message, message, sizeof(message));
        make_nv(&nv[n++], "grpc-message", message);
    }
    return nghttp2_submit_trailer(call->conn->session, call->stream_id, nv, n);
}

static ssize_t read_cb(nghttp2_session *session, int32_t stream_id, uint8_t *out,
                       size_t length, uint32_t *flags, nghttp2_data_source *source,
                       void *user_data)
{
    (void)session;
    (void)stream_id;
    (void)user_data;
    struct ks_grpc_call *call = source->ptr;
    size_t n = buf_avail(&call->tx);
    if (n > length)
        n = length;
    if (n > 0) {
        memcpy(out, call->tx.data + call->tx.off, n);
        call->tx.off += n;
    }
    if (buf_avail(&call->tx) == 0) {
        if (call->tx_eof) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
            if (call->conn->opts.server) {
                *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                if (submit_trailers(call) != 0)
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
        } else if (n == 0) {
            call->deferred = true;
            return NGHTTP2_ERR_DEFERRED;
        }
    }
    return (ssize_t)n;
}

static void resume(struct ks_grpc_call *call)
{
    if (call->deferred) {
        call->deferred = false;
        nghttp2_session_resume_data(call->conn->session, call->stream_id);
    }
}

/* ---- receiving ------------------------------------------------------------ */

static int call_status_from_http(int http)
{
    switch (http) {
    case 400: return KS_GRPC_INTERNAL;
    case 401: return KS_GRPC_UNAUTHENTICATED;
    case 403: return KS_GRPC_PERMISSION_DENIED;
    case 404: return KS_GRPC_UNIMPLEMENTED;
    case 429: case 502: case 503: case 504: return KS_GRPC_UNAVAILABLE;
    }
    return KS_GRPC_UNKNOWN;
}

static void server_reject(struct ks_grpc_call *call, int status, const char *msg);

/* Splits call->rx into messages. Returns -1 if the call was failed. */
static int deframe(struct ks_grpc_call *call)
{
    struct ks_grpc_conn *c = call->conn;
    size_t max = c->opts.max_recv ? c->opts.max_recv : KS_GRPC_MAX_RECV_DEFAULT;
    while (!call->reported && buf_avail(&call->rx) >= 5) {
        const uint8_t *p = call->rx.data + call->rx.off;
        uint32_t len = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 |
                       (uint32_t)p[3] << 8 | p[4];
        char msg[128];
        if (p[0] != 0) {
            snprintf(msg, sizeof(msg), "grpc: compressed flag set with identity or "
                                       "empty encoding");
            goto fail_internal;
        }
        if (len > max) {
            snprintf(msg, sizeof(msg),
                     "grpc: received message larger than max (%u vs. %zu)", len, max);
            if (c->opts.server) {
                server_reject(call, KS_GRPC_RESOURCE_EXHAUSTED, msg);
            } else {
                nghttp2_submit_rst_stream(c->session, NGHTTP2_FLAG_NONE, call->stream_id,
                                          NGHTTP2_CANCEL);
                call_report(call, KS_GRPC_RESOURCE_EXHAUSTED, msg);
            }
            return -1;
        }
        if (buf_avail(&call->rx) - 5 < len)
            return 0;
        call->rx.off += 5 + (size_t)len;
        if (call->cbs.on_message) {
            c->depth++;
            call->cbs.on_message(call, p + 5, len, call->data);
            c->depth--;
        }
        continue;
fail_internal:
        if (c->opts.server) {
            server_reject(call, KS_GRPC_INTERNAL, msg);
        } else {
            nghttp2_submit_rst_stream(c->session, NGHTTP2_FLAG_NONE, call->stream_id,
                                      NGHTTP2_CANCEL);
            call_report(call, KS_GRPC_INTERNAL, msg);
        }
        return -1;
    }
    return 0;
}

static int on_data_chunk(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                         const uint8_t *data, size_t len, void *user_data)
{
    (void)flags;
    (void)user_data;
    struct ks_grpc_call *call = nghttp2_session_get_stream_user_data(session, stream_id);
    if (call == NULL || call->reported)
        return 0;
    if (buf_append(&call->rx, data, len) < 0) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id,
                                  NGHTTP2_INTERNAL_ERROR);
        call_report(call, KS_GRPC_RESOURCE_EXHAUSTED, "out of memory");
        return 0;
    }
    deframe(call);
    return 0;
}

static bool name_is(const uint8_t *name, size_t namelen, const char *s)
{
    return namelen == strlen(s) && memcmp(name, s, namelen) == 0;
}

static char *dup_n(const uint8_t *p, size_t n)
{
    char *s = malloc(n + 1);
    if (s != NULL) {
        memcpy(s, p, n);
        s[n] = '\0';
    }
    return s;
}

static int on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame,
                            void *user_data)
{
    struct ks_grpc_conn *c = user_data;
    if (!c->opts.server || frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    struct ks_grpc_call *call = call_new(c);
    if (call == NULL)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    call->stream_id = frame->hd.stream_id;
    nghttp2_session_set_stream_user_data(session, call->stream_id, call);
    return 0;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen, const uint8_t *value,
                     size_t valuelen, uint8_t flags, void *user_data)
{
    (void)flags;
    struct ks_grpc_conn *c = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    struct ks_grpc_call *call =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (call == NULL)
        return 0;

    if (c->opts.server) {
        if (name_is(name, namelen, ":path") && call->path == NULL) {
            call->path = dup_n(value, valuelen);
            if (call->path == NULL)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        } else if (name_is(name, namelen, "content-type")) {
            call->grpc_content_type =
                valuelen >= 16 && memcmp(value, "application/grpc", 16) == 0 &&
                (valuelen == 16 || value[16] == '+' || value[16] == ';');
        } else if (name_is(name, namelen, "grpc-timeout")) {
            int64_t t = ks_grpc_parse_timeout((const char *)value, valuelen);
            if (t >= 0) {
                int64_t now = ks_grpc_now();
                call->deadline = t > INT64_MAX - now ? INT64_MAX : now + t;
            }
        }
        return 0;
    }

    if (name_is(name, namelen, ":status")) {
        int v = 0;
        for (size_t i = 0; i < valuelen && i < 4; i++)
            v = v * 10 + (value[i] >= '0' && value[i] <= '9' ? value[i] - '0' : 0);
        call->http_status = v;
    } else if (name_is(name, namelen, "content-type")) {
        call->grpc_content_type =
            valuelen >= 16 && memcmp(value, "application/grpc", 16) == 0 &&
            (valuelen == 16 || value[16] == '+' || value[16] == ';');
    } else if (name_is(name, namelen, "grpc-status")) {
        int v = 0;
        bool ok = valuelen > 0 && valuelen <= 9;
        for (size_t i = 0; ok && i < valuelen; i++) {
            if (value[i] < '0' || value[i] > '9')
                ok = false;
            else
                v = v * 10 + (value[i] - '0');
        }
        call->have_status = true;
        call->status = ok ? v : KS_GRPC_UNKNOWN;
    } else if (name_is(name, namelen, "grpc-message")) {
        char *m = malloc(valuelen + 1);
        if (m == NULL)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        ks_grpc_percent_decode((const char *)value, valuelen, m, valuelen + 1);
        free(call->message);
        call->message = m;
    }
    return 0;
}

/* Client: the outcome of the call once its stream is over. */
static void client_status(struct ks_grpc_call *call, uint32_t error_code, int *status,
                          char *msg, size_t msglen)
{
    if (call->http_status != 0 && call->http_status != 200) {
        *status = call_status_from_http(call->http_status);
        snprintf(msg, msglen, "unexpected HTTP status code received from server: %d",
                 call->http_status);
        return;
    }
    if (call->have_status) {
        *status = call->status;
        snprintf(msg, msglen, "%s", call->message ? call->message : "");
        return;
    }
    if (error_code == NGHTTP2_CANCEL) {
        *status = KS_GRPC_CANCELLED;
        snprintf(msg, msglen, "stream terminated by RST_STREAM with error code: CANCEL");
    } else if (error_code == NGHTTP2_REFUSED_STREAM) {
        *status = KS_GRPC_UNAVAILABLE;
        snprintf(msg, msglen, "stream terminated by RST_STREAM with error code: "
                              "REFUSED_STREAM");
    } else if (error_code != NGHTTP2_NO_ERROR) {
        *status = KS_GRPC_INTERNAL;
        snprintf(msg, msglen, "stream terminated by RST_STREAM with error code: %u",
                 error_code);
    } else {
        *status = KS_GRPC_INTERNAL;
        snprintf(msg, msglen, "server closed the stream without sending trailers");
    }
}

static int server_start_call(struct ks_grpc_conn *c, struct ks_grpc_call *call)
{
    if (call->path == NULL || !call->grpc_content_type) {
        server_reject(call, KS_GRPC_INTERNAL, "invalid gRPC request headers");
        return 0;
    }
    int st = KS_GRPC_UNIMPLEMENTED;
    if (c->cbs.on_call) {
        c->depth++;
        st = c->cbs.on_call(c, call, call->path, c->data);
        c->depth--;
    }
    if (st != KS_GRPC_OK) {
        char msg[300];
        snprintf(msg, sizeof(msg), "unknown method %s", call->path);
        server_reject(call, st, st == KS_GRPC_UNIMPLEMENTED ? msg : NULL);
    }
    return 0;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *user_data)
{
    struct ks_grpc_conn *c = user_data;
    c->last_rx = ks_grpc_now();
    c->ping_sent = 0;

    switch (frame->hd.type) {
    case NGHTTP2_SETTINGS:
        if (!c->opts.server && !c->ready && !(frame->hd.flags & NGHTTP2_FLAG_ACK)) {
            c->ready = true;
            if (c->cbs.on_ready) {
                c->depth++;
                c->cbs.on_ready(c, c->data);
                c->depth--;
            }
        }
        break;
    case NGHTTP2_HEADERS: {
        struct ks_grpc_call *call =
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (call == NULL)
            break;
        if (c->opts.server && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
            server_start_call(c, call);
        if (c->opts.server && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
            !call->reported && call->cbs.on_half_close) {
            c->depth++;
            call->cbs.on_half_close(call, call->data);
            c->depth--;
        }
        if (!c->opts.server && frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            call->http_status == 200 && !call->grpc_content_type &&
            !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, call->stream_id,
                                      NGHTTP2_CANCEL);
            call_report(call, KS_GRPC_INTERNAL,
                        "transport: received unexpected content-type");
        }
        break;
    }
    case NGHTTP2_DATA:
        if (c->opts.server && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            struct ks_grpc_call *call =
                nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (call != NULL && !call->reported && call->cbs.on_half_close) {
                c->depth++;
                call->cbs.on_half_close(call, call->data);
                c->depth--;
            }
        }
        break;
    case NGHTTP2_GOAWAY:
        /* Running streams finish; nothing new may start. */
        break;
    }
    return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *user_data)
{
    struct ks_grpc_conn *c = user_data;
    struct ks_grpc_call *call = nghttp2_session_get_stream_user_data(session, stream_id);
    if (call == NULL)
        return 0;
    if (!call->reported) {
        if (c->opts.server) {
            if (call->tx_eof && error_code == NGHTTP2_NO_ERROR)
                call_report(call, call->finish_status,
                            call->finish_message ? call->finish_message : "");
            else
                call_report(call, KS_GRPC_CANCELLED, "stream reset by the client");
        } else {
            int status;
            char msg[512];
            if (buf_avail(&call->rx) > 0 && !call->have_status) {
                status = KS_GRPC_INTERNAL;
                snprintf(msg, sizeof(msg), "stream ended with a partial message");
            } else {
                client_status(call, error_code, &status, msg, sizeof(msg));
            }
            call_report(call, status, msg);
        }
    }
    call->stream_id = -1; /* nghttp2 forgets it */
    call_unlink_free(call);
    return 0;
}

static ssize_t send_cb(nghttp2_session *session, const uint8_t *data, size_t length,
                       int flags, void *user_data)
{
    (void)session;
    (void)flags;
    struct ks_grpc_conn *c = user_data;
    for (;;) {
        ssize_t n = send(c->fd, data, length, MSG_NOSIGNAL);
        if (n >= 0) {
            c->blocked = false;
            return n;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            c->blocked = true;
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        conn_fail(c, strerror(errno));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

/* ---- public API ----------------------------------------------------------- */

struct ks_grpc_conn *ks_grpc_conn_new(int fd, const struct ks_grpc_conn_opts *opts,
                                      const struct ks_grpc_conn_cbs *cbs, void *data)
{
    struct ks_grpc_conn *c = calloc(1, sizeof(*c));
    nghttp2_session_callbacks *cb = NULL;
    if (c == NULL || nghttp2_session_callbacks_new(&cb) != 0)
        goto fail;
    c->fd = fd;
    c->opts = *opts;
    c->cbs = *cbs;
    c->data = data;
    c->authority = strdup(opts->authority ? opts->authority : "localhost");
    if (c->authority == NULL)
        goto fail;
    c->opts.authority = c->authority;
    c->last_rx = ks_grpc_now();
    /* The driver starts watching for writability too (connect() may still
     * be in progress); the first flush tells it to stop. */
    c->want_write = true;

    nghttp2_session_callbacks_set_send_callback(cb, send_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers);
    int rv = opts->server ? nghttp2_session_server_new(&c->session, cb, c)
                          : nghttp2_session_client_new(&c->session, cb, c);
    nghttp2_session_callbacks_del(cb);
    cb = NULL;
    if (rv != 0)
        goto fail;
    if (nghttp2_submit_settings(c->session, NGHTTP2_FLAG_NONE, NULL, 0) != 0)
        goto fail;
    /* Nothing is written yet: the driver's first writable event flushes. */
    return c;

fail:
    if (cb)
        nghttp2_session_callbacks_del(cb);
    if (c) {
        if (c->session)
            nghttp2_session_del(c->session);
        free(c->authority);
        free(c);
    }
    close(fd);
    return NULL;
}

void ks_grpc_conn_free(struct ks_grpc_conn *c)
{
    if (c == NULL)
        return;
    c->depth++; /* no flushing from here on */
    while (c->calls != NULL) {
        struct ks_grpc_call *call = c->calls;
        call_report(call, KS_GRPC_CANCELLED, "connection closed by us");
        call_unlink_free(call);
    }
    if (c->session)
        nghttp2_session_del(c->session);
    close(c->fd);
    free(c->authority);
    free(c);
}

int ks_grpc_conn_fd(const struct ks_grpc_conn *c)
{
    return c->fd;
}

bool ks_grpc_conn_ready(const struct ks_grpc_conn *c)
{
    return c->ready && !c->closed && !c->failing;
}

bool ks_grpc_conn_closed(const struct ks_grpc_conn *c)
{
    return c->closed || c->failing;
}

void ks_grpc_conn_on_io(struct ks_grpc_conn *c, bool readable, bool writable)
{
    if (c->closed)
        return;
    if (writable)
        c->blocked = false;
    if (readable) {
        uint8_t buf[16384];
        for (int i = 0; i < 64 && !c->failing; i++) {
            ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    conn_fail(c, strerror(errno));
                break;
            }
            if (n == 0) {
                conn_fail(c, "EOF");
                break;
            }
            c->depth++;
            ssize_t rv = nghttp2_session_mem_recv(c->session, buf, (size_t)n);
            c->depth--;
            if (rv < 0) {
                conn_fail(c, nghttp2_strerror((int)rv));
                /* Tell the peer why, if we can. */
                c->failing = false;
                flush(c);
                c->failing = true;
                break;
            }
        }
    }
    flush(c);
    finish_close(c);
}

int64_t ks_grpc_conn_tick(struct ks_grpc_conn *c)
{
    if (c->closed)
        return -1;
    int64_t now = ks_grpc_now();
    int64_t next = -1;

    struct ks_grpc_call *call = c->calls;
    while (call != NULL) {
        struct ks_grpc_call *nx = call->next;
        if (call->deadline > 0 && !call->reported) {
            if (call->deadline <= now) {
                nghttp2_submit_rst_stream(c->session, NGHTTP2_FLAG_NONE, call->stream_id,
                                          NGHTTP2_CANCEL);
                call_report(call, KS_GRPC_DEADLINE_EXCEEDED, "context deadline exceeded");
            } else if (next < 0 || call->deadline < next) {
                next = call->deadline;
            }
        }
        call = nx;
    }

    if (c->opts.keepalive_time_ns > 0 && c->ready && !c->failing) {
        if (c->ping_sent == 0) {
            int64_t due = c->last_rx + c->opts.keepalive_time_ns;
            if (due <= now) {
                if (nghttp2_submit_ping(c->session, NGHTTP2_FLAG_NONE, NULL) == 0)
                    c->ping_sent = now;
                due = now + c->opts.keepalive_timeout_ns;
            }
            if (next < 0 || due < next)
                next = due;
        } else {
            int64_t due = c->ping_sent + c->opts.keepalive_timeout_ns;
            if (due <= now)
                conn_fail(c, "keepalive ping timeout");
            else if (next < 0 || due < next)
                next = due;
        }
    }
    flush(c);
    finish_close(c); /* may free c */
    return next;
}

static void call_send_headers(struct ks_grpc_call *call);

struct ks_grpc_call *ks_grpc_call_start(struct ks_grpc_conn *c, const char *path,
                                        int64_t timeout_ns,
                                        const struct ks_grpc_call_cbs *cbs, void *data)
{
    if (c->opts.server || c->closed || c->failing)
        return NULL;
    struct ks_grpc_call *call = call_new(c);
    if (call == NULL)
        return NULL;
    call->cbs = *cbs;
    call->data = data;

    char timeout[16];
    nghttp2_nv nv[9];
    size_t n = 0;
    make_nv(&nv[n++], ":method", "POST");
    make_nv(&nv[n++], ":scheme", "http");
    make_nv(&nv[n++], ":path", path);
    make_nv(&nv[n++], ":authority", c->authority);
    make_nv(&nv[n++], "content-type", "application/grpc");
    make_nv(&nv[n++], "user-agent", "grpc-c-kisnitch/" KS_VERSION);
    make_nv(&nv[n++], "te", "trailers");
    if (timeout_ns > 0) {
        int64_t now = ks_grpc_now();
        call->deadline = now + timeout_ns;
        ks_grpc_format_timeout(timeout_ns, timeout, sizeof(timeout));
        make_nv(&nv[n++], "grpc-timeout", timeout);
    }
    nghttp2_data_provider prd = {.source.ptr = call, .read_callback = read_cb};
    int32_t id = nghttp2_submit_request(c->session, NULL, nv, n, &prd, call);
    if (id < 0) {
        call_unlink_free(call);
        return NULL;
    }
    call->stream_id = id;
    call->provider = true;
    flush(c);
    return call;
}

void ks_grpc_call_set_cbs(struct ks_grpc_call *call, const struct ks_grpc_call_cbs *cbs,
                          void *data)
{
    call->cbs = *cbs;
    call->data = data;
}

/* Server: response headers with the data provider attached. */
static void call_send_headers(struct ks_grpc_call *call)
{
    if (call->headers_sent)
        return;
    call->headers_sent = true;
    nghttp2_nv nv[2];
    make_nv(&nv[0], ":status", "200");
    make_nv(&nv[1], "content-type", "application/grpc");
    nghttp2_data_provider prd = {.source.ptr = call, .read_callback = read_cb};
    if (nghttp2_submit_response(call->conn->session, call->stream_id, nv, 2, &prd) == 0)
        call->provider = true;
}

int ks_grpc_call_send(struct ks_grpc_call *call, const uint8_t *msg, size_t len)
{
    struct ks_grpc_conn *c = call->conn;
    if (call->reported || call->tx_eof || c->closed || c->failing || len > UINT32_MAX)
        return -1;
    uint8_t hdr[5] = {0, (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8),
                      (uint8_t)len};
    if (buf_append(&call->tx, hdr, 5) < 0 || buf_append(&call->tx, msg, len) < 0)
        return -1;
    if (c->opts.server)
        call_send_headers(call);
    resume(call);
    flush(c);
    return 0;
}

int ks_grpc_call_close_send(struct ks_grpc_call *call)
{
    if (call->conn->opts.server || call->reported || call->tx_eof)
        return -1;
    call->tx_eof = true;
    resume(call);
    flush(call->conn);
    return 0;
}

int ks_grpc_call_finish(struct ks_grpc_call *call, int status, const char *message)
{
    struct ks_grpc_conn *c = call->conn;
    if (!c->opts.server || call->reported || call->tx_eof)
        return -1;
    call->tx_eof = true;
    call->finish_status = status;
    if (message != NULL && message[0] != '\0') {
        call->finish_message = strdup(message);
        if (call->finish_message == NULL)
            return -1;
    }
    if (!call->headers_sent) {
        /* Trailers-only response. */
        call->headers_sent = true;
        char st[16], m[512];
        snprintf(st, sizeof(st), "%d", status);
        nghttp2_nv nv[4];
        size_t n = 0;
        make_nv(&nv[n++], ":status", "200");
        make_nv(&nv[n++], "content-type", "application/grpc");
        make_nv(&nv[n++], "grpc-status", st);
        if (call->finish_message) {
            ks_grpc_percent_encode(call->finish_message, m, sizeof(m));
            make_nv(&nv[n++], "grpc-message", m);
        }
        nghttp2_submit_response(c->session, call->stream_id, nv, n, NULL);
    } else {
        resume(call);
    }
    flush(c);
    return 0;
}

static void server_reject(struct ks_grpc_call *call, int status, const char *msg)
{
    ks_grpc_call_finish(call, status, msg);
}

void ks_grpc_call_cancel(struct ks_grpc_call *call)
{
    struct ks_grpc_conn *c = call->conn;
    if (call->reported)
        return;
    if (call->stream_id > 0)
        nghttp2_submit_rst_stream(c->session, NGHTTP2_FLAG_NONE, call->stream_id,
                                  NGHTTP2_CANCEL);
    call_report(call, KS_GRPC_CANCELLED, "context canceled");
    flush(c);
}

struct ks_grpc_conn *ks_grpc_call_conn(const struct ks_grpc_call *call)
{
    return call->conn;
}

struct ks_grpc_call *ks_grpc_unary(struct ks_grpc_conn *conn, const char *path,
                                   int64_t timeout_ns, const uint8_t *msg, size_t len,
                                   const struct ks_grpc_call_cbs *cbs, void *data)
{
    struct ks_grpc_call *call = ks_grpc_call_start(conn, path, timeout_ns, cbs, data);
    if (call == NULL)
        return NULL;
    if (ks_grpc_call_send(call, msg, len) < 0 || ks_grpc_call_close_send(call) < 0) {
        call->reported = true; /* the caller learns it from the NULL */
        nghttp2_submit_rst_stream(conn->session, NGHTTP2_FLAG_NONE, call->stream_id,
                                  NGHTTP2_CANCEL);
        flush(conn);
        return NULL;
    }
    return call;
}
