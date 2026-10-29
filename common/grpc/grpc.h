/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal gRPC over HTTP/2 (nghttp2), client and server, for the daemon <->
 * UI protocol (docs/PROTOCOL.md). Covers what proto/ui.proto needs: unary
 * calls and bidirectional streams, deadlines (grpc-timeout), trailers,
 * trailers-only responses and keepalive pings. No compression: we never
 * advertise grpc-accept-encoding, and a compressed message is an error.
 *
 * The connection doesn't own a loop. Whoever drives it watches its fd and
 * calls ks_grpc_conn_on_io() when it's readable or writable. It starts
 * waiting for both, and the want_write callback then says when to stop or
 * start waiting for writability again. Timers
 * (deadlines, keepalive) run from ks_grpc_conn_tick(), which says when it
 * wants to be called next. Times are CLOCK_MONOTONIC nanoseconds.
 *
 * Callbacks may start, send on, finish and cancel calls; those operations
 * are queued and flushed when the callback returns. ks_grpc_conn_free()
 * must not be called from a callback: on_closed is the last one, and it
 * runs from ks_grpc_conn_on_io() or ks_grpc_conn_tick() after the session
 * is done, where freeing right after it returns is safe.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_grpc_conn owns its fd, its nghttp2 session and every
 * call on it. A struct ks_grpc_call stays valid until its on_close callback
 * returns (then it's freed), or until the connection is freed. Message
 * buffers passed to callbacks are valid only during the callback; buffers
 * passed to send functions are copied.
 */
#ifndef KS_COMMON_GRPC_GRPC_H
#define KS_COMMON_GRPC_GRPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Status codes (grpc/codes). */
enum ks_grpc_status {
    KS_GRPC_OK = 0,
    KS_GRPC_CANCELLED = 1,
    KS_GRPC_UNKNOWN = 2,
    KS_GRPC_INVALID_ARGUMENT = 3,
    KS_GRPC_DEADLINE_EXCEEDED = 4,
    KS_GRPC_NOT_FOUND = 5,
    KS_GRPC_PERMISSION_DENIED = 7,
    KS_GRPC_RESOURCE_EXHAUSTED = 8,
    KS_GRPC_UNIMPLEMENTED = 12,
    KS_GRPC_INTERNAL = 13,
    KS_GRPC_UNAVAILABLE = 14,
    KS_GRPC_UNAUTHENTICATED = 16,
};

/* Default limit on received messages, as gRPC (4 MiB). */
#define KS_GRPC_MAX_RECV_DEFAULT (4u * 1024 * 1024)

struct ks_grpc_conn;
struct ks_grpc_call;

struct ks_grpc_call_cbs {
    /* A complete message arrived. */
    void (*on_message)(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                       void *data);
    /* Server only, optional: the client finished sending (half-close). */
    void (*on_half_close)(struct ks_grpc_call *call, void *data);
    /* The call is over: called exactly once, then the call is freed. On the
     * server `status` is what was sent (or CANCELLED if the client reset
     * the stream or the connection died). `message` is never NULL. */
    void (*on_close)(struct ks_grpc_call *call, int status, const char *message,
                     void *data);
};

struct ks_grpc_conn_cbs {
    /* The peer's SETTINGS arrived. On a client, the connection is usable
     * (grpc-go's connectivity.Ready). Optional. */
    void (*on_ready)(struct ks_grpc_conn *conn, void *data);
    /* Server: a new call to `path` ("/protocol.UI/Ping"). Set its callbacks
     * with ks_grpc_call_set_cbs() and return 0, or return a status to
     * reject it (UNIMPLEMENTED for unknown methods). */
    int (*on_call)(struct ks_grpc_conn *conn, struct ks_grpc_call *call,
                   const char *path, void *data);
    /* The connection is over (EOF, error, GOAWAY, keepalive timeout): every
     * call got its on_close already. `reason` is never NULL. */
    void (*on_closed)(struct ks_grpc_conn *conn, const char *reason, void *data);
    /* The fd must (or no longer must) be watched for writability. */
    void (*want_write)(struct ks_grpc_conn *conn, bool on, void *data);
};

struct ks_grpc_conn_opts {
    bool server;
    /* Client: the :authority header (e.g. "localhost", "host:port"). */
    const char *authority;
    /* Messages bigger than this are rejected (RESOURCE_EXHAUSTED).
     * 0 = KS_GRPC_MAX_RECV_DEFAULT. */
    size_t max_recv;
    /* Keepalive (grpc-go keepalive.ClientParameters; on a server, grpc
     * core's grpc.keepalive_time_ms / keepalive_timeout_ms): after
     * `keepalive_time_ns` without receiving anything, send a PING; if
     * nothing arrives within `keepalive_timeout_ns` more, close. 0 = off. */
    int64_t keepalive_time_ns;
    int64_t keepalive_timeout_ns;
    /* TLS (common/grpc/tls.h), NULL for none: the handshake runs before
     * the HTTP/2 preface. `tls_host` (client) is the name verified. */
    struct ks_tls_ctx *tls;
    const char *tls_host;
};

/* Takes ownership of `fd` (connected or connecting, non-blocking) also on
 * failure. Queues the HTTP/2 preface and SETTINGS, which go out on the
 * first ks_grpc_conn_on_io() (the driver waits for writability at first).
 * No callback runs from here. NULL on OOM. */
struct ks_grpc_conn *ks_grpc_conn_new(int fd, const struct ks_grpc_conn_opts *opts,
                                      const struct ks_grpc_conn_cbs *cbs, void *data);

/* Cancels every call (their on_close runs with CANCELLED, on_closed does
 * not run), closes the fd and frees everything. NULL is fine. */
void ks_grpc_conn_free(struct ks_grpc_conn *conn);

int ks_grpc_conn_fd(const struct ks_grpc_conn *conn);
bool ks_grpc_conn_ready(const struct ks_grpc_conn *conn);
bool ks_grpc_conn_closed(const struct ks_grpc_conn *conn);

/* Reads what's available, processes it and writes what's pending. */
void ks_grpc_conn_on_io(struct ks_grpc_conn *conn, bool readable, bool writable);

/* Expires calls past their deadline (DEADLINE_EXCEEDED, the stream is
 * reset) and runs the keepalive. Returns the time of the next thing to do,
 * or -1 if nothing is scheduled. */
int64_t ks_grpc_conn_tick(struct ks_grpc_conn *conn);

/* Starts a client call. `timeout_ns` > 0 sets a deadline (sent as
 * grpc-timeout too). The request headers go out right away. NULL if the
 * connection is closed or on OOM. */
struct ks_grpc_call *ks_grpc_call_start(struct ks_grpc_conn *conn, const char *path,
                                        int64_t timeout_ns,
                                        const struct ks_grpc_call_cbs *cbs, void *data);

void ks_grpc_call_set_cbs(struct ks_grpc_call *call, const struct ks_grpc_call_cbs *cbs,
                          void *data);

/* Sends one message (framed with the 5-byte gRPC prefix). On the server
 * the response headers go first. -1 if the call can't send anymore. */
int ks_grpc_call_send(struct ks_grpc_call *call, const uint8_t *msg, size_t len);

/* Client: no more messages (END_STREAM after what's queued). */
int ks_grpc_call_close_send(struct ks_grpc_call *call);

/* Server: ends the call with `status` and `message` (may be NULL) in the
 * trailers, after what's queued. */
int ks_grpc_call_finish(struct ks_grpc_call *call, int status, const char *message);

/* Resets the stream (RST_STREAM CANCEL). on_close runs with CANCELLED,
 * possibly before this returns. */
void ks_grpc_call_cancel(struct ks_grpc_call *call);

struct ks_grpc_conn *ks_grpc_call_conn(const struct ks_grpc_call *call);

/* Client unary helper: start + send + close_send. NULL on failure. */
struct ks_grpc_call *ks_grpc_unary(struct ks_grpc_conn *conn, const char *path,
                                   int64_t timeout_ns, const uint8_t *msg, size_t len,
                                   const struct ks_grpc_call_cbs *cbs, void *data);

/* Name of a status code as grpc-go prints it ("DeadlineExceeded"). */
const char *ks_grpc_status_name(int status);

/* CLOCK_MONOTONIC in nanoseconds: the clock deadlines use. */
int64_t ks_grpc_now(void);

/* grpc-timeout header value for `ns` ("1000m", "120S"...): at most 8
 * digits, as the spec says, picking the finest unit that fits. */
void ks_grpc_format_timeout(int64_t ns, char *buf, size_t len);
/* Parses a grpc-timeout value; -1 if invalid. */
int64_t ks_grpc_parse_timeout(const char *s, size_t len);

/* Percent-encoding of grpc-message (spec: bytes outside 0x20-0x7E and
 * '%'), and its decoding (invalid escapes are kept verbatim). */
void ks_grpc_percent_encode(const char *in, char *out, size_t outlen);
void ks_grpc_percent_decode(const char *in, size_t inlen, char *out, size_t outlen);

#endif
