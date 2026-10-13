/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the gRPC transport (common/grpc/): the input is what
 * the peer sends. The first byte picks the side:
 *   even: we are the client (the daemon, facing a UI that may be remote and
 *         hostile, over TCP) with a unary call and a stream already open;
 *   odd:  we are the server (the UI side), echoing every message.
 * The rest is fed to the connection in chunks whose sizes also come from
 * the input, then the timers run.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/grpc/grpc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                       void *data)
{
    (void)data;
    /* exercise the send path too */
    ks_grpc_call_send(call, msg, len > 64 ? 64 : len);
}

static void on_half_close(struct ks_grpc_call *call, void *data)
{
    (void)data;
    ks_grpc_call_finish(call, KS_GRPC_OK, "done\n%");
}

static void on_close(struct ks_grpc_call *call, int status, const char *message,
                     void *data)
{
    (void)call;
    (void)status;
    (void)data;
    if (message == NULL)
        abort();
}

static const struct ks_grpc_call_cbs cbs = {on_message, on_half_close, on_close};

static int on_call(struct ks_grpc_conn *conn, struct ks_grpc_call *call, const char *path,
                   void *data)
{
    (void)conn;
    (void)data;
    if (path[0] != '/')
        return KS_GRPC_UNIMPLEMENTED;
    ks_grpc_call_set_cbs(call, &cbs, NULL);
    return KS_GRPC_OK;
}

static void on_closed(struct ks_grpc_conn *conn, const char *reason, void *data)
{
    (void)conn;
    (void)data;
    if (reason == NULL)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    bool server = data[0] & 1;
    data++;
    size--;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0)
        return 0;
    struct ks_grpc_conn_opts o = {.server = server, .max_recv = 1 << 16,
                                  .keepalive_time_ns = 1, .keepalive_timeout_ns = 1};
    struct ks_grpc_conn_cbs ccbs = {.on_call = on_call, .on_closed = on_closed};
    struct ks_grpc_conn *c = ks_grpc_conn_new(sv[0], &o, &ccbs, NULL);
    if (c == NULL) {
        close(sv[1]);
        return 0;
    }
    ks_grpc_conn_on_io(c, false, true); /* our preface and SETTINGS */
    if (!server) {
        ks_grpc_unary(c, "/protocol.UI/AskRule", 1000000000LL, (const uint8_t *)"x", 1,
                      &cbs, NULL);
        ks_grpc_call_start(c, "/protocol.UI/Notifications", 0, &cbs, NULL);
    }

    /* drain what we sent, so the socket never fills */
    uint8_t sink[65536];
    size_t off = 0;
    while (off < size && !ks_grpc_conn_closed(c)) {
        size_t chunk = 1 + data[off] % 251;
        off++;
        if (chunk > size - off)
            chunk = size - off;
        if (chunk > 0 && write(sv[1], data + off, chunk) < 0)
            break;
        off += chunk;
        ks_grpc_conn_on_io(c, true, true);
        while (read(sv[1], sink, sizeof(sink)) > 0)
            ;
    }
    ks_grpc_conn_tick(c);
    ks_grpc_conn_on_io(c, true, true);
    ks_grpc_conn_free(c);
    close(sv[1]);
    return 0;
}
