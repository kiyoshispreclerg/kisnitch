/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "common/grpc/grpc.h"
#include "common/grpc/tls.h"

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tests/harness.h"

/* ---- a tiny driver: polls both ends, runs their I/O and timers ---------- */

static struct ks_grpc_conn *ends[2];
static bool closed_flag[2];
static char closed_reason[2][128];

static void pump(int ms)
{
    int64_t until = ks_grpc_now() + (int64_t)ms * 1000000;
    while (ks_grpc_now() < until) {
        struct pollfd pfd[2];
        int n = 0;
        int idx[2];
        for (int i = 0; i < 2; i++) {
            if (ends[i] == NULL || closed_flag[i])
                continue;
            pfd[n].fd = ks_grpc_conn_fd(ends[i]);
            pfd[n].events = POLLIN | POLLOUT;
            pfd[n].revents = 0;
            idx[n++] = i;
        }
        if (n == 0)
            return;
        poll(pfd, (nfds_t)n, 5);
        for (int k = 0; k < n; k++) {
            int i = idx[k];
            if (ends[i] == NULL || closed_flag[i])
                continue;
            ks_grpc_conn_on_io(ends[i], (pfd[k].revents & (POLLIN | POLLHUP)) != 0,
                               (pfd[k].revents & POLLOUT) != 0);
            if (ends[i] != NULL && !closed_flag[i])
                ks_grpc_conn_tick(ends[i]);
        }
    }
}

/* Pumps until `cond` holds (or 3 s pass: slow under valgrind). */
#define WAIT(cond)                                                            \
    do {                                                                      \
        int64_t until_ = ks_grpc_now() + 3000000000LL;                        \
        while (!(cond) && ks_grpc_now() < until_)                             \
            pump(5);                                                          \
    } while (0)

static void on_closed(struct ks_grpc_conn *conn, const char *reason, void *data)
{
    (void)conn;
    int i = (int)(intptr_t)data;
    closed_flag[i] = true;
    snprintf(closed_reason[i], sizeof(closed_reason[i]), "%s", reason);
}

/* ---- the server: echoes on /t.S/Echo, streams on /t.S/Stream, never answers
 * /t.S/Hang ------------------------------------------------------------------ */

static int server_msgs;
static int server_close_status = -1;

static void srv_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    const char *method = data;
    server_msgs++;
    if (strcmp(method, "echo") == 0) {
        ks_grpc_call_send(call, msg, len);
        ks_grpc_call_finish(call, KS_GRPC_OK, NULL);
    } else if (strcmp(method, "stream") == 0) {
        /* reply twice to each message */
        ks_grpc_call_send(call, msg, len);
        ks_grpc_call_send(call, msg, len);
    }
}

static void srv_on_half_close(struct ks_grpc_call *call, void *data)
{
    if (strcmp(data, "stream") == 0)
        ks_grpc_call_finish(call, KS_GRPC_NOT_FOUND, "bye 100% ünicode");
}

static void srv_on_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    (void)call;
    (void)message;
    (void)data;
    server_close_status = status;
}

static int srv_on_call(struct ks_grpc_conn *conn, struct ks_grpc_call *call,
                       const char *path, void *data)
{
    (void)conn;
    (void)data;
    static const struct ks_grpc_call_cbs cbs = {srv_on_message, srv_on_half_close,
                                                srv_on_close};
    if (strcmp(path, "/t.S/Echo") == 0)
        ks_grpc_call_set_cbs(call, &cbs, "echo");
    else if (strcmp(path, "/t.S/Stream") == 0)
        ks_grpc_call_set_cbs(call, &cbs, "stream");
    else if (strcmp(path, "/t.S/Hang") == 0)
        ks_grpc_call_set_cbs(call, &cbs, "hang");
    else
        return KS_GRPC_UNIMPLEMENTED;
    return KS_GRPC_OK;
}

/* ---- client side bookkeeping ---------------------------------------------- */

static int ready_count;
static int cli_msgs;
static size_t cli_last_len;
static char cli_last[256];
static int cli_status = -1;
static char cli_message[256];

static void cli_on_ready(struct ks_grpc_conn *conn, void *data)
{
    (void)conn;
    (void)data;
    ready_count++;
}

static void cli_on_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    (void)call;
    (void)data;
    cli_msgs++;
    cli_last_len = len;
    size_t n = len < sizeof(cli_last) - 1 ? len : sizeof(cli_last) - 1;
    memcpy(cli_last, msg, n);
    cli_last[n] = '\0';
}

static void cli_on_close(struct ks_grpc_call *call, int status, const char *message,
                         void *data)
{
    (void)call;
    (void)data;
    cli_status = status;
    snprintf(cli_message, sizeof(cli_message), "%s", message);
}

static const struct ks_grpc_call_cbs cli_cbs = {cli_on_message, NULL, cli_on_close};

static void reset(void)
{
    server_msgs = 0;
    server_close_status = -1;
    ready_count = 0;
    cli_msgs = 0;
    cli_last_len = 0;
    cli_last[0] = '\0';
    cli_status = -1;
    cli_message[0] = '\0';
    closed_flag[0] = closed_flag[1] = false;
}

static int setup(size_t max_recv, int64_t ka_time, int64_t ka_timeout)
{
    reset();
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0)
        return -1;
    struct ks_grpc_conn_opts copts = {.server = false, .authority = "localhost",
                                      .max_recv = max_recv,
                                      .keepalive_time_ns = ka_time,
                                      .keepalive_timeout_ns = ka_timeout};
    struct ks_grpc_conn_opts sopts = {.server = true, .max_recv = max_recv};
    struct ks_grpc_conn_cbs ccbs = {.on_ready = cli_on_ready, .on_closed = on_closed};
    struct ks_grpc_conn_cbs scbs = {.on_call = srv_on_call, .on_closed = on_closed};
    ends[0] = ks_grpc_conn_new(sv[0], &copts, &ccbs, (void *)(intptr_t)0);
    ends[1] = ks_grpc_conn_new(sv[1], &sopts, &scbs, (void *)(intptr_t)1);
    return ends[0] && ends[1] ? 0 : -1;
}

static void teardown(void)
{
    ks_grpc_conn_free(ends[0]);
    ks_grpc_conn_free(ends[1]);
    ends[0] = ends[1] = NULL;
}

TEST(unary_roundtrip)
{
    CHECK(setup(0, 0, 0) == 0);
    WAIT(ready_count == 1);
    CHECK_INT_EQ(ready_count, 1);
    CHECK(ks_grpc_conn_ready(ends[0]));
    CHECK(ks_grpc_unary(ends[0], "/t.S/Echo", 0, (const uint8_t *)"hello", 5, &cli_cbs,
                        NULL) != NULL);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_msgs, 1);
    CHECK_STR_EQ(cli_last, "hello");
    CHECK_INT_EQ(cli_status, KS_GRPC_OK);
    CHECK_INT_EQ(server_close_status, KS_GRPC_OK);

    /* an empty message is a valid message */
    cli_status = -1;
    CHECK(ks_grpc_unary(ends[0], "/t.S/Echo", 0, NULL, 0, &cli_cbs, NULL) != NULL);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_msgs, 2);
    CHECK_INT_EQ(cli_last_len, 0);
    CHECK_INT_EQ(cli_status, KS_GRPC_OK);
    teardown();
}

TEST(unknown_method_is_trailers_only)
{
    CHECK(setup(0, 0, 0) == 0);
    WAIT(ready_count == 1);
    CHECK(ks_grpc_unary(ends[0], "/t.S/Nope", 1000000000, (const uint8_t *)"x", 1,
                        &cli_cbs, NULL) != NULL);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_msgs, 0);
    CHECK_INT_EQ(cli_status, KS_GRPC_UNIMPLEMENTED);
    CHECK_STR_EQ(cli_message, "unknown method /t.S/Nope");
    teardown();
}

TEST(bidi_stream_and_trailers)
{
    CHECK(setup(0, 0, 0) == 0);
    WAIT(ready_count == 1);
    struct ks_grpc_call *call = ks_grpc_call_start(ends[0], "/t.S/Stream", 0, &cli_cbs,
                                                   NULL);
    CHECK(call != NULL);
    CHECK(ks_grpc_call_send(call, (const uint8_t *)"a", 1) == 0);
    WAIT(cli_msgs == 2);
    CHECK_INT_EQ(cli_msgs, 2);
    CHECK(ks_grpc_call_send(call, (const uint8_t *)"bc", 2) == 0);
    WAIT(cli_msgs == 4);
    CHECK_INT_EQ(cli_msgs, 4);
    CHECK_STR_EQ(cli_last, "bc");
    CHECK_INT_EQ(cli_status, -1); /* still open */
    CHECK(ks_grpc_call_close_send(call) == 0);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_status, KS_GRPC_NOT_FOUND);
    CHECK_STR_EQ(cli_message, "bye 100% ünicode"); /* percent-encoded on the wire */
    CHECK_INT_EQ(server_msgs, 2);
    teardown();
}

TEST(deadline_exceeded)
{
    CHECK(setup(0, 0, 0) == 0);
    WAIT(ready_count == 1);
    CHECK(ks_grpc_unary(ends[0], "/t.S/Hang", 50 * 1000000LL, (const uint8_t *)"x", 1,
                        &cli_cbs, NULL) != NULL);
    WAIT(cli_status != -1 || server_msgs > 0);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_status, KS_GRPC_DEADLINE_EXCEEDED);
    WAIT(server_close_status != -1);
    /* the server also saw the deadline (grpc-timeout) or the reset */
    CHECK(server_close_status == KS_GRPC_DEADLINE_EXCEEDED ||
          server_close_status == KS_GRPC_CANCELLED);
    teardown();
}

TEST(big_messages_and_limit)
{
    CHECK(setup(300000, 0, 0) == 0);
    WAIT(ready_count == 1);
    size_t len = 200000;
    uint8_t *big = malloc(len + 200000);
    CHECK(big != NULL);
    memset(big, 'z', len + 200000);
    memcpy(big + len - 3, "end", 3);
    CHECK(ks_grpc_unary(ends[0], "/t.S/Echo", 0, big, len, &cli_cbs, NULL) != NULL);
    WAIT(cli_status != -1);
    CHECK_INT_EQ(cli_status, KS_GRPC_OK);
    CHECK_INT_EQ(cli_last_len, len);

    /* over the server's limit */
    cli_status = -1;
    CHECK(ks_grpc_unary(ends[0], "/t.S/Echo", 0, big, len + 200000, &cli_cbs, NULL) !=
          NULL);
    WAIT(cli_status != -1);
    free(big);
    CHECK_INT_EQ(cli_status, KS_GRPC_RESOURCE_EXHAUSTED);
    teardown();
}

TEST(peer_goes_away)
{
    CHECK(setup(0, 0, 0) == 0);
    WAIT(ready_count == 1);
    struct ks_grpc_call *call = ks_grpc_call_start(ends[0], "/t.S/Stream", 0, &cli_cbs,
                                                   NULL);
    CHECK(call != NULL);
    WAIT(ready_count == 1);
    ks_grpc_conn_free(ends[1]);
    ends[1] = NULL;
    WAIT(closed_flag[0]);
    CHECK(closed_flag[0]);
    CHECK_INT_EQ(cli_status, KS_GRPC_UNAVAILABLE);
    CHECK(ks_grpc_conn_closed(ends[0]));
    CHECK(ks_grpc_call_start(ends[0], "/t.S/Echo", 0, &cli_cbs, NULL) == NULL);
    teardown();
}

TEST(keepalive_timeout)
{
    reset();
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
    /* A server that sends its SETTINGS and then never answers anything. */
    static const uint8_t settings[9] = {0, 0, 0, 4, 0, 0, 0, 0, 0};
    CHECK(write(sv[1], settings, sizeof(settings)) == (ssize_t)sizeof(settings));
    struct ks_grpc_conn_opts o = {.keepalive_time_ns = 20 * 1000000LL,
                                  .keepalive_timeout_ns = 30 * 1000000LL};
    struct ks_grpc_conn_cbs cbs = {.on_ready = cli_on_ready, .on_closed = on_closed};
    ends[0] = ks_grpc_conn_new(sv[0], &o, &cbs, (void *)(intptr_t)0);
    ends[1] = NULL;
    CHECK(ends[0] != NULL);
    WAIT(ready_count == 1);
    CHECK_INT_EQ(ready_count, 1);
    WAIT(closed_flag[0]);
    CHECK(closed_flag[0]);
    CHECK_STR_EQ(closed_reason[0], "keepalive ping timeout");
    teardown();
    close(sv[1]);
}

TEST(garbage_from_client_closes_server)
{
    reset();
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
    struct ks_grpc_conn_opts o = {.server = true};
    struct ks_grpc_conn_cbs cbs = {.on_call = srv_on_call, .on_closed = on_closed};
    ends[1] = ks_grpc_conn_new(sv[1], &o, &cbs, (void *)(intptr_t)1);
    ends[0] = NULL;
    CHECK(ends[1] != NULL);
    CHECK(write(sv[0], "GET / HTTP/1.1\r\n\r\n", 18) == 18);
    WAIT(closed_flag[1]);
    CHECK(closed_flag[1]);
    teardown();
    close(sv[0]);
}

TEST(timeout_header_format)
{
    char b[16];
    ks_grpc_format_timeout(1000000000LL, b, sizeof(b));
    CHECK_STR_EQ(b, "1000000u");
    ks_grpc_format_timeout(120LL * 1000000000, b, sizeof(b));
    CHECK_STR_EQ(b, "120000m");
    ks_grpc_format_timeout(5, b, sizeof(b));
    CHECK_STR_EQ(b, "5n");
    ks_grpc_format_timeout(0, b, sizeof(b));
    CHECK_STR_EQ(b, "0n");
    ks_grpc_format_timeout(1000000001LL, b, sizeof(b));
    CHECK_STR_EQ(b, "1000001u"); /* rounded up */
    CHECK_INT_EQ(ks_grpc_parse_timeout("120000m", 7), 120LL * 1000000000);
    CHECK_INT_EQ(ks_grpc_parse_timeout("3S", 2), 3000000000LL);
    CHECK_INT_EQ(ks_grpc_parse_timeout("S", 1), -1);
    CHECK_INT_EQ(ks_grpc_parse_timeout("123456789S", 10), -1);
    CHECK_INT_EQ(ks_grpc_parse_timeout("1x", 2), -1);
}

TEST(percent_coding)
{
    char b[64];
    ks_grpc_percent_encode("a b%\n\xc3\xa9", b, sizeof(b));
    CHECK_STR_EQ(b, "a b%25%0A%C3%A9");
    char d[64];
    ks_grpc_percent_decode(b, strlen(b), d, sizeof(d));
    CHECK_STR_EQ(d, "a b%\n\xc3\xa9");
    ks_grpc_percent_decode("%zz%4", 5, d, sizeof(d));
    CHECK_STR_EQ(d, "%zz%4");
    ks_grpc_percent_encode("abcdef", b, 4);
    CHECK_STR_EQ(b, "abc");
}

/* ---- TLS (TLS=1) ------------------------------------------------------------ */

#define CERT(f) KS_FIXTURES_DIR "/tls/" f

static struct ks_tls_ctx *cli_tls, *srv_tls;

/* the two ends over TLS; `host` is the name the client verifies */
static int setup_tls(const struct ks_tls_client_opts *co, const char *srv_ca, const char *host)
{
    reset();
    char err[256];
    cli_tls = ks_tls_client_new(co, err, sizeof(err));
    srv_tls = ks_tls_server_new(CERT("server.pem"), CERT("server.key"), srv_ca, err, sizeof(err));
    if (cli_tls == NULL || srv_tls == NULL)
        return -1;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0)
        return -1;
    struct ks_grpc_conn_opts copts = {.authority = "localhost", .tls = cli_tls, .tls_host = host};
    struct ks_grpc_conn_opts sopts = {.server = true, .tls = srv_tls};
    struct ks_grpc_conn_cbs ccbs = {.on_ready = cli_on_ready, .on_closed = on_closed};
    struct ks_grpc_conn_cbs scbs = {.on_call = srv_on_call, .on_closed = on_closed};
    ends[0] = ks_grpc_conn_new(sv[0], &copts, &ccbs, (void *)(intptr_t)0);
    ends[1] = ks_grpc_conn_new(sv[1], &sopts, &scbs, (void *)(intptr_t)1);
    /* the connections hold their own references */
    ks_tls_ctx_free(cli_tls);
    ks_tls_ctx_free(srv_tls);
    return ends[0] && ends[1] ? 0 : -1;
}

/* a working connection: an echo, big enough to block the writes */
static void check_echo(void)
{
    WAIT(ready_count == 1);
    CHECK_INT_EQ(ready_count, 1);
    size_t len = 300000;
    uint8_t *big = malloc(len);
    CHECK(big != NULL);
    memset(big, 'q', len);
    memcpy(big + len - 3, "end", 3);
    CHECK(ks_grpc_unary(ends[0], "/t.S/Echo", 0, big, len, &cli_cbs, NULL) != NULL);
    WAIT(cli_status != -1);
    free(big);
    CHECK_INT_EQ(cli_status, KS_GRPC_OK);
    CHECK_INT_EQ(cli_last_len, len);
}

TEST(tls_connections)
{
    if (!ks_tls_available()) {
        printf("SKIP (tls): built without TLS=1\n");
        return;
    }
    /* tls-simple with the CA; the name and the IP address of the cert */
    struct ks_tls_client_opts co = {.ca_cert = CERT("ca.pem")};
    CHECK(setup_tls(&co, NULL, "localhost") == 0);
    check_echo();
    teardown();
    CHECK(setup_tls(&co, NULL, "127.0.0.1") == 0);
    check_echo();
    teardown();

    /* the server's own certificate as the root (not self-signed) */
    struct ks_tls_client_opts own = {.server_cert = CERT("server.pem")};
    CHECK(setup_tls(&own, NULL, "localhost") == 0);
    check_echo();
    teardown();

    /* another name, another CA, no roots at all: refused */
    CHECK(setup_tls(&co, NULL, "example.com") == 0);
    WAIT(closed_flag[0]);
    CHECK(closed_flag[0]);
    CHECK_STR_HAS(closed_reason[0], "x509: ");
    CHECK_INT_EQ(ready_count, 0);
    teardown();
    struct ks_tls_client_opts other = {.ca_cert = CERT("other-ca.pem")};
    CHECK(setup_tls(&other, NULL, "localhost") == 0);
    WAIT(closed_flag[0]);
    CHECK_STR_HAS(closed_reason[0], "x509: ");
    teardown();
    struct ks_tls_client_opts none = {0};
    CHECK(setup_tls(&none, NULL, "localhost") == 0);
    WAIT(closed_flag[0]);
    CHECK(closed_flag[0]);
    teardown();
    /* SkipVerify takes anything */
    other.skip_verify = true;
    CHECK(setup_tls(&other, NULL, "example.com") == 0);
    check_echo();
    teardown();

    /* the server with a CA requires a client certificate */
    CHECK(setup_tls(&co, CERT("ca.pem"), "localhost") == 0);
    WAIT(closed_flag[0] || closed_flag[1]);
    CHECK(closed_flag[0] || closed_flag[1]);
    CHECK_INT_EQ(ready_count, 0);
    teardown();
    struct ks_tls_client_opts mutual = {.ca_cert = CERT("ca.pem"),
                                        .client_cert = CERT("client.pem"),
                                        .client_key = CERT("client.key"),
                                        .mutual = true};
    CHECK(setup_tls(&mutual, CERT("ca.pem"), "localhost") == 0);
    check_echo();
    teardown();

    /* a key that isn't the certificate's */
    char err[256];
    mutual.client_key = CERT("server.key");
    CHECK(ks_tls_client_new(&mutual, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "private key does not match");
    CHECK(ks_tls_server_new(CERT("server.pem"), CERT("nope.key"), NULL, err, sizeof(err)) == NULL);
    CHECK(ks_tls_server_new("", "", NULL, err, sizeof(err)) == NULL);
}

int main(void)
{
    RUN(unary_roundtrip);
    RUN(unknown_method_is_trailers_only);
    RUN(bidi_stream_and_trailers);
    RUN(deadline_exceeded);
    RUN(big_messages_and_limit);
    RUN(peer_goes_away);
    RUN(keepalive_timeout);
    RUN(garbage_from_client_closes_server);
    RUN(timeout_header_format);
    RUN(percent_coding);
    RUN(tls_connections);
    return harness_report();
}
