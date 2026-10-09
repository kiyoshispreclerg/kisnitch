/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * systemd-resolved monitor (daemon/dns/resolved.c): the replies, and the
 * varlink connection against a fake resolved on a temporary Unix socket.
 */
#include "daemon/dns/resolved.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/dns/cache.h"
#include "daemon/evloop.h"
#include "tests/harness.h"

static enum ks_resolved_reply reply(const char *s)
{
    return ks_resolved_handle_reply(s, strlen(s));
}

/* What real resolved sends (systemd 252+, `resolvectl monitor`). */
static const char a_reply[] =
    "{\"parameters\":{\"state\":\"success\","
    "\"question\":[{\"class\":1,\"type\":1,\"name\":\"www.example.com\"}],"
    "\"answer\":["
    "{\"rr\":{\"key\":{\"class\":1,\"type\":5,\"name\":\"www.example.com\"},"
    "\"name\":\"cdn.example.net\"},\"raw\":\"AAA=\",\"ifindex\":2},"
    "{\"rr\":{\"key\":{\"class\":1,\"type\":1,\"name\":\"cdn.example.net\"},"
    "\"address\":[93,184,216,34]},\"raw\":\"AAA=\",\"ifindex\":2},"
    "{\"rr\":{\"key\":{\"class\":1,\"type\":28,\"name\":\"cdn.example.net\"},"
    "\"address\":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,9]}},"
    "{\"rr\":{\"key\":{\"class\":1,\"type\":16,\"name\":\"txt.example.net\"},"
    "\"address\":[1,1,1,1]}}],"
    "\"collectedQuestions\":[{\"class\":1,\"type\":1,\"name\":\"www.example.com\"}]},"
    "\"continues\":true}";

TEST(tracks_answers)
{
    ks_dns_cache_reset();
    CHECK_INT_EQ(reply(a_reply), KS_RESOLVED_CONTINUE);
    CHECK_STR_EQ(ks_dns_host("93.184.216.34"), "cdn.example.net");
    CHECK_STR_EQ(ks_dns_host("cdn.example.net"), "www.example.com");
    CHECK_STR_EQ(ks_dns_host("2001:db8::9"), "cdn.example.net");
    CHECK(ks_dns_host("1.1.1.1") == NULL); /* TXT is excluded */
    CHECK_INT_EQ(ks_dns_cache_count(), 3);
}

TEST(replies_that_are_not_tracked)
{
    ks_dns_cache_reset();
    /* the first reply to a subscription */
    CHECK_INT_EQ(reply("{\"parameters\":{\"ready\":true},\"continues\":true}"),
                 KS_RESOLVED_CONTINUE);
    /* not "success" */
    CHECK_INT_EQ(reply("{\"parameters\":{\"state\":\"rcode-failure\",\"answer\":[{\"rr\":"
                       "{\"key\":{\"type\":1,\"name\":\"x\"},\"address\":[1,2,3,4]}}]},"
                       "\"continues\":true}"),
                 KS_RESOLVED_CONTINUE);
    CHECK_INT_EQ(ks_dns_cache_count(), 0);

    /* a reply that doesn't continue ends the monitor, unprocessed */
    CHECK_INT_EQ(reply("{\"parameters\":{\"state\":\"success\",\"answer\":[{\"rr\":"
                       "{\"key\":{\"type\":1,\"name\":\"x\"},\"address\":[1,2,3,4]}}]}}"),
                 KS_RESOLVED_END);
    CHECK_INT_EQ(ks_dns_cache_count(), 0);
    CHECK_INT_EQ(reply("null"), KS_RESOLVED_END);
    CHECK_INT_EQ(reply("{}"), KS_RESOLVED_END);

    /* errors */
    CHECK_INT_EQ(reply("{\"error\":\"io.systemd.System\",\"parameters\":{}}"),
                 KS_RESOLVED_ERROR);
    CHECK_INT_EQ(reply("{\"continues\":1}"), KS_RESOLVED_ERROR);
    CHECK_INT_EQ(reply("{\"error\":5,\"continues\":true}"), KS_RESOLVED_ERROR);
    CHECK_INT_EQ(reply("[1]"), KS_RESOLVED_ERROR);
    CHECK_INT_EQ(reply("{\"continues\":true"), KS_RESOLVED_ERROR);
    CHECK_INT_EQ(reply(""), KS_RESOLVED_ERROR);
}

TEST(decoding_is_lenient_like_upstream)
{
    /* Upstream ignores the error of json.Unmarshal into MonitorResponse:
     * fields of the wrong type stay zero, the rest decodes. */
    ks_dns_cache_reset();
    CHECK_INT_EQ(
        reply("{\"Continues\":true,\"PARAMETERS\":{\"State\":\"success\",\"question\":5,"
              "\"Answer\":["
              "7,"                                                   /* not an object */
              "{\"rr\":{\"key\":{\"type\":\"1\",\"name\":\"a\"},\"address\":[1,1,1,1]}},"
              "{\"rr\":{\"key\":{\"type\":1.5,\"name\":\"b\"},\"address\":[2,2,2,2]}},"
              "{\"rr\":{\"key\":{\"type\":1,\"name\":\"c\"},\"address\":[3,300,\"x\",3]}},"
              "{\"rr\":{\"key\":{\"type\":1,\"name\":\"d\"},\"address\":\"BAQEBA==\"}},"
              "{\"rr\":{\"key\":{\"type\":1,\"name\":\"e\"},\"address\":\"!!\"}},"
              "{\"rr\":{\"key\":{\"type\":1},\"key\":{\"name\":\"f\"},\"address\":[6,6,6,6]}}"
              "]}}"),
        KS_RESOLVED_CONTINUE);
    CHECK(ks_dns_host("1.1.1.1") == NULL); /* type is a string: 0 */
    CHECK(ks_dns_host("2.2.2.2") == NULL); /* 1.5 isn't an int */
    CHECK_STR_EQ(ks_dns_host("3.0.0.3"), "c");   /* bad elements become 0 */
    CHECK_STR_EQ(ks_dns_host("4.4.4.4"), "d");   /* []byte from base64 */
    CHECK_STR_EQ(ks_dns_host("<nil>"), "e");     /* invalid base64: nil */
    CHECK_STR_EQ(ks_dns_host("6.6.6.6"), "f");   /* repeated objects merge */

    /* invalid UTF-8 becomes U+FFFD, as encoding/json does */
    ks_dns_cache_reset();
    CHECK_INT_EQ(reply("{\"continues\":true,\"parameters\":{\"state\":\"success\",\"answer\":"
                       "[{\"rr\":{\"key\":{\"type\":1,\"name\":\"\xff.example\"},"
                       "\"address\":[9,9,9,9]}}]}}"),
                 KS_RESOLVED_CONTINUE);
    CHECK_STR_EQ(ks_dns_host("9.9.9.9"), "\xef\xbf\xbd.example");
}

/* ---- the connection ----------------------------------------------------- */

static int64_t fake_now;
static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

static char dir[32], path[96];

static int listen_unix(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, 4) < 0)
        return -1;
    return fd;
}

/* Reads one NUL-terminated message from `fd` into buf. */
static bool read_msg(int fd, char *buf, size_t len)
{
    size_t n = 0;
    while (n < len) {
        if (read(fd, buf + n, 1) != 1)
            return false;
        if (buf[n] == '\0')
            return true;
        n++;
    }
    return false;
}

static bool send_msg(int fd, const char *s)
{
    size_t n = strlen(s) + 1;
    return write(fd, s, n) == (ssize_t)n;
}

static const char subscribe[] =
    "{\"method\":\"io.systemd.Resolve.Monitor.SubscribeQueryResults\","
    "\"parameters\":{},\"more\":true}";

TEST(connection)
{
    ks_dns_cache_reset();
    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1000;

    /* no socket: nothing starts */
    CHECK(ks_resolved_start(loop, path) == NULL);

    int srv = listen_unix();
    CHECK(srv >= 0);
    struct ks_resolved *r = ks_resolved_start(loop, path);
    CHECK(r != NULL);
    CHECK(ks_resolved_connected(r));
    int c = accept(srv, NULL, NULL);
    char buf[512];
    CHECK(c >= 0 && read_msg(c, buf, sizeof(buf)));
    CHECK_STR_EQ(buf, subscribe);

    /* replies may arrive split and several at once */
    CHECK(send_msg(c, "{\"parameters\":{\"ready\":true},\"continues\":true}"));
    const char *half = strstr(a_reply, "\"answer\"");
    CHECK(write(c, a_reply, (size_t)(half - a_reply)) > 0);
    ks_evloop_run_once(loop, 1000);
    CHECK(ks_dns_host("93.184.216.34") == NULL);
    CHECK(send_msg(c, half));
    ks_evloop_run_once(loop, 1000);
    CHECK_STR_EQ(ks_dns_host("93.184.216.34"), "cdn.example.net");

    /* resolved goes away: disconnected, retry in 5 s */
    close(c);
    ks_evloop_run_once(loop, 1000);
    CHECK(!ks_resolved_connected(r));
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 1);

    /* still away at the first retry (upstream gives up here) */
    close(srv);
    unlink(path);
    fake_now += KS_RESOLVED_RECONNECT_NS;
    ks_evloop_fire_due(loop);
    CHECK(!ks_resolved_connected(r));
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 1);

    /* back: the next retry subscribes again */
    srv = listen_unix();
    fake_now += KS_RESOLVED_RECONNECT_NS;
    ks_evloop_fire_due(loop);
    CHECK(ks_resolved_connected(r));
    c = accept(srv, NULL, NULL);
    CHECK(c >= 0 && read_msg(c, buf, sizeof(buf)));
    CHECK_STR_EQ(buf, subscribe);

    /* an error reply disconnects too */
    CHECK(send_msg(c, "{\"error\":\"org.varlink.service.MethodNotFound\"}"));
    ks_evloop_run_once(loop, 1000);
    CHECK(!ks_resolved_connected(r));
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 1);

    ks_resolved_stop(r);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    close(c);
    close(srv);
    unlink(path);
    ks_evloop_free(loop);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    snprintf(dir, sizeof(dir), "/tmp/ks-resolved-XXXXXX");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/io.systemd.Resolve.Monitor", dir);

    RUN(tracks_answers);
    RUN(replies_that_are_not_tracked);
    RUN(decoding_is_lenient_like_upstream);
    RUN(connection);
    ks_dns_cache_reset();
    unlink(path);
    rmdir(dir);
    return harness_report();
}
