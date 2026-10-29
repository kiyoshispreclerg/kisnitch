/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The event loggers (daemon/loggers.c) and their formats
 * (daemon/logformats.c): the exact lines, and the remote (TCP, UDP) and
 * local syslog writers against local servers.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _DEFAULT_SOURCE /* mkdtemp */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/config.h"
#include "daemon/logformats.h"
#include "daemon/loggers.h"
#include "tests/harness.h"

static Protocol__Connection conn(void)
{
    static char *args[] = {"curl", "-s", "https://example.com"};
    static Protocol__Connection__ProcessChecksumsEntry s1 =
        PROTOCOL__CONNECTION__PROCESS_CHECKSUMS_ENTRY__INIT;
    static Protocol__Connection__ProcessChecksumsEntry *sums[1];
    static Protocol__Connection__ProcessEnvEntry e1 = PROTOCOL__CONNECTION__PROCESS_ENV_ENTRY__INIT,
                                                 e2 = PROTOCOL__CONNECTION__PROCESS_ENV_ENTRY__INIT;
    static Protocol__Connection__ProcessEnvEntry *env[2];
    static Protocol__StringInt t1 = PROTOCOL__STRING_INT__INIT, t2 = PROTOCOL__STRING_INT__INIT;
    static Protocol__StringInt *tree[2];
    s1.key = "process.hash.md5";
    s1.value = "abc";
    sums[0] = &s1;
    e1.key = "Z";
    e1.value = "1";
    e2.key = "A";
    e2.value = "<2>";
    env[0] = &e1;
    env[1] = &e2;
    t1.key = "/usr/bin/curl";
    t1.value = 42;
    t2.key = "/usr/bin/bash";
    t2.value = 1;
    tree[0] = &t1;
    tree[1] = &t2;
    Protocol__Connection c = PROTOCOL__CONNECTION__INIT;
    c.protocol = "tcp";
    c.src_ip = "10.0.0.2";
    c.src_port = 40000;
    c.dst_ip = "93.184.216.34";
    c.dst_host = "example.com";
    c.dst_port = 443;
    c.user_id = 1000;
    c.process_id = 42;
    c.process_path = "/usr/bin/curl";
    c.process_cwd = "/home/u";
    c.n_process_args = 3;
    c.process_args = args;
    c.n_process_env = 2;
    c.process_env = env;
    c.n_process_checksums = 1;
    c.process_checksums = sums;
    c.n_process_tree = 2;
    c.process_tree = tree;
    return c;
}

TEST(formats)
{
    setenv("TZ", "UTC", 1);
    tzset();
    Protocol__Connection c = conn();
    struct ks_log_event ev = {.conn = &c, .action = "allow", .rule = "allow-curl"};
    time_t now = 1700000000; /* 2023-11-14T22:13:20Z */
    char want[2048];
    const char sd[] = "SRC=\"10.0.0.2\" SPT=\"40000\" DST=\"93.184.216.34\" DSTHOST=\"example.com\" "
                      "DPT=\"443\" PROTO=\"tcp\" PID=\"42\" UID=\"1000\" PATH=\"/usr/bin/curl\" "
                      "CMDLINE=\"curl -s https://example.com\" CWD=\"/home/u\" "
                      "CHECKSUMS=\"process.hash.md5:abc\" PROCTREE=\"/usr/bin/curl,/usr/bin/bash,\" "
                      "ARG1=\"allow\" ARG2=\"allow-curl\"";

    char *s = ks_logfmt_transform(KS_FMT_RFC5424, &ev, "host", "opensnitch", now);
    snprintf(want, sizeof(want), "<29>1 2023-11-14T22:13:20Z host opensnitch %ld CONNECTION - [%s]\n",
             (long)getpid(), sd);
    CHECK_STR_EQ(s, want);
    free(s);
    /* the local syslog logger has no hostname nor tag */
    s = ks_logfmt_transform(KS_FMT_RFC5424, &ev, NULL, NULL, now);
    snprintf(want, sizeof(want), "<29>1 2023-11-14T22:13:20Z   %ld CONNECTION - [%s]\n",
             (long)getpid(), sd);
    CHECK_STR_EQ(s, want);
    free(s);

    s = ks_logfmt_transform(KS_FMT_RFC3164, &ev, "host", "tag", now);
    snprintf(want, sizeof(want), "<29>2023-11-14T22:13:20Z host tag[%ld]: [%s]\n", (long)getpid(),
             sd);
    CHECK_STR_EQ(s, want);
    free(s);

    s = ks_logfmt_transform(KS_FMT_CSV, &ev, "host", "tag", now);
    CHECK_STR_EQ(s, "10.0.0.2,40000,93.184.216.34,example.com,443,tcp,42,1000,/usr/bin/curl,"
                    "[curl -s https://example.com],/home/u,allow,allow-curl");
    free(s);

    s = ks_logfmt_transform(KS_FMT_JSON, &ev, "host", "tag", now);
    CHECK_STR_EQ(s, "{\"Event\":{\"protocol\":\"tcp\",\"src_ip\":\"10.0.0.2\",\"src_port\":40000,"
                    "\"dst_ip\":\"93.184.216.34\",\"dst_host\":\"example.com\",\"dst_port\":443,"
                    "\"user_id\":1000,\"process_id\":42,\"process_path\":\"/usr/bin/curl\","
                    "\"process_cwd\":\"/home/u\",\"process_args\":[\"curl\",\"-s\","
                    "\"https://example.com\"],\"process_env\":{\"A\":\"\\u003c2\\u003e\",\"Z\":\"1\"},"
                    "\"process_checksums\":{\"process.hash.md5\":\"abc\"},\"process_tree\":"
                    "[{\"key\":\"/usr/bin/curl\",\"value\":42},{\"key\":\"/usr/bin/bash\",\"value\":1}]},"
                    "\"Rule\":\"allow-curl\",\"Action\":\"allow\",\"Type\":0}\n\n");
    free(s);

    /* omitempty: a connection with nothing set */
    Protocol__Connection empty = PROTOCOL__CONNECTION__INIT;
    struct ks_log_event e2 = {.conn = &empty, .action = "<nil>", .rule = "<nil>"};
    s = ks_logfmt_transform(KS_FMT_JSON, &e2, "h", "t", now);
    CHECK_STR_EQ(s, "{\"Event\":{},\"Rule\":\"\\u003cnil\\u003e\",\"Action\":\"\\u003cnil\\u003e\","
                    "\"Type\":0}\n\n");
    free(s);

    /* a task notification, with its two nil values */
    struct ks_log_event task = {.task_name = "downloader", .task_data = "lists updated"};
    s = ks_logfmt_transform(KS_FMT_RFC5424, &task, "host", "tag", now);
    snprintf(want, sizeof(want),
             "<29>1 2023-11-14T22:13:20Z host tag %ld TASK_NOTIFICATION - [TASK=\"downloader\" "
             "DATA=\"lists updated\" ARG1=\"<nil>\" ARG2=\"<nil>\"]\n",
             (long)getpid());
    CHECK_STR_EQ(s, want);
    free(s);
    s = ks_logfmt_transform(KS_FMT_CSV, &task, "host", "tag", now);
    CHECK_STR_EQ(s, "{lists updated downloader},<nil>,<nil>");
    free(s);
    s = ks_logfmt_transform(KS_FMT_JSON, &task, "host", "tag", now);
    CHECK_STR_EQ(s, "{\"Event\":{\"Data\":\"lists updated\",\"Name\":\"downloader\"},\"Rule\":\"\","
                    "\"Action\":\"\",\"Type\":2}\n\n");
    free(s);

    /* a time zone west of UTC */
    setenv("TZ", "BRT3", 1);
    tzset();
    s = ks_logfmt_transform(KS_FMT_RFC3164, &task, "h", "t", now);
    CHECK(strncmp(s, "<29>2023-11-14T19:13:20-03:00 h t[", 34) == 0);
    free(s);
    setenv("TZ", "UTC", 1);
    tzset();
}

/* ---- the writers ------------------------------------------------------ */

static struct ks_logger_config cfgs[4];

static struct ks_array configs(size_t n)
{
    struct ks_array a = {cfgs, n, true};
    return a;
}

static struct ks_logger_config cfg(char *name, char *server, char *proto, char *format)
{
    struct ks_logger_config c;
    memset(&c, 0, sizeof(c));
    c.name = name;
    c.server = server;
    c.protocol = proto;
    c.format = format;
    c.tag = "";
    c.write_timeout = "";
    c.connect_timeout = "";
    return c;
}

/* waits until `fd` is readable and reads into buf */
static ssize_t recv_wait(int fd, char *buf, size_t len, int ms)
{
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, ms) <= 0)
        return -1;
    ssize_t n = recv(fd, buf, len - 1, 0);
    buf[n > 0 ? n : 0] = '\0';
    return n;
}

static int listen_on(int type, struct sockaddr_in *sa)
{
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa->sin_port = 0;
    socklen_t sl = sizeof(*sa);
    if (bind(fd, (struct sockaddr *)sa, sizeof(*sa)) < 0 ||
        (type == SOCK_STREAM && listen(fd, 4) < 0))
        return -1;
    getsockname(fd, (struct sockaddr *)sa, &sl);
    return fd;
}

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}

TEST(remote_tcp_and_udp)
{
    struct sockaddr_in ta, ua;
    int tl = listen_on(SOCK_STREAM, &ta), us = listen_on(SOCK_DGRAM, &ua);
    CHECK(tl >= 0 && us >= 0);
    char tsrv[64], usrv[64];
    snprintf(tsrv, sizeof(tsrv), "127.0.0.1:%d", ntohs(ta.sin_port));
    snprintf(usrv, sizeof(usrv), "127.0.0.1:%d", ntohs(ua.sin_port));
    cfgs[0] = cfg("remote", tsrv, "tcp", "csv");
    cfgs[1] = cfg("remote_syslog", usrv, "udp", "rfc3164");
    cfgs[1].tag = "mytag";
    cfgs[2] = cfg("elastic", "x", "tcp", ""); /* unknown: ignored */
    struct ks_array a = configs(3);
    struct ks_loggers *l = ks_loggers_new();
    ks_loggers_load(l, &a);
    CHECK(ks_loggers_active(l));

    struct pollfd p = {tl, POLLIN, 0};
    CHECK(poll(&p, 1, 3000) == 1);
    int tc = accept(tl, NULL, NULL);
    CHECK(tc >= 0);
    sleep_ms(100); /* the writers count themselves connected */

    struct ks_log_event task = {.task_name = "looper", .task_data = "5s"};
    ks_loggers_log(l, &task);
    char buf[2048];
    CHECK(recv_wait(tc, buf, sizeof(buf), 3000) > 0);
    CHECK_STR_EQ(buf, "{5s looper},<nil>,<nil>"); /* CSV: no newline */
    CHECK(recv_wait(us, buf, sizeof(buf), 3000) > 0);
    char host[256] = "";
    gethostname(host, sizeof(host) - 1);
    char want[512];
    snprintf(want, sizeof(want), " %s mytag[%ld]: [TASK=\"looper\" DATA=\"5s\" ARG1=\"<nil>\" "
             "ARG2=\"<nil>\"]\n", host, (long)getpid());
    CHECK(strncmp(buf, "<29>", 4) == 0);
    CHECK_STR_HAS(buf, want);
    CHECK(ks_loggers_written(l) >= 2);

    /* Stop(): nothing more is sent */
    ks_loggers_stop(l);
    CHECK(!ks_loggers_active(l));
    ks_loggers_log(l, &task);
    CHECK(recv_wait(us, buf, sizeof(buf), 200) < 0);

    ks_loggers_free(l, 2000);
    close(tc);
    close(tl);
    close(us);
}

TEST(syslog_and_failures)
{
    char dir[64] = "/tmp/ks-loggers-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[96];
    snprintf(path, sizeof(path), "%.60s/log", dir);
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    CHECK(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    ks_loggers_set_syslog_path(path);

    cfgs[0] = cfg("syslog", "", "", "json"); /* syslog knows rfc5424 and csv only */
    struct ks_array a = configs(1);
    struct ks_loggers *l = ks_loggers_new();
    ks_loggers_load(l, &a);
    struct ks_log_event task = {.task_name = "t", .task_data = "d"};
    ks_loggers_log(l, &task);
    char buf[2048];
    CHECK(recv_wait(fd, buf, sizeof(buf), 3000) > 0);
    char want[256];
    snprintf(want, sizeof(want), " opensnitch[%ld]: <29>1 ", (long)getpid());
    CHECK(strncmp(buf, "<29>", 4) == 0);
    CHECK_STR_HAS(buf, want);
    snprintf(want, sizeof(want), "   %ld TASK_NOTIFICATION - [TASK=\"t\" DATA=\"d\" ARG1=\"<nil>\" "
             "ARG2=\"<nil>\"]\n", (long)getpid());
    CHECK_STR_HAS(buf, want);
    ks_loggers_free(l, 2000);

    /* no syslog daemon: the logger is skipped (upstream crashes) */
    unlink(path);
    l = ks_loggers_new();
    ks_loggers_load(l, &a);
    ks_loggers_log(l, &task);
    ks_loggers_free(l, 2000);
    ks_loggers_set_syslog_path("");
    close(fd);
    rmdir(dir);

    /* an unsupported protocol and a server that doesn't answer: nothing is
     * written, and stopping doesn't wait for the connection attempts */
    cfgs[0] = cfg("remote", "127.0.0.1:9", "sctp", "");
    cfgs[0].max_connect_attempts = 1;
    cfgs[1] = cfg("remote", "10.255.255.1:9", "tcp", "");
    cfgs[1].connect_timeout = "30s";
    a = configs(2);
    l = ks_loggers_new();
    ks_loggers_load(l, &a);
    ks_loggers_log(l, &task);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ks_loggers_free(l, 2000);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(t1.tv_sec - t0.tv_sec < 2);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(formats);
    RUN(remote_tcp_and_udp);
    RUN(syslog_and_failures);
    return harness_report();
}
