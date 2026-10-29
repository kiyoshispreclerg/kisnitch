/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The tasks loaded from disk (daemon/tasks/disk.h): the tasks list and its
 * reloads, the looper, the scheduler, the IOC scanner's tools and the
 * downloader (with a local HTTP server when built with CURL=1).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _DEFAULT_SOURCE /* mkdtemp */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/duration.h"
#include "common/json_schema.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/tasks/disk.h"
#include "daemon/tasks/iocscanner.h"
#include "daemon/tasks/scheduler.h"
#include "daemon/tasks/tasks.h"
#include "tests/harness.h"

static char dir[64];

static void write_at(const char *rel, const char *data)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return;
    fputs(data, f);
    fclose(f);
}

static void mktmp(void)
{
    snprintf(dir, sizeof(dir), "/tmp/ks-dtasks-XXXXXX");
    if (mkdtemp(dir) == NULL)
        dir[0] = '\0';
}

static void rmtmp(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "could not remove %s\n", dir);
}

/* ---- []string and []int in schemas ----------------------------------- */

struct lists {
    struct ks_strs s;
    struct ks_ints i;
};
static const struct ks_schema_field lists_fields[] = {
    KS_FIELD(struct lists, "Strs", KS_T_STRS, s),
    KS_FIELD(struct lists, "Ints", KS_T_INTS, i),
};
static const struct ks_schema lists_schema = KS_SCHEMA("t.Lists", struct lists, lists_fields);

TEST(schema_scalar_slices)
{
    struct lists a, b;
    char err[256];
    const char *j = "{\"strs\": [\"a\", null, \"c\"], \"INTS\": [1, -2, null]}";
    CHECK_INT_EQ(ks_schema_decode_buf(&lists_schema, j, strlen(j), &a, err, sizeof(err)), 0);
    CHECK_INT_EQ(a.s.len, 3);
    CHECK_STR_EQ(a.s.v[1], "");
    CHECK_STR_EQ(a.s.v[2], "c");
    CHECK_INT_EQ(a.i.len, 3);
    CHECK_INT_EQ(a.i.v[1], -2);
    CHECK_INT_EQ(a.i.v[2], 0);
    cJSON *enc = ks_schema_encode(&lists_schema, &a);
    char *txt = ks_json_print_go(enc, false);
    CHECK_STR_EQ(txt, "{\"Strs\":[\"a\",\"\",\"c\"],\"Ints\":[1,-2,0]}");
    free(txt);
    cJSON_Delete(enc);
    CHECK_INT_EQ(ks_schema_copy(&lists_schema, &b, &a), 0);
    CHECK(ks_schema_equal(&lists_schema, &a, &b));
    b.i.v[0] = 9;
    CHECK(!ks_schema_equal(&lists_schema, &a, &b));
    ks_schema_free(&lists_schema, &a);
    ks_schema_free(&lists_schema, &b);

    /* null slices; [] is not nil */
    j = "{\"Strs\": null, \"Ints\": []}";
    CHECK_INT_EQ(ks_schema_decode_buf(&lists_schema, j, strlen(j), &a, err, sizeof(err)), 0);
    CHECK(!a.s.non_nil && a.i.non_nil && a.i.len == 0);
    ks_schema_free(&lists_schema, &a);

    j = "{\"Ints\": [1.5]}";
    CHECK_INT_EQ(ks_schema_decode_buf(&lists_schema, j, strlen(j), &a, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "Ints[0]: number 1.5 does not fit in int");
    j = "{\"Strs\": [1]}";
    CHECK_INT_EQ(ks_schema_decode_buf(&lists_schema, j, strlen(j), &a, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "Strs[0]: expected string, got number");
    j = "{\"Strs\": \"x\"}";
    CHECK_INT_EQ(ks_schema_decode_buf(&lists_schema, j, strlen(j), &a, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "Strs: expected array of string, got string");
}

/* ---- the scheduler ---------------------------------------------------- */

static struct ks_sched_config sched(const char *json)
{
    struct ks_sched_config c;
    char err[256];
    if (ks_schema_decode_buf(&ks_sched_config_schema, json, strlen(json), &c, err,
                             sizeof(err)) < 0)
        memset(&c, 0, sizeof(c));
    return c;
}

static struct tm at(int wday, int h, int m, int s)
{
    struct tm t;
    memset(&t, 0, sizeof(t));
    t.tm_wday = wday;
    t.tm_hour = h;
    t.tm_min = m;
    t.tm_sec = s;
    return t;
}

TEST(scheduler_matching)
{
    setenv("TZ", "UTC", 1);
    tzset();
    /* 2023-11-14 (a Tuesday) 10:00:00.5 UTC */
    struct timespec now = {1699956000, 500000000};
    CHECK(ks_sched_daily_wait("11:00:00", &now) == KS_HOUR - 500 * KS_MILLISECOND);
    CHECK(ks_sched_daily_wait("09:00", &now) == 23 * KS_HOUR - 500 * KS_MILLISECOND);
    CHECK(ks_sched_daily_wait("9:30:00", &now) == 23 * KS_HOUR + 30 * KS_MINUTE -
                                                       500 * KS_MILLISECOND);
    struct timespec exact = {1699956000, 0};
    CHECK(ks_sched_daily_wait("10:00:00", &exact) == KS_MILLISECOND);
    CHECK(ks_sched_daily_wait("10:00:00.250", &now) > 0); /* Go takes the fraction */
    CHECK(ks_sched_daily_wait("09:5:00", &now) == -1);   /* "04" wants two digits */
    CHECK(ks_sched_daily_wait("24:00", &now) == -1);
    CHECK(ks_sched_daily_wait("10:00:00x", &now) == -1);
    CHECK(ks_sched_daily_wait("", &now) == -1);

    struct ks_sched_config c = sched("{\"weekday\": [2, 2], \"minute\": [30]}");
    CHECK(ks_sched_resolution(&c) == KS_MINUTE);
    struct tm t = at(2, 8, 30, 12);
    CHECK(ks_sched_matches(&c, &t));
    t = at(3, 8, 30, 0);
    CHECK(!ks_sched_matches(&c, &t)); /* another weekday */
    t = at(2, 8, 0, 0);
    CHECK_INT_EQ(ks_sched_daily_ticks(&c, &t), 2); /* one per matching entry */
    ks_schema_free(&ks_sched_config_schema, &c);

    c = sched("{\"weekday\": [0,1,2,3,4,5,6], \"hour\": [8], \"minute\": [30]}");
    t = at(2, 8, 30, 0);
    CHECK(!ks_sched_matches(&c, &t)); /* hours + minutes alone never tick upstream */
    ks_schema_free(&ks_sched_config_schema, &c);
    c = sched("{\"weekday\": [2], \"hour\": [8], \"minute\": [30], \"second\": [5]}");
    CHECK(ks_sched_resolution(&c) == KS_SECOND);
    t = at(2, 8, 30, 5);
    CHECK(ks_sched_matches(&c, &t));
    t = at(2, 8, 30, 6);
    CHECK(!ks_sched_matches(&c, &t));
    ks_schema_free(&ks_sched_config_schema, &c);
    c = sched("{\"weekday\": [2], \"hour\": [8]}");
    CHECK(ks_sched_resolution(&c) == KS_HOUR);
    t = at(2, 8, 59, 59);
    CHECK(ks_sched_matches(&c, &t));
    ks_schema_free(&ks_sched_config_schema, &c);
    c = sched("{\"hour\": [8]}"); /* no weekday: never */
    t = at(2, 8, 0, 0);
    CHECK(!ks_sched_matches(&c, &t));
    ks_schema_free(&ks_sched_config_schema, &c);
}

/* ---- the loader, with a fake clock ------------------------------------- */

static int64_t fake_now;
static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

static int results;
static char last[4096];
static uint64_t last_id;

static void sink(void *ctx, const struct ks_task *t, const char *data, const char *err)
{
    (void)ctx;
    results++;
    last_id = t->id;
    snprintf(last, sizeof(last), "%s", data ? data : err);
}

TEST(loader_lists_and_reloads)
{
    mktmp();
    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1;
    struct ks_taskmgr *m = ks_taskmgr_new(loop, sink, NULL);
    struct ks_taskloader *l = ks_taskloader_new(m, loop);
    results = 0;

    char list[1024], path[256];
    snprintf(list, sizeof(list),
             "{\"tasks\": [{\"name\": \"looper\", \"configfile\": \"%s/looper.json\", "
             "\"enabled\": true},"
             "{\"name\": \"looper\", \"configfile\": \"%s/off.json\", \"enabled\": false},"
             "{\"name\": \"looper\", \"configfile\": \"%s/missing.json\", \"enabled\": true},"
             "{\"name\": \"nope\", \"configfile\": \"%s/looper.json\", \"enabled\": true}]}",
             dir, dir, dir, dir);
    write_at("tasks.json", list);
    write_at("looper.json", "{\"name\": \"loop-1\", \"data\": {\"interval\": \"2s\"}}");
    write_at("off.json", "{\"name\": \"loop-off\", \"data\": {\"interval\": \"1s\"}}");
    snprintf(path, sizeof(path), "%s/tasks.json", dir);
    ks_taskloader_load(l, path);
    CHECK_STR_EQ(ks_taskloader_file(l), path);
    CHECK_INT_EQ(ks_taskmgr_count(m), 1);
    struct ks_task *t = ks_taskmgr_get(m, "loop-1");
    CHECK(t != NULL);

    /* the looper: no result before the first tick, then the interval */
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(results, 0);
    fake_now += 2 * KS_SECOND;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(results, 1);
    CHECK_STR_EQ(last, "2s");
    CHECK(last_id == 9999);

    /* loading the list again keeps a running task */
    ks_taskloader_load(l, path);
    CHECK(ks_taskmgr_get(m, "loop-1") == t);

    /* the task's file changes: the instance named after the task type
     * restarts; "loop-1" isn't a type, so it's removed and not loaded */
    write_at("looper.json", "{\"name\": \"looper\", \"data\": {\"interval\": \"3s\"}}");
    snprintf(path, sizeof(path), "%s/looper.json", dir);
    ks_taskloader_file_changed(l, path);
    CHECK(ks_taskmgr_get(m, "looper") != NULL);
    ks_taskloader_file_changed(l, path); /* again: replaced */
    CHECK_INT_EQ(ks_taskmgr_count(m), 2);

    /* disabling it in the list removes it */
    snprintf(list, sizeof(list),
             "{\"tasks\": [{\"name\": \"looper\", \"configfile\": \"%s/looper.json\", "
             "\"enabled\": false}]}",
             dir);
    write_at("tasks.json", list);
    snprintf(path, sizeof(path), "%s/tasks.json", dir);
    ks_taskloader_file_changed(l, path);
    CHECK(ks_taskmgr_get(m, "looper") == NULL);
    CHECK(ks_taskmgr_get(m, "loop-1") != NULL); /* gone from the list, still running */

    /* a looper without "interval" (a panic upstream) */
    write_at("looper.json", "{\"name\": \"looper\", \"data\": {}}");
    snprintf(path, sizeof(path), "%s/looper.json", dir);
    ks_taskloader_file_changed(l, path);
    CHECK(ks_taskmgr_get(m, "looper") == NULL);

    /* an unreadable list keeps the previous one */
    write_at("tasks.json", "{\"tasks\": 3}");
    snprintf(path, sizeof(path), "%s/tasks.json", dir);
    ks_taskloader_load(l, path);
    CHECK_STR_EQ(ks_taskloader_file(l), path);
    write_at("tasks.json", "");
    ks_taskloader_load(l, path);

    ks_taskloader_free(l);
    ks_taskmgr_free(m);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
    rmtmp();
}

/* ---- the IOC scanner -------------------------------------------------- */

static bool run_until(struct ks_evloop *loop, int want, int ms)
{
    for (int i = 0; i < ms / 10 && results < want; i++)
        ks_evloop_run_once(loop, 10);
    return results >= want;
}

TEST(iocscanner_runs_tools)
{
    mktmp();
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_taskmgr *m = ks_taskmgr_new(loop, sink, NULL);
    results = 0;
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"interval\": \"5s\", \"schedule\": [],"
             " \"tools\": [{\"name\": \"script-test\", \"enabled\": true,"
             "  \"cmd\": [\"/bin/sh\", \"-c\", \"echo one; echo /skip/me; echo two; printf tail\"],"
             "  \"options\": {\"exclusions\": {\"dirs\": [\"/skip\"]},"
             "    \"reports\": [{\"type\": \"file\", \"path\": \"%s/reports\"}]}},"
             " {\"name\": \"script-off\", \"enabled\": false, \"cmd\": [\"false\"]}]}",
             dir);
    cJSON *data = cJSON_Parse(json);
    char err[256];
    struct ks_task *t = ks_iocscanner_new("IOC-scanner", data, err, sizeof(err));
    cJSON_Delete(data);
    CHECK(t != NULL);
    CHECK_INT_EQ(ks_taskmgr_add(m, t, err, sizeof(err)), 0);
    CHECK(t->running);

    ks_iocscanner_tick(t);
    ks_iocscanner_tick(t); /* still running: skipped */
    CHECK(run_until(loop, 1, 5000));
    char host[256] = "";
    gethostname(host, sizeof(host) - 1);
    char want[512];
    snprintf(want, sizeof(want), "==== script-test - %s (", host);
    CHECK(strncmp(last, want, strlen(want)) == 0);
    /* the excluded line is gone; the last one, without a newline, too */
    CHECK_STR_HAS(last, ") ====<br><br><br>one<br>two<br><br><br>=== script-test - (");
    CHECK(strstr(last, "tail") == NULL);
    CHECK(strstr(last, "/skip") == NULL);
    CHECK_STR_HAS(last, "s) ===<br>");
    CHECK(last_id == 9006);

    /* it runs again on the next tick (upstream's would not) */
    for (int i = 0; i < 100 && results < 2; i++) {
        ks_evloop_run_once(loop, 10);
        ks_iocscanner_tick(t);
    }
    CHECK(results >= 2);

    /* the report file */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "grep -c '^one$' %s/reports/ioc-report-script-test-*.log", dir);
    FILE *p = popen(cmd, "r");
    char count[16] = "";
    CHECK(p != NULL && fgets(count, sizeof(count), p) != NULL);
    if (p != NULL)
        pclose(p);
    CHECK(atoi(count) >= 2);

    ks_taskmgr_free(m);
    ks_evloop_free(loop);

    /* no tools: the task stays without starting; no interval: an error */
    data = cJSON_Parse("{\"interval\": \"\", \"tools\": []}");
    loop = ks_evloop_new();
    m = ks_taskmgr_new(loop, sink, NULL);
    t = ks_iocscanner_new("IOC-scanner", data, err, sizeof(err));
    ks_taskmgr_add(m, t, err, sizeof(err));
    CHECK(!t->running);
    cJSON_Delete(data);
    data = cJSON_Parse("{\"tools\": []}");
    CHECK(ks_iocscanner_new("x", data, err, sizeof(err)) == NULL);
    CHECK_STR_EQ(err, "interface conversion: interface {} is nil, not string");
    cJSON_Delete(data);
    ks_taskmgr_free(m);
    ks_evloop_free(loop);
    rmtmp();
}

static char *cmdline(const char *json)
{
    cJSON *j = cJSON_Parse(json);
    char *s = ks_ioc_tool_cmdline(j);
    cJSON_Delete(j);
    return s;
}

TEST(iocscanner_cmdlines)
{
    mktmp();
    write_at("a.yar", "");
    write_at("b.yar", "");
    write_at(".c.yar", "");
    char json[1024], want[1024];
    snprintf(json, sizeof(json),
             "{\"name\": \"yara-x\", \"cmd\": [\"/usr/bin/yara\"], \"dataDir\": \"%s\","
             " \"options\": {\"debug\": true, \"recursive\": true, \"fastscan\": true,"
             " \"threads\": 4, \"maxRunningTime\": \"1h30m\", \"maxSize\": 1000,"
             " \"tags\": [\"t1\"], \"rules\": [\"%s/*.yar\", \"/no/such.yar\"],"
             " \"dirs\": [\"/tmp\"]}}",
             dir, dir);
    char *s = cmdline(json);
    snprintf(want, sizeof(want),
             "/usr/bin/yara --print-tags --no-warnings --print-strings --recursive "
             "--fast-scan --threads=4 --timeout=5400 --skip-larger=1000 --tag=t1 "
             "%s/.c.yar %s/a.yar %s/b.yar /tmp",
             dir, dir, dir);
    CHECK_STR_EQ(s, want);
    free(s);

    /* dirs and files together: a scan list in the data directory */
    snprintf(json, sizeof(json),
             "{\"name\": \"yara\", \"cmd\": [\"yara\"], \"dataDir\": \"%s\","
             " \"options\": {\"rules\": [\"r.yar\"], \"dirs\": [\"/d\"], \"files\": [\"/f\"]}}",
             dir);
    s = cmdline(json);
    snprintf(want, sizeof(want), "yara --print-tags --no-warnings --scan-list %s/.opensnitch-yarascan.",
             dir);
    CHECK(s != NULL && strncmp(s, want, strlen(want)) == 0);
    free(s);

    snprintf(json, sizeof(json), "{\"name\": \"yara\", \"cmd\": [\"yara\"], \"dataDir\": \"%s\"}",
             dir);
    CHECK(cmdline(json) == NULL); /* no rules */
    CHECK(cmdline("{\"name\": \"debsums\", \"cmd\": []}") == NULL);
    s = cmdline("{\"name\": \"debsums-pkgs\", \"cmd\": [\"debsums\", \"-c\"]}");
    CHECK_STR_EQ(s, "debsums -c");
    free(s);

    char b[64];
    ks_go_ftoa(5400, b, sizeof(b));
    CHECK_STR_EQ(b, "5400");
    ks_go_ftoa(1.5, b, sizeof(b));
    CHECK_STR_EQ(b, "1.5");
    ks_go_ftoa(1e-9, b, sizeof(b));
    CHECK_STR_EQ(b, "1e-09");
    ks_go_ftoa(0.0001, b, sizeof(b));
    CHECK_STR_EQ(b, "0.0001");
    ks_go_ftoa(1e21, b, sizeof(b));
    CHECK_STR_EQ(b, "1e+21");
    ks_go_ftoa(123456789012.0, b, sizeof(b));
    CHECK_STR_EQ(b, "123456789012");

    /* debsums/dpkg lines: "<tag> <path>" */
    struct ks_ioc_scan o;
    memset(&o, 0, sizeof(o));
    char *dirs[] = {"/usr/share/doc"}, *files[] = {".conf"}, *tags[] = {"missing"};
    o.exclusions.dirs = (struct ks_strs){dirs, 1, true};
    o.exclusions.files = (struct ks_strs){files, 1, true};
    o.exclusions.tags = (struct ks_strs){tags, 1, true};
    CHECK(!ks_ioc_keep_line(KS_IOC_DPKG, &o, "??5?????? /usr/share/doc/x\n"));
    CHECK(ks_ioc_keep_line(KS_IOC_DPKG, &o, "??5?????? c /etc/a.conf\n"));
    CHECK(!ks_ioc_keep_line(KS_IOC_DPKG, &o, "??5?????? /etc/a.conf\n"));
    CHECK(!ks_ioc_keep_line(KS_IOC_DPKG, &o, "missing /usr/bin/x\n"));
    CHECK(ks_ioc_keep_line(KS_IOC_DPKG, &o, "??5?????? /usr/bin/x\n"));
    CHECK(ks_ioc_keep_line(KS_IOC_DPKG, &o, "lonely\n"));
    CHECK(ks_ioc_keep_line(KS_IOC_YARA, &o, "/usr/share/doc/x\n"));
    rmtmp();
}

/* ---- the downloader --------------------------------------------------- */

struct http {
    int fd;
    int requests;
};

static void *serve(void *data)
{
    struct http *h = data;
    for (;;) {
        int c = accept(h->fd, NULL, NULL);
        if (c < 0)
            return NULL;
        char req[2048];
        ssize_t n = recv(c, req, sizeof(req) - 1, 0);
        req[n > 0 ? n : 0] = '\0';
        h->requests++;
        const char *resp;
        if (strstr(req, "GET /list ") != NULL)
            resp = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0.0.0.0 a\n";
        else if (strstr(req, "GET /empty ") != NULL)
            resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        else
            resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if (send(c, resp, strlen(resp), 0) < 0)
            fprintf(stderr, "send failed\n");
        close(c);
    }
}

TEST(downloader)
{
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_taskmgr *m = ks_taskmgr_new(loop, sink, NULL);
    results = 0;
    char err[256];
    if (!ks_downloader_available()) {
        /* without CURL=1 the task doesn't start */
        cJSON *d = cJSON_Parse("{\"urls\": []}");
        struct ks_task *t = ks_downloader_new("downloader", d);
        cJSON_Delete(d);
        CHECK_INT_EQ(ks_taskmgr_add(m, t, err, sizeof(err)), 0);
        CHECK(!t->running);
        ks_taskmgr_free(m);
        ks_evloop_free(loop);
        return;
    }
    mktmp();
    struct http h = {socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), 0};
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof(sa);
    CHECK(bind(h.fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(h.fd, 8) == 0);
    getsockname(h.fd, (struct sockaddr *)&sa, &sl);
    pthread_t th;
    pthread_create(&th, NULL, serve, &h);

    int port = ntohs(sa.sin_port);
    char json[2048];
    /* the old file is longer than the new list: it must be replaced */
    write_at("old.txt", "0.0.0.0 old-entry-longer-than-the-new-list\n");
    snprintf(json, sizeof(json),
             "{\"interval\": \"1h\", \"timeout\": \"5s\", \"notify\": {\"enabled\": true},"
             " \"urls\": ["
             "  {\"name\": \"a\", \"remote\": \"http://127.0.0.1:%d/list\", \"localfile\": \"%s/new/dir/a.txt\"},"
             "  {\"name\": \"b\", \"remote\": \"http://127.0.0.1:%d/list\", \"localfile\": \"%s/old.txt\"},"
             "  {\"name\": \"c\", \"remote\": \"http://127.0.0.1:%d/empty\", \"localfile\": \"%s/c.txt\"},"
             "  {\"name\": \"d\", \"remote\": \"http://127.0.0.1:%d/gone\", \"localfile\": \"%s/d.txt\"}]}",
             port, dir, port, dir, port, dir, port, dir);
    cJSON *d = cJSON_Parse(json);
    struct ks_task *t = ks_downloader_new("downloader", d);
    cJSON_Delete(d);
    CHECK_INT_EQ(ks_taskmgr_add(m, t, err, sizeof(err)), 0);
    CHECK(t->running);
    CHECK(run_until(loop, 1, 10000));
    char want[512];
    snprintf(want, sizeof(want),
             "[blocklists] lists updated\n\nErrors:\n, http://127.0.0.1:%d/empty, "
             "http://127.0.0.1:%d/gone",
             port, port);
    CHECK_STR_EQ(last, want);
    CHECK(last_id == 9003);
    /* one download per remote: the second entry with /list wins */
    char path[256], buf[128] = "";
    snprintf(path, sizeof(path), "%s/old.txt", dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL && fgets(buf, sizeof(buf), f) != NULL);
    if (f != NULL)
        fclose(f);
    CHECK_STR_EQ(buf, "0.0.0.0 a\n");
    struct stat st;
    snprintf(path, sizeof(path), "%s/new/dir", dir);
    CHECK(stat(path, &st) == 0 && S_ISDIR(st.st_mode));
    snprintf(path, sizeof(path), "%s/c.txt", dir);
    CHECK(stat(path, &st) < 0); /* nothing written for a failure */
    CHECK_INT_EQ(h.requests, 3);

    ks_taskmgr_free(m);
    ks_evloop_free(loop);
    shutdown(h.fd, SHUT_RDWR);
    close(h.fd);
    pthread_join(th, NULL);
    rmtmp();
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(schema_scalar_slices);
    RUN(scheduler_matching);
    RUN(loader_lists_and_reloads);
    RUN(iocscanner_runs_tools);
    RUN(iocscanner_cmdlines);
    RUN(downloader);
    return harness_report();
}
