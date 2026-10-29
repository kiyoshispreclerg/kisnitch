/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The task manager and the UI's monitor tasks (daemon/tasks/), with the
 * JSON they send: procmon.Process (GetExtraInfo from a fake /proc),
 * syscall.Sysinfo_t and the sockets table.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _DEFAULT_SOURCE /* symlink, mkdtemp */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/procmon/process.h"
#include "daemon/sockdiag.h"
#include "daemon/tasks/monitors.h"
#include "daemon/tasks/tasks.h"
#include "tests/harness.h"

/* ---- the manager, with a fake clock ---------------------------------- */

static int64_t fake_now;
static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

struct counter {
    int runs, frees;
    bool fail_start, exit_at_2, remove_in_sink;
};

static int c_start(struct ks_task *t, char *err, size_t errlen)
{
    struct counter *c = t->priv;
    if (c->fail_start) {
        snprintf(err, errlen, "bad");
        return -1;
    }
    t->interval_ns = 1000;
    return 0;
}

static enum ks_task_status c_run(struct ks_task *t, char **data, char *err, size_t errlen)
{
    struct counter *c = t->priv;
    c->runs++;
    if (c->exit_at_2 && c->runs == 2) {
        snprintf(err, errlen, "gone");
        return KS_TASK_EXIT;
    }
    if (c->runs == 3) {
        snprintf(err, errlen, "an error");
        return KS_TASK_ERROR;
    }
    char b[32];
    snprintf(b, sizeof(b), "run %d", c->runs);
    *data = strdup(b);
    return KS_TASK_RESULT;
}

static void c_free(void *priv)
{
    ((struct counter *)priv)->frees++;
}

static const struct ks_task_ops counter_ops = {c_start, c_run, c_free};

static struct ks_taskmgr *mgr;
static char last_data[64], last_err[64];
static int results;

static void sink(void *ctx, const struct ks_task *t, const char *data, const char *err)
{
    (void)ctx;
    results++;
    snprintf(last_data, sizeof(last_data), "%s", data ? data : "");
    snprintf(last_err, sizeof(last_err), "%s", err ? err : "");
    struct counter *c = t->priv;
    if (c->remove_in_sink) {
        char e[128];
        ks_taskmgr_remove(mgr, t->name, e, sizeof(e));
    }
}

TEST(manager_runs_removes_and_stops)
{
    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1;
    mgr = ks_taskmgr_new(loop, sink, NULL);
    results = 0;

    struct counter a = {0}, dup = {0};
    char err[256];
    CHECK_INT_EQ(ks_taskmgr_add(mgr, ks_task_new("a", &counter_ops, &a), err, sizeof(err)), 0);
    /* the name is taken: the new task is freed */
    CHECK_INT_EQ(ks_taskmgr_add(mgr, ks_task_new("a", &counter_ops, &dup), err, sizeof(err)),
                 -1);
    CHECK_STR_EQ(err, "task with name a already exists");
    CHECK_INT_EQ(dup.frees, 1);

    /* the first iteration runs right away, then every interval */
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(a.runs, 1);
    CHECK_STR_EQ(last_data, "run 1");
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    CHECK_STR_EQ(last_data, "run 2");
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    CHECK_STR_EQ(last_err, "an error"); /* and it keeps running */
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(a.runs, 4);

    /* a task that fails to start stays added, without running */
    struct counter b = {.fail_start = true};
    CHECK_INT_EQ(ks_taskmgr_add(mgr, ks_task_new("b", &counter_ops, &b), err, sizeof(err)), 0);
    CHECK_INT_EQ(ks_taskmgr_count(mgr), 2);
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(b.runs, 0);

    /* KS_TASK_EXIT stops the iterations */
    struct counter e = {.exit_at_2 = true};
    ks_taskmgr_add(mgr, ks_task_new("e", &counter_ops, &e), err, sizeof(err));
    ks_evloop_fire_due(loop);
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    fake_now += 1000;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(e.runs, 2);
    CHECK(ks_taskmgr_get(mgr, "e") != NULL);

    /* removing the task from its own result */
    struct counter r = {.remove_in_sink = true};
    ks_taskmgr_add(mgr, ks_task_new("r", &counter_ops, &r), err, sizeof(err));
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(r.frees, 1);
    CHECK(ks_taskmgr_get(mgr, "r") == NULL);

    CHECK_INT_EQ(ks_taskmgr_remove(mgr, "nope", err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "task with name nope does not exist");

    /* StopTempTasks only stops the temporary ones */
    struct counter t1 = {0};
    struct ks_task *tt = ks_task_new("t", &counter_ops, &t1);
    tt->temporary = true;
    ks_taskmgr_add(mgr, tt, err, sizeof(err));
    CHECK_INT_EQ(ks_taskmgr_count(mgr), 4);
    ks_taskmgr_stop_temp(mgr);
    CHECK_INT_EQ(ks_taskmgr_count(mgr), 3);
    CHECK_INT_EQ(t1.frees, 1);

    ks_taskmgr_free(mgr);
    CHECK_INT_EQ(a.frees, 1);
    CHECK_INT_EQ(b.frees, 1);
    CHECK_INT_EQ(e.frees, 1);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
}

/* ---- Go's error texts ------------------------------------------------ */

TEST(go_errors)
{
    char err[256];
    long long v;
    CHECK_INT_EQ(ks_task_atoi("1234", &v, err, sizeof(err)), 0);
    CHECK_INT_EQ(v, 1234);
    CHECK_INT_EQ(ks_task_atoi("-9223372036854775808", &v, err, sizeof(err)), 0);
    CHECK(v == INT64_MIN);
    CHECK_INT_EQ(ks_task_atoi("+7", &v, err, sizeof(err)), 0);
    CHECK_INT_EQ(v, 7);
    CHECK_INT_EQ(ks_task_atoi("", &v, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "strconv.Atoi: parsing \"\": invalid syntax");
    CHECK_INT_EQ(ks_task_atoi("12a", &v, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "strconv.Atoi: parsing \"12a\": invalid syntax");
    CHECK_INT_EQ(ks_task_atoi("9223372036854775808", &v, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "strconv.Atoi: parsing \"9223372036854775808\": value out of range");
    CHECK_INT_EQ(ks_task_atoi("-", &v, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "strconv.Atoi: parsing \"-\": invalid syntax");

    cJSON *j = cJSON_Parse("{\"s\": \"x\", \"n\": 1, \"a\": [], \"o\": {}, \"b\": true}");
    CHECK(ks_task_assert(cJSON_GetObjectItem(j, "s"), "string", err, sizeof(err)) == NULL);
    CHECK(ks_task_assert(cJSON_GetObjectItem(j, "x"), "string", err, sizeof(err)) != NULL);
    CHECK_STR_EQ(err, "interface conversion: interface {} is nil, not string");
    ks_task_assert(cJSON_GetObjectItem(j, "a"), "float64", err, sizeof(err));
    CHECK_STR_EQ(err, "interface conversion: interface {} is []interface {}, not float64");
    ks_task_assert(cJSON_GetObjectItem(j, "o"), "string", err, sizeof(err));
    CHECK_STR_EQ(err, "interface conversion: interface {} is map[string]interface {}, not string");
    ks_task_assert(cJSON_GetObjectItem(j, "b"), "string", err, sizeof(err));
    CHECK_STR_EQ(err, "interface conversion: interface {} is bool, not string");
    cJSON_Delete(j);

    int64_t ns;
    CHECK_INT_EQ(ks_task_parse_interval("", &ns, err, sizeof(err)), 0);
    CHECK(ns == 5000000000LL);
    CHECK_INT_EQ(ks_task_parse_interval("1m30s", &ns, err, sizeof(err)), 0);
    CHECK(ns == 90000000000LL);
    CHECK_INT_EQ(ks_task_parse_interval("0s", &ns, err, sizeof(err)), -1);
    CHECK_INT_EQ(ks_task_parse_interval("5", &ns, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "time: missing unit in duration \"5\"");
}

TEST(sockmon_config)
{
    struct ks_sockmon_config cfg;
    char err[256];
    cJSON *j = cJSON_Parse("{\"interval\": \"\", \"state\": 10, \"proto\": 6, \"family\": 2}");
    CHECK_INT_EQ(ks_sockmon_config_parse(j, &cfg, err, sizeof(err)), 0);
    CHECK_STR_EQ(cfg.interval, "5s");
    CHECK_INT_EQ(cfg.state, 10);
    CHECK_INT_EQ(cfg.proto, 6);
    CHECK_INT_EQ(cfg.family, 2);
    cJSON_Delete(j);

    j = cJSON_Parse("{\"interval\": \"1s\", \"state\": -1, \"proto\": 300.7, \"family\": 0}");
    CHECK_INT_EQ(ks_sockmon_config_parse(j, &cfg, err, sizeof(err)), 0);
    CHECK_INT_EQ(cfg.state, 255);
    CHECK_INT_EQ(cfg.proto, 44);
    cJSON_Delete(j);

    /* the UI's TASK_STOP data, as a start: interval missing */
    j = cJSON_Parse("{}");
    CHECK_INT_EQ(ks_sockmon_config_parse(j, &cfg, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "interface conversion: interface {} is nil, not string");
    cJSON_Delete(j);
    j = cJSON_Parse("{\"interval\": \"1s\", \"state\": \"0\"}");
    CHECK_INT_EQ(ks_sockmon_config_parse(j, &cfg, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "interface conversion: interface {} is string, not float64");
    cJSON_Delete(j);
    j = cJSON_Parse("[1]");
    CHECK_INT_EQ(ks_sockmon_config_parse(j, &cfg, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "[sockmon] invalid config received: [1]");
    cJSON_Delete(j);
    CHECK_INT_EQ(ks_sockmon_config_parse(NULL, &cfg, err, sizeof(err)), -1);
    CHECK_STR_EQ(err, "[sockmon] invalid config received: <nil>");
}

/* ---- AF_PACKET messages ---------------------------------------------- */

static void put16(uint8_t *b, uint16_t v)
{
    memcpy(b, &v, 2);
}

static void put32(uint8_t *b, uint32_t v)
{
    memcpy(b, &v, 4);
}

TEST(packet_diag_parse)
{
    /* what the kernel sends for PACKET_SHOW_INFO | PACKET_SHOW_MCLIST:
     * packet_diag_msg, PACKET_DIAG_INFO (28 bytes), PACKET_DIAG_UID,
     * PACKET_DIAG_MCLIST (empty nest) */
    uint8_t b[56];
    memset(b, 0, sizeof(b));
    b[0] = 17; /* AF_PACKET */
    b[1] = 3;  /* SOCK_RAW */
    put16(b + 2, 3); /* ETH_P_ALL */
    put32(b + 4, 12345);
    put32(b + 8, 7);
    put16(b + 16, 28); /* nla_len */
    put16(b + 18, 0);  /* PACKET_DIAG_INFO */
    put32(b + 20, 0x0102); /* pdi_index */
    put16(b + 44, 8);
    put16(b + 46, 5); /* PACKET_DIAG_UID */
    put32(b + 48, 1000);
    put16(b + 52, 4);
    put16(b + 54, 1); /* PACKET_DIAG_MCLIST */
    struct ks_packet_sock s;
    ks_packet_diag_parse(b, sizeof(b), &s);
    CHECK_INT_EQ(s.family, 17);
    CHECK_INT_EQ(s.num, 3);
    CHECK_INT_EQ(s.inode, 12345);
    CHECK_INT_EQ(s.cookie[0], 7);
    CHECK_INT_EQ(s.uid, 1000);
    /* upstream reads the index big-endian, one byte too early: only the
     * low byte of the interface index survives */
    CHECK_INT_EQ(s.index, 2);

    /* short messages don't read past the end */
    ks_packet_diag_parse(b, 4, &s);
    CHECK_INT_EQ(s.inode, 0);
}

/* ---- Process JSON ---------------------------------------------------- */

static char dir[64];

static void write_at(const char *rel, const char *data, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return;
    fwrite(data, 1, len, f);
    fclose(f);
}

static void set(char **dst, const char *v)
{
    free(*dst);
    *dst = strdup(v);
}

TEST(process_json)
{
    setenv("TZ", "UTC", 1);
    tzset();
    snprintf(dir, sizeof(dir), "/tmp/ks-tasks-XXXXXX");
    CHECK(mkdtemp(dir) != NULL);
    char path[256], target[256];
    snprintf(path, sizeof(path), "%s/4242", dir);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/4242/fd", dir);
    mkdir(path, 0700);
    write_at("4242/environ", "B=2\0A=1\0A=3\0X\0", 15);
    write_at("4242/status", "Name:\tx\n", 8);
    write_at("4242/stat", "4242 (x) S 1\n", 13);
    write_at("4242/maps", "m <a> & b\n", 10);
    write_at("4242/statm", "10 5 3 1 0 2 0\n", 15);
    const char io[] = "rchar: 100\nwchar: 200\nsyscr: 3\nsyscw: 4\nread_bytes: 5\n"
                      "write_bytes: 6\ncancelled_write_bytes: 0\n";
    write_at("4242/io", io, sizeof(io) - 1);
    /* fd 0 -> a file with a known mtime, fd 1 -> a target that doesn't exist */
    snprintf(target, sizeof(target), "%s/target", dir);
    write_at("target", "12345", 5);
    struct timespec ts[2] = {{1700000000, 120000000}, {1700000000, 120000000}};
    utimensat(AT_FDCWD, target, ts, 0);
    snprintf(path, sizeof(path), "%s/4242/fd/0", dir);
    CHECK(symlink(target, path) == 0);

    struct ks_proc *p = ks_proc_new_empty(4242, "comm");
    p->starttime = 1700000000123456789LL;
    set(&p->path, "/usr/bin/x");
    set(&p->root, "/");
    set(&p->real_path, "/usr/bin/x");
    set(&p->cwd, "/tmp");
    p->args = calloc(2, sizeof(*p->args));
    p->args[0] = strdup("x");
    p->args[1] = strdup("-v");
    p->nargs = 2;
    p->checksum_md5 = strdup("abc");
    p->tree = calloc(2, sizeof(*p->tree));
    p->tree[0].path = strdup("/usr/bin/x");
    p->tree[0].pid = 4242;
    p->tree[1].path = strdup("");
    p->tree[1].pid = 1;
    p->ntree = 2;
    ks_proc_sync(p);

    /* before GetExtraInfo: the zero values of NewProcessEmpty */
    char *j = ks_proc_json(p);
    CHECK_STR_HAS(j, "{\"Statm\":{\"Size\":0,\"Resident\":0,\"Shared\":0,\"Text\":0,\"Lib\":0,"
                     "\"Data\":0,\"Dt\":0},\"Parent\":null,\"IOStats\":{\"RChar\":0,");
    CHECK_STR_HAS(j, "\"Env\":{},\"Checksums\":{\"process.hash.md5\":\"abc\"},\"Status\":\"\"");
    CHECK_STR_HAS(j, "\"Descriptors\":null,");
    free(j);

    ks_proc_get_extra_info_at(p, dir);
    j = ks_proc_json(p);
    long pg = sysconf(_SC_PAGESIZE);
    char want[2048];
    snprintf(want, sizeof(want),
             "{\"Statm\":{\"Size\":%ld,\"Resident\":%ld,\"Shared\":%ld,\"Text\":%ld,\"Lib\":0,"
             "\"Data\":%ld,\"Dt\":0},\"Parent\":null,"
             "\"IOStats\":{\"RChar\":100,\"WChar\":200,\"SyscallRead\":3,\"SyscallWrite\":4,"
             "\"ReadBytes\":5,\"WriteBytes\":6},\"NetStats\":{\"ReadBytes\":0,\"WriteBytes\":0},"
             "\"Env\":{\"A\":\"3\",\"B\":\"2\"},\"Checksums\":{\"process.hash.md5\":\"abc\"},"
             "\"Status\":\"Name:\\tx\\n\",\"Stat\":\"4242 (x) S 1\\n\",\"Stack\":\"\","
             "\"Maps\":\"m \\u003ca\\u003e \\u0026 b\\n\",\"Comm\":\"comm\",\"Path\":\"/usr/bin/x\","
             "\"Root\":\"/\",\"RealPath\":\"/usr/bin/x\",\"CWD\":\"/tmp\","
             "\"Tree\":[{\"key\":\"/usr/bin/x\",\"value\":4242},{\"value\":1}],"
             "\"Descriptors\":[{\"ModTime\":\"2023-11-14T22:13:20.12Z\",\"Name\":\"0\","
             "\"SymLink\":\"%s\",\"Size\":5}],"
             "\"Args\":[\"x\",\"-v\"],\"Starttime\":1700000000123456789,\"ID\":4242,\"PPID\":0,"
             "\"UID\":0}",
             10 * pg, 5 * pg, 3 * pg, 1 * pg, 2 * pg, target);
    CHECK_STR_EQ(j, want);
    free(j);

    /* the descriptor's target gone: zero time, no size; a parent */
    unlink(target);
    struct ks_proc *parent = ks_proc_new_empty(1, "init");
    parent->starttime = 5;
    p->parent = parent;
    ks_proc_get_extra_info_at(p, dir);
    j = ks_proc_json(p);
    CHECK_STR_HAS(j, "\"ModTime\":\"0001-01-01T00:00:00Z\"");
    CHECK_STR_HAS(j, "\"Size\":0}]");
    CHECK_STR_HAS(j, "\"Parent\":{\"Statm\":{\"Size\":0,");
    CHECK_STR_HAS(j, "\"Comm\":\"init\",");
    CHECK_STR_HAS(j, "\"Descriptors\":null,\"Args\":[],\"Starttime\":5,\"ID\":1,");
    free(j);

    /* a copy keeps the data and shares the parent */
    struct ks_proc *c = ks_proc_clone(p);
    CHECK(c != NULL && c->parent == parent && c->nenv == 2 && c->ntree == 2);
    CHECK(c->extra == NULL);
    CHECK_STR_EQ(c->checksum_md5, "abc");
    ks_proc_unref(c);
    ks_proc_unref(p);

    cJSON *z = ks_proc_zero_cjson();
    j = ks_json_print_go(z, false);
    CHECK_STR_EQ(j, "{\"Statm\":null,\"Parent\":null,\"IOStats\":null,\"NetStats\":null,"
                    "\"Env\":null,\"Checksums\":null,\"Status\":\"\",\"Stat\":\"\",\"Stack\":\"\","
                    "\"Maps\":\"\",\"Comm\":\"\",\"Path\":\"\",\"Root\":\"\",\"RealPath\":\"\","
                    "\"CWD\":\"\",\"Tree\":null,\"Descriptors\":null,\"Args\":null,"
                    "\"Starttime\":0,\"ID\":0,\"PPID\":0,\"UID\":0}");
    free(j);
    cJSON_Delete(z);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

TEST(go_time)
{
    char b[KS_GO_TIME_STRLEN];
    setenv("TZ", "UTC", 1);
    tzset();
    ks_go_time_rfc3339nano(KS_GO_ZERO_TIME, 0, b, sizeof(b));
    CHECK_STR_EQ(b, "0001-01-01T00:00:00Z");
    ks_go_time_rfc3339nano(0, 0, b, sizeof(b));
    CHECK_STR_EQ(b, "1970-01-01T00:00:00Z");
    ks_go_time_rfc3339nano(1700000000, 1, b, sizeof(b));
    CHECK_STR_EQ(b, "2023-11-14T22:13:20.000000001Z");
    /* POSIX TZ: three hours west of UTC */
    setenv("TZ", "BRT3", 1);
    tzset();
    ks_go_time_rfc3339nano(1700000000, 500000000, b, sizeof(b));
    CHECK_STR_EQ(b, "2023-11-14T19:13:20.5-03:00");
    setenv("TZ", "IST-5:30", 1);
    tzset();
    ks_go_time_rfc3339nano(1700000000, 0, b, sizeof(b));
    CHECK_STR_EQ(b, "2023-11-15T03:43:20+05:30");
    setenv("TZ", "UTC", 1);
    tzset();
}

/* ---- the system's JSON ----------------------------------------------- */

TEST(sysinfo_and_sockets_json)
{
    char *j = ks_nodemon_sysinfo_json();
    CHECK(j != NULL);
    cJSON *o = cJSON_Parse(j);
    CHECK(o != NULL);
    /* the field order of syscall.Sysinfo_t (linux/amd64) */
    static const char *const fields[] = {"Uptime",    "Loads",     "Totalram",  "Freeram",
                                         "Sharedram", "Bufferram", "Totalswap", "Freeswap",
                                         "Procs",     "Pad",       "Pad_cgo_0", "Totalhigh",
                                         "Freehigh",  "Unit",      "X_f",       "Pad_cgo_1"};
    const cJSON *c = o ? o->child : NULL;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]) && sizeof(long) == 8; i++) {
        CHECK(c != NULL);
        if (c == NULL)
            break;
        CHECK_STR_EQ(c->string, fields[i]);
        c = c->next;
    }
    CHECK_STR_HAS(j, "\"Pad_cgo_0\":[0,0,0,0],");
    CHECK_STR_HAS(j, "\"X_f\":[],\"Pad_cgo_1\":[0,0,0,0]}");
    CHECK(cJSON_GetObjectItem(o, "Totalram")->valuedouble > 0);
    cJSON_Delete(o);
    free(j);

    /* only TCP listening sockets: every row matches the filter */
    struct ks_sockmon_config cfg = {"5s", 10, 6, 2};
    j = ks_sockmon_dump_json(&cfg);
    CHECK(j != NULL);
    o = cJSON_Parse(j);
    CHECK(o != NULL);
    CHECK_STR_EQ(o->child->string, "Table");
    CHECK_STR_EQ(o->child->next->string, "Processes");
    const cJSON *row;
    cJSON_ArrayForEach(row, cJSON_GetObjectItem(o, "Table"))
    {
        const cJSON *s = cJSON_GetObjectItem(row, "Socket");
        CHECK_INT_EQ(cJSON_GetObjectItem(s, "State")->valueint, 10);
        CHECK_INT_EQ(cJSON_GetObjectItem(s, "Family")->valueint, 2);
        CHECK_INT_EQ(cJSON_GetObjectItem(row, "Proto")->valueint, 6);
        char pid[16];
        snprintf(pid, sizeof(pid), "%d", cJSON_GetObjectItem(row, "PID")->valueint);
        CHECK(cJSON_HasObjectItem(cJSON_GetObjectItem(o, "Processes"), pid));
    }
    /* the PIDs, sorted as strings */
    const cJSON *prev = NULL, *pr;
    cJSON_ArrayForEach(pr, cJSON_GetObjectItem(o, "Processes"))
    {
        if (prev != NULL)
            CHECK(strcmp(prev->string, pr->string) < 0);
        prev = pr;
    }
    cJSON_Delete(o);
    free(j);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(manager_runs_removes_and_stops);
    RUN(go_errors);
    RUN(sockmon_config);
    RUN(packet_diag_parse);
    RUN(process_json);
    RUN(go_time);
    RUN(sysinfo_and_sockets_json);
    return harness_report();
}
