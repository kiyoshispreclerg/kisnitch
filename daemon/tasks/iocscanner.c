/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/iocscanner (main.go, run_tools.go,
 * config/config.go, tools/{base,executer,yara,dpkg,generic}).
 *
 * The tools run as child processes whose stdout is read on the event
 * loop. Upstream cancels each tool's context when its first run ends, so
 * later runs start no command and the report file is closed; here every
 * scheduled run executes, and the report file and yara's scan list live
 * until the task stops (see docs/UPSTREAM.md).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _GNU_SOURCE /* GLOB_PERIOD, mkstemps */
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <math.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/duration.h"
#include "common/json_schema.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/tasks/disk.h"
#include "daemon/tasks/iocscanner.h"
#include "daemon/tasks/scheduler.h"

extern char **environ;

/* base.REDFLAGS: the IOC scanner's TaskBase.ID */
#define IOCS_ID 9006
#define YARA_DATA_DIR "/etc/opensnitchd/tasks/iocscanner/data/yara"
#define MSG_START "IOC scanner started"
#define MSG_END "IOC scanner finished"
/* upstream keeps the whole output in memory (its FIXME mentions ~60MB from
 * debsums); the report is cut here */
#define REPORT_MAX (64u * 1024 * 1024)

/* ---- config.IOCConfig ------------------------------------------------- */

static const struct ks_schema_field excl_fields[] = {
    KS_FIELD(struct ks_ioc_exclusions, "Dirs", KS_T_STRS, dirs),
    KS_FIELD(struct ks_ioc_exclusions, "Files", KS_T_STRS, files),
    KS_FIELD(struct ks_ioc_exclusions, "Tags", KS_T_STRS, tags),
};
static const struct ks_schema excl_schema =
    KS_SCHEMA("config.ExclusionsOpts", struct ks_ioc_exclusions, excl_fields);
static const struct ks_schema_field report_fields[] = {
    KS_FIELD(struct ks_ioc_report, "Type", KS_T_STRING, type),
    KS_FIELD(struct ks_ioc_report, "Path", KS_T_STRING, path),
    KS_FIELD(struct ks_ioc_report, "Format", KS_T_STRING, format),
    KS_FIELD(struct ks_ioc_report, "Sync", KS_T_BOOL, sync),
};
static const struct ks_schema report_schema =
    KS_SCHEMA("config.ReportOpts", struct ks_ioc_report, report_fields);
static const struct ks_schema_field scan_fields[] = {
    KS_FIELD(struct ks_ioc_scan, "Dirs", KS_T_STRS, dirs),
    KS_FIELD(struct ks_ioc_scan, "Files", KS_T_STRS, files),
    KS_FIELD(struct ks_ioc_scan, "Rules", KS_T_STRS, rules),
    KS_FIELD(struct ks_ioc_scan, "Tags", KS_T_STRS, tags),
    KS_FIELD_SUB(struct ks_ioc_scan, "Exclusions", KS_T_STRUCT, exclusions, excl_schema),
    KS_FIELD_SUB(struct ks_ioc_scan, "Reports", KS_T_ARRAY, reports, report_schema),
    KS_FIELD(struct ks_ioc_scan, "MaxRunningTime", KS_T_STRING, max_running_time),
    KS_FIELD(struct ks_ioc_scan, "MaxSize", KS_T_INT, max_size),
    KS_FIELD(struct ks_ioc_scan, "Threads", KS_T_INT, threads),
    KS_FIELD(struct ks_ioc_scan, "Priority", KS_T_INT, priority),
    KS_FIELD(struct ks_ioc_scan, "ScanProcs", KS_T_BOOL, scan_procs),
    KS_FIELD(struct ks_ioc_scan, "Recursive", KS_T_BOOL, recursive),
    KS_FIELD(struct ks_ioc_scan, "FastScan", KS_T_BOOL, fast_scan),
    KS_FIELD(struct ks_ioc_scan, "Debug", KS_T_BOOL, debug),
};
static const struct ks_schema scan_schema =
    KS_SCHEMA("config.ScanOpts", struct ks_ioc_scan, scan_fields);
static const struct ks_schema_field tool_fields[] = {
    KS_FIELD_SUB(struct ks_ioc_tool_opts, "Options", KS_T_STRUCT, options, scan_schema),
    KS_FIELD(struct ks_ioc_tool_opts, "Cmd", KS_T_STRS, cmd),
    KS_FIELD(struct ks_ioc_tool_opts, "Name", KS_T_STRING, name),
    KS_FIELD(struct ks_ioc_tool_opts, "MsgStart", KS_T_STRING, msg_start),
    KS_FIELD(struct ks_ioc_tool_opts, "MsgEnd", KS_T_STRING, msg_end),
    KS_FIELD(struct ks_ioc_tool_opts, "DataDir", KS_T_STRING, data_dir),
    KS_FIELD(struct ks_ioc_tool_opts, "ReadBuffer", KS_T_INT, read_buffer),
    KS_FIELD(struct ks_ioc_tool_opts, "Workers", KS_T_INT, workers),
    KS_FIELD(struct ks_ioc_tool_opts, "Enabled", KS_T_BOOL, enabled),
};
static const struct ks_schema tool_schema =
    KS_SCHEMA("config.ToolOpts", struct ks_ioc_tool_opts, tool_fields);
static const struct ks_schema_field status_fields[] = {
    KS_FIELD(struct ks_ioc_notify_status, "type", KS_T_STRING, type),
    KS_FIELD(struct ks_ioc_notify_status, "message", KS_T_STRING, message),
};
static const struct ks_schema status_schema =
    KS_SCHEMA("config.NotifyStatus", struct ks_ioc_notify_status, status_fields);
static const struct ks_schema_field notify_fields[] = {
    KS_FIELD_SUB(struct ks_ioc_notify, "success", KS_T_STRUCT, success, status_schema),
    KS_FIELD_SUB(struct ks_ioc_notify, "error", KS_T_STRUCT, error, status_schema),
    KS_FIELD(struct ks_ioc_notify, "enabled", KS_T_BOOL, enabled),
};
const struct ks_schema ks_ioc_notify_schema =
    KS_SCHEMA("config.NotifyOpts", struct ks_ioc_notify, notify_fields);
static const struct ks_schema_field action_fields[] = {
    KS_FIELD(struct ks_ioc_action, "Type", KS_T_STRING, type),
    KS_FIELD(struct ks_ioc_action, "Data", KS_T_STRING, data),
};
static const struct ks_schema action_schema =
    KS_SCHEMA("config.ActionsOpts", struct ks_ioc_action, action_fields);
static const struct ks_schema_field ioc_fields[] = {
    KS_FIELD_SUB(struct ks_ioc_config, "schedule", KS_T_ARRAY, schedule, ks_sched_config_schema),
    KS_FIELD_SUB(struct ks_ioc_config, "Tools", KS_T_ARRAY, tools, tool_schema),
    KS_FIELD_SUB(struct ks_ioc_config, "Notify", KS_T_STRUCT, notify, ks_ioc_notify_schema),
    KS_FIELD_SUB(struct ks_ioc_config, "Actions", KS_T_ARRAY, actions, action_schema),
    KS_FIELD(struct ks_ioc_config, "Interval", KS_T_STRING, interval),
};
const struct ks_schema ks_ioc_config_schema =
    KS_SCHEMA("config.IOCConfig", struct ks_ioc_config, ioc_fields);

/* ---- helpers ---------------------------------------------------------- */

static bool has_prefix(const char *s, const char *p)
{
    return strncmp(s, p, strlen(p)) == 0;
}

static bool has_suffix(const char *s, const char *p)
{
    size_t a = strlen(s), b = strlen(p);
    return a >= b && strcmp(s + a - b, p) == 0;
}

static void mkdir_all(const char *path)
{
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buf, 0700);
            *p = '/';
        }
    }
    mkdir(buf, 0700);
}

/* fmt.Sprint(float64): strconv 'g' with the shortest digits, in exponent
 * form below 1e-4 or from 1e21 on */
void ks_go_ftoa(double v, char *buf, size_t len)
{
    if (v == 0) {
        snprintf(buf, len, "0");
        return;
    }
    char e[40];
    int p;
    for (p = 1; p <= 17; p++) {
        snprintf(e, sizeof(e), "%.*e", p - 1, v);
        if (strtod(e, NULL) == v)
            break;
    }
    int x = atoi(strchr(e, 'e') + 1);
    if (x < -4 || x >= 21) {
        char *ep = strchr(e, 'e');
        *ep = '\0';
        snprintf(buf, len, "%se%c%02d", e, x < 0 ? '-' : '+', abs(x));
        return;
    }
    int decimals = p - 1 - x;
    snprintf(buf, len, "%.*f", decimals > 0 ? decimals : 0, v);
}

struct sbuf {
    char *p;
    size_t len, cap;
    bool full;
};

static void sb_add(struct sbuf *b, const char *s, size_t n)
{
    if (b->full)
        return;
    if (b->len + n > REPORT_MAX) {
        b->full = true;
        return;
    }
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1)
            cap *= 2;
        char *np = realloc(b->p, cap);
        if (np == NULL) {
            b->full = true;
            return;
        }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void sb_str(struct sbuf *b, const char *s)
{
    sb_add(b, s, strlen(s));
}

/* ---- tools ------------------------------------------------------------ */

enum tool_kind { TOOL_YARA = KS_IOC_YARA, TOOL_DPKG = KS_IOC_DPKG, TOOL_SCRIPT = KS_IOC_SCRIPT };

struct tool {
    struct iocs *owner;
    enum tool_kind kind;
    struct ks_ioc_tool_opts opts; /* copy */
    char *name, *msg_start, *msg_end;
    char **argv; /* Cmd, then Cmdline */
    size_t argc;
    int workers;
    FILE *logger; /* the report file */
    char *scan_list;

    /* the running command (Executer) */
    pid_t pid;
    int out_fd;
    bool running;
    struct sbuf line, report;
    struct timespec started;
    struct ks_timer *reap_timer;
};

struct iocs {
    struct ks_task *task;
    struct ks_evloop *loop;
    struct ks_ioc_config cfg;
    char hostname[256];
    struct tool **tools;
    size_t ntools;
    struct ks_sched **scheds;
    size_t nscheds;
};

static int argv_add(struct tool *t, const char *a)
{
    char **v = realloc(t->argv, (t->argc + 2) * sizeof(*v));
    if (v == NULL)
        return -1;
    t->argv = v;
    if ((v[t->argc] = strdup(a)) == NULL)
        return -1;
    v[++t->argc] = NULL;
    return 0;
}

static void open_report(struct tool *t, const char *dir, bool dash)
{
    struct stat st;
    if (stat(dir, &st) < 0)
        mkdir_all(dir);
    time_t now = time(NULL);
    struct tm lt;
    char stamp[32] = "";
    if (localtime_r(&now, &lt) != NULL)
        strftime(stamp, sizeof(stamp), "%d-%m-%YT%H:%M:%S", &lt);
    char path[4096];
    snprintf(path, sizeof(path), "%s/ioc-report-%s%s%s.log", dir, t->name, dash ? "-" : "",
             stamp);
    if (t->logger != NULL)
        fclose(t->logger);
    /* os.O_RDWR|os.O_CREATE, 0600: no truncation */
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    t->logger = fd >= 0 ? fdopen(fd, "r+") : NULL;
    if (t->logger == NULL) {
        ks_warning("[IOCScanner][%s] warning: open %s: %s", t->kind == TOOL_YARA ? "yara" : "dpkg",
                   path, strerror(errno));
        if (fd >= 0)
            close(fd);
    }
}

static void tool_free(struct tool *t)
{
    if (t == NULL)
        return;
    if (t->running && t->pid > 0) {
        kill(t->pid, SIGKILL);
        waitpid(t->pid, NULL, 0);
    }
    if (t->out_fd >= 0) {
        ks_evloop_del_fd(t->owner->loop, t->out_fd);
        close(t->out_fd);
    }
    if (t->reap_timer != NULL)
        ks_evloop_cancel_timer(t->owner->loop, t->reap_timer);
    /* Cleanup() */
    if (t->logger != NULL)
        fclose(t->logger);
    if (t->scan_list != NULL) {
        unlink(t->scan_list);
        ks_debug("[yara-tool] removing %s", t->scan_list);
        free(t->scan_list);
    }
    for (size_t i = 0; i < t->argc; i++)
        free(t->argv[i]);
    free(t->argv);
    free(t->name);
    free(t->msg_start);
    free(t->msg_end);
    free(t->line.p);
    free(t->report.p);
    ks_schema_free(&tool_schema, &t->opts);
    free(t);
}

static struct tool *tool_base(struct iocs *owner, const struct ks_ioc_tool_opts *opts,
                              enum tool_kind kind, const char *def_name)
{
    struct tool *t = calloc(1, sizeof(*t));
    if (t == NULL)
        return NULL;
    t->owner = owner;
    t->kind = kind;
    t->out_fd = -1;
    if (ks_schema_copy(&tool_schema, &t->opts, opts) < 0) {
        free(t);
        return NULL;
    }
    t->workers = opts->workers != 0 ? (int)opts->workers : 1; /* SetWorkers */
    t->name = strdup(opts->name[0] ? opts->name : def_name);
    t->msg_start = strdup(opts->msg_start[0] ? opts->msg_start : MSG_START);
    t->msg_end = strdup(opts->msg_end[0] ? opts->msg_end : MSG_END);
    if (t->name == NULL || t->msg_start == NULL || t->msg_end == NULL) {
        tool_free(t);
        return NULL;
    }
    return t;
}

/* generic.New and dpkg.New */
static struct tool *cmd_tool_new(struct iocs *owner, const struct ks_ioc_tool_opts *opts,
                                 enum tool_kind kind)
{
    struct tool *t = tool_base(owner, opts, kind, kind == TOOL_DPKG ? "dpkg" : "script");
    if (t == NULL)
        return NULL;
    if (kind == TOOL_DPKG ? !has_prefix(opts->name, "debsums") && !has_prefix(opts->name, "dpkg")
                          : !has_prefix(opts->name, "script")) {
        ks_warning(kind == TOOL_DPKG ? "DpkgTool: invalid dpkg config: %s"
                                     : "[IOCScanner][generic]: invalid generic config: %s",
                   opts->name);
        tool_free(t);
        return NULL;
    }
    for (size_t i = 0; i < opts->options.reports.len; i++) {
        const struct ks_ioc_report *r =
            KS_ARRAY_ITEM(opts->options.reports, struct ks_ioc_report, i);
        if (strcmp(r->type, "file") == 0 && r->path[0] != '\0')
            open_report(t, r->path, true);
    }
    /* opts.Cmd[0] panics upstream on an empty command */
    if (opts->cmd.len == 0) {
        ks_warning("[IOCScanner] %s: no command (\"cmd\")", t->name);
        tool_free(t);
        return NULL;
    }
    for (size_t i = 0; i < opts->cmd.len; i++)
        if (argv_add(t, opts->cmd.v[i]) < 0) {
            tool_free(t);
            return NULL;
        }
    return t;
}

/* yara.New */
static struct tool *yara_new(struct iocs *owner, const struct ks_ioc_tool_opts *opts)
{
    struct tool *t = tool_base(owner, opts, TOOL_YARA, "yara");
    if (t == NULL)
        return NULL;
    const char *data_dir = opts->data_dir[0] ? opts->data_dir : YARA_DATA_DIR;
    struct stat st;
    if (stat(data_dir, &st) < 0)
        mkdir_all(data_dir);
    if (!has_prefix(opts->name, "yara")) {
        ks_warning("buildYaraCmdline: invalid yara config: %s", opts->name);
        tool_free(t);
        return NULL;
    }
    for (size_t i = 0; i < opts->options.reports.len; i++) {
        const struct ks_ioc_report *r =
            KS_ARRAY_ITEM(opts->options.reports, struct ks_ioc_report, i);
        if (r->path[0] != '\0')
            open_report(t, r->path, false);
    }
    const struct ks_ioc_scan *o = &opts->options;
    if (opts->cmd.len == 0) {
        ks_warning("[IOCScanner] %s: no command (\"cmd\")", t->name);
        tool_free(t);
        return NULL;
    }
    char arg[512];
    bool ok = argv_add(t, opts->cmd.v[0]) == 0 && argv_add(t, "--print-tags") == 0 &&
              argv_add(t, "--no-warnings") == 0;
    if (ok && o->debug)
        ok = argv_add(t, "--print-strings") == 0;
    if (ok && o->recursive)
        ok = argv_add(t, "--recursive") == 0;
    if (ok && o->fast_scan)
        ok = argv_add(t, "--fast-scan") == 0;
    if (ok && o->threads > 0) {
        snprintf(arg, sizeof(arg), "--threads=%lld", (long long)o->threads);
        ok = argv_add(t, arg) == 0;
    }
    if (ok && o->max_running_time[0] != '\0') {
        int64_t d;
        char err[256];
        if (ks_parse_duration(o->max_running_time, &d, err, sizeof(err)) == 0) {
            char secs[64];
            ks_go_ftoa((double)d / 1e9, secs, sizeof(secs));
            snprintf(arg, sizeof(arg), "--timeout=%s", secs);
            ok = argv_add(t, arg) == 0;
        } else {
            ks_warning("[IOCScanner][yara] invalid MaxRunningTime %s: %s", o->max_running_time,
                       err);
        }
    }
    if (ok && o->max_size > 0) {
        snprintf(arg, sizeof(arg), "--skip-larger=%lld", (long long)o->max_size);
        ok = argv_add(t, arg) == 0;
    }
    for (size_t i = 0; ok && i < o->tags.len; i++) {
        snprintf(arg, sizeof(arg), "--tag=%s", o->tags.v[i]);
        ok = argv_add(t, arg) == 0;
    }
    if (ok && o->rules.len == 0) {
        ks_warning("yara tool: no rules specified");
        tool_free(t);
        return NULL;
    }
    /* filepath.Glob: the shell isn't there to expand wildcards */
    for (size_t i = 0; ok && i < o->rules.len; i++) {
        glob_t g;
        int r = glob(o->rules.v[i], GLOB_PERIOD, NULL, &g);
        if (r == 0)
            for (size_t k = 0; ok && k < g.gl_pathc; k++)
                ok = argv_add(t, g.gl_pathv[k]) == 0;
        else if (r != GLOB_NOMATCH)
            ok = argv_add(t, o->rules.v[i]) == 0;
        globfree(&g);
    }
    size_t dirs = o->dirs.len, files = o->files.len;
    if (ok && dirs + files > 1) {
        if (dirs == 0) {
            for (size_t i = 0; ok && i < files; i++)
                ok = argv_add(t, o->files.v[i]) == 0;
        } else if (files == 0) {
            for (size_t i = 0; ok && i < dirs; i++)
                ok = argv_add(t, o->dirs.v[i]) == 0;
        } else {
            /* os.CreateTemp(DataDir, ".opensnitch-yarascan.*.txt") */
            char path[4096];
            snprintf(path, sizeof(path), "%s/.opensnitch-yarascan.XXXXXX.txt", data_dir);
            int fd = mkstemps(path, 4);
            if (fd < 0) {
                ks_warning("Yara warning, DataDir does not exist %s: %s", data_dir,
                           strerror(errno));
                tool_free(t);
                return NULL;
            }
            FILE *f = fdopen(fd, "w");
            for (size_t i = 0; f != NULL && i < files; i++)
                fprintf(f, "%s\n", o->files.v[i]);
            for (size_t i = 0; f != NULL && i < dirs; i++)
                fprintf(f, "%s\n", o->dirs.v[i]);
            if (f != NULL)
                fclose(f);
            else
                close(fd);
            t->scan_list = strdup(path);
            ok = t->scan_list != NULL && argv_add(t, "--scan-list") == 0 &&
                 argv_add(t, path) == 0;
        }
    } else if (ok && files == 1) {
        ok = argv_add(t, o->files.v[0]) == 0;
    } else if (ok && dirs == 1) {
        ok = argv_add(t, o->dirs.v[0]) == 0;
    }
    if (!ok) {
        tool_free(t);
        return NULL;
    }
    return t;
}

/* strings.Fields(line)[i], "" if there's none (upstream indexes [1] of
 * one-field lines, a panic) */
static void field(const char *line, int idx, char *out, size_t len)
{
    out[0] = '\0';
    const char *s = line;
    for (int i = 0;; i++) {
        while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' || *s == '\v' || *s == '\f')
            s++;
        if (*s == '\0')
            return;
        const char *e = s;
        while (*e && !(*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r' || *e == '\v' ||
                       *e == '\f'))
            e++;
        if (i == idx) {
            snprintf(out, len, "%.*s", (int)(e - s), s);
            return;
        }
        s = e;
    }
}

/* TransformLogline: whether the line goes in the report */
bool ks_ioc_keep_line(int kind, const struct ks_ioc_scan *o, const char *line)
{
    if (kind == TOOL_SCRIPT) {
        for (size_t i = 0; i < o->exclusions.dirs.len; i++)
            if (strstr(line, o->exclusions.dirs.v[i]) != NULL)
                return false;
        for (size_t i = 0; i < o->exclusions.files.len; i++)
            if (strstr(line, o->exclusions.files.v[i]) != NULL)
                return false;
        return true;
    }
    if (kind != TOOL_DPKG)
        return true;
    char f0[4096], f1[4096];
    field(line, 0, f0, sizeof(f0));
    field(line, 1, f1, sizeof(f1));
    bool nf = f0[0] != '\0';
    for (size_t i = 0; nf && i < o->exclusions.dirs.len; i++)
        if (has_prefix(f1, o->exclusions.dirs.v[i]))
            return false;
    for (size_t i = 0; f1[0] && i < o->exclusions.files.len; i++)
        if (has_suffix(f1, o->exclusions.files.v[i]))
            return false;
    for (size_t i = 0; nf && i < o->exclusions.tags.len; i++)
        if (has_prefix(f0, o->exclusions.tags.v[i]))
            return false;
    /* the Dirs and Files filters return the line either way */
    return true;
}

/* ---- running a tool (Executer + runTool) ------------------------------ */

static void finish_run(struct tool *t)
{
    struct iocs *s = t->owner;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t el = ((int64_t)(now.tv_sec - t->started.tv_sec) * KS_SECOND +
                  (now.tv_nsec - t->started.tv_nsec));
    el -= el % KS_SECOND; /* Truncate(time.Second) */
    char dur[KS_DURATION_STRLEN];
    ks_format_duration(el, dur, sizeof(dur));
    char footer[512];
    snprintf(footer, sizeof(footer), "\n\n=== %s - (%s) ===\n", t->name, dur);
    /* each of the read workers appends its footer and sends the report */
    for (int w = 0; w < t->workers; w++) {
        sb_str(&t->report, footer);
        if (t->logger != NULL && t->report.p != NULL) {
            fwrite(t->report.p, 1, t->report.len, t->logger);
            fflush(t->logger);
        }
        /* the UI shows it with QTextEdit.setHtml(): newlines as <br> */
        struct sbuf html = {0};
        for (size_t i = 0; i < t->report.len; i++) {
            if (t->report.p[i] == '\n')
                sb_add(&html, "<br>", 4);
            else
                sb_add(&html, &t->report.p[i], 1);
        }
        ks_task_emit(s->task, html.p != NULL ? html.p : "", NULL);
        free(html.p);
    }
    free(t->report.p);
    memset(&t->report, 0, sizeof(t->report));
    free(t->line.p);
    memset(&t->line, 0, sizeof(t->line));
}

static void on_reap(void *data)
{
    struct tool *t = data;
    int st;
    pid_t r = waitpid(t->pid, &st, WNOHANG);
    if (r == 0)
        return; /* still running: try again */
    ks_evloop_cancel_timer(t->owner->loop, t->reap_timer);
    t->reap_timer = NULL;
    if (r > 0 && !(WIFEXITED(st) && WEXITSTATUS(st) == 0))
        ks_debug("[executer] Wait error: exit status %d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    ks_info("[executer] finished");
    t->pid = 0;
    t->running = false;
}

static void on_output(int fd, uint32_t events, void *data)
{
    (void)events;
    struct tool *t = data;
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return;
    if (n > 0) {
        for (ssize_t i = 0; i < n; i++) {
            sb_add(&t->line, &buf[i], 1);
            if (buf[i] == '\n') {
                /* ReadString('\n'): the line with its newline */
                if (t->line.p != NULL && ks_ioc_keep_line((int)t->kind, &t->opts.options, t->line.p))
                    sb_add(&t->report, t->line.p, t->line.len);
                t->line.len = 0;
                t->line.full = false;
            }
        }
        return;
    }
    /* EOF: a last line without a newline is dropped, as ReadString's error
     * ends the reader; then the executer stops (kills the command if it
     * still runs) */
    ks_debug("[executer] stdout reader exit");
    ks_evloop_del_fd(t->owner->loop, fd);
    close(fd);
    t->out_fd = -1;
    if (t->pid > 0 && waitpid(t->pid, NULL, WNOHANG) == 0)
        kill(t->pid, SIGKILL);
    finish_run(t);
    t->reap_timer = ks_evloop_add_timer(t->owner->loop, 0, 50 * KS_MILLISECOND, on_reap, t);
    if (t->reap_timer == NULL) {
        waitpid(t->pid, NULL, 0);
        t->pid = 0;
        t->running = false;
    }
}

static void run_tool(struct tool *t)
{
    struct iocs *s = t->owner;
    time_t now = time(NULL);
    struct tm lt;
    char stamp[32] = "";
    if (localtime_r(&now, &lt) != NULL)
        strftime(stamp, sizeof(stamp), "%d-%m-%Y, %H:%M:%S", &lt);
    char header[1024];
    snprintf(header, sizeof(header), "==== %s - %s (%s) ====\n\n\n", t->name, s->hostname, stamp);

    ks_debug("[executer] Start() %s", t->argv[0]);
    int p[2];
    if (pipe2(p, O_CLOEXEC | O_NONBLOCK) < 0) {
        ks_error("[executer] error: %s", strerror(errno));
        return;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    pid_t pid;
    int r = posix_spawnp(&pid, t->argv[0], &fa, &attr, t->argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    close(p[1]);
    if (r != 0) {
        ks_error("Executer.Start() exec: \"%s\": %s", t->argv[0], strerror(r));
        close(p[0]);
        return;
    }
    if (setpriority(PRIO_PROCESS, (id_t)pid, (int)t->opts.options.priority) < 0)
        ks_debug("[executer] unable to the change process priority");
    if (ks_evloop_add_fd(s->loop, p[0], EPOLLIN, on_output, t) < 0) {
        close(p[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return;
    }
    t->pid = pid;
    t->out_fd = p[0];
    t->running = true;
    clock_gettime(CLOCK_MONOTONIC, &t->started);
    sb_str(&t->report, header);
}

static void on_schedule(void *ctx)
{
    struct iocs *s = ctx;
    for (size_t i = 0; i < s->ntools; i++) {
        struct tool *t = s->tools[i];
        /* a tool still running from an earlier tick is skipped */
        if (t->running) {
            ks_trace("IOCScanner tick, task already running: %s", t->name);
            continue;
        }
        ks_trace("IOCScanner tick, running task: %s", t->name);
        run_tool(t);
    }
}

void ks_iocscanner_tick(struct ks_task *t)
{
    on_schedule(t->priv);
}

char *ks_ioc_tool_cmdline(const cJSON *json)
{
    struct ks_ioc_tool_opts o;
    char err[256];
    if (ks_schema_decode(&tool_schema, json, &o, err, sizeof(err)) < 0)
        return NULL;
    struct iocs owner = {0};
    struct tool *t = NULL;
    if (has_prefix(o.name, "yara"))
        t = yara_new(&owner, &o);
    else if (has_prefix(o.name, "debsums") || has_prefix(o.name, "dpkg"))
        t = cmd_tool_new(&owner, &o, TOOL_DPKG);
    else if (has_prefix(o.name, "script"))
        t = cmd_tool_new(&owner, &o, TOOL_SCRIPT);
    ks_schema_free(&tool_schema, &o);
    if (t == NULL)
        return NULL;
    struct sbuf b = {0};
    for (size_t i = 0; i < t->argc; i++) {
        if (i > 0)
            sb_str(&b, " ");
        sb_str(&b, t->argv[i]);
    }
    tool_free(t);
    return b.p;
}

/* ---- the task --------------------------------------------------------- */

static void stop_all(struct iocs *s)
{
    for (size_t i = 0; i < s->nscheds; i++)
        ks_sched_free(s->scheds[i]);
    free(s->scheds);
    s->scheds = NULL;
    s->nscheds = 0;
    for (size_t i = 0; i < s->ntools; i++) {
        ks_debug("[IOCScanner] stopping tool %s", s->tools[i]->name);
        tool_free(s->tools[i]);
    }
    free(s->tools);
    s->tools = NULL;
    s->ntools = 0;
}

static int iocs_start(struct ks_task *t, char *err, size_t errlen)
{
    struct iocs *s = t->priv;
    s->task = t;
    s->loop = ks_task_loop(t);
    for (size_t i = 0; i < s->cfg.tools.len; i++) {
        const struct ks_ioc_tool_opts *o = KS_ARRAY_ITEM(s->cfg.tools, struct ks_ioc_tool_opts, i);
        if (!o->enabled)
            continue;
        struct tool *tool = NULL;
        if (has_prefix(o->name, "yara"))
            tool = yara_new(s, o);
        else if (has_prefix(o->name, "debsums") || has_prefix(o->name, "dpkg"))
            tool = cmd_tool_new(s, o, TOOL_DPKG);
        else if (has_prefix(o->name, "script"))
            tool = cmd_tool_new(s, o, TOOL_SCRIPT);
        if (tool == NULL)
            continue;
        struct tool **v = realloc(s->tools, (s->ntools + 1) * sizeof(*v));
        if (v == NULL) {
            tool_free(tool);
            continue;
        }
        s->tools = v;
        s->tools[s->ntools++] = tool;
    }
    if (s->ntools == 0) {
        snprintf(err, errlen, "no tools configured");
        return -1;
    }
    for (size_t i = 0; i < s->cfg.schedule.len; i++) {
        const struct ks_sched_config *c = KS_ARRAY_ITEM(s->cfg.schedule, struct ks_sched_config, i);
        struct ks_sched *sc = ks_sched_new(s->loop, c, on_schedule, s);
        struct ks_sched **v = sc ? realloc(s->scheds, (s->nscheds + 1) * sizeof(*v)) : NULL;
        if (v == NULL || ks_sched_start(sc) < 0) {
            ks_sched_free(sc);
            if (v != NULL)
                s->scheds = v;
            continue;
        }
        s->scheds = v;
        s->scheds[s->nscheds++] = sc;
    }
    ks_debug("[IOCScanner] stopped");
    return 0;
}

static void iocs_free(void *priv)
{
    struct iocs *s = priv;
    if (s == NULL)
        return;
    ks_debug("[IOCScanner] Stop()");
    stop_all(s);
    ks_schema_free(&ks_ioc_config_schema, &s->cfg);
    free(s);
}

static const struct ks_task_ops iocs_ops = {iocs_start, NULL, iocs_free};

struct ks_task *ks_iocscanner_new(const char *name, const cJSON *data, char *err, size_t errlen)
{
    /* taskcfg["interval"].(string) */
    const cJSON *iv = cJSON_GetObjectItemCaseSensitive(data, "interval");
    if (ks_task_assert(iv, "string", err, errlen) != NULL)
        return NULL;
    struct iocs *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    if (gethostname(s->hostname, sizeof(s->hostname) - 1) < 0)
        s->hostname[0] = '\0';
    char cerr[512];
    if (ks_schema_decode(&ks_ioc_config_schema, data, &s->cfg, cerr, sizeof(cerr)) < 0) {
        /* upstream goes on with what json.Unmarshal filled before the error;
         * here the configuration is empty */
        ks_warning("IOCScanner config warning: %s", cerr);
        cJSON *empty = cJSON_CreateObject();
        int r = empty ? ks_schema_decode(&ks_ioc_config_schema, empty, &s->cfg, cerr, sizeof(cerr))
                      : -1;
        cJSON_Delete(empty);
        if (r < 0) {
            free(s);
            snprintf(err, errlen, "out of memory");
            return NULL;
        }
    }
    struct ks_task *t = ks_task_new(name, &iocs_ops, s);
    if (t == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    t->id = IOCS_ID;
    return t;
}
