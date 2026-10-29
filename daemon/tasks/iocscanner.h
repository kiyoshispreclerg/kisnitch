/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The IOC scanner's configuration (upstream's iocscanner/config) and the
 * pieces of its tools that tests check. The task itself is created with
 * ks_iocscanner_new() (disk.h).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the config structs are decoded with ks_ioc_config_schema and
 * own everything reachable from them (ks_schema_free()).
 */
#ifndef KS_DAEMON_TASKS_IOCSCANNER_H
#define KS_DAEMON_TASKS_IOCSCANNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/json_schema.h"

struct ks_ioc_exclusions {
    struct ks_strs dirs, files, tags;
};

struct ks_ioc_report {
    char *type; /* "file" */
    char *path;
    char *format;
    bool sync;
};

/* config.ScanOpts */
struct ks_ioc_scan {
    struct ks_strs dirs, files, rules, tags;
    struct ks_ioc_exclusions exclusions;
    struct ks_array reports; /* of struct ks_ioc_report */
    char *max_running_time;
    int64_t max_size, threads, priority;
    bool scan_procs, recursive, fast_scan, debug;
};

/* config.ToolOpts */
struct ks_ioc_tool_opts {
    struct ks_ioc_scan options;
    struct ks_strs cmd;
    char *name; /* yara*, dpkg*, debsums*, script* */
    char *msg_start, *msg_end, *data_dir;
    int64_t read_buffer, workers;
    bool enabled;
};

struct ks_ioc_notify_status {
    char *type, *message;
};

struct ks_ioc_notify {
    struct ks_ioc_notify_status success, error;
    bool enabled;
};
extern const struct ks_schema ks_ioc_notify_schema;

struct ks_ioc_action {
    char *type, *data;
};

/* config.IOCConfig */
struct ks_ioc_config {
    struct ks_array schedule; /* of struct ks_sched_config */
    struct ks_array tools;    /* of struct ks_ioc_tool_opts */
    struct ks_ioc_notify notify;
    struct ks_array actions;  /* of struct ks_ioc_action */
    char *interval;
};
extern const struct ks_schema ks_ioc_config_schema;

/* The kinds of tool, for ks_ioc_keep_line(). */
enum { KS_IOC_YARA, KS_IOC_DPKG, KS_IOC_SCRIPT };

/* TransformLogline: false if the tool's exclusions drop `line`. */
bool ks_ioc_keep_line(int kind, const struct ks_ioc_scan *o, const char *line);

/* Tests: a scheduler tick (runs the tools that aren't running). */
struct ks_task;
void ks_iocscanner_tick(struct ks_task *t);
/* Tests: the command a tool's configuration (a "tools" entry) builds,
 * arguments separated by spaces; NULL if the tool is invalid. */
struct cJSON;
char *ks_ioc_tool_cmdline(const struct cJSON *tool);

/* fmt.Sprint of a float64 (yara's --timeout=<seconds>). */
void ks_go_ftoa(double v, char *buf, size_t len);

#endif
