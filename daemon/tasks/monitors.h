/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The tasks the UI starts: pid-monitor, node-monitor and sockets-monitor.
 * Ports of upstream daemon/tasks/pidmonitor, nodemonitor and
 * socketsmonitor. Each iteration's result is the JSON upstream sends:
 * json.Marshal of procmon.Process, of syscall.Sysinfo_t and of
 * socketsmonitor.SocketsTable.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the constructors return a task owned by the caller until it's
 * handed to ks_taskmgr_add().
 */
#ifndef KS_DAEMON_TASKS_MONITORS_H
#define KS_DAEMON_TASKS_MONITORS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "daemon/tasks/tasks.h"

#define KS_TASK_PID_MONITOR     "pid-monitor"
#define KS_TASK_NODE_MONITOR    "node-monitor"
#define KS_TASK_SOCKETS_MONITOR "sockets-monitor"

/* pidmonitor.New: named "pid-monitor-<pid>". The process comes from the
 * events cache (a copy) or from /proc when the task starts. */
struct ks_task *ks_pidmon_new(int pid, const char *interval, bool temporary);

/* nodemonitor.New: named "node-monitor-<node>". */
struct ks_task *ks_nodemon_new(const char *node, const char *interval, bool temporary);
/* json.Marshal(syscall.Sysinfo_t) of the running system. NULL on error
 * (errno set). */
char *ks_nodemon_sysinfo_json(void);

/* socketsmonitor's monConfig. 0 is "any" (AnySocket). */
struct ks_sockmon_config {
    char interval[64];
    uint8_t state, proto, family;
};
/* initConfig: the "data" object of the notification. Returns 0, or -1 with
 * `err` filled with upstream's message (or the panic it would hit). */
int ks_sockmon_config_parse(const struct cJSON *data, struct ks_sockmon_config *cfg,
                            char *err, size_t errlen);
/* socketsmonitor.New: named "sockets-monitor". */
struct ks_task *ks_sockmon_new(const struct ks_sockmon_config *cfg, bool temporary);
/* One dumpSockets() as JSON. NULL on OOM. */
char *ks_sockmon_dump_json(const struct ks_sockmon_config *cfg);

#endif
