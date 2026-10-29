/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The tasks loaded from disk: the loader of the tasks list (upstream's
 * daemon/tasks/load.go and config/), and the tasks it knows: looper
 * (looptask), downloader and IOC-scanner (iocscanner).
 *
 * The tasks list is TasksOptions.ConfigPath (default
 * /etc/opensnitchd/tasks/tasks.json):
 *   {"tasks": [{"name": "downloader", "configfile": "/etc/...json", "enabled": true}]}
 * and each task's file is a TaskData:
 *   {"parent": "", "name": "<instance>", "data": {...}}
 * Both are watched; a change reloads the list, or restarts that task.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the loader owns its copy of the list, its inotify descriptor and
 * its timers; the manager and the loop are borrowed. The constructors
 * return a task owned by the caller until ks_taskmgr_add().
 */
#ifndef KS_DAEMON_TASKS_DISK_H
#define KS_DAEMON_TASKS_DISK_H

#include <stdbool.h>
#include <stddef.h>

#include "daemon/tasks/tasks.h"

#define KS_TASKS_DEFAULT_FILE "/etc/opensnitchd/tasks/tasks.json"

/* The Name of each package, which the list's "name" must be. */
#define KS_TASK_LOOPER     "looper"
#define KS_TASK_DOWNLOADER "downloader"
#define KS_TASK_IOCSCANNER "IOC-scanner"

struct cJSON;
struct ks_evloop;
struct ks_taskloader;

struct ks_taskloader *ks_taskloader_new(struct ks_taskmgr *m, struct ks_evloop *loop);
void ks_taskloader_free(struct ks_taskloader *l);

/* LoadTaskFile: reads the list (`cfgfile` "" is the default), starts its
 * enabled tasks that aren't running, stops the disabled ones, and watches
 * the files. Errors are logged, as upstream (which returns nil). */
void ks_taskloader_load(struct ks_taskloader *l, const char *cfgfile);
/* The list file in use (Loader.CfgFile), "" before a successful load. */
const char *ks_taskloader_file(const struct ks_taskloader *l);
/* Tests: what an inotify event would do after its one second wait. */
void ks_taskloader_file_changed(struct ks_taskloader *l, const char *file);

/* looptask.New: every `interval`, a result with the interval. */
struct ks_task *ks_looper_new(const char *name, const char *interval);

/* downloader.New: the "data" of its TaskData. Without CURL=1 the task
 * fails to start (logged). */
struct ks_task *ks_downloader_new(const char *name, const struct cJSON *data);
/* Whether this build can download (CURL=1). */
bool ks_downloader_available(void);

/* iocscanner.New: `data` must have an "interval" string (upstream panics
 * otherwise; NULL with `err` filled here). */
struct ks_task *ks_iocscanner_new(const char *name, const struct cJSON *data, char *err,
                                  size_t errlen);

#endif
