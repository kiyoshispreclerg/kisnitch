/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The task manager. Port of upstream daemon/tasks/main.go and base/main.go.
 *
 * Upstream runs each task in a goroutine that writes to its Results and
 * Errors channels, and the UI client forwards them (monitorTaskEvents).
 * Here a task is a timer on the event loop: each iteration runs the task
 * and hands the result, or the error, to the manager's sink.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the manager owns its tasks (ks_taskmgr_add() takes ownership,
 * also on failure) and each task owns its name and its private data. The
 * loop is borrowed and must outlive the manager.
 */
#ifndef KS_DAEMON_TASKS_TASKS_H
#define KS_DAEMON_TASKS_TASKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ks_evloop;
struct ks_timer;
struct ks_task;
struct ks_taskmgr;

/* base: the IDs of the tasks loaded from disk (the UI's are the
 * notification IDs, timestamps). */
#define KS_TASK_ID_PID_MON     9000
#define KS_TASK_ID_NODE_MON    9001
#define KS_TASK_ID_SOCKETS_MON 9002
#define KS_TASK_ID_DOWNLOADER  9003
#define KS_TASK_ID_IOCS        9005

/* What an iteration produced. */
enum ks_task_status {
    KS_TASK_NONE,   /* nothing to send */
    KS_TASK_RESULT, /* *data is a result (malloc'd, the manager frees it) */
    KS_TASK_ERROR,  /* err is filled; the task keeps running */
    KS_TASK_EXIT,   /* err is filled; the task stops iterating (it stays added) */
};

struct ks_task_ops {
    /* Start(): 0, or -1 with `err` filled. A task that fails to start stays
     * in the manager without running, as upstream. NULL: nothing to do. */
    int (*start)(struct ks_task *t, char *err, size_t errlen);
    /* One iteration. */
    enum ks_task_status (*run)(struct ks_task *t, char **data, char *err, size_t errlen);
    void (*free)(void *priv);
};

struct ks_task {
    char *name;      /* the instance's name, e.g. "pid-monitor-1234" */
    uint64_t id;     /* SetID: the notification ID, or KS_TASK_ID_* */
    bool temporary;  /* IsTemporary: stopped when the UI disconnects */
    int64_t interval_ns; /* set by start(); <= 0: run once */
    const struct ks_task_ops *ops;
    void *priv;

    /* managed */
    struct ks_taskmgr *mgr;
    struct ks_timer *timer;
    bool running;
};

/* Results and errors. `data` is NULL with an error, `err` NULL with a
 * result. */
typedef void (*ks_task_sink)(void *ctx, const struct ks_task *t, const char *data,
                             const char *err);

/* A new task (not added). Takes `priv` (freed with ops->free, also on
 * failure). NULL on OOM. */
struct ks_task *ks_task_new(const char *name, const struct ks_task_ops *ops, void *priv);
void ks_task_free(struct ks_task *t);

/* The interval of a task: "" is "5s"; time.ParseDuration's errors, and a
 * non-positive interval (time.NewTicker panics with it) is an error too. */
int ks_task_parse_interval(const char *s, int64_t *ns, char *err, size_t errlen);

struct ks_taskmgr *ks_taskmgr_new(struct ks_evloop *loop, ks_task_sink sink, void *ctx);
/* Stop(): stops and frees every task. */
void ks_taskmgr_free(struct ks_taskmgr *m);

/* AddTask: "task with name %s already exists" if the name is taken.
 * Otherwise the task is started and its first iteration is scheduled
 * right away. Returns 0 or -1 with `err` filled. */
int ks_taskmgr_add(struct ks_taskmgr *m, struct ks_task *t, char *err, size_t errlen);
/* RemoveTask: "task with name %s does not exist". */
int ks_taskmgr_remove(struct ks_taskmgr *m, const char *name, char *err, size_t errlen);
struct ks_task *ks_taskmgr_get(struct ks_taskmgr *m, const char *name);
size_t ks_taskmgr_count(const struct ks_taskmgr *m);
/* StopTempTasks / StopAll */
void ks_taskmgr_stop_temp(struct ks_taskmgr *m);
void ks_taskmgr_stop_all(struct ks_taskmgr *m);

/* Go's error texts for the type assertions on a TaskNotification's data,
 * conf["x"].(string): "interface conversion: interface {} is nil, not
 * string". Returns NULL when `v` has the type (`want` is "string" or
 * "float64"); else fills `err`. */
struct cJSON;
const char *ks_task_assert(const struct cJSON *v, const char *want, char *err, size_t errlen);

/* strconv.Atoi, with its error text. */
int ks_task_atoi(const char *s, long long *out, char *err, size_t errlen);

#endif
