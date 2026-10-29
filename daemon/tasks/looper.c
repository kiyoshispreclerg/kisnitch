/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/looptask/main.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/tasks/disk.h"

/* looptask's TaskBase.ID */
#define LOOPER_ID 9999

static int looper_start(struct ks_task *t, char *err, size_t errlen)
{
    char **interval = t->priv;
    if ((*interval)[0] == '\0') {
        free(*interval);
        if ((*interval = strdup("5s")) == NULL) {
            snprintf(err, errlen, "out of memory");
            return -1;
        }
    }
    return ks_task_parse_interval(*interval, &t->interval_ns, err, errlen);
}

static enum ks_task_status looper_run(struct ks_task *t, char **data, char *err, size_t errlen)
{
    char **interval = t->priv;
    ks_info("[tasks.Looper] loooping %s", *interval);
    if ((*data = strdup(*interval)) == NULL) {
        snprintf(err, errlen, "out of memory");
        return KS_TASK_ERROR;
    }
    return KS_TASK_RESULT;
}

static void looper_free(void *priv)
{
    char **interval = priv;
    if (interval == NULL)
        return;
    ks_debug("[task.looper] Stop()");
    free(*interval);
    free(interval);
}

static const struct ks_task_ops looper_ops = {looper_start, looper_run, looper_free};

struct ks_task *ks_looper_new(const char *name, const char *interval)
{
    char **iv = malloc(sizeof(*iv));
    if (iv == NULL)
        return NULL;
    if ((*iv = strdup(interval != NULL ? interval : "")) == NULL) {
        free(iv);
        return NULL;
    }
    struct ks_task *t = ks_task_new(name, &looper_ops, iv);
    if (t != NULL) {
        t->id = LOOPER_ID;
        t->delay_first = true; /* the first result comes with the first tick */
    }
    return t;
}
