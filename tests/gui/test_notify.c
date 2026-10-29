/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Desktop notifications (ui/notify.c, built with NOTIFY=1) against
 * tests/integration/fake_notifyd.py in a private D-Bus session: run by
 * tests/integration/notify.sh. argv[1] is the daemon's log.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "tests/harness.h"
#include "ui/notify.h"
#include "ui/service.h"

static const char *logfile;
static int opened;

static void on_open(void *ud)
{
    (void)ud;
    opened++;
}

static void spin_ms(int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        while (g_main_context_iteration(NULL, FALSE))
            ;
        g_usleep(10000);
    }
}

static char *read_log(void)
{
    char *text = NULL;
    g_file_get_contents(logfile, &text, NULL, NULL);
    return text != NULL ? text : g_strdup("");
}

TEST(notifications)
{
    ks_notify_init();
    CHECK(ks_notify_available());
    CHECK(ks_notify_supports_actions());

    /* an alert with HIGH priority: critical, with the "Open" action */
    CHECK(ks_notify_show("Warning", "something <b>happened</b>", KS_URGENCY_CRITICAL, on_open,
                         NULL));
    for (int i = 0; i < 300 && opened == 0; i++)
        spin_ms(10);
    CHECK_INT_EQ(opened, 1);
    char *log = read_log();
    CHECK_STR_HAS(log, "\"app\": \"kisnitch\"");
    CHECK_STR_HAS(log, "\"summary\": \"Warning\"");
    CHECK_STR_HAS(log, "\"body\": \"something <b>happened</b>\"");
    CHECK_STR_HAS(log, "\"actions\": [\"action-open\", \"Open\"]");
    CHECK_STR_HAS(log, "\"urgency\": 2");
    CHECK_STR_HAS(log, "\"category\": \"network\"");
    g_free(log);

    /* no callback: no action (the preferences' test) */
    CHECK(ks_notify_show("title", "body", KS_URGENCY_LOW, NULL, NULL));
    spin_ms(300);
    log = read_log();
    CHECK_STR_HAS(log, "\"summary\": \"title\", \"body\": \"body\", \"actions\": [], "
                       "\"timeout\": -1, \"urgency\": 0");
    g_free(log);
    CHECK_INT_EQ(opened, 1);
    ks_notify_uninit();
    CHECK(!ks_notify_available());
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fake notification daemon log>\n", argv[0]);
        return 2;
    }
    logfile = argv[1];
    RUN(notifications);
    return harness_report();
}
