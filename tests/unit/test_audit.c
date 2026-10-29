/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The audit process monitor method (daemon/procmon/audit.c): the parser
 * of auditd records, the reader of the af_unix socket (a fake audisp
 * here), the auditctl rules (a fake auditctl), and the method switch.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _DEFAULT_SOURCE /* mkdtemp */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/procmon/audit.h"
#include "daemon/procmon/procmon.h"
#include "tests/harness.h"

/* a connect() to 1.1.1.1:443 by curl, as the af_unix plugin sends it */
#define SYSCALL_LINE                                                                        \
    "type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=42 success=no "    \
    "exit=-115 a0=5 a1=7ffd a2=10 a3=0 items=0 ppid=1000 pid=%d auid=1000 uid=1000 gid=1000 " \
    "euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 "          \
    "comm=\"curl\" exe=\"/usr/bin/curl\" key=\"opensnitch\""
#define SOCKADDR_LINE "type=SOCKADDR msg=audit(1700000000.123:4567): saddr=020001BB01010101"
#define CWD_LINE "type=CWD msg=audit(1700000000.123:4567): cwd=2F686F6D652F75207370616365"
#define EOE_LINE "type=EOE msg=audit(1700000000.123:4567): "

/* the SYSCALL line for `pid`, or another record (pid 0) */
static void line(const char *rec, int pid)
{
    char buf[1024];
    if (strcmp(rec, SYSCALL_LINE) == 0)
        snprintf(buf, sizeof(buf), SYSCALL_LINE, pid);
    else
        snprintf(buf, sizeof(buf), "%s", rec);
    ks_audit_parse_line(buf);
}

TEST(parser)
{
    ks_audit_reset();
    /* not ours, and no event being parsed: ignored */
    ks_audit_parse_line("type=SYSCALL msg=audit(1:2): syscall=42 pid=7 key=(null)");
    CHECK_INT_EQ(ks_audit_count(), 0);

    line(SYSCALL_LINE, 4242);
    line(SOCKADDR_LINE, 0);
    line(CWD_LINE, 0);
    line(EOE_LINE, 0);
    CHECK_INT_EQ(ks_audit_count(), 1);
    const struct ks_audit_event *ev = ks_audit_event_by_pid(4242);
    CHECK(ev != NULL);
    CHECK_INT_EQ(ev->ppid, 1000);
    CHECK_INT_EQ(ev->uid, 1000);
    CHECK_INT_EQ(ev->syscall, 42);
    CHECK_INT_EQ(ev->exit, -115);
    CHECK_STR_EQ(ev->proc_name, "curl");
    CHECK_STR_EQ(ev->proc_path, "/usr/bin/curl");
    CHECK_STR_EQ(ev->tty, "pts1");
    CHECK_STR_EQ(ev->success, "no");
    CHECK_STR_EQ(ev->timestamp, "1700000000.123");
    CHECK_STR_EQ(ev->serial, "4567");
    /* hex-encoded values (audit encodes the ones with spaces) */
    CHECK_STR_EQ(ev->proc_dir, "/home/u space");
    CHECK_STR_EQ(ev->event_type, "CWD"); /* the last record's type */

    /* the same PID and syscall again: refreshed, not added */
    line(SYSCALL_LINE, 4242);
    line(EOE_LINE, 0);
    CHECK_INT_EQ(ks_audit_count(), 1);
    /* another PID goes on top */
    line(SYSCALL_LINE, 4343);
    CHECK_INT_EQ(ks_audit_count(), 2);
    CHECK_INT_EQ(ks_audit_event_at(0)->pid, 4343);
    line(EOE_LINE, 0);

    /* a local (unix) socket is dropped, with its records */
    ks_audit_parse_line("type=SYSCALL msg=audit(1:3): syscall=41 pid=5555 fam=local "
                        "key=\"opensnitch\"");
    line(CWD_LINE, 0);
    line(EOE_LINE, 0);
    CHECK(ks_audit_event_by_pid(5555) == NULL);

    /* a value with a space, unencoded: cut there, quotes trimmed */
    ks_audit_parse_line("type=SYSCALL msg=audit(1:4): syscall=41 pid=6666 "
                        "exe=\"/opt/my app/bin\" key=\"opensnitch\"");
    CHECK_STR_EQ(ks_audit_event_by_pid(6666)->proc_path, "/opt/my");
    line(EOE_LINE, 0);

    /* cleanOldEvents: processes that are gone */
    CHECK_INT_EQ(ks_audit_count(), 3);
    ks_audit_clean_old_events();
    CHECK_INT_EQ(ks_audit_count(), 0);
    line(SYSCALL_LINE, (int)getpid());
    line(EOE_LINE, 0);
    ks_audit_clean_old_events();
    CHECK_INT_EQ(ks_audit_count(), 1);
    ks_audit_reset();
}

/* ---- the reader, with a fake audisp socket and auditctl --------------- */

static char dir[64], sock_path[96], ctl_log[128];

static int64_t fake_now;
static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

static int listen_unix(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sock_path);
    unlink(sock_path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, 2) < 0)
        return -1;
    return fd;
}

static void spin(struct ks_evloop *loop)
{
    for (int i = 0; i < 20; i++)
        ks_evloop_run_once(loop, 10);
}

static char *read_all(const char *path)
{
    static char buf[4096];
    buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
    }
    return buf;
}

TEST(reader_and_rules)
{
    snprintf(dir, sizeof(dir), "/tmp/ks-audit-XXXXXX");
    CHECK(mkdtemp(dir) != NULL);
    snprintf(sock_path, sizeof(sock_path), "%.40s/audispd_events", dir);
    snprintf(ctl_log, sizeof(ctl_log), "%.40s/auditctl.log", dir);
    char ctl[128];
    snprintf(ctl, sizeof(ctl), "%.40s/auditctl", dir);
    FILE *f = fopen(ctl, "w");
    CHECK(f != NULL);
    fprintf(f, "#!/bin/sh\necho \"$@\" >> '%s'\n", ctl_log);
    fclose(f);
    chmod(ctl, 0755);
    ks_audit_set_auditctl(ctl);
    ks_audit_reset();

    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = KS_SECOND;
    int lfd = listen_unix();
    CHECK(lfd >= 0);

    /* the method switch: audit starts, with its rules */
    char err[256];
    CHECK_INT_EQ(ks_procmon_reconfigure(loop, "audit", sock_path, err, sizeof(err)),
                 KS_MONITOR_NO_ERROR);
    CHECK_STR_EQ(ks_procmon_get_method(), "audit");
    CHECK(ks_audit_running());
    char want[512];
    snprintf(want, sizeof(want),
             "-A exit,always -F arch=b64 -F ppid!=%d -F pid!=%d -S socket,connect -k opensnitch\n"
             "-A exit,always -F arch=b32 -F ppid!=%d -F pid!=%d -S socketcall -F a0=1 -k "
             "opensnitch\n",
             (int)getpid(), (int)getpid(), (int)getpid(), (int)getpid());
    CHECK_STR_EQ(read_all(ctl_log), want);

    /* events through the socket, in pieces */
    int c = accept(lfd, NULL, NULL);
    CHECK(c >= 0);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), SYSCALL_LINE "\n" SOCKADDR_LINE "\n", 7777);
    CHECK(write(c, buf, 30) == 30);
    spin(loop);
    CHECK_INT_EQ(ks_audit_count(), 0); /* half a line */
    CHECK(write(c, buf + 30, (size_t)n - 30) == n - 30);
    CHECK(write(c, EOE_LINE "\n", sizeof(EOE_LINE)) == (ssize_t)sizeof(EOE_LINE));
    spin(loop);
    CHECK(ks_audit_event_by_pid(7777) != NULL);

    /* auditd stops: the rules go, and every 30s it reconnects */
    close(c);
    spin(loop);
    CHECK_STR_HAS(read_all(ctl_log), "-D -k opensnitch\n-D -k opensnitch\n");
    fake_now += 30 * KS_SECOND;
    ks_evloop_fire_due(loop);
    c = accept(lfd, NULL, NULL);
    CHECK(c >= 0);
    n = snprintf(buf, sizeof(buf), SYSCALL_LINE "\n" EOE_LINE "\n", 8888);
    CHECK(write(c, buf, (size_t)n) == n);
    spin(loop);
    CHECK(ks_audit_event_by_pid(8888) != NULL);

    /* back to proc: audit stops */
    CHECK_INT_EQ(ks_procmon_reconfigure(loop, "proc", "", err, sizeof(err)), KS_MONITOR_NO_ERROR);
    CHECK(!ks_audit_running());
    CHECK_STR_EQ(ks_procmon_get_method(), "proc");

    /* no audisp socket: an error of the audit kind, and proc stays */
    unlink(sock_path);
    CHECK_INT_EQ(ks_procmon_reconfigure(loop, "audit", sock_path, err, sizeof(err)),
                 KS_MONITOR_AUDITD_ERR);
    CHECK_STR_HAS(err, "dial unix");
    CHECK_STR_EQ(ks_procmon_get_method(), "proc");
    CHECK(!ks_audit_running());

    close(c);
    close(lfd);
    ks_procmon_end();
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
    ks_audit_reset();
    ks_audit_set_auditctl(NULL);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(parser);
    RUN(reader_and_rules);
    return harness_report();
}
