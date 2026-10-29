/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The "audit" process monitor method: auditd events read from audisp's
 * af_unix plugin socket (Audit.AudispSocketPath, usually
 * /var/run/audispd_events), keeping the processes that opened sockets so
 * the owner of a connection is looked up among them first. Port of
 * upstream daemon/procmon/audit (client.go, parse.go, config.go).
 *
 * Requisites, as upstream's: auditd and audispd-plugins, with the af_unix
 * plugin enabled; the daemon adds its rules with auditctl ("-k
 * opensnitch") when it starts and deletes them when it stops.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: module state (upstream's package globals); the events are owned
 * by the module and valid until the next parse or cleanup.
 */
#ifndef KS_DAEMON_PROCMON_AUDIT_H
#define KS_DAEMON_PROCMON_AUDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ks_evloop;

#define KS_AUDIT_MAX_EVENT_AGE_MIN 10

/* audit.Event: the fields upstream fills */
struct ks_audit_event {
    char timestamp[32], serial[32];
    char proc_name[256], proc_path[4096], proc_dir[4096];
    char tty[32], success[8], dev[32], mode[16], event_type[32], net_family[16];
    int pid, ppid, uid, gid, ouid, ogid, inode, syscall, exit, dst_port;
    int64_t last_seen; /* CLOCK_REALTIME ns */
};

/* Start(): adds the auditctl rules and connects to the socket. 0, or -1
 * with `err` (the rules are deleted again). */
int ks_audit_start(struct ks_evloop *loop, const char *socket_path, char *err, size_t errlen);
/* Stop(): closes the socket, stops the cleaner, deletes the rules. The
 * events stay, as upstream. */
void ks_audit_stop(void);
bool ks_audit_running(void);

/* GetEvents(): newest first. */
size_t ks_audit_count(void);
const struct ks_audit_event *ks_audit_event_at(size_t i);
/* GetEventByPid */
const struct ks_audit_event *ks_audit_event_by_pid(int pid);

/* parseEvent(): one line from the socket. */
void ks_audit_parse_line(const char *line);
/* cleanOldEvents() */
void ks_audit_clean_old_events(void);

/* Tests: drops the events and the parser state; the auditctl to run
 * (NULL: "auditctl" from PATH). */
void ks_audit_reset(void);
void ks_audit_set_auditctl(const char *path);

#endif
