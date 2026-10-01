/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A connection as seen by the rules engine: the fields of upstream's
 * conman.Connection, procmon.Process and netstat.Entry that operators read.
 * Phases 2 (process monitor) and 3 (packet parsing) fill these in from the
 * system; for now tests build them by hand.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: these structs only borrow. Whoever builds a ks_conn keeps the
 * strings, the process and its parents alive while rules are evaluated.
 */
#ifndef KS_DAEMON_CONN_H
#define KS_DAEMON_CONN_H

#include <stddef.h>

#include "common/netaddr.h"

struct ks_env_var {
    const char *name;
    const char *value;
};

/* procmon.Process (the fields rules use). */
struct ks_process {
    int pid;                        /* ID */
    const char *path;               /* Path */
    const char *const *args;        /* Args */
    size_t nargs;
    const struct ks_env_var *env;   /* Env */
    size_t nenv;
    /* Checksums["process.hash.md5"], Checksums["process.hash.sha1"]:
     * NULL when not computed (absent from the Go map). */
    const char *checksum_md5;
    const char *checksum_sha1;
    const struct ks_process *parent; /* Parent */
};

/* conman.Connection. */
struct ks_conn {
    const char *protocol;  /* Protocol */
    const char *dst_host;  /* DstHost ("" when unknown) */
    struct ks_ip src_ip;   /* SrcIP */
    struct ks_ip dst_ip;   /* DstIP */
    unsigned src_port;     /* SrcPort */
    unsigned dst_port;     /* DstPort */
    int iface_in;          /* Pkt.IfaceInIdx */
    int iface_out;         /* Pkt.IfaceOutIdx */
    int uid;               /* Entry.UserId */
    const struct ks_process *process;
};

#endif
