/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The process details dialog's data: what the daemon's "pid-monitor" task
 * reports (the JSON of daemon/procmon.Process) and how upstream's
 * ui/opensnitch/dialogs/processdetails.py shows it (_load_data,
 * _load_descriptors, _load_env_vars, _load_iostats, _load_mem_data).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_procinfo owns the parsed JSON; the strings the
 * functions return are malloc'd (g_free) and owned by the caller.
 */
#ifndef KS_UI_PROCINFO_H
#define KS_UI_PROCINFO_H

#include <stdbool.h>

#include "cJSON.h"

struct ks_procinfo {
    cJSON *j;
};

/* False if `json` isn't a process. */
bool ks_procinfo_parse(struct ks_procinfo *p, const char *json);
void ks_procinfo_free(struct ks_procinfo *p);

/* The header labels (Pango markup; `text` fields are escaped). */
char *ks_procinfo_path(const struct ks_procinfo *p);     /* "(path)", NULL if it is in Args */
char *ks_procinfo_args(const struct ks_procinfo *p);     /* " ".join(Args) */
char *ks_procinfo_cwd(const struct ks_procinfo *p);      /* "<b>CWD: </b>..." */
char *ks_procinfo_parents(const struct ks_procinfo *p);  /* "<b>Parent(s): </b>a ➡ b" */
char *ks_procinfo_checksums(const struct ks_procinfo *p);
char *ks_procinfo_mem(const struct ks_procinfo *p);      /* VIRT, RSS, ... */

/* The tabs (plain text, except I/O: markup). NULL if the field is missing. */
char *ks_procinfo_status(const struct ks_procinfo *p);
char *ks_procinfo_maps(const struct ks_procinfo *p);
char *ks_procinfo_stack(const struct ks_procinfo *p);
char *ks_procinfo_iostats(const struct ks_procinfo *p);
char *ks_procinfo_env(const struct ks_procinfo *p);
/* The open files; the two checkboxes of the tab. */
char *ks_procinfo_descriptors(const struct ks_procinfo *p, bool filter_files, bool filter_sockets);

#endif
