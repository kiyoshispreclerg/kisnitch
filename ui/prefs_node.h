/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The Nodes tab of the preferences dialog, without widgets: how a node's
 * configuration (the JSON the daemon sent in its ClientConfig) fills the
 * form (PreferencesDialog._load_node_settings, _load_node_auth_settings)
 * and how the form becomes the configuration that goes back in a
 * CHANGE_CONFIG notification (_build_node_config, _save_node_auth_config),
 * defaults and quirks included, in upstream
 * ui/opensnitch/dialogs/preferences.py. The GTK dialog (ui/prefs.c) only
 * fills and reads a struct ks_nform.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_nform owns its strings (ks_nform_free); the functions
 * return malloc'd strings.
 */
#ifndef KS_UI_PREFS_NODE_H
#define KS_UI_PREFS_NODE_H

#include <stdbool.h>
#include <stddef.h>

#define KS_DEFAULT_RULES_PATH "/etc/opensnitchd/rules"

/* the combo boxes' items, in the order of the .ui */
extern const char *const ks_node_actions[3];        /* deny, allow, reject */
extern const char *const ks_node_monitors[3];       /* proc, ebpf, audit */
extern const char *const ks_node_auth_types[3];     /* simple, tls-simple, tls-mutual */
extern const char *const ks_node_verify_types[5];   /* no-client-cert ... req-and-verify-cert */

struct ks_nform {
    char *version, *name;        /* the labels */
    int action;                  /* index in ks_node_actions; -1: none */
    int monitor;                 /* index in ks_node_monitors; -1: none */
    bool intercept_unknown;
    int log_level;               /* DEBUG .. FATAL; -1 none */
    bool log_utc, log_micro;
    bool server_enabled;         /* comboNodeAddress and comboNodeLogFile enabled */
    char *address, *log_file;
    int auth_type;               /* index in ks_node_auth_types; -1 none */
    bool ca_enabled;             /* the CA file: for mutual TLS */
    bool certs_enabled;          /* the server cert, client cert and key, skip verify, verify type */
    char *ca_cert, *server_cert, *client_cert, *client_key;
    bool skip_verify;
    int verify_type;             /* index in ks_node_verify_types */
    bool checksums;
    char *rules_path;
    bool flush_conns;
    int gc;
    char *fw_interval;           /* "15" for "15s" */
    bool block_on_fail;          /* checkNodeBypassQueue: not QueueBypass */
    char *max_events, *max_stats;
    bool needs_update;           /* _node_needs_update */
};

void ks_nform_init(struct ks_nform *f);
void ks_nform_free(struct ks_nform *f);
void ks_nform_set(char **dst, const char *text);
/* _reset_node_settings() */
void ks_nform_reset(struct ks_nform *f);

/* _load_node_settings(): fills the form from `config` (the node's JSON). On
 * success returns true and the normalized configuration (json.dumps with
 * indent=4) in *normalized, which upstream stores back as the node's. On an
 * error returns false, `err` has what the status label would say, and the
 * form is filled as far as upstream got. *normalized is NULL then. */
bool ks_prefs_load_node(struct ks_nform *f, const char *version, const char *name,
                        unsigned log_level, const char *config, char **normalized, char *err,
                        size_t errlen);

/* _build_node_config(): the configuration to send, from the node's current
 * `config` and the form. false and `err`: the message of the (None, error)
 * upstream returns. The form may be changed too (defaults the code writes
 * back into widgets). */
bool ks_prefs_build_node(struct ks_nform *f, const char *addr, const char *config, char **out,
                         char *err, size_t errlen);

/* PreferencesDialog.AUTH_*: the index of a combo's data, -1 if not there */
int ks_node_auth_index(const char *type);
int ks_node_verify_index(const char *type);

#endif
