/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The logic of the rules editor, without widgets: the form's values and how
 * they become a rule (RulesEditorDialog._save_rule) and back
 * (_load_rule, _load_rule_operator) in upstream
 * ui/opensnitch/dialogs/ruleseditor.py, quirks included. The GTK dialog
 * (ui/rules_editor.c) only fills and reads a struct ks_rform.
 *
 * Regular expressions are checked with PCRE2 (Python's `re` module is the
 * closest widely available engine; the daemon matches them with Go's RE2).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_rform owns its strings (ks_rform_free); the rule
 * ks_rform_to_rule() builds lives in the arena the caller gives.
 */
#ifndef KS_UI_RULEGEN_H
#define KS_UI_RULEGEN_H

#include <stdbool.h>
#include <stddef.h>

#include "common/arena.h"
#include "common/pb/ui.pb-c.h"
#include "ui/prompt_rule.h"

/* RulesEditorDialog.LAN_RANGES, MULTICAST_RANGE and their labels */
extern const char *const KS_RULE_LAN_RANGES;
extern const char *const KS_RULE_MULTICAST_RANGE;
#define KS_RULE_LAN_LABEL "LAN"
#define KS_RULE_MULTICAST_LABEL "MULTICAST"
#define KS_RULE_INVALID_NAME_CHARS "/"

enum { KS_RACTION_DENY, KS_RACTION_ALLOW, KS_RACTION_REJECT };

struct ks_rcheck {
    bool on;     /* the checkbox */
    char *text;  /* the line or combo's text */
};

struct ks_rform {
    char *name, *desc;
    bool enabled, precedence, nolog, sensitive;
    int action;   /* KS_RACTION_* */
    int duration; /* the combo's index: once, 30s, 5m, 15m, 30m, 1h, 12h, until reboot, always */
    struct ks_rcheck proto, proc, cmdline, iface, srcport, dstport, srcip, dstip, dsthost, uid,
        pid, lists, lists_regexp, lists_ips, lists_nets, md5;
    bool proc_regexp, cmdline_regexp;
    /* the node: lists must name a directory only for a local node that
     * isn't "apply to all" */
    bool node_is_local, apply_all;
};

void ks_rform_init(struct ks_rform *f);
void ks_rform_free(struct ks_rform *f);
/* _reset_state() */
void ks_rform_reset(struct ks_rform *f);
void ks_rform_set(struct ks_rcheck *c, const char *text);
void ks_rform_set_name(struct ks_rform *f, const char *name);
void ks_rform_set_desc(struct ks_rform *f, const char *desc);

/* _save_rule(): the rule of the form, in `a`. On failure false and the
 * message upstream would show in `err`. `aliases` are the network aliases. */
bool ks_rform_to_rule(const struct ks_rform *f, const struct ks_py_aliases *aliases,
                      struct ks_arena *a, Protocol__Rule **out, char *err, size_t errlen);

/* _load_rule() without the nodes: the form of a rule. `err` gets the last
 * message _set_status_error() would have shown ("" if none). */
void ks_rform_load_rule(struct ks_rform *f, const Protocol__Rule *r, char *err, size_t errlen);

/* set_fields_from_connection(): only the texts; no check is toggled.
 * Strings as the connections table has them. */
void ks_rform_from_connection(struct ks_rform *f, const char *protocol, const char *src_ip,
                              const char *src_port, const char *dst_ip, const char *dst_host,
                              const char *dst_port, const char *uid, const char *pid,
                              const char *process, const char *cmdline);

/* The duration combo <-> the rule's duration */
const char *ks_rform_duration_name(int idx);
int ks_rform_duration_index(const char *duration);

/* The helpers, for the tests */
bool ks_rule_is_regex(const char *text);
bool ks_rule_valid_regex(const char *re, char *err, size_t errlen);
/* _comma_to_regexp(): true and the regexp, or false and the message */
bool ks_rule_comma_to_regexp(const char *text, bool ints, char *out, size_t outlen);
/* _regexp_to_comma(): 1 and the list, 0 if it doesn't look like ^(a|b)$, -1 and the message */
int ks_rule_regexp_to_comma(const char *text, bool ints, char *out, size_t outlen);

#endif
