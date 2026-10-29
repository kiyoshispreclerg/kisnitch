/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall seen from the UI, without widgets. Port of upstream
 * ui/opensnitch/firewall/ (__init__.py, rules.py, chains.py, exprs.py,
 * enums.py, profiles.py), utils.NetworkServices, and the logic of the
 * firewall rule dialog (dialogs/firewall_rule.py) that doesn't touch
 * widgets: the statements it offers, the rule a form makes, the form a
 * rule makes, and the title of each statement.
 *
 * A node's firewall (upstream's node['firewall']) is a struct ks_sysfw
 * (common/sysfw.h); "flat" rules (Rules.new_flat: a chain holding just
 * one rule) are struct ks_fw_chain with one rule.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: functions taking a `struct ks_sysfw *` change it in place and
 * copy what they keep from their arguments. Strings returned through
 * `char **` and the columns of ks_fwr_to_array() are malloc'd (caller
 * frees). struct ks_fw_services owns its lists. struct ks_fwf_form owns
 * nothing but its fixed buffers.
 */
#ifndef KS_UI_FWRULES_H
#define KS_UI_FWRULES_H

#include <stdbool.h>
#include <stddef.h>

#include "common/sysfw.h"

/* ---- enums.py, exprs.py ---------------------------------------------- */

/* Verdicts.values(): "" first */
extern const char *const ks_fw_verdicts[];
#define KS_FW_NVERDICTS 11
/* Operator.values() */
extern const char *const ks_fw_operators[];
#define KS_FW_NOPERATORS 6
/* PortProtocols.values() */
extern const char *const ks_fw_port_protocols[];
#define KS_FW_NPORT_PROTOCOLS 6
/* Protocols.values() */
extern const char *const ks_fw_protocols[];
#define KS_FW_NPROTOCOLS 18
/* Family.values() */
extern const char *const ks_fw_families[];
#define KS_FW_NFAMILIES 3
/* ExprMeta.values() */
extern const char *const ks_fw_expr_meta[];
#define KS_FW_NEXPR_META 7
/* ExprICMP.values() */
extern const char *const ks_fw_icmp_types[];
#define KS_FW_NICMP_TYPES 18
/* ExprLogLevels.values() */
extern const char *const ks_fw_log_levels[];
#define KS_FW_NLOG_LEVELS 9
/* RateUnits.values(), TimeUnits.values() */
extern const char *const ks_fw_rate_units[];
#define KS_FW_NRATE_UNITS 4
extern const char *const ks_fw_time_units[];
#define KS_FW_NTIME_UNITS 4

/* Index of `v` in a NULL-terminated or `n`-long list, -1 if absent. */
int ks_fw_index_of(const char *const *list, size_t n, const char *v);

/* ---- rules.py, chains.py, __init__.py ----------------------------------- */

/* The rule with `uuid` (and its chain), or NULL. */
struct ks_fw_rule *ks_fwr_find(struct ks_sysfw *fw, const char *uuid, struct ks_fw_chain **chain);
/* get_rule_by_uuid: the flat rule, copied into `out` (free with
 * ks_fwr_free_chain). -1 if not found ("" never is). */
int ks_fwr_flat_by_uuid(struct ks_sysfw *fw, const char *uuid, struct ks_fw_chain *out);
void ks_fwr_free_chain(struct ks_fw_chain *c);
int ks_fwr_copy_chain(struct ks_fw_chain *dst, const struct ks_fw_chain *src);

/* Rules.is_duplicated: a rule equal to flat's (UUIDs aside), or with its
 * UUID, in the same chain (name, hook, table, family and type). */
bool ks_fwr_is_duplicated(struct ks_sysfw *fw, const struct ks_fw_chain *flat);
/* Rules.add (append) and Rules.insert (at `position`). 0, or -1 with an
 * error message in `err` (translatable English, as upstream's). */
int ks_fwr_add(struct ks_sysfw *fw, const struct ks_fw_chain *flat, const char **err);
int ks_fwr_insert(struct ks_sysfw *fw, const struct ks_fw_chain *flat, size_t position,
                  const char **err);
/* Rules.update: replaces the rule with `uuid` by flat's rule. */
int ks_fwr_update(struct ks_sysfw *fw, const char *uuid, const struct ks_fw_chain *flat,
                  const char **err);
/* Rules.delete. 0 or -1 (not found). */
int ks_fwr_delete(struct ks_sysfw *fw, const char *uuid);
/* Rules.swap: exchanges the rules at old_pos and new_pos of the chain of
 * the rule with `uuid`. */
bool ks_fwr_swap(struct ks_sysfw *fw, const char *uuid, size_t old_pos, size_t new_pos);
/* Firewall.enable_rule, change_rule_field (Enabled or Target). */
int ks_fwr_enable(struct ks_sysfw *fw, const char *uuid, bool enable);
int ks_fwr_set_target(struct ks_sysfw *fw, const char *uuid, const char *target);

/* Chains.get_policy: of the first chain with that hook, type and family
 * (case-insensitive), or NULL. */
const char *ks_fwr_get_policy(const struct ks_sysfw *fw, const char *hook, const char *type,
                              const char *family);

/* Rules.to_array: the 11 columns of the firewall rules table (uuid, node,
 * chain name, table, family, hook, "True"/"False", description,
 * expressions, target, target parameters). Each one malloc'd. */
#define KS_FWR_NCOLS 11
int ks_fwr_to_array(const char *addr, const struct ks_fw_chain *c, const struct ks_fw_rule *r,
                    char *cols[KS_FWR_NCOLS]);
/* Firewall.filter_rules: does the rule match the search text? */
bool ks_fwr_matches(const struct ks_fw_chain *c, const struct ks_fw_rule *r, const char *nail);

/* ---- profiles.py ----------------------------------------------------------- */

enum ks_fw_profile {
    KS_FW_PROFILE_ACCEPT_INPUT,
    KS_FW_PROFILE_DROP_INPUT,
    KS_FW_PROFILE_ACCEPT_OUTPUT,
    KS_FW_PROFILE_DROP_OUTPUT,
    KS_FW_PROFILE_ACCEPT_FORWARD,
    KS_FW_PROFILE_DROP_FORWARD,
};
/* The profile as a chain (caller frees with ks_fwr_free_chain). */
int ks_fwr_profile(enum ks_fw_profile p, struct ks_fw_chain *out);
/* Firewall.apply_profile: sets the policy of the matching chain and adds
 * the profile's rules not already there. 0, or -1 with `err` ("profile not
 * applied"). */
int ks_fwr_apply_profile(struct ks_sysfw *fw, const struct ks_fw_chain *profile,
                         const char **err);
/* Firewall.delete_profile: deletes the profile's rules (by UUID). */
void ks_fwr_delete_profile(struct ks_sysfw *fw, const struct ks_fw_chain *profile);

/* ---- utils.NetworkServices --------------------------------------------- */

struct ks_fw_services {
    char **names; /* "ssh/22 (tcp)" */
    char **ports; /* "22" */
    size_t n;
};
/* Loads /etc/services (or `path` if not NULL), plus WireGuard's port. */
void ks_fw_services_load(struct ks_fw_services *s, const char *path);
void ks_fw_services_free(struct ks_fw_services *s);
int ks_fw_services_by_name(const struct ks_fw_services *s, const char *name);
int ks_fw_services_by_port(const struct ks_fw_services *s, const char *port);

/* ---- the rule dialog's form ------------------------------------------------ */

/* FwRuleDialog.STATM_*: the statements offered (index in STATM_LIST - 1) */
enum ks_fwf_statm {
    KS_FWF_DPORT, KS_FWF_SPORT, KS_FWF_DEST_IP, KS_FWF_SOURCE_IP, KS_FWF_IIFNAME,
    KS_FWF_OIFNAME, KS_FWF_CT_SET, KS_FWF_CT_MARK, KS_FWF_CT_STATE, KS_FWF_META_SET_MARK,
    KS_FWF_META, KS_FWF_ICMP, KS_FWF_ICMPV6, KS_FWF_LOG, KS_FWF_QUOTA, KS_FWF_COUNTER,
    KS_FWF_LIMIT,
};
#define KS_FWF_NSTATM 17
/* STATM_LIST: "" and the labels, in the combo's order */
extern const char *const ks_fwf_statm_labels[KS_FWF_NSTATM + 1];
/* the tooltip of a statement */
const char *ks_fwf_statm_tooltip(int statm);

/* directions (comboDirection) */
enum { KS_FWF_IN, KS_FWF_OUT, KS_FWF_FORWARD, KS_FWF_PREROUTING, KS_FWF_POSTROUTING };
/* form types */
enum { KS_FWF_SIMPLE, KS_FWF_EXCLUDE_SERVICE, KS_FWF_ALLOW_IN_SERVICE };
/* comboVerdict: ACCEPT ... REDIRECT, Verdicts.values()[i + 1] */
#define KS_FWF_NVERDICT_ITEMS 8

#define KS_FWF_VALUE_MAX 512
#define KS_FWF_MAX_STATEMENTS 32

struct ks_fwf_statement {
    int what;  /* enum ks_fwf_statm, -1: none selected */
    int opts;  /* index in ks_fwf_opts(what) */
    int op;    /* index in ks_fw_operators */
    char value[KS_FWF_VALUE_MAX];
};

struct ks_fwf_form {
    int form_type;
    int direction;
    int verdict;       /* comboVerdict index (-1: none) */
    int verdict_parm;  /* comboVerdictParms index */
    char verdict_parms[KS_FWF_VALUE_MAX];
    bool enabled;
    char description[KS_FWF_VALUE_MAX];
    char uuid[KS_UUID_STRLEN + 64];
    struct ks_fwf_statement st[KS_FWF_MAX_STATEMENTS];
    size_t nst;
};

/* The options combo of a statement (_configure_statem_value_opts), with
 * its visibility and the operator's. Returns the number of options; the
 * list is static. */
size_t ks_fwf_opts(int statm, const char *const **opts, bool *show_opts, bool *show_op);
/* The default option (the log level is "warn"). */
int ks_fwf_default_opts(int statm);
/* The predefined values of a statement's value combo (services, protocols,
 * states...). `services` may be NULL. Fills up to `max` pointers. */
size_t ks_fwf_values(int statm, const struct ks_fw_services *services, const char **out,
                     size_t max);
/* _set_statement_title */
void ks_fwf_title(const struct ks_fwf_statement *st, char *buf, size_t len);

/* _has_verdict_parms, _configure_verdict_parms: the items (label, data)
 * of comboVerdictParms for the verdict combo index. */
bool ks_fwf_has_verdict_parms(int verdict);
size_t ks_fwf_verdict_parm_items(int verdict, const char *const **data);
/* _is_valid_rule: NULL, or the message to show (and the direction to
 * switch to in *direction, if it must change). */
const char *ks_fwf_check_direction(int verdict, int *direction);
/* The direction _configure_verdict_parms forces for a verdict, or -1. */
int ks_fwf_verdict_direction(int verdict, int direction);

/* form_to_protobuf: the flat rule for the form. 0, or -1 with the error
 * message in `err`. A new rule gets a uuid1. */
int ks_fwf_to_rule(const struct ks_fwf_form *f, const struct ks_fw_services *services,
                   struct ks_fw_chain *out, char *err, size_t errlen);
/* load(): the form for a flat rule. 0; -1 with the error in `err` if the
 * rule isn't supported by the dialog (hook, statement or target). */
int ks_fwf_from_rule(const struct ks_fw_chain *flat, const struct ks_fw_services *services,
                     struct ks_fwf_form *f, char *err, size_t errlen);

#endif
