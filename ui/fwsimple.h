/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The simplified system firewall panel, without widgets. Kisnitch's own
 * feature (not upstream's), in the style of ufw and of KDE's firewall
 * panel: rules "allow/deny/reject, in/out, protocol and port, source and
 * destination address, interface", plus the default policies.
 *
 * There's no new format: a simple rule is an ordinary FwRule of the same
 * system-fw.json, made by the firewall rule dialog's own form logic
 * (ui/fwrules.h, ks_fwf_to_rule), so it's exactly the rule upstream's
 * dialog would make from the same choices. A rule of the file is shown as
 * simple only if it goes rule -> form -> simple rule -> form -> rule and
 * comes back identical; anything else is an "advanced" rule, edited in the
 * full dialog. The policies are upstream's profiles (ProfileDropInput...),
 * whose rules are shown as part of the policy.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_fws_rule and the rows are plain data with fixed
 * buffers. struct ks_fws_rows and struct ks_fws_apps own their arrays
 * (ks_fws_rows_free, ks_fws_apps_free). Chains returned through `out` are
 * owned by the caller (ks_fwr_free_chain).
 */
#ifndef KS_UI_FWSIMPLE_H
#define KS_UI_FWSIMPLE_H

#include <stdbool.h>
#include <stddef.h>

#include "common/sysfw.h"
#include "ui/fwrules.h"

enum { KS_FWS_ALLOW, KS_FWS_DENY, KS_FWS_REJECT }; /* accept, drop, reject */
enum { KS_FWS_IN, KS_FWS_OUT };
#define KS_FWS_ANY_PROTO (-1)

#define KS_FWS_TEXT_MAX 256

struct ks_fws_rule {
    char uuid[KS_UUID_STRLEN + 64]; /* "" for a new rule */
    bool enabled;
    int action;    /* KS_FWS_ALLOW... */
    int direction; /* KS_FWS_IN, KS_FWS_OUT */
    /* index in ks_fw_port_protocols ("tcp,udp", "tcp", "udp"...), or
     * KS_FWS_ANY_PROTO. A protocol without port is "meta l4proto". */
    int proto;
    char port[KS_FWS_TEXT_MAX];  /* "22", "80,443", "6000-6007"; "" any */
    char src[KS_FWS_TEXT_MAX];   /* address, network (a/n) or range (a-b); "" any */
    char dst[KS_FWS_TEXT_MAX];
    char iface[KS_FWS_TEXT_MAX]; /* iifname (in) or oifname (out); "" any */
    char description[KS_FWS_TEXT_MAX];
};

/* A new rule: allow, in, enabled, any protocol. */
void ks_fws_rule_init(struct ks_fws_rule *r);

/* The flat rule (a chain with the rule) for `r`. 0, or -1 with the
 * message in `err` (the form's own messages, plus the simple panel's). */
int ks_fws_to_flat(const struct ks_fws_rule *r, struct ks_fw_chain *out, char *err,
                   size_t errlen);
/* The simple rule for a flat rule; false if it's an advanced one. */
bool ks_fws_from_flat(const struct ks_fw_chain *flat, struct ks_fws_rule *out);

/* ---- the table ---------------------------------------------------------- */

enum ks_fws_kind {
    KS_FWS_ROW_SIMPLE,
    KS_FWS_ROW_ADVANCED,
    KS_FWS_ROW_POLICY, /* a rule of a policy profile (loopback, established...) */
};

struct ks_fws_row {
    enum ks_fws_kind kind;
    struct ks_fws_rule rule; /* KS_FWS_ROW_SIMPLE */
    char uuid[KS_UUID_STRLEN + 64];
    char chain[64]; /* chain name */
    bool enabled;
    char summary[1024]; /* advanced and policy rows: "expressions -> target" */
};

struct ks_fws_rows {
    struct ks_fws_row *v;
    size_t n;
};

/* Every rule of the firewall, in file order. */
int ks_fws_rows(const struct ks_sysfw *fw, struct ks_fws_rows *out);
void ks_fws_rows_free(struct ks_fws_rows *rows);

/* The columns of a simple rule: "Allow", "In", "tcp 22", "192.168.1.0/24"
 * or "Any", "Any", "eth0" or "Any". Static or written into the buffers. */
const char *ks_fws_action_text(int action);
const char *ks_fws_direction_text(int direction);
void ks_fws_port_text(const struct ks_fws_rule *r, char *buf, size_t len);

/* An address range that is exactly a network ("10.0.0.0-10.255.255.255")
 * as CIDR ("10.0.0.0/8"); anything else as is. Saving the CIDR gives the
 * same range back. */
void ks_fws_addr_text(const char *addr, char *buf, size_t len);

/* ---- policies ------------------------------------------------------------ */

/* The input (filter) and output (mangle) policy: true is drop. -1 if the
 * chain isn't there. */
int ks_fws_policy(const struct ks_sysfw *fw, int direction, bool *drop);
/* What the firewall dialog does: switching to accept removes the drop
 * profile's rules, then the wanted profile is applied. 0, or -1 with
 * `err` set. */
int ks_fws_set_policy(struct ks_sysfw *fw, int direction, bool drop, const char **err);

/* ---- editing ------------------------------------------------------------- */

/* Adds a rule (the last of its chain), or replaces the one with r->uuid. */
int ks_fws_save(struct ks_sysfw *fw, const struct ks_fws_rule *r, char *err, size_t errlen);
/* Moves a rule up (-1) or down (+1) in its chain; false if it can't. */
bool ks_fws_move(struct ks_sysfw *fw, const char *uuid, int delta);

/* ---- ufw application profiles --------------------------------------------- */

/* One "ports" entry of a profile, e.g. "80,443/tcp". A profile with
 * several entries ("80/tcp|8080/udp") gives one item per entry. */
struct ks_fws_app {
    char name[KS_FWS_TEXT_MAX];  /* "OpenSSH", or "Apache Full (80,443/tcp)" */
    char title[KS_FWS_TEXT_MAX]; /* title= */
    int proto;                   /* index in ks_fw_port_protocols */
    char ports[KS_FWS_TEXT_MAX]; /* nftables syntax: ranges with '-' */
};

struct ks_fws_apps {
    struct ks_fws_app *v;
    size_t n;
};

/* Reads every file of `dir` (NULL: /etc/ufw/applications.d), sorted by
 * name. Unreadable entries are skipped. */
void ks_fws_apps_load(struct ks_fws_apps *apps, const char *dir);
/* Parses one file's text (configparser-like INI). */
void ks_fws_apps_parse(struct ks_fws_apps *apps, const char *text);
void ks_fws_apps_free(struct ks_fws_apps *apps);

#endif
