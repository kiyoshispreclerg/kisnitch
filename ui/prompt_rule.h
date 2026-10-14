/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What the pop-up computes, without the widgets: the entries of its
 * combos, the defaults, the texts, and the rule built from the user's
 * choice. Port of upstream ui/opensnitch/dialogs/prompt/__init__.py
 * (_render_connection, _add_*_to_combo, _send_rule), _utils.py,
 * _details.py, _checksums.py and utils/network_aliases.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_combo and struct ks_py_aliases own their strings.
 * Messages built here live in the struct ks_arena passed in; their
 * strings may point into the connection, which must outlive them.
 * Other returned strings are malloc'd and owned by the caller.
 */
#ifndef KS_UI_PROMPT_RULE_H
#define KS_UI_PROMPT_RULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/arena.h"
#include "common/netaddr.h"
#include "common/pb/ui.pb-c.h"
#include "ui/rulesdb.h"

/* _constants.py FIELD_*: the data of each combo entry. */
enum ks_field {
    KS_FIELD_PROC_PATH,
    KS_FIELD_PROC_ARGS,
    KS_FIELD_PROC_ID,
    KS_FIELD_USER_ID,
    KS_FIELD_DST_IP,
    KS_FIELD_DST_PORT,
    KS_FIELD_DST_NETWORK,
    KS_FIELD_DST_HOST,
    KS_FIELD_REGEX_HOST,
    KS_FIELD_REGEX_IP,
    KS_FIELD_APPIMAGE,
    KS_FIELD_SNAP,
};

#define KS_APPIMAGE_PREFIX "/tmp/.mount_"
#define KS_SNAP_PREFIX "/snap"
/* _constants.DEFAULT_TIMEOUT: the countdown without the setting */
#define KS_PROMPT_DEFAULT_TIMEOUT 15

/* The duration combo: index -> rule duration (_utils.get_duration) and
 * label. */
#define KS_DURATION_COUNT 9
extern const char *const ks_durations[KS_DURATION_COUNT];
extern const char *const ks_duration_labels[KS_DURATION_COUNT];
const char *ks_prompt_duration(int idx);

/* Actions, by Config.ACTION_*_IDX. */
const char *ks_prompt_action(int idx);

struct ks_combo_item {
    char *text;
    enum ks_field field;
    bool disabled;
};

struct ks_combo {
    struct ks_combo_item *items;
    size_t len, cap;
};

void ks_combo_free(struct ks_combo *c);
/* QComboBox.findData(): first index with that field, or -1. */
int ks_combo_find(const struct ks_combo *c, enum ks_field field);

/* network_aliases.json as the UI reads it (Python's json and ipaddress):
 * aliases in file order; an address without a prefix length is a single
 * host. */
struct ks_py_net {
    char *text;
};
struct ks_py_alias {
    char *name;
    struct ks_py_net *nets;
    size_t nnets;
};
struct ks_py_aliases {
    struct ks_py_alias *items;
    size_t len;
};

int ks_py_aliases_parse(struct ks_py_aliases *a, const char *json, size_t len);
void ks_py_aliases_free(struct ks_py_aliases *a);
/* NetworkAliases.get_alias(ip): the first alias with a network holding
 * `ip`. A network Python refuses (host bits set) ends the search with
 * nothing, as the ValueError does upstream. NULL if none. */
const char *ks_py_aliases_get(const struct ks_py_aliases *a, const char *ip);

/* The uid label: "1000 (user)" for local nodes ("" if the user is
 * unknown), "1000" for remote ones. malloc'd. */
char *ks_prompt_uid_text(const Protocol__Connection *con, bool is_local);

/* Fills the "what" combo and the destination IP combo as
 * _render_connection() does. */
int ks_prompt_fill_combos(const Protocol__Connection *con, const char *uid_text,
                          const struct ks_py_aliases *aliases, struct ks_combo *what,
                          struct ks_combo *what_ip);

/* _utils.set_default_target(): the index of the "what" combo to select,
 * given the default_target setting. -1 if out of range (nothing
 * selected). */
int ks_prompt_default_target(const struct ks_combo *what, const Protocol__Connection *con,
                             int cfg_target, const char *app_name, const char *app_args);

/* _utils.truncate_text(): first `max` characters plus "...". */
char *ks_prompt_truncate(const char *text, size_t max);
/* "".join(filter(str.isprintable, text)), for control and format
 * characters. In place. */
void ks_prompt_printable(char *text);
/* Escapes <, >, & and quotes for Pango markup. malloc'd. */
char *ks_markup_escape(const char *s);

/* _utils.get_popup_message(), as Pango markup. `node` is the peer
 * ("unix:/local"). */
char *ks_prompt_message(bool is_local, const char *node, const char *hostname,
                        const char *app_name, const Protocol__Connection *con);

/* _utils.set_app_path(): the path label, or NULL when hidden. */
char *ks_prompt_path_label(const char *app_name, const char *app_args,
                           const Protocol__Connection *con);
/* _utils.set_app_args(): the args label, or NULL when hidden. */
char *ks_prompt_args_label(const char *app_name, const char *app_args);

/* _details.render(), as plain text. */
char *ks_prompt_details(const Protocol__Connection *con);

/* The md5 the daemon computed ("" if none). */
const char *ks_prompt_md5(const Protocol__Connection *con);

/* What the user chose (or what the dialog had selected on timeout). */
struct ks_prompt_choice {
    int action_idx;   /* Config.ACTION_*_IDX */
    int duration_idx; /* durationCombo */
    const struct ks_combo_item *what;    /* NULL: nothing selected */
    const struct ks_combo_item *what_ip; /* the IP combo's selection */
    bool dst_ip, dst_port, user_id, checksum;
    const char *checksum_text; /* checksumLabel */
};

/* _send_rule(): the rule to answer with, named with `db`'s rules of
 * `peer`, or NULL if the choice gives an empty operator (the pop-up then
 * answers nothing). `now` is the creation time. */
Protocol__Rule *ks_prompt_build_rule(struct ks_arena *a, const Protocol__Connection *con,
                                     const struct ks_prompt_choice *ch,
                                     const struct ks_py_aliases *aliases,
                                     const struct ks_rulesdb *db, const char *peer,
                                     int64_t now);

/* _display_checksums_warning(): the rules of `peer` whose operator_data
 * mentions the process path (LIKE), enabled ones, minus the first match
 * (upstream skips it, docs/UPSTREAM.md); returns true if one of them has a
 * different md5. Their names go to `names` (up to `max`), the md5 they
 * expect to `expected` (malloc'd, comma-separated, as Python prints the
 * list). */
bool ks_prompt_checksum_mismatch(const struct ks_rulesdb *db, const char *peer,
                                 const Protocol__Connection *con, char **names, size_t max,
                                 size_t *nnames, char **expected);

/* _checksums.update_rule(): the rule `name` of `peer` with the process md5
 * replaced by the current one, stored back in `db`. NULL if not found. */
Protocol__Rule *ks_prompt_checksum_update(struct ks_arena *a, struct ks_rulesdb *db,
                                          const char *peer, const char *name,
                                          const Protocol__Connection *con);

#endif
