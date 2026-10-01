/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The rule set: loading from disk, live reload, temporary rules and matching.
 * Port of upstream daemon/rule/loader.go.
 *
 * Matching (FindFirstMatch) walks the enabled rules sorted by name. Each
 * match is remembered and the walk continues; it stops at the first matching
 * rule whose action is deny or reject, or that has precedence. So with only
 * allow rules matching, the last one (by name) wins.
 *
 * Live reload follows upstream's fsnotify watcher: a write to a *.json file
 * in the rules directory (re)loads it, and its removal deletes the rule if
 * its duration is "always". Temporary rules (durations like "30s") are
 * removed when their time is up, unless the rule was replaced meanwhile with
 * a different duration.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the loader owns every rule in it. Pointers it returns stay valid
 * until the rule set changes (load, add, replace, delete, expiry, reload).
 * Functions taking a struct ks_rule * take ownership of it, also on error.
 */
#ifndef KS_DAEMON_RULES_LOADER_H
#define KS_DAEMON_RULES_LOADER_H

#include <stdbool.h>
#include <stddef.h>

#include "daemon/conn.h"
#include "daemon/rules/rule.h"

#define KS_RULES_DEFAULT_PATH "/etc/opensnitchd/rules"

struct ks_loader;
struct ks_evloop;
struct ks_aliases;

/* `loop` runs live reload, temporary rule expiry and list monitors; it may
 * be NULL only if none of that is wanted. `aliases` may be NULL. */
struct ks_loader *ks_loader_new(struct ks_evloop *loop,
                                const struct ks_aliases *aliases,
                                bool live_reload);
void ks_loader_free(struct ks_loader *l);

/* Load: adds the *.json rules in `path` (invalid ones are logged and
 * skipped) and starts watching it. */
int ks_loader_load(struct ks_loader *l, const char *path, char *err,
                   size_t errlen);

/* Reload: drops every rule and loads `path` ("" = default path). */
int ks_loader_reload(struct ks_loader *l, const char *path, char *err,
                     size_t errlen);

/* loadRule: (re)loads one rule file. */
int ks_loader_load_rule(struct ks_loader *l, const char *file, char *err,
                        size_t errlen);

/* Add: adds a rule (renamed "name-2", "name-3"... if the name is taken).
 * "once" rules are not kept. With `save`, writes it to <path>/<name>.json. */
int ks_loader_add(struct ks_loader *l, struct ks_rule *r, bool save,
                  char *err, size_t errlen);

/* Replace: adds or replaces the rule with the same name. */
int ks_loader_replace(struct ks_loader *l, struct ks_rule *r, bool save,
                      char *err, size_t errlen);

/* Delete: removes a rule; "always" rules are also removed from disk. */
int ks_loader_delete(struct ks_loader *l, const char *name, char *err,
                     size_t errlen);

/* Save: sets the rule's "updated" field to now and writes it to `path`
 * (mode 0600 if created). Doesn't take ownership. */
int ks_loader_save(struct ks_loader *l, struct ks_rule *r, const char *path,
                   char *err, size_t errlen);

/* FindFirstMatch. NULL if no rule matches. */
const struct ks_rule *ks_loader_find_first_match(struct ks_loader *l,
                                                 const struct ks_conn *c);

void ks_loader_enable_checksums(struct ks_loader *l, bool enable);

size_t ks_loader_num_rules(const struct ks_loader *l);
/* Rules in name order, i < ks_loader_num_rules(). */
const struct ks_rule *ks_loader_rule_at(const struct ks_loader *l, size_t i);
const struct ks_rule *ks_loader_get(const struct ks_loader *l, const char *name);
/* The loaded path (after ~ expansion), or "". */
const char *ks_loader_path(const struct ks_loader *l);

#endif
