/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI settings file, ~/.config/opensnitch/settings.conf, in the INI
 * format QSettings writes (upstream ui/opensnitch/config.py uses
 * QSettings("opensnitch", "settings")), so the original UI and ours can
 * share it.
 *
 * Keys are "group/key" ("global/default_timeout"); keys outside a group go
 * to [General], as in QSettings. Values are kept as written in the file,
 * so entries we don't touch (geometries, @ByteArray, lists) survive a
 * rewrite unchanged; the typed getters decode them as QVariant would.
 * Writing re-reads the file first and applies only our changes, like
 * QSettings::sync(). Existing groups and keys keep their order; new ones
 * are appended (QSettings may order them differently; both read the same).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_settings owns its path and every entry. Strings
 * returned by ks_settings_get_string() are malloc'd and owned by the
 * caller; ks_settings_raw() returns a pointer valid until the next change
 * or reload.
 */
#ifndef KS_UI_SETTINGS_H
#define KS_UI_SETTINGS_H

#include <stdbool.h>
#include <stddef.h>

/* Keys used by the upstream UI (config.py). */
#define KS_CFG_DEFAULT_TIMEOUT_KEY  "global/default_timeout"
#define KS_CFG_DEFAULT_ACTION_KEY   "global/default_action"
#define KS_CFG_DEFAULT_DURATION_KEY "global/default_duration"
#define KS_CFG_DEFAULT_TARGET_KEY   "global/default_target"
#define KS_CFG_DEFAULT_IGNORE_RULES "global/default_ignore_rules"
#define KS_CFG_DEFAULT_IGNORE_TEMPORARY_RULES "global/default_ignore_temporary_rules"
#define KS_CFG_DEFAULT_POPUP_POSITION "global/default_popup_position"
#define KS_CFG_DEFAULT_POPUP_ADVANCED "global/default_popup_advanced"
#define KS_CFG_DEFAULT_POPUP_ADVANCED_DSTIP "global/default_popup_advanced_dstip"
#define KS_CFG_DEFAULT_POPUP_ADVANCED_DSTPORT "global/default_popup_advanced_dstport"
#define KS_CFG_DEFAULT_POPUP_ADVANCED_UID "global/default_popup_advanced_uid"
#define KS_CFG_DEFAULT_POPUP_ADVANCED_CHECKSUM "global/default_popup_advanced_checksum"
#define KS_CFG_DEFAULT_LANGUAGE     "global/language"
#define KS_CFG_DEFAULT_LANGNAME     "global/langname"
#define KS_CFG_DEFAULT_SERVER_ADDR  "global/server_address"
#define KS_CFG_DEFAULT_SERVER_MAX_CLIENTS "global/max_clients"
#define KS_CFG_DEFAULT_HIDE_SYSTRAY_WARN "global/hide_systray_warning"
#define KS_CFG_DEFAULT_DISABLE_POPUPS "global/disable_popups"
#define KS_CFG_DEFAULT_DB_TYPE_KEY  "database/type"
#define KS_CFG_DEFAULT_DB_FILE_KEY  "database/file"
#define KS_CFG_DEFAULT_DB_JRNL_WAL  "database/jrnl_wal"
#define KS_CFG_DB_PURGE_OLDEST      "database/purge_oldest"
#define KS_CFG_DB_MAX_DAYS          "database/max_days"
#define KS_CFG_DB_PURGE_INTERVAL    "database/purge_interval"
#define KS_CFG_AUTH_TYPE            "auth/type"

/* Defaults (config.py, database/__init__.py). */
#define KS_CFG_DEFAULT_TIMEOUT 30
#define KS_CFG_ACTION_DENY_IDX 0
#define KS_CFG_ACTION_ALLOW_IDX 1
#define KS_CFG_ACTION_REJECT_IDX 2
#define KS_CFG_DEFAULT_DURATION_IDX 6
#define KS_CFG_DEFAULT_TARGET_PROCESS 0
#define KS_CFG_DB_TYPE_MEMORY 0
#define KS_CFG_DB_IN_MEMORY "file::memory:"

#define KS_CFG_POPUP_CENTER 0
#define KS_CFG_POPUP_TOP_RIGHT 1
#define KS_CFG_POPUP_BOTTOM_RIGHT 2
#define KS_CFG_POPUP_TOP_LEFT 3
#define KS_CFG_POPUP_BOTTOM_LEFT 4

struct ks_setting {
    char *group; /* "" for keys without one (written as [General]) */
    char *key;   /* the rest, with "/" separators */
    char *raw;   /* the value as written in the file */
};

struct ks_settings {
    char *path;
    struct ks_setting *items;
    size_t len, cap;
    /* changes not written yet (applied on top of the file by sync) */
    struct ks_setting *pending;
    size_t npending, cappending;
};

/* $XDG_CONFIG_HOME/opensnitch/settings.conf (~/.config if unset), into
 * `buf`. -1 if it doesn't fit or there's no home. */
int ks_settings_default_path(char *buf, size_t len);

/* Loads `path` (a missing file is an empty configuration). -1 on OOM or
 * read errors other than ENOENT. */
int ks_settings_open(struct ks_settings *s, const char *path);
void ks_settings_close(struct ks_settings *s);
/* Re-reads the file, keeping changes not written yet (Config.reload()). */
int ks_settings_reload(struct ks_settings *s);

/* Parses INI text into `s` (replacing its entries). A struct ks_settings
 * zeroed and parsed this way has no file: changes stay in memory. */
int ks_settings_parse(struct ks_settings *s, const char *text, size_t len);
/* The file contents for the current entries. malloc'd; NULL on OOM. */
char *ks_settings_serialize(const struct ks_settings *s);

bool ks_settings_has(const struct ks_settings *s, const char *key);
const char *ks_settings_raw(const struct ks_settings *s, const char *key);
/* The value as a string (QSettings::value().toString()): unescaped and
 * unquoted; a list ("a, b") is joined with ", "; "@@x" is "@x". NULL if
 * the key doesn't exist. */
char *ks_settings_get_string(const struct ks_settings *s, const char *key);
/* QVariant::toInt(): `def` if missing or not a number. */
int ks_settings_get_int(const struct ks_settings *s, const char *key, int def);
/* QVariant::toBool(): "", "0" and "false" (any case) are false. */
bool ks_settings_get_bool(const struct ks_settings *s, const char *key, bool def);

/* setValue() + sync(), as Config.setSettings() does. -1 on error. */
int ks_settings_set_string(struct ks_settings *s, const char *key, const char *value);
int ks_settings_set_int(struct ks_settings *s, const char *key, int value);
int ks_settings_set_bool(struct ks_settings *s, const char *key, bool value);
/* setValue() without writing; ks_settings_sync() writes. */
int ks_settings_set_raw(struct ks_settings *s, const char *key, const char *raw);
int ks_settings_sync(struct ks_settings *s);

/* QSettings' escaping of a string value (iniEscapedString), plus the "@"
 * doubling of variantToString. malloc'd. */
char *ks_settings_escape(const char *value);
/* iniUnescapedStringList, joined with ", " if it was a list. malloc'd. */
char *ks_settings_unescape(const char *raw);

/* Config.__init__(): writes the defaults the upstream UI writes on start
 * when they're missing. */
int ks_settings_init_defaults(struct ks_settings *s);

#endif
