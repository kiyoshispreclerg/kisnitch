/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI database: port of upstream ui/opensnitch/database/__init__.py on
 * SQLite. Same file format as the original UI (tables connections, nodes,
 * rules, alerts, sockets, hosts, procs, addrs, ports, users; PRAGMA
 * user_version = 3), so both UIs can open each other's database file.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_db owns the SQLite handle. ks_db_handle() lends it to
 * code that prepares its own statements (the statistics window); it is
 * valid until ks_db_close(). All calls are for the GLib main thread only.
 */
#ifndef KS_UI_DB_H
#define KS_UI_DB_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Database.DB_VERSION */
#define KS_DB_VERSION 3
#define KS_DB_IN_MEMORY ":memory:"

/* Database.DB_JOURNAL_MODE_LIST */
enum ks_db_journal { KS_JRNL_DELETE, KS_JRNL_TRUNCATE, KS_JRNL_PERSIST, KS_JRNL_MEMORY,
                     KS_JRNL_WAL, KS_JRNL_OFF };

/* Database.initialize(): `file` NULL or KS_DB_IN_MEMORY for the in-memory
 * database (journal off, whatever `wal` says). Runs the quick check,
 * creates the tables and applies the pending migrations. NULL and a
 * message in `err` on failure. */
struct ks_db *ks_db_open(const char *file, bool wal, char *err, size_t errlen);
/* Database.close(): optimize + vacuum are the caller's (service.py does them first). */
void ks_db_close(struct ks_db *db);
sqlite3 *ks_db_handle(struct ks_db *db);

int ks_db_schema_version(struct ks_db *db);
void ks_db_set_schema_version(struct ks_db *db, int version);
bool ks_db_set_journal_mode(struct ks_db *db, enum ks_db_journal mode);
/* PRAGMA journal_mode, lowercase as SQLite reports it. */
const char *ks_db_journal_mode(struct ks_db *db, char *buf, size_t len);

/* Runs SQL that returns nothing; false (and a log line) on error. */
bool ks_db_exec(struct ks_db *db, const char *sql);
/* Runs one statement with `n` text parameters (NULL binds as ""); false
 * (and a log line) on error. `changes`, if given, gets the rows affected. */
bool ks_db_run(struct ks_db *db, const char *sql, const char *const *args, int n,
               int *changes);
/* SELECT count(*) FROM `table` (the name is ours, never user input). */
int64_t ks_db_count(struct ks_db *db, const char *table);
void ks_db_clean(struct ks_db *db, const char *table);
void ks_db_vacuum(struct ks_db *db);
void ks_db_optimize(struct ks_db *db);

/* get_oldest_record / get_newest_record: the `time` of the connections row,
 * "" if none. */
bool ks_db_oldest_record(struct ks_db *db, char *buf, size_t len);
bool ks_db_newest_record(struct ks_db *db, char *buf, size_t len);
/* purge_oldest(): deletes connections older than `max_days` days, if the
 * stored ones span at least that many. Returns rows deleted, -1 if nothing
 * was done. */
int ks_db_purge_oldest(struct ks_db *db, int max_days);

/* Database.empty_rule(): deletes the events of a rule. */
void ks_db_empty_rule(struct ks_db *db, const char *name);

/* Database.delete_alert(); NULL node = any. */
bool ks_db_delete_alert(struct ks_db *db, const char *time, const char *node);

#endif
