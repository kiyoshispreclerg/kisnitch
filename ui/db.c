/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/database/__init__.py on SQLite.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "common/log.h"

struct ks_db {
    sqlite3 *h;
    bool memory;
};

static const char *const journal_names[] = {"DELETE", "TRUNCATE", "PERSIST",
                                            "MEMORY", "WAL",      "OFF"};

sqlite3 *ks_db_handle(struct ks_db *db)
{
    return db->h;
}

bool ks_db_exec(struct ks_db *db, const char *sql)
{
    char *msg = NULL;
    if (sqlite3_exec(db->h, sql, NULL, NULL, &msg) != SQLITE_OK) {
        ks_error("db: %s: %s", sql, msg != NULL ? msg : "error");
        sqlite3_free(msg);
        return false;
    }
    return true;
}

bool ks_db_run(struct ks_db *db, const char *sql, const char *const *args, int n,
               int *changes)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
        ks_error("db: %s: %s", sql, sqlite3_errmsg(db->h));
        return false;
    }
    for (int i = 0; i < n; i++)
        sqlite3_bind_text(st, i + 1, args[i] != NULL ? args[i] : "", -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok)
        ks_error("db: %s: %s", sql, sqlite3_errmsg(db->h));
    else if (changes != NULL)
        *changes = sqlite3_changes(db->h);
    sqlite3_finalize(st);
    return ok;
}

/* The same, for the statements upstream runs without checking the result
 * (a CREATE INDEX on a table that already has it fails; so does the
 * index it declares on sockets.dst_host, a column that doesn't exist). */
static void exec_quiet(struct ks_db *db, const char *sql)
{
    sqlite3_exec(db->h, sql, NULL, NULL, NULL);
}

/* First column of the first row, as text; false if there is none. */
static bool query_text(struct ks_db *db, const char *sql, char *buf, size_t len)
{
    sqlite3_stmt *st;
    bool ok = false;
    if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        snprintf(buf, len, "%s", v != NULL ? (const char *)v : "");
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

int ks_db_schema_version(struct ks_db *db)
{
    char buf[32];
    if (query_text(db, "PRAGMA user_version;", buf, sizeof(buf)))
        return atoi(buf);
    return 0;
}

void ks_db_set_schema_version(struct ks_db *db, int version)
{
    char sql[64];
    snprintf(sql, sizeof(sql), "PRAGMA user_version = %d", version);
    ks_info("db: setting schema version to %d", version);
    ks_db_exec(db, sql);
}

const char *ks_db_journal_mode(struct ks_db *db, char *buf, size_t len)
{
    if (!query_text(db, "PRAGMA journal_mode;", buf, len))
        snprintf(buf, len, "%s", "unknown");
    return buf;
}

bool ks_db_set_journal_mode(struct ks_db *db, enum ks_db_journal mode)
{
    char cur[32], sql[64];
    const char *name = journal_names[mode];
    ks_db_journal_mode(db, cur, sizeof(cur));
    if (strcasecmp(cur, name) != 0) {
        ks_info("db: setting journal_mode: %s", name);
        snprintf(sql, sizeof(sql), "PRAGMA journal_mode = %s;", name);
        /* the pragma returns a row */
        char out[32];
        if (!query_text(db, sql, out, sizeof(out)))
            return false;
    }
    if (mode == KS_JRNL_MEMORY || mode == KS_JRNL_OFF) {
        if (!ks_db_exec(db, "PRAGMA synchronous = OFF;") ||
            !ks_db_exec(db, "PRAGMA cache_size=10000;"))
            return false;
    } else {
        ks_db_exec(db, "PRAGMA synchronous = NORMAL;");
    }
    return true;
}

static void create_tables(struct ks_db *db, bool wal)
{
    if (db->memory) {
        ks_db_set_schema_version(db, KS_DB_VERSION);
        ks_db_set_journal_mode(db, KS_JRNL_OFF);
    } else if (wal) {
        ks_db_set_journal_mode(db, KS_JRNL_WAL);
    } else {
        ks_db_set_journal_mode(db, KS_JRNL_DELETE);
    }
    ks_db_exec(db, "create table if not exists connections ("
                   "time text, node text, action text, protocol text, src_ip text, "
                   "src_port text, dst_ip text, dst_host text, dst_port text, uid text, "
                   "pid text, process text, process_args text, process_cwd text, rule text, "
                   "UNIQUE(node, action, protocol, src_ip, src_port, dst_ip, dst_port, uid, "
                   "pid, process, process_args))");
    static const char *const conn_idx[] = {
        "create index time_index on connections (time)",
        "create index action_index on connections (action)",
        "create index protocol_index on connections (protocol)",
        "create index dst_host_index on connections (dst_host)",
        "create index process_index on connections (process)",
        "create index dst_ip_index on connections (dst_ip)",
        "create index dst_port_index on connections (dst_port)",
        "create index rule_index on connections (rule)",
        "create index node_index on connections (node)",
        ("CREATE INDEX details_query_index on connections (process, process_args, uid, pid, "
         "dst_ip, dst_host, dst_port, action, node, protocol)"),
    };
    for (size_t i = 0; i < sizeof(conn_idx) / sizeof(conn_idx[0]); i++)
        exec_quiet(db, conn_idx[i]);

    ks_db_exec(db, "create table if not exists nodes ("
                   "addr text primary key, hostname text, daemon_version text, "
                   "daemon_uptime text, daemon_rules text, cons text, cons_dropped text, "
                   "version text, status text, last_connection text)");
    ks_db_exec(db, "create table if not exists rules ("
                   "time text, node text, name text, enabled text, precedence text, "
                   "action text, duration text, operator_type text, operator_sensitive text, "
                   "operator_operand text, operator_data text, description text, nolog text, "
                   "created text, UNIQUE(node, name))");
    ks_db_exec(db, "create table if not exists alerts ("
                   "time text, node text, type text, action text, priority text, "
                   "what text, body text, status int )");
    ks_db_exec(db, "create table if not exists sockets ("
                   "id int primary key, last_seen text, node text, src_port text, "
                   "src_ip text, dst_ip text, dst_port text, proto text, uid text, "
                   "inode text, iface text, family text, state text, cookies text, "
                   "rqueue text, wqueue text, expires text, retrans text, timer text, "
                   "mark text, proc_pid text, proc_comm text, proc_path text, "
                   "UNIQUE(node, src_port, src_ip, dst_ip, dst_port, proto, family, inode))");
    static const char *const other_idx[] = {
        "create index sck_srcport_index on sockets (src_port)",
        "create index sck_dstip_index on sockets (dst_ip)",
        "create index sck_srcip_index on sockets (src_ip)",
        "create index sck_dsthost_index on sockets (dst_host)",
        "create index sck_state_index on sockets (state)",
        "create index sck_comm_index on sockets (proc_comm)",
        "create index sck_path_index on sockets (proc_path)",
        "create index rules_index on rules (time)",
    };
    for (size_t i = 0; i < sizeof(other_idx) / sizeof(other_idx[0]); i++)
        exec_quiet(db, other_idx[i]);
    static const char *const stat_tables[] = {"hosts", "procs", "addrs", "ports", "users"};
    for (size_t i = 0; i < sizeof(stat_tables) / sizeof(stat_tables[0]); i++) {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "create table if not exists %s (what text primary key, hits integer)",
                 stat_tables[i]);
        ks_db_exec(db, sql);
    }
}

/* database/migrations/upgrade_N.sql, one statement per entry. */
static const char *const migrations[KS_DB_VERSION + 1] = {
    [1] = "ALTER TABLE rules ADD COLUMN description;",
    [2] = "ALTER TABLE rules ADD COLUMN nolog;",
    [3] = "ALTER TABLE rules ADD COLUMN created;",
};

static void upgrade_schema(struct ks_db *db)
{
    int v = ks_db_schema_version(db);
    if (v == KS_DB_VERSION) {
        ks_info("db: schema is up to date");
        return;
    }
    while (v < KS_DB_VERSION) {
        v++;
        ks_info("db: applying schema upgrade %d", v);
        /* a failing statement is reported and skipped, as upstream does */
        ks_db_exec(db, migrations[v]);
    }
    ks_db_set_schema_version(db, v);
}

struct ks_db *ks_db_open(const char *file, bool wal, char *err, size_t errlen)
{
    struct ks_db *db = calloc(1, sizeof(*db));
    if (db == NULL) {
        snprintf(err, errlen, "%s", "out of memory");
        return NULL;
    }
    db->memory = file == NULL || strcmp(file, KS_DB_IN_MEMORY) == 0 ||
                 strcmp(file, "file::memory:") == 0;
    const char *path = db->memory ? ":memory:" : file;
    bool is_new = db->memory || access(path, F_OK) != 0;
    if (sqlite3_open(path, &db->h) != SQLITE_OK) {
        snprintf(err, errlen, "%s: %s", path, db->h ? sqlite3_errmsg(db->h) : "open failed");
        sqlite3_close(db->h);
        free(db);
        return NULL;
    }
    char check[128] = "";
    if (!query_text(db, "PRAGMA quick_check;", check, sizeof(check)) ||
        strcmp(check, "ok") != 0) {
        snprintf(err, errlen, "%s: %s", path,
                 check[0] ? "Database is corrupted (1)" : sqlite3_errmsg(db->h));
        sqlite3_close(db->h);
        free(db);
        return NULL;
    }
    if (is_new)
        ks_db_set_schema_version(db, KS_DB_VERSION);
    create_tables(db, wal && !db->memory);
    upgrade_schema(db);
    return db;
}

void ks_db_close(struct ks_db *db)
{
    if (db == NULL)
        return;
    sqlite3_close(db->h);
    free(db);
}

int64_t ks_db_count(struct ks_db *db, const char *table)
{
    char sql[96], buf[32];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table);
    return query_text(db, sql, buf, sizeof(buf)) ? atoll(buf) : 0;
}

void ks_db_clean(struct ks_db *db, const char *table)
{
    char sql[96];
    snprintf(sql, sizeof(sql), "delete from %s", table);
    ks_db_exec(db, sql);
}

void ks_db_vacuum(struct ks_db *db)
{
    ks_db_exec(db, "VACUUM;");
}

void ks_db_optimize(struct ks_db *db)
{
    ks_db_exec(db, "PRAGMA optimize;");
}

bool ks_db_oldest_record(struct ks_db *db, char *buf, size_t len)
{
    buf[0] = '\0';
    return query_text(db, "SELECT time FROM connections ORDER BY 1 ASC LIMIT 1", buf, len);
}

bool ks_db_newest_record(struct ks_db *db, char *buf, size_t len)
{
    buf[0] = '\0';
    return query_text(db, "SELECT time FROM connections ORDER BY 1 DESC LIMIT 1", buf, len);
}

/* Days since 1970-01-01 of a civil date (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f"), as seconds of a naive
 * clock (no time zone, no DST: like subtracting two naive datetimes). */
static bool parse_stamp(const char *s, int64_t *secs)
{
    int y, mo, d, h, mi, se, n = 0;
    if (sscanf(s, "%4d-%2d-%2d %2d:%2d:%2d.%n", &y, &mo, &d, &h, &mi, &se, &n) < 6 || n == 0)
        return false;
    int digits = 0;
    while (s[n + digits] >= '0' && s[n + digits] <= '9')
        digits++;
    if (digits < 1 || digits > 6 || s[n + digits] != '\0')
        return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 61)
        return false;
    *secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

int ks_db_purge_oldest(struct ks_db *db, int max_days)
{
    char oldt[64], newt[64];
    if (!ks_db_oldest_record(db, oldt, sizeof(oldt)) ||
        !ks_db_newest_record(db, newt, sizeof(newt)) || oldt[0] == '\0' || newt[0] == '\0')
        return -1;
    int64_t o, n;
    if (!parse_stamp(oldt, &o) || !parse_stamp(newt, &n))
        return -1;
    int64_t diff = n - o;
    int64_t days = diff >= 0 ? diff / 86400 : -((-diff + 86399) / 86400); /* floor */
    if (days < max_days)
        return -1;

    /* str(datetime.now() - timedelta(days=max_days)) */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    time_t t = ts.tv_sec - (time_t)max_days * 86400;
    struct tm tm;
    if (localtime_r(&t, &tm) == NULL)
        return -1;
    char lim[64];
    size_t l = strftime(lim, sizeof(lim), "%Y-%m-%d %H:%M:%S", &tm);
    if (l == 0)
        return -1;
    if (ts.tv_nsec / 1000 != 0)
        snprintf(lim + l, sizeof(lim) - l, ".%06ld", (long)(ts.tv_nsec / 1000));

    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->h, "DELETE FROM connections WHERE time < ?", -1, &st, NULL) !=
        SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, lim, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    int deleted = sqlite3_changes(db->h);
    ks_info("db: purge_oldest() %d records deleted", deleted);
    return deleted;
}

void ks_db_empty_rule(struct ks_db *db, const char *name)
{
    if (name == NULL || name[0] == '\0')
        return;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->h, "DELETE FROM connections WHERE rule = ?", -1, &st, NULL) !=
        SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        ks_error("db: empty_rule(): %s", sqlite3_errmsg(db->h));
    sqlite3_finalize(st);
}

bool ks_db_delete_alert(struct ks_db *db, const char *time_s, const char *node)
{
    sqlite3_stmt *st;
    const char *sql = node != NULL ? "DELETE FROM alerts WHERE time=? AND node=?"
                                   : "DELETE FROM alerts WHERE time=?";
    if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, time_s, -1, SQLITE_TRANSIENT);
    if (node != NULL)
        sqlite3_bind_text(st, 2, node, -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok)
        ks_error("db: delete_alert(): %s", sqlite3_errmsg(db->h));
    sqlite3_finalize(st);
    return ok;
}
