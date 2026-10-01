/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Daemon configuration (default-config.json).
 *
 * Port of upstream daemon/ui/config/config.go, plus the nested structs it
 * embeds: procmon/audit.Config, procmon/ebpf.Config, statistics.StatsConfig
 * and log/loggers.LoggerConfig.
 *
 * Decoding follows Go's encoding/json rules for these types:
 *   - Missing keys keep the zero value; unknown keys are ignored.
 *   - Key matching is case-insensitive; with duplicate keys the last wins.
 *   - `null` leaves strings, bools, numbers and objects untouched, and resets
 *     LogLevel (a *int32 upstream) and Server.Loggers (a slice) to nil.
 *   - Wrong JSON types and out-of-range integers are errors.
 * No semantic validation happens here (e.g. DefaultAction "foo" is accepted),
 * same as upstream's config.Parse().
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a struct ks_config owns every string and array reachable from it.
 * Release with ks_config_free(). Strings are never NULL after a successful
 * ks_config_parse() (absent values are ""), but code must also accept NULL
 * strings in a zero-initialized config.
 */
#ifndef KS_DAEMON_CONFIG_H
#define KS_DAEMON_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KS_CONFIG_DEFAULT_FILE "/etc/opensnitchd/default-config.json"
/* Configs are tiny; anything bigger than this is certainly not one. */
#define KS_CONFIG_MAX_SIZE (1024 * 1024)

/* ServerTLSOptions */
struct ks_tls_options {
    char *ca_cert;          /* CACert */
    char *server_cert;      /* ServerCert */
    char *server_key;       /* ServerKey */
    char *client_cert;      /* ClientCert */
    char *client_key;       /* ClientKey */
    char *client_auth_type; /* ClientAuthType */
    bool skip_verify;       /* SkipVerify */
};

/* ServerAuth */
struct ks_server_auth {
    char *type;                    /* Type */
    struct ks_tls_options tls;     /* TLSOptions */
};

/* loggers.LoggerConfig (no json tags upstream: keys are the field names) */
struct ks_logger_config {
    char *name;                    /* Name */
    char *format;                  /* Format */
    char *protocol;                /* Protocol */
    char *server;                  /* Server */
    char *write_timeout;           /* WriteTimeout */
    char *connect_timeout;         /* ConnectTimeout */
    char *tag;                     /* Tag */
    int64_t workers;               /* Workers (Go int) */
    uint16_t max_connect_attempts; /* MaxConnectAttempts */
};

/* A Go slice: distinguishes nil (marshals to null) from empty (marshals to
 * []). Owns `items`. */
struct ks_logger_list {
    struct ks_logger_config *items;
    size_t len;
    bool non_nil;
};

/* ServerConfig */
struct ks_server_config {
    char *address;                 /* Address */
    struct ks_server_auth auth;    /* Authentication */
    char *log_file;                /* LogFile */
    struct ks_logger_list loggers; /* Loggers */
};

/* RulesOptions */
struct ks_rules_options {
    char *path;            /* Path */
    bool enable_checksums; /* EnableChecksums */
};

/* FwOptions */
struct ks_fw_options {
    char *firewall;         /* Firewall */
    char *config_path;      /* ConfigPath */
    char *monitor_interval; /* MonitorInterval */
    uint16_t queue_num;     /* QueueNum */
    bool queue_bypass;      /* QueueBypass */
};

/* TasksOptions */
struct ks_tasks_options {
    char *config_path; /* ConfigPath */
};

/* InternalOptions */
struct ks_internal_options {
    int64_t gc_percent;         /* GCPercent (Go int) */
    bool flush_conns_on_start;  /* FlushConnsOnStart */
};

/* audit.Config */
struct ks_audit_config {
    char *audisp_socket_path; /* AudispSocketPath */
};

/* ebpf.Config */
struct ks_ebpf_config {
    char *modules_path;        /* ModulesPath */
    int64_t ring_buff_size;    /* RingBuffSize */
    int64_t events_workers;    /* EventsWorkers */
    int64_t queue_events_size; /* QueueEventsSize */
};

/* statistics.StatsConfig */
struct ks_stats_config {
    int64_t max_events; /* MaxEvents */
    int64_t max_stats;  /* MaxStats */
    int64_t workers;    /* Workers */
};

/* A Go *int32: `set` is false for nil. */
struct ks_opt_int32 {
    bool set;
    int32_t value;
};

/* Config. Field order matches the Go struct, which is also the key order
 * ks_config_to_json() emits (like json.Marshal). */
struct ks_config {
    struct ks_opt_int32 log_level;         /* LogLevel */
    char *firewall;                        /* Firewall */
    char *default_action;                  /* DefaultAction */
    char *default_duration;                /* DefaultDuration */
    char *proc_monitor_method;             /* ProcMonitorMethod */
    struct ks_fw_options fw_options;       /* FwOptions */
    struct ks_audit_config audit;          /* Audit */
    struct ks_ebpf_config ebpf;            /* Ebpf */
    struct ks_server_config server;        /* Server */
    struct ks_rules_options rules;         /* Rules */
    struct ks_internal_options internal;   /* Internal */
    struct ks_stats_config stats;          /* Stats */
    struct ks_tasks_options tasks;         /* Tasks */
    bool intercept_unknown;                /* InterceptUnknown */
    bool log_utc;                          /* LogUTC */
    bool log_micro;                        /* LogMicro */
};

/* Parses a JSON document (`len` bytes, need not be NUL-terminated) into
 * `out`, which is initialized first (any previous content is NOT freed).
 * Returns 0 on success. On error returns -1, leaves `out` zeroed and writes
 * a message naming the offending line/column or field to `err`. */
int ks_config_parse(const char *json, size_t len, struct ks_config *out,
                    char *err, size_t errlen);

/* Reads and parses `path`. An empty file is an error, as upstream. */
int ks_config_load(const char *path, struct ks_config *out, char *err,
                   size_t errlen);

/* Reloads `path` into `cfg`. On error `cfg` is left untouched (upstream keeps
 * running with the previous configuration). */
int ks_config_reload(const char *path, struct ks_config *cfg, char *err,
                     size_t errlen);

/* Validates `raw` with ks_config_parse() and writes it verbatim to `path`,
 * as upstream config.Save(): chmod 0600 first (only warns on failure), then
 * truncate-and-write (mode 0644 if the file is created). */
int ks_config_save_raw(const char *path, const char *raw, size_t len,
                       char *err, size_t errlen);

/* Serializes every field, in Go struct order, as json.Marshal would.
 * Returns a malloc'd string owned by the caller, or NULL on OOM. */
char *ks_config_to_json(const struct ks_config *cfg, bool pretty);

/* Deep comparison of all fields (NULL and "" strings are equal). */
bool ks_config_equal(const struct ks_config *a, const struct ks_config *b);

/* Frees everything `cfg` owns and zeroes it. Safe on a zeroed struct. */
void ks_config_free(struct ks_config *cfg);

#endif
