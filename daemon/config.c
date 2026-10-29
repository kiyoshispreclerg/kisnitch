/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/ui/config/config.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Every Go struct is described by a field table (common/json_schema.h), so
 * adding a field upstream added is a one-line change here.
 */
#include "daemon/config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/json_schema.h"
#include "common/json_util.h"
#include "common/log.h"

static const struct ks_schema_field tls_fields[] = {
    KS_FIELD(struct ks_tls_options, "CACert", KS_T_STRING, ca_cert),
    KS_FIELD(struct ks_tls_options, "ServerCert", KS_T_STRING, server_cert),
    KS_FIELD(struct ks_tls_options, "ServerKey", KS_T_STRING, server_key),
    KS_FIELD(struct ks_tls_options, "ClientCert", KS_T_STRING, client_cert),
    KS_FIELD(struct ks_tls_options, "ClientKey", KS_T_STRING, client_key),
    KS_FIELD(struct ks_tls_options, "ClientAuthType", KS_T_STRING, client_auth_type),
    KS_FIELD(struct ks_tls_options, "SkipVerify", KS_T_BOOL, skip_verify),
};
static const struct ks_schema tls_schema = KS_SCHEMA("config.ServerTLSOptions", struct ks_tls_options, tls_fields);

static const struct ks_schema_field auth_fields[] = {
    KS_FIELD(struct ks_server_auth, "Type", KS_T_STRING, type),
    KS_FIELD_SUB(struct ks_server_auth, "TLSOptions", KS_T_STRUCT, tls, tls_schema),
};
static const struct ks_schema auth_schema = KS_SCHEMA("config.ServerAuth", struct ks_server_auth, auth_fields);

static const struct ks_schema_field logger_fields[] = {
    KS_FIELD(struct ks_logger_config, "Name", KS_T_STRING, name),
    KS_FIELD(struct ks_logger_config, "Format", KS_T_STRING, format),
    KS_FIELD(struct ks_logger_config, "Protocol", KS_T_STRING, protocol),
    KS_FIELD(struct ks_logger_config, "Server", KS_T_STRING, server),
    KS_FIELD(struct ks_logger_config, "WriteTimeout", KS_T_STRING, write_timeout),
    KS_FIELD(struct ks_logger_config, "ConnectTimeout", KS_T_STRING, connect_timeout),
    KS_FIELD(struct ks_logger_config, "Tag", KS_T_STRING, tag),
    KS_FIELD(struct ks_logger_config, "Workers", KS_T_INT, workers),
    KS_FIELD(struct ks_logger_config, "MaxConnectAttempts", KS_T_UINT16, max_connect_attempts),
};
static const struct ks_schema logger_schema = KS_SCHEMA("loggers.LoggerConfig", struct ks_logger_config, logger_fields);

static const struct ks_schema_field server_fields[] = {
    KS_FIELD(struct ks_server_config, "Address", KS_T_STRING, address),
    KS_FIELD_SUB(struct ks_server_config, "Authentication", KS_T_STRUCT, auth, auth_schema),
    KS_FIELD(struct ks_server_config, "LogFile", KS_T_STRING, log_file),
    KS_FIELD_SUB(struct ks_server_config, "Loggers", KS_T_ARRAY, loggers, logger_schema),
};
static const struct ks_schema server_schema = KS_SCHEMA("config.ServerConfig", struct ks_server_config, server_fields);

static const struct ks_schema_field rules_fields[] = {
    KS_FIELD(struct ks_rules_options, "Path", KS_T_STRING, path),
    KS_FIELD(struct ks_rules_options, "EnableChecksums", KS_T_BOOL, enable_checksums),
};
static const struct ks_schema rules_schema = KS_SCHEMA("config.RulesOptions", struct ks_rules_options, rules_fields);

static const struct ks_schema_field fw_fields[] = {
    KS_FIELD(struct ks_fw_options, "Firewall", KS_T_STRING, firewall),
    KS_FIELD(struct ks_fw_options, "ConfigPath", KS_T_STRING, config_path),
    KS_FIELD(struct ks_fw_options, "MonitorInterval", KS_T_STRING, monitor_interval),
    KS_FIELD(struct ks_fw_options, "QueueNum", KS_T_UINT16, queue_num),
    KS_FIELD(struct ks_fw_options, "QueueBypass", KS_T_BOOL, queue_bypass),
};
static const struct ks_schema fw_schema = KS_SCHEMA("config.FwOptions", struct ks_fw_options, fw_fields);

static const struct ks_schema_field tasks_fields[] = {
    KS_FIELD(struct ks_tasks_options, "ConfigPath", KS_T_STRING, config_path),
};
static const struct ks_schema tasks_schema = KS_SCHEMA("config.TasksOptions", struct ks_tasks_options, tasks_fields);

static const struct ks_schema_field internal_fields[] = {
    KS_FIELD(struct ks_internal_options, "GCPercent", KS_T_INT, gc_percent),
    KS_FIELD(struct ks_internal_options, "FlushConnsOnStart", KS_T_BOOL, flush_conns_on_start),
};
static const struct ks_schema internal_schema = KS_SCHEMA("config.InternalOptions", struct ks_internal_options, internal_fields);

static const struct ks_schema_field audit_fields[] = {
    KS_FIELD(struct ks_audit_config, "AudispSocketPath", KS_T_STRING, audisp_socket_path),
};
static const struct ks_schema audit_schema = KS_SCHEMA("audit.Config", struct ks_audit_config, audit_fields);

static const struct ks_schema_field ebpf_fields[] = {
    KS_FIELD(struct ks_ebpf_config, "ModulesPath", KS_T_STRING, modules_path),
    KS_FIELD(struct ks_ebpf_config, "RingBuffSize", KS_T_INT, ring_buff_size),
    KS_FIELD(struct ks_ebpf_config, "EventsWorkers", KS_T_INT, events_workers),
    KS_FIELD(struct ks_ebpf_config, "QueueEventsSize", KS_T_INT, queue_events_size),
};
static const struct ks_schema ebpf_schema = KS_SCHEMA("ebpf.Config", struct ks_ebpf_config, ebpf_fields);

static const struct ks_schema_field stats_fields[] = {
    KS_FIELD(struct ks_stats_config, "MaxEvents", KS_T_INT, max_events),
    KS_FIELD(struct ks_stats_config, "MaxStats", KS_T_INT, max_stats),
    KS_FIELD(struct ks_stats_config, "Workers", KS_T_INT, workers),
};
static const struct ks_schema stats_schema = KS_SCHEMA("statistics.StatsConfig", struct ks_stats_config, stats_fields);

static const struct ks_schema_field config_fields[] = {
    KS_FIELD(struct ks_config, "LogLevel", KS_T_OPT_INT32, log_level),
    KS_FIELD(struct ks_config, "Firewall", KS_T_STRING, firewall),
    KS_FIELD(struct ks_config, "DefaultAction", KS_T_STRING, default_action),
    KS_FIELD(struct ks_config, "DefaultDuration", KS_T_STRING, default_duration),
    KS_FIELD(struct ks_config, "ProcMonitorMethod", KS_T_STRING, proc_monitor_method),
    KS_FIELD_SUB(struct ks_config, "FwOptions", KS_T_STRUCT, fw_options, fw_schema),
    KS_FIELD_SUB(struct ks_config, "Audit", KS_T_STRUCT, audit, audit_schema),
    KS_FIELD_SUB(struct ks_config, "Ebpf", KS_T_STRUCT, ebpf, ebpf_schema),
    KS_FIELD_SUB(struct ks_config, "Server", KS_T_STRUCT, server, server_schema),
    KS_FIELD_SUB(struct ks_config, "Rules", KS_T_STRUCT, rules, rules_schema),
    KS_FIELD_SUB(struct ks_config, "Internal", KS_T_STRUCT, internal, internal_schema),
    KS_FIELD_SUB(struct ks_config, "Stats", KS_T_STRUCT, stats, stats_schema),
    KS_FIELD_SUB(struct ks_config, "Tasks", KS_T_STRUCT, tasks, tasks_schema),
    KS_FIELD(struct ks_config, "InterceptUnknown", KS_T_BOOL, intercept_unknown),
    KS_FIELD(struct ks_config, "LogUTC", KS_T_BOOL, log_utc),
    KS_FIELD(struct ks_config, "LogMicro", KS_T_BOOL, log_micro),
};
static const struct ks_schema config_schema = KS_SCHEMA("config.Config", struct ks_config, config_fields);

void ks_config_free(struct ks_config *cfg)
{
    ks_schema_free(&config_schema, cfg);
    memset(cfg, 0, sizeof(*cfg));
}

int ks_config_parse(const char *json, size_t len, struct ks_config *out,
                    char *err, size_t errlen)
{
    return ks_schema_decode_buf(&config_schema, json, len, out, err, errlen);
}

/* A config is sound if it parses: shared by the backup and the fallback read. */
static bool config_sound(const char *text, size_t len)
{
    struct ks_config c;
    char e[512];
    if (!ks_check_usable(text, len) || ks_config_parse(text, len, &c, e, sizeof(e)) < 0)
        return false;
    ks_config_free(&c);
    return true;
}

int ks_config_load(const char *path, struct ks_config *out, char *err,
                   size_t errlen)
{
    char e[512];
    size_t len;

    memset(out, 0, sizeof(*out));
    char *raw = ks_read_file_or_backup(path, KS_CONFIG_MAX_SIZE, config_sound, &len, e,
                                       sizeof(e));
    if (raw == NULL) {
        snprintf(err, errlen, "Error loading configuration %s: %s", path, e);
        return -1;
    }
    if (len == 0) {
        free(raw);
        snprintf(err, errlen, "Error loading configuration %s: empty file", path);
        return -1;
    }
    int ret = ks_config_parse(raw, len, out, e, sizeof(e));
    free(raw);
    if (ret < 0)
        snprintf(err, errlen, "Error parsing configuration %s: %s", path, e);
    return ret;
}

int ks_config_reload(const char *path, struct ks_config *cfg, char *err,
                     size_t errlen)
{
    struct ks_config fresh;
    if (ks_config_load(path, &fresh, err, errlen) < 0)
        return -1;
    ks_config_free(cfg);
    *cfg = fresh;
    return 0;
}

int ks_config_save_raw(const char *path, const char *raw, size_t len,
                       char *err, size_t errlen)
{
    struct ks_config tmp;
    char e[512];

    if (ks_config_parse(raw, len, &tmp, e, sizeof(e)) < 0) {
        snprintf(err, errlen, "Error parsing configuration: %s", e);
        return -1;
    }
    ks_config_free(&tmp);

    if (chmod(path, 0600) < 0)
        ks_warning("unable to set permissions to default config: %s",
                   strerror(errno));
    if (ks_write_file_safe(path, raw, len, 0644, config_sound, e, sizeof(e)) < 0) {
        ks_error("writing configuration to disk: %s", e);
        snprintf(err, errlen, "%s", e);
        return -1;
    }
    return 0;
}

char *ks_config_to_json(const struct ks_config *cfg, bool pretty)
{
    cJSON *root = ks_schema_encode(&config_schema, cfg);
    if (root == NULL)
        return NULL;
    char *out = ks_json_print_go(root, pretty);
    cJSON_Delete(root);
    return out;
}

bool ks_config_equal(const struct ks_config *a, const struct ks_config *b)
{
    return ks_schema_equal(&config_schema, a, b);
}
