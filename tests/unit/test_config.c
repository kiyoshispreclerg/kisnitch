/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests for daemon/config.c against the upstream sample configs in
 * tests/fixtures/upstream/ (see tools/sync-fixtures.sh).
 */
#include "daemon/config.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "tests/harness.h"

#define FIX(name) KS_FIXTURES_DIR "/upstream/" name

static const char *const upstream_configs[] = {
    FIX("default-config.json"),
    FIX("ui-testdata-default-config.json"),
    FIX("ui-testdata-config-invalid-procmon.json"),
};

static char tmpdir[64];

static void make_path(char *buf, size_t len, const char *name)
{
    snprintf(buf, len, "%s/%s", tmpdir, name);
}

static int write_str(const char *path, const char *s)
{
    char err[256];
    return ks_write_file(path, s, strlen(s), 0644, err, sizeof(err));
}

static int parse_str(const char *s, struct ks_config *cfg, char *err, size_t errlen)
{
    return ks_config_parse(s, strlen(s), cfg, err, errlen);
}

/* Every field of daemon/data/default-config.json, plus Go zero values for the
 * fields the file doesn't set. */
TEST(upstream_default_config_values)
{
    struct ks_config c;
    char err[512];
    CHECK_MSG(ks_config_load(FIX("default-config.json"), &c, err, sizeof(err)) == 0,
              "%s", err);

    CHECK_STR_EQ(c.server.address, "unix:///tmp/osui.sock");
    CHECK_STR_EQ(c.server.auth.type, "simple");
    CHECK_STR_EQ(c.server.auth.tls.ca_cert, "");
    CHECK_STR_EQ(c.server.auth.tls.server_cert, "");
    CHECK_STR_EQ(c.server.auth.tls.server_key, "");
    CHECK_STR_EQ(c.server.auth.tls.client_cert, "");
    CHECK_STR_EQ(c.server.auth.tls.client_key, "");
    CHECK(!c.server.auth.tls.skip_verify);
    CHECK_STR_EQ(c.server.auth.tls.client_auth_type, "no-client-cert");
    CHECK_STR_EQ(c.server.log_file, "/var/log/opensnitchd.log");
    CHECK(!c.server.loggers.non_nil);
    CHECK_INT_EQ(c.server.loggers.len, 0);

    CHECK_STR_EQ(c.default_action, "allow");
    CHECK_STR_EQ(c.default_duration, "once");
    CHECK(!c.intercept_unknown);
    CHECK_STR_EQ(c.proc_monitor_method, "ebpf");
    CHECK(c.log_level.set);
    CHECK_INT_EQ(c.log_level.value, 2);
    CHECK(c.log_utc);
    CHECK(!c.log_micro);
    CHECK_STR_EQ(c.firewall, "nftables");

    CHECK_STR_EQ(c.fw_options.firewall, "");
    CHECK_STR_EQ(c.fw_options.config_path, "/etc/opensnitchd/system-fw.json");
    CHECK_STR_EQ(c.fw_options.monitor_interval, "15s");
    CHECK_INT_EQ(c.fw_options.queue_num, 0);
    CHECK(c.fw_options.queue_bypass);

    CHECK_STR_EQ(c.rules.path, "/etc/opensnitchd/rules/");
    CHECK(!c.rules.enable_checksums);

    CHECK_STR_EQ(c.ebpf.modules_path, "");
    CHECK_INT_EQ(c.ebpf.ring_buff_size, 0);
    CHECK_INT_EQ(c.ebpf.events_workers, 8);
    CHECK_INT_EQ(c.ebpf.queue_events_size, 0);

    CHECK_STR_EQ(c.audit.audisp_socket_path, "");

    CHECK_INT_EQ(c.stats.max_events, 250);
    CHECK_INT_EQ(c.stats.max_stats, 25);
    CHECK_INT_EQ(c.stats.workers, 6);

    CHECK_INT_EQ(c.internal.gc_percent, 100);
    CHECK(c.internal.flush_conns_on_start);

    CHECK_STR_EQ(c.tasks.config_path, "");

    ks_config_free(&c);
}

TEST(upstream_testdata_values)
{
    struct ks_config c;
    char err[512];
    CHECK_MSG(ks_config_load(FIX("ui-testdata-config-invalid-procmon.json"), &c,
                             err, sizeof(err)) == 0, "%s", err);
    CHECK_STR_EQ(c.server.log_file, "/dev/stdout");
    CHECK_STR_EQ(c.server.auth.type, "tls-mutual");
    CHECK_STR_EQ(c.server.auth.tls.client_auth_type, "req-and-verify-cert");
    CHECK_STR_EQ(c.server.auth.tls.ca_cert, "/tmp/opensnitch/certs/unix-socket/ca-cert.pem");
    CHECK(c.log_level.set);
    CHECK_INT_EQ(c.log_level.value, 0);
    CHECK_STR_EQ(c.fw_options.monitor_interval, "25s");
    CHECK_STR_EQ(c.ebpf.modules_path, "/invalid/path/ebpf");
    CHECK_STR_EQ(c.audit.audisp_socket_path, "/var/run/audispd_events");
    CHECK_INT_EQ(c.internal.gc_percent, 75);
    CHECK(c.rules.enable_checksums);
    ks_config_free(&c);
}

/* Acceptance criterion: load, write back, and get a semantically equal
 * document. The rewrite has every key the original had, with the same value,
 * and only adds keys for fields left at Go's zero value (json.Marshal emits
 * every field). Parsing the rewrite yields the same config, and rewriting
 * that is byte-identical. */
TEST(upstream_configs_round_trip)
{
    for (size_t i = 0; i < sizeof(upstream_configs) / sizeof(upstream_configs[0]); i++) {
        const char *path = upstream_configs[i];
        char err[512];
        size_t len;

        char *raw = ks_read_file(path, KS_CONFIG_MAX_SIZE, &len, err, sizeof(err));
        CHECK_MSG(raw != NULL, "%s", err);
        cJSON *orig = ks_json_parse(raw, len, err, sizeof(err));
        free(raw);
        CHECK_MSG(orig != NULL, "%s: %s", path, err);

        struct ks_config a, b;
        CHECK_MSG(ks_config_load(path, &a, err, sizeof(err)) == 0, "%s", err);
        char *out1 = ks_config_to_json(&a, true);
        CHECK(out1 != NULL);

        cJSON *rewritten = ks_json_parse(out1, strlen(out1), err, sizeof(err));
        CHECK_MSG(rewritten != NULL, "%s", err);
        CHECK_MSG(ks_json_is_subset(orig, rewritten),
                  "%s: rewritten config lost or changed values:\n%s", path, out1);

        CHECK_MSG(parse_str(out1, &b, err, sizeof(err)) == 0, "%s", err);
        CHECK_MSG(ks_config_equal(&a, &b), "%s: reparsed config differs", path);
        char *out2 = ks_config_to_json(&b, true);
        CHECK(out2 != NULL);
        CHECK_STR_EQ(out1, out2);

        free(out1);
        free(out2);
        cJSON_Delete(orig);
        cJSON_Delete(rewritten);
        ks_config_free(&a);
        ks_config_free(&b);
    }
}

/* json.Marshal emits all fields in struct order; nil pointers/slices as null. */
TEST(marshal_matches_go_shape)
{
    struct ks_config c;
    char err[256];
    CHECK(parse_str("{}", &c, err, sizeof(err)) == 0);
    char *out = ks_config_to_json(&c, false);
    CHECK(out != NULL);
    CHECK_STR_EQ(out,
        "{\"LogLevel\":null,\"Firewall\":\"\",\"DefaultAction\":\"\","
        "\"DefaultDuration\":\"\",\"ProcMonitorMethod\":\"\","
        "\"FwOptions\":{\"Firewall\":\"\",\"ConfigPath\":\"\",\"MonitorInterval\":\"\","
        "\"QueueNum\":0,\"QueueBypass\":false},"
        "\"Audit\":{\"AudispSocketPath\":\"\"},"
        "\"Ebpf\":{\"ModulesPath\":\"\",\"RingBuffSize\":0,\"EventsWorkers\":0,"
        "\"QueueEventsSize\":0},"
        "\"Server\":{\"Address\":\"\",\"Authentication\":{\"Type\":\"\","
        "\"TLSOptions\":{\"CACert\":\"\",\"ServerCert\":\"\",\"ServerKey\":\"\","
        "\"ClientCert\":\"\",\"ClientKey\":\"\",\"ClientAuthType\":\"\","
        "\"SkipVerify\":false}},\"LogFile\":\"\",\"Loggers\":null},"
        "\"Rules\":{\"Path\":\"\",\"EnableChecksums\":false},"
        "\"Internal\":{\"GCPercent\":0,\"FlushConnsOnStart\":false},"
        "\"Stats\":{\"MaxEvents\":0,\"MaxStats\":0,\"Workers\":0},"
        "\"Tasks\":{\"ConfigPath\":\"\"},"
        "\"InterceptUnknown\":false,\"LogUTC\":false,\"LogMicro\":false}");
    free(out);
    ks_config_free(&c);
}

TEST(loggers_round_trip)
{
    const char *in =
        "{\"Server\":{\"Loggers\":[{\"Name\":\"syslog\",\"Format\":\"rfc5424\","
        "\"Protocol\":\"udp\",\"Server\":\"127.0.0.1:514\",\"WriteTimeout\":\"1s\","
        "\"ConnectTimeout\":\"5s\",\"Tag\":\"opensnitchd\",\"Workers\":4,"
        "\"MaxConnectAttempts\":3},{\"Name\":\"remote\"}]}}";
    struct ks_config a, b;
    char err[256];

    CHECK_MSG(parse_str(in, &a, err, sizeof(err)) == 0, "%s", err);
    CHECK(a.server.loggers.non_nil);
    CHECK_INT_EQ(a.server.loggers.len, 2);
    CHECK_STR_EQ(a.server.loggers.items[0].name, "syslog");
    CHECK_STR_EQ(a.server.loggers.items[0].server, "127.0.0.1:514");
    CHECK_STR_EQ(a.server.loggers.items[0].tag, "opensnitchd");
    CHECK_INT_EQ(a.server.loggers.items[0].workers, 4);
    CHECK_INT_EQ(a.server.loggers.items[0].max_connect_attempts, 3);
    CHECK_STR_EQ(a.server.loggers.items[1].name, "remote");
    CHECK_STR_EQ(a.server.loggers.items[1].format, "");

    char *out = ks_config_to_json(&a, false);
    CHECK(out != NULL);
    CHECK(parse_str(out, &b, err, sizeof(err)) == 0);
    CHECK(ks_config_equal(&a, &b));
    free(out);
    ks_config_free(&a);
    ks_config_free(&b);

    /* An empty array is not nil: it marshals back to []. */
    CHECK(parse_str("{\"Server\":{\"Loggers\":[]}}", &a, err, sizeof(err)) == 0);
    CHECK(a.server.loggers.non_nil);
    CHECK_INT_EQ(a.server.loggers.len, 0);
    out = ks_config_to_json(&a, false);
    CHECK_STR_HAS(out, "\"Loggers\":[]");
    free(out);
    ks_config_free(&a);
}

/* encoding/json semantics for null, case, duplicates and unknown keys. */
TEST(go_decoding_semantics)
{
    struct ks_config c;
    char err[256];

    /* Top-level null is a successful no-op in Go. */
    CHECK(parse_str("null", &c, err, sizeof(err)) == 0);
    CHECK_STR_EQ(c.default_action, "");
    CHECK(!c.log_level.set);
    ks_config_free(&c);

    /* null resets pointers and slices, and leaves everything else alone. */
    CHECK(parse_str("{\"LogLevel\":3,\"LogLevel\":null,\"Firewall\":\"iptables\","
                    "\"Firewall\":null,\"Server\":{\"Loggers\":[{}],\"Loggers\":null},"
                    "\"Stats\":null,\"LogUTC\":null}",
                    &c, err, sizeof(err)) == 0);
    CHECK(!c.log_level.set);
    CHECK_STR_EQ(c.firewall, "iptables");
    CHECK(!c.server.loggers.non_nil);
    CHECK_INT_EQ(c.server.loggers.len, 0);
    ks_config_free(&c);

    /* LogLevel 0 is set, unlike an absent LogLevel. */
    CHECK(parse_str("{\"LogLevel\":0}", &c, err, sizeof(err)) == 0);
    CHECK(c.log_level.set);
    CHECK_INT_EQ(c.log_level.value, 0);
    ks_config_free(&c);

    /* Keys match case-insensitively; the last duplicate wins. */
    CHECK(parse_str("{\"defaultaction\":\"deny\",\"DEFAULTDURATION\":\"always\","
                    "\"fwoptions\":{\"queuenum\":7},"
                    "\"ProcMonitorMethod\":\"ebpf\",\"ProcMonitorMethod\":\"proc\"}",
                    &c, err, sizeof(err)) == 0);
    CHECK_STR_EQ(c.default_action, "deny");
    CHECK_STR_EQ(c.default_duration, "always");
    CHECK_INT_EQ(c.fw_options.queue_num, 7);
    CHECK_STR_EQ(c.proc_monitor_method, "proc");
    ks_config_free(&c);

    /* Unknown keys are ignored, whatever their type. */
    CHECK(parse_str("{\"Bogus\":[1,{\"x\":null}],\"Server\":{\"Extra\":true},"
                    "\"DefaultAction\":\"reject\"}", &c, err, sizeof(err)) == 0);
    CHECK_STR_EQ(c.default_action, "reject");
    ks_config_free(&c);

    /* Integer limits. */
    CHECK(parse_str("{\"FwOptions\":{\"QueueNum\":65535},\"LogLevel\":-1,"
                    "\"Internal\":{\"GCPercent\":-1}}", &c, err, sizeof(err)) == 0);
    CHECK_INT_EQ(c.fw_options.queue_num, 65535);
    CHECK_INT_EQ(c.log_level.value, -1);
    CHECK_INT_EQ(c.internal.gc_percent, -1);
    ks_config_free(&c);

    /* Strings keep escapes and UTF-8. */
    CHECK(parse_str("{\"Rules\":{\"Path\":\"/tmp/r\\u00e9gles\\\\x\"}}", &c, err,
                    sizeof(err)) == 0);
    CHECK_STR_EQ(c.rules.path, "/tmp/r\xc3\xa9gles\\x");
    ks_config_free(&c);
}

/* Acceptance criterion: invalid configs fail with a clear message (and,
 * under `make asan`, without memory errors). */
TEST(invalid_configs_are_rejected_clearly)
{
    static const struct {
        const char *json;
        const char *msg;
    } cases[] = {
        {"", "line 1, column 1"},
        {"{", "line 1, column 1"},
        {"{\n  \"LogLevel\": 2,\n  \"Firewall\": nftables\n}", "line 3, column 15"},
        {"{\"DefaultAction\": \"allow\",}", "line 1"},
        {"{} {}", "line 1, column 4"},
        {"[]", "(root): expected config.Config, got array"},
        {"\"x\"", "(root): expected config.Config, got string"},
        {"{\"LogLevel\": \"2\"}", "LogLevel: expected int32, got string"},
        {"{\"LogLevel\": 3000000000}", "LogLevel: number 3000000000 does not fit in int32"},
        {"{\"LogLevel\": 1.5}", "LogLevel: number 1.5 does not fit in int32"},
        {"{\"FwOptions\": {\"QueueNum\": 70000}}",
         "FwOptions.QueueNum: number 70000 does not fit in uint16"},
        {"{\"FwOptions\": {\"QueueNum\": -1}}",
         "FwOptions.QueueNum: number -1 does not fit in uint16"},
        {"{\"FwOptions\": {\"QueueBypass\": \"true\"}}",
         "FwOptions.QueueBypass: expected bool, got string"},
        {"{\"InterceptUnknown\": 1}", "InterceptUnknown: expected bool, got number"},
        {"{\"Stats\": {\"MaxEvents\": 1e300}}", "Stats.MaxEvents: number 1.0000000000000001e+300 does not fit in int"},
        {"{\"Server\": []}", "Server: expected config.ServerConfig, got array"},
        {"{\"Server\": {\"Authentication\": {\"TLSOptions\": {\"SkipVerify\": \"no\"}}}}",
         "Server.Authentication.TLSOptions.SkipVerify: expected bool, got string"},
        {"{\"Server\": {\"Address\": 1}}", "Server.Address: expected string, got number"},
        {"{\"Server\": {\"Loggers\": {}}}",
         "Server.Loggers: expected array of loggers.LoggerConfig, got object"},
        {"{\"Server\": {\"Loggers\": [{}, {\"Workers\": \"x\"}]}}",
         "Server.Loggers[1].Workers: expected int, got string"},
        {"{\"Server\": {\"Loggers\": [1]}}",
         "Server.Loggers[0]: expected loggers.LoggerConfig, got number"},
        {"{\"Tasks\": \"/etc/tasks\"}", "Tasks: expected config.TasksOptions, got string"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct ks_config c;
        char err[256] = "";
        int rc = parse_str(cases[i].json, &c, err, sizeof(err));
        CHECK_MSG(rc == -1, "case %zu (%s): expected failure", i, cases[i].json);
        CHECK_STR_HAS(err, cases[i].msg);
        /* A failed parse leaves a zeroed, freeable config. */
        CHECK(c.default_action == NULL && c.server.loggers.items == NULL);
        ks_config_free(&c);
    }
}

TEST(deeply_nested_input_does_not_crash)
{
    size_t depth = 100000;
    char *s = malloc(2 * depth + 1);
    CHECK(s != NULL);
    memset(s, '[', depth);
    memset(s + depth, ']', depth);
    s[2 * depth] = '\0';

    struct ks_config c;
    char err[256];
    CHECK(ks_config_parse(s, 2 * depth, &c, err, sizeof(err)) == -1);
    free(s);
}

TEST(load_errors)
{
    struct ks_config c;
    char err[512], path[128];

    CHECK(ks_config_load("/nonexistent/kisnitch.json", &c, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "Error loading configuration /nonexistent/kisnitch.json");
    CHECK_STR_HAS(err, "No such file or directory");

    make_path(path, sizeof(path), "empty.json");
    CHECK(write_str(path, "") == 0);
    CHECK(ks_config_load(path, &c, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "empty file");

    make_path(path, sizeof(path), "broken.json");
    CHECK(write_str(path, "{\n\"Server\": {\n") == 0);
    CHECK(ks_config_load(path, &c, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "Error parsing configuration");
    CHECK_STR_HAS(err, "broken.json: line 2");

    /* A directory is not a config. */
    CHECK(ks_config_load(tmpdir, &c, err, sizeof(err)) == -1);
}

/* Acceptance criterion: an invalid config doesn't take the process down; on
 * reload the previous configuration stays in effect, as upstream. */
TEST(reload_keeps_previous_config_on_error)
{
    struct ks_config c;
    char err[512], path[128];

    make_path(path, sizeof(path), "reload.json");
    CHECK(write_str(path, "{\"DefaultAction\":\"deny\",\"LogLevel\":1}") == 0);
    CHECK(ks_config_load(path, &c, err, sizeof(err)) == 0);

    CHECK(write_str(path, "{\"DefaultAction\":\"allow\",\"LogLevel\":\"x\"}") == 0);
    CHECK(ks_config_reload(path, &c, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "LogLevel: expected int32");
    CHECK_STR_EQ(c.default_action, "deny");

    CHECK(write_str(path, "") == 0);
    CHECK(ks_config_reload(path, &c, err, sizeof(err)) == -1);
    CHECK_STR_EQ(c.default_action, "deny");

    CHECK(write_str(path, "{\"DefaultAction\":\"allow\"}") == 0);
    CHECK(ks_config_reload(path, &c, err, sizeof(err)) == 0);
    CHECK_STR_EQ(c.default_action, "allow");
    CHECK(!c.log_level.set);

    ks_config_free(&c);
}

TEST(save_raw_validates_and_writes_verbatim)
{
    char err[512], path[128];
    size_t len;
    struct stat st;

    make_path(path, sizeof(path), "save.json");
    CHECK(write_str(path, "{\"DefaultAction\":\"deny\"}") == 0);

    const char *bad = "{\"DefaultAction\": 1}";
    CHECK(ks_config_save_raw(path, bad, strlen(bad), err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "DefaultAction: expected string");
    char *now = ks_read_file(path, 4096, &len, err, sizeof(err));
    CHECK_STR_EQ(now, "{\"DefaultAction\":\"deny\"}");
    free(now);

    const char *good = "{\n  \"DefaultAction\": \"allow\", \"Unknown\": 1\n}\n";
    CHECK_MSG(ks_config_save_raw(path, good, strlen(good), err, sizeof(err)) == 0,
              "%s", err);
    now = ks_read_file(path, 4096, &len, err, sizeof(err));
    CHECK_STR_EQ(now, good);
    free(now);
    CHECK(stat(path, &st) == 0);
    CHECK_INT_EQ(st.st_mode & 0777, 0600);
}

TEST(free_is_idempotent)
{
    struct ks_config c;
    memset(&c, 0, sizeof(c));
    ks_config_free(&c);
    ks_config_free(&c);
    CHECK(ks_config_equal(&c, &c));
}

static void rm_tmpdir(void)
{
    static const char *const files[] = {"empty.json", "broken.json",
                                        "reload.json", "save.json"};
    char path[128];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        make_path(path, sizeof(path), files[i]);
        unlink(path);
    }
    rmdir(tmpdir);
}

int main(void)
{
    const char *base = getenv("TMPDIR");
    snprintf(tmpdir, sizeof(tmpdir), "%s/kisnitch-test-XXXXXX",
             base != NULL && strlen(base) < 32 ? base : "/tmp");
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    /* save_raw logs a warning when chmod fails; keep test output clean. */
    ks_log_set_level(KS_LOG_FATAL + 1);

    RUN(upstream_default_config_values);
    RUN(upstream_testdata_values);
    RUN(upstream_configs_round_trip);
    RUN(marshal_matches_go_shape);
    RUN(loggers_round_trip);
    RUN(go_decoding_semantics);
    RUN(invalid_configs_are_rejected_clearly);
    RUN(deeply_nested_input_does_not_crash);
    RUN(load_errors);
    RUN(reload_keeps_previous_config_on_error);
    RUN(save_raw_validates_and_writes_verbatim);
    RUN(free_is_idempotent);

    rm_tmpdir();
    return harness_report();
}
