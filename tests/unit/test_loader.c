/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Rule loader tests: a port of upstream's daemon/rule/loader_test.go and
 * rule_test.go, plus the phase 1 acceptance criteria.
 */
#include "daemon/rules/loader.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "tests/harness.h"

#define TESTDATA KS_FIXTURES_DIR "/upstream/rules"

static char tmpdir[64];
static int64_t fake_now;

static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

static struct ks_process proc = {.pid = 12345, .path = "/usr/bin/opensnitchd"};
static struct ks_conn conn;

static void restore_connection(void)
{
    memset(&conn, 0, sizeof(conn));
    conn.protocol = "TCP";
    ks_ip_parse("185.53.178.14", &conn.dst_ip);
    conn.dst_port = 443;
    conn.dst_host = "opensnitch.io";
    conn.process = &proc;
    conn.uid = 666;
    proc.path = "/usr/bin/opensnitchd";
}

static struct ks_rule *make_rule(const char *name, const char *action,
                                 const char *duration, const char *type,
                                 const char *operand, const char *data)
{
    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = (char *)type;
    op.operand = (char *)operand;
    op.data = (char *)data;
    return ks_rule_create(name, "rule description", true, false, false, action,
                          duration, &op);
}

static void copy_file(const char *src, const char *dst)
{
    char err[256];
    size_t len;
    char *raw = ks_read_file(src, 1 << 20, &len, err, sizeof(err));
    if (raw != NULL)
        ks_write_file(dst, raw, len, 0644, err, sizeof(err));
    free(raw);
}

/* Runs the loop until `cond` holds or `ms` milliseconds pass. */
static void spin(struct ks_evloop *loop, int ms)
{
    for (int i = 0; i < ms / 10; i++)
        ks_evloop_run_once(loop, 10);
}

static void rm_tree(const char *dir)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "could not remove %s\n", dir);
}

/* ---- TestRuleLoader ----------------------------------------------------- */

TEST(rule_loader)
{
    char err[512];
    struct ks_evloop *loop = ks_evloop_new();
    CHECK(loop != NULL);
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1000;
    struct ks_loader *l = ks_loader_new(loop, NULL, false);
    CHECK(l != NULL);

    CHECK(ks_loader_load(l, "/non/existent/path/", err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "does not exist");

    CHECK_MSG(ks_loader_load(l, TESTDATA, err, sizeof(err)) == 0, "%s", err);
    /* 6 valid rules, 2 invalid (bad regexps). */
    CHECK_INT_EQ(ks_loader_num_rules(l), 6);

    CHECK(ks_loader_add(l, make_rule("000-xxx-name", "allow", "1s", "simple",
                                     "true", ""), false, err, sizeof(err)) == 0);
    CHECK_INT_EQ(ks_loader_num_rules(l), 7);

    /* auto deletion of the temporary rule */
    fake_now += 2 * KS_SECOND;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(ks_loader_num_rules(l), 6);

    CHECK(ks_loader_add(l, make_rule("000-aaa-name", "allow", "until restart",
                                     "simple", "true", ""), false, err,
                        sizeof(err)) == 0);
    CHECK_INT_EQ(ks_loader_num_rules(l), 7);

    /* testRulesOrder */
    CHECK_STR_EQ(ks_loader_rule_at(l, 0)->name, "000-aaa-name");
    CHECK_STR_EQ(ks_loader_rule_at(l, 1)->name, "000-allow-chrome");
    CHECK_STR_EQ(ks_loader_rule_at(l, 2)->name, "001-deny-chrome");

    /* testFindMatch */
    restore_connection();
    proc.path = "/opt/google/chrome/chrome";
    const struct ks_rule *m = ks_loader_find_first_match(l, &conn);
    CHECK(m != NULL);
    CHECK_STR_EQ(m->name, "000-allow-chrome"); /* precedence */

    struct ks_rule *r = (struct ks_rule *)ks_loader_get(l, "000-allow-chrome");
    r->precedence = false;
    m = ks_loader_find_first_match(l, &conn);
    CHECK_STR_EQ(m->name, "001-deny-chrome"); /* deny */

    r = (struct ks_rule *)ks_loader_get(l, "001-deny-chrome");
    free(r->action);
    r->action = strdup("allow");
    m = ks_loader_find_first_match(l, &conn);
    CHECK_STR_EQ(m->name, "001-deny-chrome"); /* the last allow wins */

    /* testFindEnabled */
    r->enabled = false;
    m = ks_loader_find_first_match(l, &conn);
    CHECK(m != NULL);
    CHECK_STR_EQ(m->name, "000-allow-chrome");

    /* testDurationChange: changing the duration of a temporary rule doesn't
     * let the old timer delete the new one. */
    CHECK(ks_loader_replace(l, make_rule("000-aaa-name", "allow", "2s", "simple",
                                         "true", ""), false, err, sizeof(err)) == 0);
    CHECK(ks_loader_replace(l, make_rule("000-aaa-name", "allow", "1h", "simple",
                                         "true", ""), false, err, sizeof(err)) == 0);
    fake_now += 4 * KS_SECOND;
    ks_evloop_fire_due(loop);
    CHECK(ks_loader_get(l, "000-aaa-name") != NULL);
    fake_now += KS_HOUR;
    ks_evloop_fire_due(loop);
    CHECK(ks_loader_get(l, "000-aaa-name") == NULL);

    ks_loader_free(l);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
}

/* Acceptance criterion: a rule with duration 30s disappears after 30s. */
TEST(rule_with_30s_duration_expires_after_30s)
{
    char err[512];
    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 5 * KS_SECOND;
    struct ks_loader *l = ks_loader_new(loop, NULL, false);

    CHECK(ks_loader_add(l, make_rule("temp-30s", "deny", "30s", "simple",
                                     "dest.port", "443"), false, err,
                        sizeof(err)) == 0);
    restore_connection();
    CHECK(ks_loader_find_first_match(l, &conn) != NULL);

    fake_now += 30 * KS_SECOND - 1;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(ks_loader_num_rules(l), 1);
    CHECK(ks_loader_find_first_match(l, &conn) != NULL);

    fake_now += 1;
    ks_evloop_fire_due(loop);
    CHECK_INT_EQ(ks_loader_num_rules(l), 0);
    CHECK(ks_loader_find_first_match(l, &conn) == NULL);

    ks_loader_free(l);
    ks_evloop_free(loop);
}

/* The same, with the real clock and the loop's timerfd (1s, as upstream). */
TEST(temporary_rule_expires_in_real_time)
{
    char err[512];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, false);
    CHECK(ks_loader_add(l, make_rule("temp-1s", "allow", "1s", "simple", "true", ""),
                        false, err, sizeof(err)) == 0);
    int64_t start = ks_evloop_now(loop);
    while (ks_loader_num_rules(l) == 1 && ks_evloop_now(loop) - start < 3 * KS_SECOND)
        ks_evloop_run_once(loop, 100);
    int64_t took = ks_evloop_now(loop) - start;
    CHECK_INT_EQ(ks_loader_num_rules(l), 0);
    CHECK_MSG(took >= KS_SECOND - 5 * KS_MILLISECOND, "expired after %lld ms",
              (long long)(took / KS_MILLISECOND));
    ks_loader_free(l);
    ks_evloop_free(loop);
}

/* ---- TestRuleLoaderInvalidRegexp ---------------------------------------- */

TEST(rule_loader_invalid_regexp)
{
    char err[512];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, true);

    CHECK(ks_loader_load_rule(l, TESTDATA "/invalid-regexp.json", err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "(1) Error compiling rule: error parsing regexp");
    CHECK(ks_loader_load_rule(l, TESTDATA "/invalid-regexp-list.json", err,
                              sizeof(err)) == -1);
    CHECK_STR_HAS(err, "(1) Error compiling list rule");

    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = "list";
    op.operand = "list";
    op.data = "[{\"type\": \"regexp\", \"operand\": \"process.path\", \"sensitive\": "
              "false, \"data\": \"^(/di(rmngr)$\"}, {\"type\": \"simple\", \"operand\": "
              "\"dest.port\", \"data\": \"53\", \"sensitive\": false}]";
    struct ks_rule *r = ks_rule_create("invalid-regexp", "invalid rule description",
                                       true, false, false, "allow", "30m", &op);
    CHECK(ks_loader_replace(l, r, false, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "(2) error compiling list rule");
    CHECK_INT_EQ(ks_loader_num_rules(l), 0);

    ks_loader_free(l);
    ks_evloop_free(loop);
}

/* ---- TestRuleLoaderList -------------------------------------------------- */

TEST(rule_loader_list)
{
    static const struct {
        const char *name, *file;
    } rules[] = {
        {"rule-with-operator-list", "/rule-operator-list.json"},
        {"rule-disabled-with-operators-list-as-json-string",
         "/rule-disabled-operator-list.json"},
        {"rule-disabled-with-operators-list-expanded",
         "/rule-disabled-operator-list-expanded.json"},
        {"rule-with-operator-list-data-empty", "/rule-operator-list-data-empty.json"},
    };
    char err[512], path[256];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, true);

    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", TESTDATA, rules[i].file);
        CHECK_MSG(ks_loader_load_rule(l, path, err, sizeof(err)) == 0, "%s: %s",
                  path, err);
        const struct ks_rule *r = ks_loader_get(l, rules[i].name);
        CHECK_MSG(r != NULL, "%s not loaded", rules[i].name);
        CHECK_INT_EQ(r->operator.list.len, 2);
        const struct ks_operator *a = KS_ARRAY_ITEM(r->operator.list, struct ks_operator, 0);
        const struct ks_operator *b = KS_ARRAY_ITEM(r->operator.list, struct ks_operator, 1);
        CHECK_STR_EQ(a->type, "simple");
        CHECK_STR_EQ(a->operand, "process.path");
        CHECK_STR_EQ(a->data, "/usr/bin/telnet");
        CHECK_STR_EQ(b->type, "simple");
        CHECK_STR_EQ(b->operand, "dest.port");
        CHECK_STR_EQ(b->data, "53");
    }
    /* The deprecated JSON-in-data form is expanded and data emptied for
     * disabled rules. */
    CHECK_STR_EQ(ks_loader_get(l, rules[1].name)->operator.data, "");

    ks_loader_free(l);
    ks_evloop_free(loop);
}

/* ---- TestLiveReload ------------------------------------------------------ */

TEST(live_reload)
{
    char err[512], dst[256];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, true);
    char dir[128];
    snprintf(dir, sizeof(dir), "%s/live", tmpdir);
    CHECK(mkdir(dir, 0700) == 0);

    snprintf(dst, sizeof(dst), "%s/000-allow-chrome.json", dir);
    copy_file(TESTDATA "/000-allow-chrome.json", dst);
    snprintf(dst, sizeof(dst), "%s/001-deny-chrome.json", dir);
    copy_file(TESTDATA "/001-deny-chrome.json", dst);
    CHECK_MSG(ks_loader_load(l, dir, err, sizeof(err)) == 0, "%s", err);
    CHECK_INT_EQ(ks_loader_num_rules(l), 2);

    snprintf(dst, sizeof(dst), "%s/test-live-reload-remove.json", dir);
    copy_file(TESTDATA "/live_reload/test-live-reload-remove.json", dst);
    snprintf(dst, sizeof(dst), "%s/test-live-reload-delete.json", dir);
    copy_file(TESTDATA "/live_reload/test-live-reload-delete.json", dst);
    spin(loop, 200);
    CHECK_INT_EQ(ks_loader_num_rules(l), 4);

    snprintf(dst, sizeof(dst), "%s/test-live-reload-remove.json", dir);
    CHECK(unlink(dst) == 0);
    CHECK(ks_loader_delete(l, "test-live-reload-delete", err, sizeof(err)) == 0);
    spin(loop, 200);
    CHECK_INT_EQ(ks_loader_num_rules(l), 2);
    snprintf(dst, sizeof(dst), "%s/test-live-reload-delete.json", dir);
    CHECK(access(dst, F_OK) != 0); /* Delete() removed the file too */

    /* A modified file is reloaded. */
    snprintf(dst, sizeof(dst), "%s/001-deny-chrome.json", dir);
    size_t len;
    char *raw = ks_read_file(dst, 1 << 20, &len, err, sizeof(err));
    CHECK(raw != NULL);
    char *p = strstr(raw, "\"deny\"");
    CHECK(p != NULL);
    memcpy(p, "\"jeny\"", 6);
    CHECK(ks_write_file(dst, raw, len, 0644, err, sizeof(err)) == 0);
    free(raw);
    spin(loop, 200);
    CHECK_STR_EQ(ks_loader_get(l, "001-deny-chrome")->action, "jeny");

    ks_loader_free(l);
    ks_evloop_free(loop);
    rm_tree(dir);
}

/* ---- Add / Save / Delete -------------------------------------------------- */

TEST(add_save_and_delete)
{
    char err[512], dir[128], path[256];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, false);
    snprintf(dir, sizeof(dir), "%s/save", tmpdir);
    CHECK(mkdir(dir, 0700) == 0);
    CHECK(ks_loader_load(l, dir, err, sizeof(err)) == 0);

    /* "once" rules are not kept. */
    CHECK(ks_loader_add(l, make_rule("once-rule", "allow", "once", "simple",
                                     "true", ""), false, err, sizeof(err)) == 0);
    CHECK_INT_EQ(ks_loader_num_rules(l), 0);

    /* Saved as <path>/<name>.json, mode 0600, in Go's MarshalIndent form. */
    CHECK(ks_loader_add(l, make_rule("allow-<curl>", "allow", "always", "simple",
                                     "process.path", "/usr/bin/curl"), true,
                        err, sizeof(err)) == 0);
    snprintf(path, sizeof(path), "%s/allow-<curl>.json", dir);
    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK_INT_EQ(st.st_mode & 0777, 0600);
    size_t len;
    char *raw = ks_read_file(path, 1 << 20, &len, err, sizeof(err));
    CHECK(raw != NULL);
    CHECK_STR_HAS(raw, "{\n  \"created\": \"");
    CHECK_STR_HAS(raw, "\",\n  \"name\": \"allow-\\u003ccurl\\u003e\",\n");
    CHECK_STR_HAS(raw, "  \"operator\": {\n    \"operand\": \"process.path\",\n"
                       "    \"data\": \"/usr/bin/curl\",\n    \"type\": \"simple\",\n"
                       "    \"list\": null,\n    \"sensitive\": false\n  },\n"
                       "  \"enabled\": true,\n  \"precedence\": false,\n"
                       "  \"nolog\": false\n}");
    CHECK(strstr(raw, "\"updated\": \"\"") == NULL); /* Save stamps it */
    free(raw);

    /* Same name again: renamed with a suffix (setUniqueName). */
    CHECK(ks_loader_add(l, make_rule("allow-<curl>", "deny", "always", "simple",
                                     "true", ""), false, err, sizeof(err)) == 0);
    CHECK(ks_loader_get(l, "allow-<curl>-2") != NULL);
    CHECK(ks_loader_add(l, make_rule("allow-<curl>", "deny", "always", "simple",
                                     "true", ""), false, err, sizeof(err)) == 0);
    CHECK(ks_loader_get(l, "allow-<curl>-3") != NULL);
    CHECK_INT_EQ(ks_loader_num_rules(l), 3);

    /* Turning an "always" rule temporary removes it from disk. */
    CHECK(ks_loader_replace(l, make_rule("allow-<curl>", "allow", "until restart",
                                         "simple", "true", ""), false, err,
                            sizeof(err)) == 0);
    CHECK(access(path, F_OK) != 0);

    /* Delete of a non-"always" rule leaves the disk alone; of an unknown
     * rule is a no-op. */
    CHECK(ks_loader_delete(l, "allow-<curl>", err, sizeof(err)) == 0);
    CHECK(ks_loader_delete(l, "nope", err, sizeof(err)) == 0);
    CHECK_INT_EQ(ks_loader_num_rules(l), 2);

    /* Names with '/' can't be saved outside the rules directory. */
    CHECK(ks_loader_add(l, make_rule("../escape", "allow", "always", "simple",
                                     "true", ""), true, err, sizeof(err)) == -1);
    CHECK_STR_HAS(err, "invalid rule name");

    ks_loader_free(l);
    ks_evloop_free(loop);
    rm_tree(dir);
}

TEST(rule_json_round_trip)
{
    char err[512];
    size_t len;
    char *raw = ks_read_file(TESTDATA "/invalid-regexp-list.json", 1 << 20, &len,
                             err, sizeof(err));
    CHECK(raw != NULL);
    struct ks_rule *r = ks_rule_parse(raw, len, err, sizeof(err));
    CHECK_MSG(r != NULL, "%s", err);
    char *out = ks_rule_to_json(r);
    CHECK(out != NULL);
    cJSON *a = ks_json_parse(raw, len, err, sizeof(err));
    cJSON *b = ks_json_parse(out, strlen(out), err, sizeof(err));
    CHECK(a != NULL && b != NULL);
    /* Every field of the file survives (the rewrite adds "description" and
     * "nolog", which the file leaves at their zero value). */
    CHECK_MSG(ks_json_is_subset(a, b), "%s", out);
    cJSON_Delete(a);
    cJSON_Delete(b);
    free(out);
    free(raw);

    struct ks_rule *c = ks_rule_copy(r);
    CHECK(c != NULL);
    CHECK_STR_EQ(c->name, r->name);
    CHECK_INT_EQ(c->operator.list.len, 2);
    ks_rule_free(c);
    ks_rule_free(r);

    CHECK(ks_rule_parse("{\"enabled\": \"yes\"}", 18, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "enabled: expected bool");
    CHECK(ks_rule_parse("{\"operator\": {\"list\": {}}}", 26, err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "operator.list: expected array of rule.Operator");
}

TEST(rule_create_and_describe)
{
    struct ks_rule *r = make_rule("000-test-name", "allow", "once", "simple", "true", "");
    CHECK(r != NULL);
    CHECK_STR_EQ(r->name, "000-test-name");
    CHECK(r->enabled && !r->precedence);
    CHECK_STR_EQ(r->action, "allow");
    CHECK_STR_EQ(r->duration, "once");
    /* RFC 3339: 2006-01-02T15:04:05Z or ...+01:00 */
    CHECK(strlen(r->created) == 20 || strlen(r->created) == 25);
    CHECK(r->created[10] == 'T');
    char desc[256];
    ks_rule_describe(r, desc, sizeof(desc));
    CHECK_STR_EQ(desc, "[Enabled] 000-test-name: if(true is ''){ allow once }");
    ks_rule_free(r);
}

TEST(reload_replaces_everything)
{
    char err[512];
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_loader *l = ks_loader_new(loop, NULL, true);
    CHECK(ks_loader_add(l, make_rule("in-memory", "allow", "until restart",
                                     "simple", "true", ""), false, err,
                        sizeof(err)) == 0);
    CHECK(ks_loader_reload(l, "/nonexistent-kisnitch", err, sizeof(err)) == -1);
    CHECK_INT_EQ(ks_loader_num_rules(l), 1);
    CHECK(ks_loader_reload(l, TESTDATA, err, sizeof(err)) == 0);
    CHECK_INT_EQ(ks_loader_num_rules(l), 6);
    CHECK(ks_loader_get(l, "in-memory") == NULL);
    ks_loader_free(l);
    ks_evloop_free(loop);
}

int main(void)
{
    const char *base = getenv("TMPDIR");
    snprintf(tmpdir, sizeof(tmpdir), "%s/kisnitch-loader-XXXXXX",
             base != NULL && strlen(base) < 32 ? base : "/tmp");
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    ks_log_set_level(KS_LOG_FATAL + 1);

    RUN(rule_loader);
    RUN(rule_with_30s_duration_expires_after_30s);
    RUN(temporary_rule_expires_in_real_time);
    RUN(rule_loader_invalid_regexp);
    RUN(rule_loader_list);
    RUN(live_reload);
    RUN(add_save_and_delete);
    RUN(rule_json_round_trip);
    RUN(rule_create_and_describe);
    RUN(reload_replaces_everything);

    rm_tree(tmpdir);
    return harness_report();
}
