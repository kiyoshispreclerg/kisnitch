/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * system-fw.json (daemon/fw/sysfw.c): decoding with encoding/json's rules,
 * Serialize() to protobuf, Deserialize() as jsonpb writes it, the error
 * channel, and the file watcher.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/pb_util.h"
#include "daemon/evloop.h"
#include "daemon/fw/sysfw.h"
#include "tests/harness.h"

#define UPSTREAM_SYSFW KS_FIXTURES_DIR "/../../upstream/daemon/data/system-fw.json"

static int parse_str(const char *json, struct ks_sysfw *out, char *err, size_t errlen)
{
    return ks_sysfw_parse(json, strlen(json), out, err, errlen);
}

TEST(parses_upstream_example)
{
    char err[512];
    size_t len;
    char *raw = ks_read_file(UPSTREAM_SYSFW, KS_SYSFW_MAX_SIZE, &len, err, sizeof(err));
    CHECK_MSG(raw != NULL, "%s", err);
    struct ks_sysfw cfg;
    CHECK(ks_sysfw_parse(raw, len, &cfg, err, sizeof(err)) == 0);
    CHECK(cfg.enabled);
    CHECK_INT_EQ(cfg.version, 1);
    CHECK_INT_EQ(cfg.system_rules.len, 2);

    /* the legacy iptables rule */
    const struct ks_fw_chains_list *l0 = KS_SYSFW_RULES(&cfg, 0);
    CHECK(l0->rule != NULL);
    CHECK_STR_EQ(l0->rule->table, "mangle");
    CHECK_STR_EQ(l0->rule->chain, "OUTPUT");
    CHECK_STR_EQ(l0->rule->parameters, "-p icmp");
    CHECK(!l0->rule->enabled);
    CHECK_INT_EQ(l0->chains.len, 0);
    CHECK(l0->chains.non_nil);

    const struct ks_fw_chains_list *l1 = KS_SYSFW_RULES(&cfg, 1);
    CHECK(l1->rule == NULL);
    CHECK_INT_EQ(l1->chains.len, 12);
    const struct ks_fw_chain *out = NULL, *fwd = NULL;
    for (size_t i = 0; i < l1->chains.len; i++) {
        const struct ks_fw_chain *c = KS_SYSFW_CHAIN(l1, i);
        if (strcmp(c->name, "mangle_output") == 0)
            out = c;
        if (strcmp(c->name, "mangle_forward") == 0)
            fwd = c;
    }
    CHECK(out != NULL && fwd != NULL);
    CHECK_STR_EQ(out->family, "inet");
    CHECK_STR_EQ(out->type, "mangle");
    CHECK_STR_EQ(out->hook, "output");
    CHECK_INT_EQ(out->rules.len, 4);
    const struct ks_fw_rule *icmp = KS_SYSFW_RULE(out, 1);
    CHECK_STR_EQ(icmp->description, "Allow ICMP");
    CHECK(icmp->enabled);
    CHECK_INT_EQ(icmp->position, 0);
    const struct ks_fw_statement *st = KS_SYSFW_EXPR(icmp, 0)->statement;
    CHECK(st != NULL);
    CHECK_STR_EQ(st->name, "icmp");
    CHECK_STR_EQ(KS_SYSFW_VALUE(st, 0)->key, "type");
    CHECK_STR_EQ(KS_SYSFW_VALUE(st, 0)->value,
                 "echo-request,echo-reply,destination-unreachable");
    CHECK_STR_EQ(KS_SYSFW_RULE(fwd, 0)->uuid, "7d7394e1-100d-4b87-a90a-cd68c46edb0b");
    CHECK_STR_EQ(KS_SYSFW_RULE(fwd, 0)->target_parameters, "num 0");

    struct ks_sysfw copy;
    CHECK(ks_sysfw_copy(&copy, &cfg) == 0);
    CHECK(ks_schema_equal(&ks_sysfw_schema, &copy, &cfg));
    ks_sysfw_free(&copy);
    ks_sysfw_free(&cfg);
    free(raw);
}

TEST(go_decoding_rules)
{
    struct ks_sysfw cfg;
    char err[512];
    /* keys are case-insensitive; unknown ones are ignored */
    CHECK(parse_str("{\"enabled\": true, \"VERSION\": 2, \"Foo\": [1], \"systemrules\": "
                    "[{\"chains\": [{\"name\": \"x\", \"rules\": [{\"position\": \"12\", "
                    "\"expressions\": [{\"statement\": null}, {}]}]}]}]}",
                    &cfg, err, sizeof(err)) == 0);
    CHECK(cfg.enabled);
    CHECK_INT_EQ(cfg.version, 2);
    const struct ks_fw_chain *c = KS_SYSFW_CHAIN(KS_SYSFW_RULES(&cfg, 0), 0);
    CHECK_STR_EQ(c->name, "x");
    CHECK_STR_EQ(c->table, ""); /* absent strings are "" */
    CHECK(ks_fw_chain_is_invalid(c));
    const struct ks_fw_rule *r = KS_SYSFW_RULE(c, 0);
    CHECK_INT_EQ(r->position, 12);
    CHECK_INT_EQ(r->expressions.len, 2);
    CHECK(KS_SYSFW_EXPR(r, 0)->statement == NULL);
    CHECK(KS_SYSFW_EXPR(r, 1)->statement == NULL);
    CHECK(KS_SYSFW_RULES(&cfg, 0)->rule == NULL);
    ks_sysfw_free(&cfg);

    /* Position is `json:",string"`: it must be a quoted number */
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": {\"Position\": 0}}]}", &cfg, err,
                    sizeof(err)) < 0);
    CHECK_STR_HAS(err, "invalid use of ,string struct tag");
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": {\"Position\": \"-1\"}}]}", &cfg, err,
                    sizeof(err)) < 0);
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": {\"Position\": \"x\"}}]}", &cfg, err,
                    sizeof(err)) < 0);
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": {\"Position\": \"18446744073709551616\"}}]}",
                    &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": {\"Position\": \"18446744073709551615\"}}]}",
                    &cfg, err, sizeof(err)) == 0);
    CHECK(KS_SYSFW_RULES(&cfg, 0)->rule->position == UINT64_MAX);
    ks_sysfw_free(&cfg);

    /* wrong types */
    CHECK(parse_str("{\"Version\": 1.5}", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{\"Version\": -1}", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{\"Enabled\": \"true\"}", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{\"SystemRules\": {}}", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{\"SystemRules\": [{\"Rule\": []}]}", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("[]", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("{", &cfg, err, sizeof(err)) < 0);
    CHECK(parse_str("", &cfg, err, sizeof(err)) < 0);
    /* null leaves things as they are */
    CHECK(parse_str("null", &cfg, err, sizeof(err)) == 0);
    CHECK(!cfg.enabled && cfg.system_rules.len == 0);
    ks_sysfw_free(&cfg);
}

/* A small configuration and what golang/protobuf's jsonpb writes for it
 * (derived from jsonpb/encode.go: fields in proto order, "key": value,
 * uint64 quoted, unset messages null with EmitDefaults, empty lists as a
 * bracket pair on two lines). */
static const char small_json[] =
    "{\"Enabled\": true, \"Version\": 1, \"SystemRules\": [{\"Chains\": [{\"Name\": "
    "\"filter_input\", \"Table\": \"opensnitch\", \"Family\": \"inet\", \"Type\": "
    "\"filter\", \"Hook\": \"input\", \"Policy\": \"drop\", \"Rules\": [{\"UUID\": \"u1\", "
    "\"Enabled\": true, \"Position\": \"3\", \"Description\": \"<ssh> & co\", "
    "\"Expressions\": [{\"Statement\": {\"Op\": \"\", \"Name\": \"tcp\", \"Values\": "
    "[{\"Key\": \"dport\", \"Value\": \"22\"}]}}], \"Target\": \"accept\"}]}]}]}";

static const char small_defaults[] =
    "{\n"
    "  \"Enabled\": true,\n"
    "  \"Version\": 1,\n"
    "  \"SystemRules\": [\n"
    "    {\n"
    "      \"Rule\": null,\n"
    "      \"Chains\": [\n"
    "        {\n"
    "          \"Name\": \"filter_input\",\n"
    "          \"Table\": \"opensnitch\",\n"
    "          \"Family\": \"inet\",\n"
    "          \"Priority\": \"\",\n"
    "          \"Type\": \"filter\",\n"
    "          \"Hook\": \"input\",\n"
    "          \"Policy\": \"drop\",\n"
    "          \"Rules\": [\n"
    "            {\n"
    "              \"Table\": \"\",\n"
    "              \"Chain\": \"\",\n"
    "              \"UUID\": \"u1\",\n"
    "              \"Enabled\": true,\n"
    "              \"Position\": \"3\",\n"
    "              \"Description\": \"\\u003cssh\\u003e \\u0026 co\",\n"
    "              \"Parameters\": \"\",\n"
    "              \"Expressions\": [\n"
    "                {\n"
    "                  \"Statement\": {\n"
    "                    \"Op\": \"\",\n"
    "                    \"Name\": \"tcp\",\n"
    "                    \"Values\": [\n"
    "                      {\n"
    "                        \"Key\": \"dport\",\n"
    "                        \"Value\": \"22\"\n"
    "                      }\n"
    "                    ]\n"
    "                  }\n"
    "                }\n"
    "              ],\n"
    "              \"Target\": \"accept\",\n"
    "              \"TargetParameters\": \"\"\n"
    "            }\n"
    "          ]\n"
    "        }\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}";

static const char small_no_defaults[] =
    "{\n"
    "  \"Enabled\": true,\n"
    "  \"Version\": 1,\n"
    "  \"SystemRules\": [\n"
    "    {\n"
    "      \"Chains\": [\n"
    "        {\n"
    "          \"Name\": \"filter_input\",\n"
    "          \"Table\": \"opensnitch\",\n"
    "          \"Family\": \"inet\",\n"
    "          \"Type\": \"filter\",\n"
    "          \"Hook\": \"input\",\n"
    "          \"Policy\": \"drop\",\n"
    "          \"Rules\": [\n"
    "            {\n"
    "              \"UUID\": \"u1\",\n"
    "              \"Enabled\": true,\n"
    "              \"Position\": \"3\",\n"
    "              \"Description\": \"\\u003cssh\\u003e \\u0026 co\",\n"
    "              \"Expressions\": [\n"
    "                {\n"
    "                  \"Statement\": {\n"
    "                    \"Name\": \"tcp\",\n"
    "                    \"Values\": [\n"
    "                      {\n"
    "                        \"Key\": \"dport\",\n"
    "                        \"Value\": \"22\"\n"
    "                      }\n"
    "                    ]\n"
    "                  }\n"
    "                }\n"
    "              ],\n"
    "              \"Target\": \"accept\"\n"
    "            }\n"
    "          ]\n"
    "        }\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}";

TEST(serialize_and_deserialize)
{
    struct ks_sysfw cfg;
    char err[512];
    CHECK(parse_str(small_json, &cfg, err, sizeof(err)) == 0);
    struct ks_arena a = {0};
    Protocol__SysFirewall *pb = ks_sysfw_to_pb(&a, &cfg);
    CHECK(pb != NULL);
    CHECK(pb->enabled && pb->version == 1 && pb->n_systemrules == 1);
    CHECK(pb->systemrules[0]->rule == NULL);
    Protocol__FwRule *r = pb->systemrules[0]->chains[0]->rules[0];
    CHECK_INT_EQ(r->position, 3);
    CHECK_STR_EQ(r->expressions[0]->statement->values[0]->value, "22");

    /* through the wire and back */
    size_t len;
    uint8_t *buf = ks_pb_pack(&pb->base, &len);
    CHECK(buf != NULL);
    Protocol__SysFirewall *back = (Protocol__SysFirewall *)ks_pb_unpack(
        &protocol__sys_firewall__descriptor, buf, len);
    CHECK(back != NULL);

    char *with = ks_sysfw_pb_to_json(back, true);
    char *without = ks_sysfw_pb_to_json(back, false);
    CHECK_STR_EQ(with, small_defaults);
    CHECK_STR_EQ(without, small_no_defaults);

    /* what's written parses back to the same configuration */
    struct ks_sysfw again;
    CHECK(parse_str(with, &again, err, sizeof(err)) == 0);
    CHECK(ks_schema_equal(&ks_sysfw_schema, &cfg, &again));
    ks_sysfw_free(&again);

    /* an empty message */
    Protocol__SysFirewall empty = PROTOCOL__SYS_FIREWALL__INIT;
    char *e = ks_sysfw_pb_to_json(&empty, true);
    CHECK_STR_EQ(e, "{\n  \"Enabled\": false,\n  \"Version\": 0,\n  \"SystemRules\": [\n  ]\n}");
    free(e);
    e = ks_sysfw_pb_to_json(&empty, false);
    CHECK_STR_EQ(e, "{\n\n}");
    free(e);

    free(with);
    free(without);
    protobuf_c_message_free_unpacked(&back->base, NULL);
    free(buf);
    ks_arena_free(&a);
    ks_sysfw_free(&cfg);
}

TEST(errors_channel)
{
    struct ks_fw_errors q = {0};
    CHECK(ks_fw_errors_empty(&q));
    CHECK(ks_fw_errors_pop(&q) == NULL);
    char msg[32];
    for (int i = 0; i < KS_FW_ERRORS_CAP + 5; i++) {
        snprintf(msg, sizeof(msg), "e%d", i);
        ks_fw_errors_send(&q, msg);
    }
    /* full: the oldest go */
    char *first = ks_fw_errors_pop(&q);
    CHECK_STR_EQ(first, "e5");
    free(first);
    size_t n = 1;
    char *s;
    while ((s = ks_fw_errors_pop(&q)) != NULL) {
        n++;
        free(s);
    }
    CHECK_INT_EQ(n, KS_FW_ERRORS_CAP);
    ks_fw_errors_send(&q, "x");
    ks_fw_errors_clear(&q);
    CHECK(ks_fw_errors_empty(&q));
}

TEST(uuid)
{
    char a[KS_UUID_STRLEN], b[KS_UUID_STRLEN];
    CHECK(ks_fw_new_uuid(a, sizeof(a)) == 0);
    CHECK(ks_fw_new_uuid(b, sizeof(b)) == 0);
    CHECK_INT_EQ(strlen(a), 36);
    CHECK(strcmp(a, b) != 0);
    CHECK(a[8] == '-' && a[13] == '-' && a[18] == '-' && a[23] == '-');
    CHECK(a[14] == '4');
    CHECK(strchr("89ab", a[19]) != NULL);
}

static int preloads, reloads;
static void on_preload(void *d)
{
    (void)d;
    preloads++;
}
static void on_reload(void *d)
{
    (void)d;
    reloads++;
}

static void run_loop(struct ks_evloop *loop)
{
    for (int i = 0; i < 5; i++)
        ks_evloop_run_once(loop, 20);
}

TEST(file_and_watcher)
{
    char dir[] = "/tmp/ks-sysfw-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[256], err[256];
    snprintf(path, sizeof(path), "%s/system-fw.json", dir);
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_sysfw_conf c;
    preloads = reloads = 0;

    /* missing file: an error, nothing loaded */
    CHECK(ks_sysfw_conf_init(&c, loop, path, on_preload, on_reload, NULL) == 0);
    CHECK(ks_sysfw_conf_load(&c, false) < 0);
    CHECK_INT_EQ(preloads, 0);

    /* malformed: preloaded (old rules deleted), not loaded, but watched */
    CHECK(ks_write_file(path, "{", 1, 0644, err, sizeof(err)) == 0);
    CHECK(ks_sysfw_conf_load(&c, false) < 0);
    CHECK_INT_EQ(preloads, 1);
    CHECK_INT_EQ(reloads, 0);

    /* fixing it is noticed */
    CHECK(ks_write_file(path, small_json, strlen(small_json), 0644, err, sizeof(err)) == 0);
    run_loop(loop);
    CHECK(preloads >= 2);
    CHECK(reloads >= 1);
    CHECK(c.cfg.enabled);

    /* SaveConfiguration: 0600, applied by the watcher */
    int before = reloads;
    const char *raw = "{\"Enabled\": false, \"Version\": 1}";
    CHECK(ks_sysfw_conf_save(&c, raw, strlen(raw)) == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK_INT_EQ(st.st_mode & 0777, 0600);
    run_loop(loop);
    CHECK(reloads > before);
    CHECK(!c.cfg.enabled);

    ks_sysfw_conf_destroy(&c);
    ks_evloop_free(loop);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

int main(void)
{
    ks_log_set_level(KS_LOG_ERROR + 1);
    RUN(parses_upstream_example);
    RUN(go_decoding_rules);
    RUN(serialize_and_deserialize);
    RUN(errors_channel);
    RUN(uuid);
    RUN(file_and_watcher);
    return harness_report();
}
