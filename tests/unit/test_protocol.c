/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/protocol.h"

#include <stdlib.h>
#include <time.h>

#include "common/log.h"
#include "daemon/procmon/process.h"
#include "daemon/rules/rule.h"
#include "tests/harness.h"

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    char *buf = malloc(65536);
    size_t n = buf ? fread(buf, 1, 65535, f) : 0;
    fclose(f);
    if (buf)
        buf[n] = '\0';
    *len = n;
    return buf;
}

static struct ks_rule *load_rule(const char *name)
{
    char path[512], err[256];
    snprintf(path, sizeof(path), "%s/upstream/rules/%s", KS_FIXTURES_DIR, name);
    size_t len;
    char *json = slurp(path, &len);
    if (json == NULL)
        return NULL;
    struct ks_rule *r = ks_rule_parse(json, len, err, sizeof(err));
    free(json);
    return r;
}

/* Packs and unpacks, as the wire would. */
static Protocol__Rule *roundtrip_rule(const Protocol__Rule *pr)
{
    size_t len;
    uint8_t *buf = ks_pb_pack(&pr->base, &len);
    if (buf == NULL)
        return NULL;
    Protocol__Rule *out = (Protocol__Rule *)ks_pb_unpack(&protocol__rule__descriptor,
                                                         buf, len);
    free(buf);
    return out;
}

TEST(rfc3339)
{
    int64_t t;
    CHECK(ks_parse_rfc3339("2023-10-03T18:06:52+01:00", &t) == 0);
    CHECK_INT_EQ(t, 1696352812);
    CHECK(ks_parse_rfc3339("2020-12-13T18:06:52.209804547+01:00", &t) == 0);
    CHECK_INT_EQ(t, 1607879212);
    CHECK(ks_parse_rfc3339("2024-02-29T23:59:59-03:30", &t) == 0);
    CHECK_INT_EQ(t, 1709263799);
    CHECK(ks_parse_rfc3339("1969-12-31T23:59:59Z", &t) == 0);
    CHECK_INT_EQ(t, -1);
    CHECK(ks_parse_rfc3339("2023-02-29T00:00:00Z", &t) < 0);  /* not a leap year */
    CHECK(ks_parse_rfc3339("2023-10-03 18:06:52Z", &t) < 0);
    CHECK(ks_parse_rfc3339("2023-10-03T24:00:00Z", &t) < 0);
    CHECK(ks_parse_rfc3339("2023-10-03T18:06:52", &t) < 0);
    CHECK(ks_parse_rfc3339("2023-10-03T18:06:52.Z", &t) < 0);
    CHECK(ks_parse_rfc3339("2023-10-03T18:06:52+0100", &t) < 0);
    CHECK(ks_parse_rfc3339("", &t) < 0);
}

TEST(rule_serialize_simple)
{
    struct ks_rule *r = load_rule("000-allow-chrome.json");
    CHECK(r != NULL);
    struct ks_arena a = {0};
    Protocol__Rule *pr = ks_pb_rule(&a, r);
    CHECK(pr != NULL);
    Protocol__Rule *w = roundtrip_rule(pr);
    ks_arena_free(&a);
    ks_rule_free(r);
    CHECK(w != NULL);
    CHECK_INT_EQ(w->created, 1607879212);
    CHECK_STR_EQ(w->name, "000-allow-chrome");
    CHECK(w->enabled && w->precedence && !w->nolog);
    CHECK_STR_EQ(w->action, "allow");
    CHECK_STR_EQ(w->duration, "always");
    CHECK(w->operator_ != NULL);
    CHECK_STR_EQ(w->operator_->type, "simple");
    CHECK_STR_EQ(w->operator_->operand, "process.path");
    CHECK_STR_EQ(w->operator_->data, "/opt/google/chrome/chrome");
    CHECK_INT_EQ(w->operator_->n_list, 0);
    protobuf_c_message_free_unpacked(&w->base, NULL);
}

TEST(rule_serialize_list_blanks_data)
{
    struct ks_rule *r = load_rule("rule-operator-list.json");
    CHECK(r != NULL);
    struct ks_arena a = {0};
    Protocol__Rule *pr = ks_pb_rule(&a, r);
    CHECK(pr != NULL);
    Protocol__Rule *w = roundtrip_rule(pr);
    ks_arena_free(&a);
    ks_rule_free(r);
    CHECK(w != NULL);
    CHECK_STR_EQ(w->operator_->type, "list");
    CHECK_STR_EQ(w->operator_->data, "");
    CHECK_INT_EQ(w->operator_->n_list, 2);
    CHECK_STR_EQ(w->operator_->list[0]->operand, "process.path");
    CHECK_STR_EQ(w->operator_->list[0]->data, "/usr/bin/telnet");
    CHECK_STR_EQ(w->operator_->list[1]->operand, "dest.port");
    CHECK_STR_EQ(w->operator_->list[1]->data, "53");

    /* and back: Deserialize */
    char err[128];
    time_t before = time(NULL);
    struct ks_rule *back = ks_rule_from_pb(w, err, sizeof(err));
    protobuf_c_message_free_unpacked(&w->base, NULL);
    CHECK(back != NULL);
    CHECK_STR_EQ(back->name, "rule-with-operator-list");
    CHECK_STR_EQ(back->operator.type, "list");
    CHECK_STR_EQ(back->operator.data, "");
    CHECK_INT_EQ(back->operator.list.len, 2);
    CHECK_STR_EQ(KS_ARRAY_ITEM(back->operator.list, struct ks_operator, 1)->data, "53");
    /* Created is "now", not the one sent */
    int64_t created;
    CHECK(ks_parse_rfc3339(back->created, &created) == 0);
    CHECK(created >= before && created <= time(NULL));
    ks_rule_free(back);
}

TEST(rule_deserialize_without_operator)
{
    Protocol__Rule pr = PROTOCOL__RULE__INIT;
    pr.name = "x";
    char err[128];
    ks_log_set_level(KS_LOG_ERROR); /* the warning is expected */
    CHECK(ks_rule_from_pb(&pr, err, sizeof(err)) == NULL);
    ks_log_set_level(KS_LOG_INFO);
    CHECK_STR_EQ(err, "invalid operator");
}

TEST(rule_deserialize_keeps_data_of_non_lists)
{
    Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
    op.type = "simple";
    op.operand = "dest.host";
    op.data = "example.com";
    op.sensitive = true;
    Protocol__Rule pr = PROTOCOL__RULE__INIT;
    pr.name = "allow-example";
    pr.action = "deny";
    pr.duration = "30s";
    pr.enabled = true;
    pr.nolog = true;
    pr.operator_ = &op;
    char err[128];
    struct ks_rule *r = ks_rule_from_pb(&pr, err, sizeof(err));
    CHECK(r != NULL);
    CHECK_STR_EQ(r->operator.data, "example.com");
    CHECK(r->operator.sensitive);
    CHECK(r->nolog && r->enabled && !r->precedence);
    CHECK_STR_EQ(r->duration, "30s");
    ks_rule_free(r);
}

TEST(rule_with_bad_created_uses_now)
{
    struct ks_rule *r = load_rule("000-allow-chrome.json");
    CHECK(r != NULL);
    free(r->created);
    r->created = strdup("yesterday");
    ks_log_set_level(KS_LOG_ERROR); /* the warning is expected */
    struct ks_arena a = {0};
    time_t before = time(NULL);
    Protocol__Rule *pr = ks_pb_rule(&a, r);
    ks_log_set_level(KS_LOG_INFO);
    CHECK(pr != NULL);
    CHECK(pr->created >= before && pr->created <= time(NULL));
    ks_arena_free(&a);
    ks_rule_free(r);
    CHECK(ks_pb_rule(&a, NULL) == NULL);
}

static struct ks_proc *fake_proc(void)
{
    struct ks_proc *p = ks_proc_new_empty(4242, "curl");
    if (p == NULL)
        return NULL;
    free(p->path);
    free(p->cwd);
    p->path = strdup("/usr/bin/curl");
    p->cwd = strdup("/tmp");
    p->nargs = 2;
    p->args = calloc(2, sizeof(char *));
    p->args[0] = strdup("curl");
    p->args[1] = strdup("https://example.com");
    p->nenv = 1;
    p->env = calloc(1, sizeof(*p->env));
    p->env[0].name = strdup("HOME");
    p->env[0].value = strdup("/root");
    p->checksum_md5 = strdup("d41d8cd98f00b204e9800998ecf8427e");
    p->ntree = 2;
    p->tree = calloc(2, sizeof(*p->tree));
    p->tree[0].path = strdup("/usr/bin/curl");
    p->tree[0].pid = 4242;
    p->tree[1].path = strdup("/bin/bash");
    p->tree[1].pid = 1;
    ks_proc_sync(p);
    return p;
}

TEST(connection_serialize)
{
    struct ks_proc *p = fake_proc();
    CHECK(p != NULL);
    struct ks_conn c;
    memset(&c, 0, sizeof(c));
    c.protocol = "tcp6";
    ks_ip_parse("::1", &c.src_ip);
    ks_ip_parse("2001:db8::1", &c.dst_ip);
    c.src_port = 34567;
    c.dst_port = 443;
    c.dst_host = "example.com";
    c.uid = -1; /* unknown: uint32(-1) as in Go */
    c.process = &p->view;

    struct ks_arena a = {0};
    Protocol__Connection *pc = ks_pb_connection(&a, &c, p);
    CHECK(pc != NULL);
    size_t len;
    uint8_t *buf = ks_pb_pack(&pc->base, &len);
    ks_arena_free(&a);
    ks_proc_unref(p);
    CHECK(buf != NULL);
    Protocol__Connection *w = (Protocol__Connection *)ks_pb_unpack(
        &protocol__connection__descriptor, buf, len);
    free(buf);
    CHECK(w != NULL);
    CHECK_STR_EQ(w->protocol, "tcp6");
    CHECK_STR_EQ(w->src_ip, "::1");
    CHECK_STR_EQ(w->dst_ip, "2001:db8::1");
    CHECK_INT_EQ(w->src_port, 34567);
    CHECK_INT_EQ(w->dst_port, 443);
    CHECK_STR_EQ(w->dst_host, "example.com");
    CHECK_INT_EQ(w->user_id, 4294967295u);
    CHECK_INT_EQ(w->process_id, 4242);
    CHECK_STR_EQ(w->process_path, "/usr/bin/curl");
    CHECK_STR_EQ(w->process_cwd, "/tmp");
    CHECK_INT_EQ(w->n_process_args, 2);
    CHECK_STR_EQ(w->process_args[1], "https://example.com");
    CHECK_INT_EQ(w->n_process_env, 1);
    CHECK_STR_EQ(w->process_env[0]->key, "HOME");
    CHECK_STR_EQ(w->process_env[0]->value, "/root");
    CHECK_INT_EQ(w->n_process_checksums, 1);
    CHECK_STR_EQ(w->process_checksums[0]->key, "process.hash.md5");
    CHECK_INT_EQ(w->n_process_tree, 2);
    CHECK_STR_EQ(w->process_tree[1]->key, "/bin/bash");
    CHECK_INT_EQ(w->process_tree[1]->value, 1);
    protobuf_c_message_free_unpacked(&w->base, NULL);
}

TEST(invalid_utf8_is_refused_both_ways)
{
    Protocol__Connection pc = PROTOCOL__CONNECTION__INIT;
    char *args[] = {"ok", "bad\xff"};
    pc.process_args = args;
    pc.n_process_args = 2;
    size_t len;
    CHECK(ks_pb_pack(&pc.base, &len) == NULL);
    CHECK(!ks_pb_valid_utf8(&pc.base));

    /* raw bytes on the wire: protobuf-c accepts them, we don't */
    pc.n_process_args = 1;
    pc.process_path = "bad\xc3";
    CHECK(!ks_pb_valid_utf8(&pc.base));
    size_t n = protobuf_c_message_get_packed_size(&pc.base);
    uint8_t *buf = malloc(n);
    CHECK(buf != NULL);
    protobuf_c_message_pack(&pc.base, buf);
    ProtobufCMessage *raw = protobuf_c_message_unpack(&protocol__connection__descriptor,
                                                      NULL, n, buf);
    CHECK(raw != NULL);
    protobuf_c_message_free_unpacked(raw, NULL);
    CHECK(ks_pb_unpack(&protocol__connection__descriptor, buf, n) == NULL);
    free(buf);

    /* nested messages are checked too */
    Protocol__Operator op = PROTOCOL__OPERATOR__INIT;
    op.data = "\xe2\x82";
    Protocol__Rule r = PROTOCOL__RULE__INIT;
    r.operator_ = &op;
    CHECK(!ks_pb_valid_utf8(&r.base));
    op.data = "\xe2\x82\xac";
    CHECK(ks_pb_valid_utf8(&r.base));
}

TEST(alerts)
{
    struct ks_arena a = {0};
    Protocol__Alert *al = ks_pb_alert_text(&a, PROTOCOL__ALERT__TYPE__WARNING,
                                           PROTOCOL__ALERT__WHAT__GENERIC,
                                           PROTOCOL__ALERT__ACTION__SAVE_TO_DB,
                                           PROTOCOL__ALERT__PRIORITY__MEDIUM, "hi");
    CHECK(al != NULL);
    CHECK(al->id > 0);
    CHECK_INT_EQ(al->data_case, PROTOCOL__ALERT__DATA_TEXT);
    CHECK_STR_EQ(al->text, "hi");
    CHECK_INT_EQ(al->action, PROTOCOL__ALERT__ACTION__SAVE_TO_DB);

    al = ks_pb_alert_text(&a, PROTOCOL__ALERT__TYPE__INFO,
                          PROTOCOL__ALERT__WHAT__KERNEL_EVENT,
                          PROTOCOL__ALERT__ACTION__NONE, PROTOCOL__ALERT__PRIORITY__LOW,
                          "exec");
    CHECK(al != NULL);
    CHECK_INT_EQ(al->action, PROTOCOL__ALERT__ACTION__SHOW_ALERT);

    /* other What values carry no data */
    al = ks_pb_alert_text(&a, PROTOCOL__ALERT__TYPE__ERROR, PROTOCOL__ALERT__WHAT__FIREWALL,
                          PROTOCOL__ALERT__ACTION__NONE, PROTOCOL__ALERT__PRIORITY__HIGH,
                          "fw");
    CHECK(al != NULL);
    CHECK_INT_EQ(al->data_case, PROTOCOL__ALERT__DATA__NOT_SET);
    ks_arena_free(&a);
}

TEST(arena)
{
    struct ks_arena a = {0};
    char *s = ks_arena_printf(&a, "%s-%d", "x", 42);
    CHECK_STR_EQ(s, "x-42");
    void *big = ks_arena_alloc(&a, 100000);
    CHECK(big != NULL);
    char *after = ks_arena_strdup(&a, "small");
    CHECK_STR_EQ(after, "small");
    CHECK(ks_arena_calloc(&a, SIZE_MAX / 2, 4) == NULL);
    CHECK(a.failed);
    ks_arena_free(&a);
    CHECK(a.head == NULL && !a.failed);
}

int main(void)
{
    RUN(rfc3339);
    RUN(rule_serialize_simple);
    RUN(rule_serialize_list_blanks_data);
    RUN(rule_deserialize_without_operator);
    RUN(rule_deserialize_keeps_data_of_non_lists);
    RUN(rule_with_bad_created_uses_now);
    RUN(connection_serialize);
    RUN(invalid_utf8_is_refused_both_ways);
    RUN(alerts);
    RUN(arena);
    return harness_report();
}
