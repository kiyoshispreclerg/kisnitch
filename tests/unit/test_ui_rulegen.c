/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/rulegen.c: the rules editor's form <-> rule logic. The exhaustive
 * comparison with upstream's dialog is `make diff-ui`
 * (tests/diff/ruleseditor); these are its main cases, always run.
 */
#include "ui/rulegen.h"

#include <string.h>

#include "ui/res.h"
#include "tests/harness.h"

static struct ks_py_aliases aliases;

static Protocol__Rule *build(struct ks_rform *f, struct ks_arena *a, char *err)
{
    Protocol__Rule *r = NULL;
    if (!ks_rform_to_rule(f, &aliases, a, &r, err, 256))
        return NULL;
    return r;
}

TEST(single_fields)
{
    struct ks_arena a = {0};
    char err[256];
    struct ks_rform f;
    ks_rform_init(&f);
    ks_rform_set_name(&f, "r1");
    CHECK(build(&f, &a, err) == NULL);
    CHECK_STR_EQ(err, "Select at least one field.");

    f.dstport.on = true;
    ks_rform_set(&f.dstport, "443");
    f.action = KS_RACTION_ALLOW;
    f.duration = 8;
    Protocol__Rule *r = build(&f, &a, err);
    CHECK(r != NULL);
    CHECK_STR_EQ(r->action, "allow");
    CHECK_STR_EQ(r->duration, "always");
    CHECK_STR_EQ(r->operator_->type, "simple");
    CHECK_STR_EQ(r->operator_->operand, "dest.port");
    CHECK_STR_EQ(r->operator_->data, "443");

    /* a comma list becomes a regexp */
    ks_rform_set(&f.dstport, "80, 443,8080");
    r = build(&f, &a, err);
    CHECK_STR_EQ(r->operator_->type, "regexp");
    CHECK_STR_EQ(r->operator_->data, "^(80|443|8080)$");
    ks_rform_set(&f.dstport, "80,x");
    CHECK(build(&f, &a, err) == NULL);
    CHECK_STR_EQ(err, "Invalid text");
    /* "(" alone is not what makes a text a regexp ("\\*{[|^?$" is) */
    ks_rform_set(&f.dstport, "(80");
    CHECK(build(&f, &a, err) != NULL);
    ks_rform_set(&f.dstport, "[80");
    CHECK(build(&f, &a, err) == NULL);
    CHECK_STR_EQ(err, "Dst port regexp error");

    ks_rform_free(&f);
    ks_arena_free(&a);
}

TEST(ips_and_aliases)
{
    struct ks_arena a = {0};
    char err[256];
    struct ks_rform f;
    ks_rform_init(&f);
    ks_rform_set_name(&f, "r");
    f.dstip.on = true;
    ks_rform_set(&f.dstip, "1.2.3.4");
    Protocol__Rule *r = build(&f, &a, err);
    CHECK_STR_EQ(r->operator_->operand, "dest.ip");
    CHECK_STR_EQ(r->operator_->type, "simple");
    ks_rform_set(&f.dstip, "192.168.0.0/16");
    r = build(&f, &a, err);
    CHECK_STR_EQ(r->operator_->operand, "dest.network");
    CHECK_STR_EQ(r->operator_->type, "network");
    /* LAN and MULTICAST on the source are the ranges; on the destination they are
     * aliases of network_aliases.json first */
    f.dstip.on = false;
    f.srcip.on = true;
    ks_rform_set(&f.srcip, "LAN");
    r = build(&f, &a, err);
    CHECK_STR_EQ(r->operator_->type, "regexp");
    CHECK_STR_EQ(r->operator_->operand, "source.ip");
    CHECK_STR_EQ(r->operator_->data, KS_RULE_LAN_RANGES);
    f.srcip.on = false;
    f.dstip.on = true;
    ks_rform_set(&f.dstip, aliases.items[0].name);
    r = build(&f, &a, err);
    CHECK_STR_EQ(r->operator_->operand, "dest.network");
    CHECK_STR_EQ(r->operator_->data, aliases.items[0].name);
    ks_rform_free(&f);
    ks_arena_free(&a);
}

TEST(compound_rule)
{
    struct ks_arena a = {0};
    char err[256];
    struct ks_rform f;
    ks_rform_init(&f);
    ks_rform_set_name(&f, "curl-443");
    f.sensitive = true;
    f.proc.on = true;
    ks_rform_set(&f.proc, "/usr/bin/curl");
    f.dstport.on = true;
    ks_rform_set(&f.dstport, "443");
    f.md5.on = true;
    ks_rform_set(&f.md5, "ABCDEF");
    Protocol__Rule *r = build(&f, &a, err);
    CHECK(r != NULL);
    CHECK_STR_EQ(r->operator_->type, "list");
    CHECK_STR_EQ(r->operator_->operand, "list");
    CHECK_STR_EQ(r->operator_->data, "");
    CHECK_INT_EQ((int)r->operator_->n_list, 3);
    CHECK_STR_EQ(r->operator_->list[0]->operand, "process.path");
    CHECK_STR_EQ(r->operator_->list[1]->operand, "dest.port");
    CHECK_STR_EQ(r->operator_->list[2]->operand, "process.hash.md5");
    CHECK_STR_EQ(r->operator_->list[2]->data, "abcdef");
    CHECK(r->operator_->list[0]->sensitive);
    CHECK(!r->operator_->list[2]->sensitive);
    ks_rform_free(&f);
    ks_arena_free(&a);
}

TEST(load_roundtrip)
{
    struct ks_arena a = {0};
    char err[256];
    struct ks_rform f;
    ks_rform_init(&f);
    ks_rform_set_name(&f, "rt");
    f.enabled = true;
    f.action = KS_RACTION_REJECT;
    f.duration = 3;
    f.proto.on = true;
    ks_rform_set(&f.proto, "tcp,udp");
    f.srcport.on = true;
    ks_rform_set(&f.srcport, "1,2,3");
    f.srcip.on = true;
    ks_rform_set(&f.srcip, "MULTICAST");
    Protocol__Rule *r = build(&f, &a, err);
    CHECK(r != NULL);

    struct ks_rform g;
    ks_rform_init(&g);
    ks_rform_load_rule(&g, r, err, sizeof(err));
    CHECK_STR_EQ(err, "");
    CHECK_STR_EQ(g.name, "rt");
    CHECK(g.enabled);
    CHECK_INT_EQ(g.action, KS_RACTION_REJECT);
    CHECK_INT_EQ(g.duration, 3);
    CHECK(g.proto.on);
    CHECK_STR_EQ(g.proto.text, "TCP,UDP");
    CHECK_STR_EQ(g.srcport.text, "1,2,3");
    CHECK_STR_EQ(g.srcip.text, "MULTICAST");
    CHECK(!g.dstport.on);
    ks_rform_free(&f);
    ks_rform_free(&g);
    ks_arena_free(&a);
}

TEST(helpers)
{
    char out[256];
    CHECK(ks_rule_comma_to_regexp("1, 2", true, out, sizeof(out)));
    CHECK_STR_EQ(out, "^(1|2)$");
    CHECK(!ks_rule_comma_to_regexp("", true, out, sizeof(out)));
    CHECK_STR_EQ(out, "Invalid text");
    CHECK_INT_EQ(ks_rule_regexp_to_comma("^(1|2)$", true, out, sizeof(out)), 1);
    CHECK_STR_EQ(out, "1,2");
    CHECK_INT_EQ(ks_rule_regexp_to_comma("^(1||2)$", true, out, sizeof(out)), -1);
    CHECK_INT_EQ(ks_rule_regexp_to_comma("nope", false, out, sizeof(out)), 0);
    CHECK(ks_rule_is_regex("a|b"));
    CHECK(!ks_rule_is_regex("a.b"));
    /* Python's `re` refuses these escapes, PCRE2 takes them */
    CHECK(!ks_rule_valid_regex("\\p{L}", NULL, 0));
    CHECK(!ks_rule_valid_regex("(?<n>a)", NULL, 0));
    CHECK(ks_rule_valid_regex("(?<=a)b", NULL, 0));
    /* global flags: only at the start (Python 3.11 on); scoped ones anywhere */
    CHECK(ks_rule_valid_regex("(?i)ab", NULL, 0));
    CHECK(!ks_rule_valid_regex("a(?i)b", NULL, 0));
    CHECK(ks_rule_valid_regex("a(?i:b)", NULL, 0));
    CHECK(!ks_rule_valid_regex("[\\d-z]+", NULL, 0)); /* bad character range, in both */
    CHECK(ks_rule_valid_regex("[a-z]+\\.org", NULL, 0));
    CHECK(!ks_rule_valid_regex("(", NULL, 0));
}

int main(void)
{
    ks_py_aliases_parse(&aliases, (const char *)ks_res_network_aliases_json,
                        ks_res_network_aliases_json_len);
    RUN(single_fields);
    RUN(ips_and_aliases);
    RUN(compound_rule);
    RUN(load_roundtrip);
    RUN(helpers);
    ks_py_aliases_free(&aliases);
    return harness_report();
}
