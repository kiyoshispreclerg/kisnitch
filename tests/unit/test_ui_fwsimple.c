/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The simplified firewall panel's logic (ui/fwsimple.c): simple rules to
 * and from system-fw.json rules, the round trip that tells simple from
 * advanced rules, the rows, the policies and the ufw application profiles.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _DEFAULT_SOURCE /* mkdtemp */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/json_util.h"
#include "tests/harness.h"
#include "ui/fwsimple.h"

/* the chains of upstream's default system-fw.json, an advanced rule in
 * the input chain */
static const char base_fw[] =
    "{\"Enabled\": true, \"Version\": 1, \"SystemRules\": [{\"Chains\": ["
    "{\"Name\": \"filter_input\", \"Table\": \"opensnitch\", \"Family\": \"inet\", "
    " \"Priority\": \"\", \"Type\": \"filter\", \"Hook\": \"input\", \"Policy\": \"accept\", "
    " \"Rules\": [{\"UUID\": \"adv-1\", \"Enabled\": true, \"Description\": \"log ssh\", "
    "  \"Expressions\": [{\"Statement\": {\"Op\": \"==\", \"Name\": \"tcp\", "
    "   \"Values\": [{\"Key\": \"dport\", \"Value\": \"22\"}]}}, "
    "   {\"Statement\": {\"Op\": \"\", \"Name\": \"log\", \"Values\": [{\"Key\": \"prefix\", "
    "   \"Value\": \"ssh\"}]}}], \"Target\": \"accept\", \"TargetParameters\": \"\"}]},"
    "{\"Name\": \"mangle_output\", \"Table\": \"opensnitch\", \"Family\": \"inet\", "
    " \"Priority\": \"\", \"Type\": \"mangle\", \"Hook\": \"output\", \"Policy\": \"accept\", "
    " \"Rules\": []}]}]}";

static void load(struct ks_sysfw *fw)
{
    char err[256];
    CHECK(ks_sysfw_parse(base_fw, strlen(base_fw), fw, err, sizeof(err)) == 0);
}

static struct ks_fws_rule rule(int action, int dir, int proto, const char *port, const char *src,
                               const char *dst, const char *iface)
{
    struct ks_fws_rule r;
    ks_fws_rule_init(&r);
    r.action = action;
    r.direction = dir;
    r.proto = proto;
    snprintf(r.port, sizeof(r.port), "%s", port);
    snprintf(r.src, sizeof(r.src), "%s", src);
    snprintf(r.dst, sizeof(r.dst), "%s", dst);
    snprintf(r.iface, sizeof(r.iface), "%s", iface);
    return r;
}

static int idx(const char *proto)
{
    return ks_fw_index_of(ks_fw_port_protocols, KS_FW_NPORT_PROTOCOLS, proto);
}

/* to a rule, then back: the same simple rule */
static void round_trip(struct ks_fws_rule r, const char *want_src)
{
    struct ks_fw_chain flat;
    char err[256] = "";
    CHECK_MSG(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == 0, "%s", err);
    struct ks_fws_rule back;
    CHECK(ks_fws_from_flat(&flat, &back));
    CHECK_INT_EQ(back.action, r.action);
    CHECK_INT_EQ(back.direction, r.direction);
    CHECK_INT_EQ(back.proto, r.proto);
    CHECK_STR_EQ(back.port, r.port);
    CHECK_STR_EQ(back.src, want_src ? want_src : r.src);
    CHECK_STR_EQ(back.dst, r.dst);
    CHECK_STR_EQ(back.iface, r.iface);
    CHECK(back.uuid[0] != '\0'); /* a new rule gets a UUID */
    ks_fwr_free_chain(&flat);
}

TEST(simple_rules_round_trip)
{
    /* a network becomes the range the dialog writes */
    round_trip(rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "22", "192.168.1.0/24", "", "eth0"),
               "192.168.1.0-192.168.1.255");
    round_trip(rule(KS_FWS_DENY, KS_FWS_OUT, idx("udp"), "53", "", "8.8.8.8", "wlan0"), NULL);
    round_trip(rule(KS_FWS_REJECT, KS_FWS_IN, idx("tcp,udp"), "80,443", "", "", ""), NULL);
    round_trip(rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "6000-6007", "fe80::1", "", ""), NULL);
    round_trip(rule(KS_FWS_DENY, KS_FWS_IN, idx("sctp"), "", "", "", ""), NULL); /* l4proto */
    round_trip(rule(KS_FWS_DENY, KS_FWS_OUT, KS_FWS_ANY_PROTO, "", "", "10.0.0.1", ""), NULL);

    /* the rule is the dialog's: tcp dport, then ip saddr, then iifname */
    struct ks_fws_rule r = rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "22", "10.0.0.2", "", "eth0");
    struct ks_fw_chain flat;
    char err[256];
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == 0);
    CHECK_STR_EQ(flat.name, "filter_input");
    const struct ks_fw_rule *fr = KS_SYSFW_RULE(&flat, 0);
    CHECK_STR_EQ(fr->target, "accept");
    CHECK_INT_EQ(fr->expressions.len, 3);
    CHECK_STR_EQ(KS_SYSFW_EXPR(fr, 0)->statement->name, "tcp");
    CHECK_STR_EQ(KS_SYSFW_EXPR(fr, 1)->statement->name, "ip");
    CHECK_STR_EQ(KS_SYSFW_EXPR(fr, 2)->statement->name, "iifname");
    ks_fwr_free_chain(&flat);
    r.direction = KS_FWS_OUT;
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == 0);
    CHECK_STR_EQ(flat.name, "mangle_output");
    CHECK_STR_EQ(KS_SYSFW_EXPR(KS_SYSFW_RULE(&flat, 0), 2)->statement->name, "oifname");
    ks_fwr_free_chain(&flat);

    /* errors */
    r = rule(KS_FWS_ALLOW, KS_FWS_IN, KS_FWS_ANY_PROTO, "22", "", "", "");
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == -1);
    CHECK_STR_EQ(err, "Select the protocol of the port.");
    r = rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp,udp"), "", "", "", "");
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == -1);
    r = rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "ssh", "", "", "");
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == -1);
    CHECK_STR_EQ(err, "port not valid.");
    r = rule(KS_FWS_ALLOW, KS_FWS_IN, KS_FWS_ANY_PROTO, "", "10.0.0.1", "::1", "");
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == -1);
    r = rule(KS_FWS_ALLOW, KS_FWS_IN, KS_FWS_ANY_PROTO, "", "10.0.0.300", "", "");
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == -1);
}

TEST(advanced_rules)
{
    struct ks_sysfw fw;
    load(&fw);
    struct ks_fw_chain flat;
    struct ks_fws_rule r;
    /* a log statement: advanced */
    CHECK(ks_fwr_flat_by_uuid(&fw, "adv-1", &flat) == 0);
    CHECK(!ks_fws_from_flat(&flat, &r));
    ks_fwr_free_chain(&flat);

    /* the same statements in another order are another rule: advanced */
    struct ks_fws_rule s = rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "22", "10.0.0.2", "", "");
    char err[256];
    CHECK(ks_fws_to_flat(&s, &flat, err, sizeof(err)) == 0);
    struct ks_fw_rule *fr = KS_SYSFW_RULE(&flat, 0);
    struct ks_fw_expression tmp = *KS_SYSFW_EXPR(fr, 0);
    *KS_SYSFW_EXPR(fr, 0) = *KS_SYSFW_EXPR(fr, 1);
    *KS_SYSFW_EXPR(fr, 1) = tmp;
    CHECK(!ks_fws_from_flat(&flat, &r));
    /* a "!=" operator */
    *KS_SYSFW_EXPR(fr, 1) = *KS_SYSFW_EXPR(fr, 0);
    *KS_SYSFW_EXPR(fr, 0) = tmp;
    free(KS_SYSFW_EXPR(fr, 0)->statement->op);
    KS_SYSFW_EXPR(fr, 0)->statement->op = strdup("!=");
    CHECK(!ks_fws_from_flat(&flat, &r));
    ks_fwr_free_chain(&flat);
    ks_sysfw_free(&fw);
}

TEST(rows_policies_and_editing)
{
    struct ks_sysfw fw;
    load(&fw);
    bool drop;
    CHECK(ks_fws_policy(&fw, KS_FWS_IN, &drop) == 0 && !drop);
    const char *e = NULL;
    CHECK(ks_fws_set_policy(&fw, KS_FWS_IN, true, &e) == 0);
    CHECK(ks_fws_policy(&fw, KS_FWS_IN, &drop) == 0 && drop);

    struct ks_fws_rule a = rule(KS_FWS_ALLOW, KS_FWS_IN, idx("tcp"), "22", "", "", "");
    struct ks_fws_rule b = rule(KS_FWS_DENY, KS_FWS_OUT, idx("udp"), "53", "", "1.1.1.1", "");
    char err[256];
    CHECK(ks_fws_save(&fw, &a, err, sizeof(err)) == 0);
    CHECK(ks_fws_save(&fw, &b, err, sizeof(err)) == 0);
    CHECK(ks_fws_save(&fw, &a, err, sizeof(err)) == -1); /* the same rule again */
    CHECK_STR_EQ(err, "duplicated.");

    struct ks_fws_rows rows;
    CHECK(ks_fws_rows(&fw, &rows) == 0);
    /* the advanced rule, the two of the drop profile, ours */
    CHECK_INT_EQ(rows.n, 5);
    int simple = 0, policy = 0, adv = 0;
    const char *uuid_a = NULL;
    for (size_t i = 0; i < rows.n; i++) {
        simple += rows.v[i].kind == KS_FWS_ROW_SIMPLE;
        policy += rows.v[i].kind == KS_FWS_ROW_POLICY;
        adv += rows.v[i].kind == KS_FWS_ROW_ADVANCED;
        if (rows.v[i].kind == KS_FWS_ROW_SIMPLE && strcmp(rows.v[i].rule.port, "22") == 0)
            uuid_a = rows.v[i].uuid;
        if (rows.v[i].kind == KS_FWS_ROW_ADVANCED)
            CHECK_STR_EQ(rows.v[i].summary, "log ssh -> accept");
    }
    CHECK_INT_EQ(simple, 2);
    CHECK_INT_EQ(policy, 2);
    CHECK_INT_EQ(adv, 1);
    CHECK(uuid_a != NULL);

    /* editing: same chain in place; another direction moves it */
    struct ks_fws_rule edit = a;
    snprintf(edit.uuid, sizeof(edit.uuid), "%s", uuid_a);
    snprintf(edit.port, sizeof(edit.port), "2222");
    CHECK(ks_fws_save(&fw, &edit, err, sizeof(err)) == 0);
    struct ks_fw_chain *ch = NULL;
    CHECK(ks_fwr_find(&fw, uuid_a, &ch) != NULL);
    CHECK_STR_EQ(ch->name, "filter_input");
    CHECK_STR_EQ(KS_SYSFW_EXPR(ks_fwr_find(&fw, uuid_a, NULL), 0)->statement->values.items
                     ? KS_SYSFW_VALUE(KS_SYSFW_EXPR(ks_fwr_find(&fw, uuid_a, NULL), 0)->statement,
                                      0)->value
                     : "",
                 "2222");
    edit.direction = KS_FWS_OUT;
    CHECK(ks_fws_save(&fw, &edit, err, sizeof(err)) == 0);
    CHECK(ks_fwr_find(&fw, uuid_a, &ch) != NULL);
    CHECK_STR_EQ(ch->name, "mangle_output");
    /* moving: it's last in mangle_output, after b */
    CHECK(!ks_fws_move(&fw, uuid_a, +1));
    CHECK(ks_fws_move(&fw, uuid_a, -1));
    CHECK_STR_EQ(KS_SYSFW_RULE(ch, 0)->uuid, uuid_a);
    CHECK(!ks_fws_move(&fw, uuid_a, -1));
    ks_fws_rows_free(&rows);

    /* back to accept: the profile's rules go */
    CHECK(ks_fws_set_policy(&fw, KS_FWS_IN, false, &e) == 0);
    CHECK(ks_fws_rows(&fw, &rows) == 0);
    CHECK_INT_EQ(rows.n, 3);
    ks_fws_rows_free(&rows);
    CHECK(ks_fws_set_policy(&fw, KS_FWS_OUT, true, &e) == 0);
    CHECK(ks_fws_policy(&fw, KS_FWS_OUT, &drop) == 0 && drop);
    ks_sysfw_free(&fw);

    char buf[64];
    struct ks_fws_rule p = rule(0, 0, idx("tcp,udp"), "53", "", "", "");
    ks_fws_port_text(&p, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "tcp+udp 53");
    p.proto = KS_FWS_ANY_PROTO;
    ks_fws_port_text(&p, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "Any");
}

TEST(address_text)
{
    char b[128];
    ks_fws_addr_text("10.0.0.0-10.255.255.255", b, sizeof(b));
    CHECK_STR_EQ(b, "10.0.0.0/8");
    ks_fws_addr_text("192.168.1.0-192.168.1.255", b, sizeof(b));
    CHECK_STR_EQ(b, "192.168.1.0/24");
    ks_fws_addr_text("10.0.0.1-10.0.0.1", b, sizeof(b));
    CHECK_STR_EQ(b, "10.0.0.1/32");
    ks_fws_addr_text("10.0.0.1-10.0.0.5", b, sizeof(b)); /* not a network */
    CHECK_STR_EQ(b, "10.0.0.1-10.0.0.5");
    ks_fws_addr_text("fe80::-fe80::ffff:ffff:ffff:ffff", b, sizeof(b));
    CHECK_STR_EQ(b, "fe80::/64");
    ks_fws_addr_text("10.0.0.1", b, sizeof(b));
    CHECK_STR_EQ(b, "10.0.0.1");
    /* the CIDR gives the same rule back */
    struct ks_fws_rule r = rule(KS_FWS_ALLOW, KS_FWS_IN, KS_FWS_ANY_PROTO, "", "10.0.0.0/8", "", "");
    struct ks_fw_chain flat;
    char err[256];
    CHECK(ks_fws_to_flat(&r, &flat, err, sizeof(err)) == 0);
    CHECK_STR_EQ(KS_SYSFW_VALUE(KS_SYSFW_EXPR(KS_SYSFW_RULE(&flat, 0), 0)->statement, 0)->value,
                 "10.0.0.0-10.255.255.255");
    ks_fwr_free_chain(&flat);
}

TEST(ufw_profiles)
{
    struct ks_fws_apps apps = {0};
    ks_fws_apps_parse(&apps, "[OpenSSH]\ntitle=Secure shell server\n"
                             "description=OpenSSH is a free implementation\nports=22/tcp\n\n"
                             "# comment\n[Apache Full]\ntitle=Web Server (HTTP,HTTPS)\n"
                             "ports=80,443/tcp\n"
                             "[Samba]\ntitle=LanManager-like\nports=137,138/udp|139,445/tcp\n"
                             "[X11]\nports=6000:6007/tcp\n[Both]\nports=53\n"
                             "[Bad]\nports=abc/tcp|1/icmp\n");
    CHECK_INT_EQ(apps.n, 6);
    CHECK_STR_EQ(apps.v[0].name, "OpenSSH");
    CHECK_STR_EQ(apps.v[0].title, "Secure shell server");
    CHECK_INT_EQ(apps.v[0].proto, idx("tcp"));
    CHECK_STR_EQ(apps.v[0].ports, "22");
    CHECK_STR_EQ(apps.v[1].ports, "80,443");
    CHECK_STR_EQ(apps.v[2].name, "Samba (137,138/udp)");
    CHECK_INT_EQ(apps.v[2].proto, idx("udp"));
    CHECK_STR_EQ(apps.v[3].name, "Samba (139,445/tcp)");
    CHECK_STR_EQ(apps.v[4].ports, "6000-6007");
    CHECK_INT_EQ(apps.v[5].proto, idx("tcp,udp")); /* no protocol: both */
    ks_fws_apps_free(&apps);

    char dir[64] = "/tmp/ks-ufw-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/b-ssh", dir);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs("[OpenSSH]\nports=22/tcp\n", f);
        fclose(f);
    }
    snprintf(path, sizeof(path), "%s/a-web", dir);
    f = fopen(path, "w");
    if (f != NULL) {
        fputs("[WWW]\nports=80/tcp\n", f);
        fclose(f);
    }
    ks_fws_apps_load(&apps, dir);
    CHECK_INT_EQ(apps.n, 2);
    CHECK_STR_EQ(apps.v[0].name, "WWW"); /* files in name order */
    ks_fws_apps_free(&apps);
    ks_fws_apps_load(&apps, "/no/such/dir");
    CHECK_INT_EQ(apps.n, 0);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

int main(void)
{
    RUN(simple_rules_round_trip);
    RUN(advanced_rules);
    RUN(rows_policies_and_editing);
    RUN(address_text);
    RUN(ufw_profiles);
    return harness_report();
}
