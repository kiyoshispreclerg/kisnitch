/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI's system firewall logic (ui/fwrules.c): rules and profiles on a
 * node's configuration, the table columns, /etc/services, and the rule
 * dialog's form <-> rule conversions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/json_util.h"
#include "tests/harness.h"
#include "ui/fwrules.h"

#define UPSTREAM_SYSFW KS_FIXTURES_DIR "/../../upstream/daemon/data/system-fw.json"

static struct ks_fw_services services;

static void load_upstream(struct ks_sysfw *fw)
{
    char err[256];
    size_t len;
    char *raw = ks_read_file(UPSTREAM_SYSFW, 1 << 20, &len, err, sizeof(err));
    CHECK(raw != NULL);
    CHECK(ks_sysfw_parse(raw, len, fw, err, sizeof(err)) == 0);
    free(raw);
}

static struct ks_fw_chain *chain_named(struct ks_sysfw *fw, const char *name)
{
    struct ks_fw_chains_list *l = KS_SYSFW_RULES(fw, 1);
    for (size_t i = 0; i < l->chains.len; i++)
        if (strcmp(KS_SYSFW_CHAIN(l, i)->name, name) == 0)
            return KS_SYSFW_CHAIN(l, i);
    return NULL;
}

TEST(policies_and_profiles)
{
    struct ks_sysfw fw;
    load_upstream(&fw);
    CHECK_STR_EQ(ks_fwr_get_policy(&fw, "input", "filter", "inet"), "accept");
    CHECK_STR_EQ(ks_fwr_get_policy(&fw, "output", "mangle", "inet"), "accept");
    CHECK(ks_fwr_get_policy(&fw, "egress", "filter", "inet") == NULL);

    struct ks_fw_chain drop;
    const char *err = NULL;
    CHECK(ks_fwr_profile(KS_FW_PROFILE_DROP_INPUT, &drop) == 0);
    CHECK_INT_EQ(drop.rules.len, 2);
    CHECK(ks_fwr_apply_profile(&fw, &drop, &err) == 0);
    CHECK_STR_EQ(ks_fwr_get_policy(&fw, "input", "filter", "inet"), "drop");
    struct ks_fw_chain *in = chain_named(&fw, "filter_input");
    CHECK_INT_EQ(in->rules.len, 3);
    CHECK_STR_EQ(KS_SYSFW_RULE(in, 1)->uuid,
                 "profile-drop-inbound-2d7e6fe4-c21d-11ec-99a6-3c970e298b0c");
    /* applying it again adds nothing */
    CHECK(ks_fwr_apply_profile(&fw, &drop, &err) == 0);
    CHECK_INT_EQ(in->rules.len, 3);

    /* back to accept: the profile's rules go */
    struct ks_fw_chain accept;
    CHECK(ks_fwr_profile(KS_FW_PROFILE_ACCEPT_INPUT, &accept) == 0);
    ks_fwr_delete_profile(&fw, &drop);
    CHECK(ks_fwr_apply_profile(&fw, &accept, &err) == 0);
    CHECK_INT_EQ(in->rules.len, 1);
    CHECK_STR_EQ(ks_fwr_get_policy(&fw, "input", "filter", "inet"), "accept");

    /* a profile for a chain that isn't there */
    struct ks_fw_chain fwd;
    CHECK(ks_fwr_profile(KS_FW_PROFILE_DROP_FORWARD, &fwd) == 0);
    free(fwd.family);
    fwd.family = strdup("ip6");
    CHECK(ks_fwr_apply_profile(&fw, &fwd, &err) < 0);
    CHECK_STR_EQ(err, "profile not applied");

    ks_fwr_free_chain(&fwd);
    ks_fwr_free_chain(&accept);
    ks_fwr_free_chain(&drop);
    ks_sysfw_free(&fw);
}

static void port_form(struct ks_fwf_form *f, int dir, const char *port, int proto)
{
    memset(f, 0, sizeof(*f));
    f->direction = dir;
    f->enabled = true;
    f->verdict = 0; /* ACCEPT */
    f->nst = 1;
    f->st[0].what = KS_FWF_DPORT;
    f->st[0].opts = proto;
    snprintf(f->st[0].value, sizeof(f->st[0].value), "%s", port);
}

TEST(rules_crud)
{
    struct ks_sysfw fw;
    load_upstream(&fw);
    struct ks_fwf_form f;
    struct ks_fw_chain flat;
    char err[256];
    const char *e = NULL;

    port_form(&f, KS_FWF_IN, "22", 1);
    snprintf(f.description, sizeof(f.description), "ssh");
    CHECK(ks_fwf_to_rule(&f, &services, &flat, err, sizeof(err)) == 0);
    CHECK_STR_EQ(flat.name, "filter_input");
    const char *uuid_c = KS_SYSFW_RULE(&flat, 0)->uuid;
    CHECK_INT_EQ(strlen(uuid_c), 36);
    CHECK(uuid_c[14] == '1'); /* uuid1 */
    char uuid[64];
    snprintf(uuid, sizeof(uuid), "%s", uuid_c);

    CHECK(ks_fwr_insert(&fw, &flat, 0, &e) == 0);
    CHECK(ks_fwr_insert(&fw, &flat, 0, &e) < 0);
    CHECK_STR_EQ(e, "duplicated");
    CHECK(ks_fwr_add(&fw, &flat, &e) < 0);
    CHECK_STR_EQ(e, "duplicated.");
    struct ks_fw_chain *in = chain_named(&fw, "filter_input");
    CHECK_INT_EQ(in->rules.len, 2);
    CHECK_STR_EQ(KS_SYSFW_RULE(in, 0)->uuid, uuid);

    /* the table's columns */
    char *cols[KS_FWR_NCOLS];
    CHECK(ks_fwr_to_array("unix:/local", in, KS_SYSFW_RULE(in, 0), cols) == 0);
    CHECK_STR_EQ(cols[1], "unix:/local");
    CHECK_STR_EQ(cols[2], "filter_input");
    CHECK_STR_EQ(cols[6], "True");
    CHECK_STR_EQ(cols[7], "ssh");
    CHECK_STR_EQ(cols[8], "tcp dport 22 "); /* op "==" is omitted */
    CHECK_STR_EQ(cols[9], "accept");
    for (int i = 0; i < KS_FWR_NCOLS; i++)
        free(cols[i]);
    struct ks_fw_chain *out = chain_named(&fw, "mangle_output");
    CHECK(ks_fwr_to_array("a", out, KS_SYSFW_RULE(out, 1), cols) == 0);
    /* an empty op is shown */
    CHECK_STR_EQ(cols[8], "icmp type  echo-request,echo-reply,destination-unreachable ");
    for (int i = 0; i < KS_FWR_NCOLS; i++)
        free(cols[i]);
    CHECK(ks_fwr_matches(in, KS_SYSFW_RULE(in, 0), "dport 2"));
    CHECK(ks_fwr_matches(in, KS_SYSFW_RULE(in, 0), uuid));
    CHECK(ks_fwr_matches(in, KS_SYSFW_RULE(in, 0), "inet"));
    CHECK(!ks_fwr_matches(in, KS_SYSFW_RULE(in, 0), "udp"));

    /* edit: drop instead of accept, disabled */
    CHECK(ks_fwr_set_target(&fw, uuid, "drop") == 0);
    CHECK(ks_fwr_enable(&fw, uuid, false) == 0);
    CHECK_STR_EQ(KS_SYSFW_RULE(in, 0)->target, "drop");
    CHECK(!KS_SYSFW_RULE(in, 0)->enabled);
    struct ks_fw_chain again;
    CHECK(ks_fwr_flat_by_uuid(&fw, uuid, &again) == 0);
    CHECK_INT_EQ(again.rules.len, 1);
    CHECK_STR_EQ(again.hook, "input");
    CHECK(ks_fwr_update(&fw, uuid, &flat, &e) == 0);
    CHECK_STR_EQ(KS_SYSFW_RULE(in, 0)->target, "accept");
    CHECK(ks_fwr_update(&fw, "nope", &flat, &e) < 0);

    CHECK(ks_fwr_swap(&fw, uuid, 0, 1));
    CHECK_STR_EQ(KS_SYSFW_RULE(in, 1)->uuid, uuid);
    CHECK(!ks_fwr_swap(&fw, uuid, 1, 2));
    CHECK(ks_fwr_delete(&fw, uuid) == 0);
    CHECK(ks_fwr_delete(&fw, uuid) < 0);
    CHECK_INT_EQ(in->rules.len, 1);
    CHECK(ks_fwr_flat_by_uuid(&fw, "", &again) < 0);

    ks_fwr_free_chain(&again);
    ks_fwr_free_chain(&flat);
    ks_sysfw_free(&fw);
}

/* form -> rule, checking the statement and values */
static void expect_rule(const struct ks_fwf_form *f, const char *chain, const char *name,
                        const char *kv, const char *target, const char *tparms)
{
    struct ks_fw_chain flat;
    char err[256];
    CHECK_MSG(ks_fwf_to_rule(f, &services, &flat, err, sizeof(err)) == 0, "%s", err);
    if (flat.rules.len == 0)
        return;
    CHECK_STR_EQ(flat.name, chain);
    const struct ks_fw_rule *r = KS_SYSFW_RULE(&flat, 0);
    CHECK_STR_EQ(r->target, target);
    CHECK_STR_EQ(r->target_parameters, tparms);
    const struct ks_fw_statement *st = KS_SYSFW_EXPR(r, 0)->statement;
    CHECK_STR_EQ(st->name, name);
    char buf[512] = "";
    size_t off = 0;
    for (size_t i = 0; i < st->values.len; i++)
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%s%s=%s", i ? " " : "",
                                KS_SYSFW_VALUE(st, i)->key, KS_SYSFW_VALUE(st, i)->value);
    CHECK_STR_EQ(buf, kv);

    /* load() gives a form that makes the same rule */
    struct ks_fwf_form g;
    CHECK_MSG(ks_fwf_from_rule(&flat, &services, &g, err, sizeof(err)) == 0, "%s", err);
    struct ks_fw_chain flat2;
    CHECK_MSG(ks_fwf_to_rule(&g, &services, &flat2, err, sizeof(err)) == 0, "%s", err);
    CHECK(ks_schema_equal(&ks_fw_chain_schema, &flat, &flat2));
    ks_fwr_free_chain(&flat2);
    ks_fwr_free_chain(&flat);
}

static void expect_error(const struct ks_fwf_form *f, const char *msg)
{
    struct ks_fw_chain flat;
    char err[256];
    CHECK(ks_fwf_to_rule(f, &services, &flat, err, sizeof(err)) < 0);
    CHECK_STR_EQ(err, msg);
}

TEST(form_to_rule)
{
    struct ks_fwf_form f;
    port_form(&f, KS_FWF_OUT, "22", 1);
    expect_rule(&f, "mangle_output", "tcp", "dport=22", "accept", "");
    port_form(&f, KS_FWF_IN, "53", 0); /* tcp,udp */
    expect_rule(&f, "filter_input", "meta", "l4proto=tcp,udp dport=53", "accept", "");
    port_form(&f, KS_FWF_IN, "80,443", 2);
    expect_rule(&f, "filter_input", "udp", "dport=80,443", "accept", "");
    port_form(&f, KS_FWF_IN, "ssh", 1);
    expect_error(&f, "port not valid.");
    port_form(&f, KS_FWF_IN, "", 1);
    expect_error(&f, "value cannot be 0 or empty.");
    port_form(&f, KS_FWF_IN, "0", 1);
    expect_error(&f, "value cannot be 0 or empty.");
    int ssh = ks_fw_services_by_port(&services, "22");
    if (ssh >= 0) {
        port_form(&f, KS_FWF_IN, services.names[ssh], 1);
        expect_rule(&f, "filter_input", "tcp", "dport=22", "accept", "");
    }

    /* IPs and networks */
    port_form(&f, KS_FWF_IN, "10.0.0.0/24", 0);
    f.st[0].what = KS_FWF_DEST_IP;
    expect_rule(&f, "filter_input", "ip", "daddr=10.0.0.0-10.0.0.255", "accept", "");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "10.0.0.1/24");
    expect_error(&f, "IP network format error, 10.0.0.1/24 has host bits set");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "10.0.0.256");
    expect_error(&f, "'10.0.0.256' does not appear to be an IPv4 or IPv6 address");
    f.st[0].what = KS_FWF_SOURCE_IP;
    f.st[0].opts = 1;
    snprintf(f.st[0].value, sizeof(f.st[0].value), "::1");
    expect_rule(&f, "filter_input", "ip6", "saddr=::1", "accept", "");

    /* interfaces go in the key */
    port_form(&f, KS_FWF_IN, "eth0", 0);
    f.st[0].what = KS_FWF_IIFNAME;
    expect_rule(&f, "filter_input", "iifname", "eth0=", "accept", "");

    /* ct, meta */
    port_form(&f, KS_FWF_FORWARD, "new, established", 0);
    f.st[0].what = KS_FWF_CT_STATE;
    expect_rule(&f, "mangle_forward", "ct", "state=new,established", "accept", "");
    port_form(&f, KS_FWF_IN, "12", 0);
    f.st[0].what = KS_FWF_CT_SET;
    expect_rule(&f, "filter_input", "ct", "set= mark=12", "accept", "");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "x");
    expect_error(&f, "Invalid value x, number expected.");
    port_form(&f, KS_FWF_IN, "0", 0);
    f.st[0].what = KS_FWF_META;
    expect_rule(&f, "filter_input", "meta", "mark=0", "accept", "");
    f.st[0].opts = 1; /* l4proto */
    snprintf(f.st[0].value, sizeof(f.st[0].value), "udp");
    expect_rule(&f, "filter_input", "meta", "l4proto=udp", "accept", "");

    /* icmp, log, quota, limit, counter */
    port_form(&f, KS_FWF_IN, "echo-request,echo-reply", 0);
    f.st[0].what = KS_FWF_ICMP;
    expect_rule(&f, "filter_input", "icmp", "type=echo-request,echo-reply", "accept", "");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "echo");
    expect_error(&f, "Invalid ICMP type \"echo\".");
    port_form(&f, KS_FWF_IN, "fw: ", 0);
    f.st[0].what = KS_FWF_LOG;
    f.st[0].opts = ks_fwf_default_opts(KS_FWF_LOG);
    expect_rule(&f, "filter_input", "log", "level=warn prefix=fw:", "accept", "");
    port_form(&f, KS_FWF_IN, "10/mbytes", 0);
    f.st[0].what = KS_FWF_QUOTA; /* over */
    expect_rule(&f, "filter_input", "quota", "over= mbytes=10", "accept", "");
    f.st[0].opts = 1; /* until */
    expect_rule(&f, "filter_input", "quota", "mbytes=10", "accept", "");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "10/tbytes");
    expect_error(&f, "the value format is 1024/kbytes (or bytes, mbytes, gbytes)");
    port_form(&f, KS_FWF_IN, "10/kbytes/minute", 0);
    f.st[0].what = KS_FWF_LIMIT;
    f.st[0].opts = 0;
    expect_rule(&f, "filter_input", "limit",
                "over= units=10 rate-units=kbytes time-units=minute", "accept", "");
    snprintf(f.st[0].value, sizeof(f.st[0].value), "10/kbytes/week");
    expect_error(&f, "time-limit not valid, use: second, minute, hour or day");
    port_form(&f, KS_FWF_IN, "web", 0);
    f.st[0].what = KS_FWF_COUNTER;
    expect_rule(&f, "filter_input", "counter", "packets= name=web", "accept", "");

    /* verdicts with parameters, and the chain they need */
    port_form(&f, KS_FWF_OUT, "80", 1);
    f.verdict = 5; /* DNAT */
    snprintf(f.verdict_parms, sizeof(f.verdict_parms), "10.0.0.1 : 8080");
    expect_rule(&f, "nat_output", "tcp", "dport=80", "dnat", "to 10.0.0.1:8080");
    snprintf(f.verdict_parms, sizeof(f.verdict_parms), "10.0.0.1");
    expect_error(&f, "Verdict (dnat) parameters format is: <IP>:port.");
    f.verdict = 4; /* QUEUE */
    snprintf(f.verdict_parms, sizeof(f.verdict_parms), "x");
    expect_error(&f, "Verdict (queue) parameters format must be a number");
    snprintf(f.verdict_parms, sizeof(f.verdict_parms), "3");
    expect_rule(&f, "mangle_output", "tcp", "dport=80", "queue", "num 3");
    f.verdict = 6; /* SNAT */
    f.direction = KS_FWF_POSTROUTING;
    snprintf(f.verdict_parms, sizeof(f.verdict_parms), "1.2.3.4:0");
    expect_rule(&f, "nat_postrouting", "tcp", "dport=80", "snat", "to 1.2.3.4:0");

    /* no statement selected */
    port_form(&f, KS_FWF_IN, "1", 1);
    f.st[0].what = -1;
    expect_error(&f, "select a statement.");
}

TEST(direction_rules)
{
    int dir = KS_FWF_IN;
    CHECK_STR_EQ(ks_fwf_check_direction(5, &dir),
                 "DNAT cannot be used with IN or POSTROUTING directions.");
    dir = KS_FWF_IN;
    CHECK_STR_EQ(ks_fwf_check_direction(6, &dir), "SNAT can only be used with POSTROUTING.");
    CHECK_INT_EQ(dir, KS_FWF_POSTROUTING);
    dir = KS_FWF_OUT;
    CHECK(ks_fwf_check_direction(0, &dir) == NULL);
    CHECK_INT_EQ(ks_fwf_verdict_direction(7, KS_FWF_IN), KS_FWF_OUT);
    CHECK_INT_EQ(ks_fwf_verdict_direction(7, KS_FWF_PREROUTING), -1);
    CHECK(ks_fwf_has_verdict_parms(4));
    CHECK(!ks_fwf_has_verdict_parms(0));
    CHECK(!ks_fwf_has_verdict_parms(-1));
}

TEST(titles)
{
    struct ks_fwf_statement st = {KS_FWF_DPORT, 1, 0, "22"};
    char t[256];
    ks_fwf_title(&st, t, sizeof(t));
    CHECK_STR_EQ(t, "tcp dport == 22");
    st.what = KS_FWF_META;
    st.opts = 1;
    st.op = 1;
    ks_fwf_title(&st, t, sizeof(t));
    CHECK_STR_EQ(t, "meta l4proto != 22");
    st.what = KS_FWF_QUOTA;
    st.opts = 0;
    snprintf(st.value, sizeof(st.value), "1/kbytes");
    ks_fwf_title(&st, t, sizeof(t));
    CHECK_STR_EQ(t, "quota over 1/kbytes");
    st.what = KS_FWF_CT_SET;
    ks_fwf_title(&st, t, sizeof(t));
    CHECK_STR_EQ(t, "ct set mark != 1/kbytes");
    st.what = -1;
    ks_fwf_title(&st, t, sizeof(t));
    CHECK_STR_EQ(t, "");
}

TEST(load_unsupported)
{
    struct ks_sysfw fw;
    load_upstream(&fw);
    struct ks_fw_chain flat;
    struct ks_fwf_form f;
    char err[256];
    /* the forward rule queues: a supported target with parameters */
    struct ks_fw_chain *fwd = chain_named(&fw, "mangle_forward");
    const char *uuid = KS_SYSFW_RULE(fwd, 0)->uuid;
    CHECK(ks_fwr_flat_by_uuid(&fw, uuid, &flat) == 0);
    CHECK(ks_fwf_from_rule(&flat, &services, &f, err, sizeof(err)) == 0);
    CHECK_INT_EQ(f.direction, KS_FWF_FORWARD);
    CHECK_INT_EQ(f.verdict, 4);
    CHECK_STR_EQ(f.verdict_parms, "0");
    CHECK_INT_EQ(f.st[0].what, KS_FWF_CT_STATE);
    CHECK_STR_EQ(f.st[0].value, "new");
    /* masquerade isn't in the dialog */
    free(KS_SYSFW_RULE(&flat, 0)->target);
    KS_SYSFW_RULE(&flat, 0)->target = strdup("masquerade");
    CHECK(ks_fwf_from_rule(&flat, &services, &f, err, sizeof(err)) < 0);
    CHECK_STR_EQ(err, "Rule target (masquerade) not supported yet");
    /* nor notrack */
    free(KS_SYSFW_EXPR(KS_SYSFW_RULE(&flat, 0), 0)->statement->name);
    KS_SYSFW_EXPR(KS_SYSFW_RULE(&flat, 0), 0)->statement->name = strdup("notrack");
    CHECK(ks_fwf_from_rule(&flat, &services, &f, err, sizeof(err)) < 0);
    CHECK_STR_EQ(err, "This rule is not supported yet.");
    ks_fwr_free_chain(&flat);
    ks_sysfw_free(&fw);
}

TEST(etc_services)
{
    char path[] = "/tmp/ks-services-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    const char *txt = "# comment\ntcpmux\t\t1/tcp\t\t# TCP port service multiplexer\n"
                      "ssh\t\t22/tcp\t\t\t# SSH\nhttp 80/tcp www\n\nbad line\nlast 9/udp";
    CHECK(write(fd, txt, strlen(txt)) == (ssize_t)strlen(txt));
    close(fd);
    struct ks_fw_services s;
    ks_fw_services_load(&s, path);
    CHECK_INT_EQ(s.n, 4); /* the last line has no newline */
    CHECK_STR_EQ(s.names[0], "tcpmux/1 (tcp)");
    CHECK_STR_EQ(s.names[2], "http/80 (tcp)");
    CHECK_STR_EQ(s.names[3], "wireguard/51820 WireGuard VPN");
    CHECK_INT_EQ(ks_fw_services_by_port(&s, "22"), 1);
    CHECK_INT_EQ(ks_fw_services_by_name(&s, "ssh/22 (tcp)"), 1);
    ks_fw_services_free(&s);
    unlink(path);
}

int main(void)
{
    ks_fw_services_load(&services, NULL);
    RUN(policies_and_profiles);
    RUN(rules_crud);
    RUN(form_to_rule);
    RUN(direction_rules);
    RUN(titles);
    RUN(load_unsupported);
    RUN(etc_services);
    ks_fw_services_free(&services);
    return harness_report();
}
