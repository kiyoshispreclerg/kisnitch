/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The pop-up's logic (ui/prompt_rule.c), the UI's rules table
 * (ui/rulesdb.c) and Python's json.dumps (ui/pyjson.c). The expected
 * values follow upstream's dialogs/prompt code; tests/diff/prompt/ runs
 * the same cases through that code itself.
 */
#include "ui/prompt_rule.h"

#include <stdlib.h>
#include <time.h>

#include "common/json_util.h"
#include "ui/pyjson.h"
#include "ui/res.h"
#include "ui/rulesdb.h"
#include "ui/service.h"
#include "ui/slug.h"
#include "tests/harness.h"

static struct ks_py_aliases aliases;

/* a connection with string fields pointing to literals */
struct conn {
    Protocol__Connection c;
    char *args[4];
    Protocol__Connection__ProcessChecksumsEntry md5;
    Protocol__Connection__ProcessChecksumsEntry *sums[1];
};

static void conn_init(struct conn *k, const char *path, const char *args, const char *dst_ip,
                      const char *dst_host, uint32_t port)
{
    memset(k, 0, sizeof(*k));
    protocol__connection__init(&k->c);
    k->c.protocol = (char *)(uintptr_t) "tcp";
    k->c.src_ip = (char *)(uintptr_t) "10.0.0.2";
    k->c.src_port = 40000;
    k->c.dst_ip = (char *)(uintptr_t)dst_ip;
    k->c.dst_host = (char *)(uintptr_t)dst_host;
    k->c.dst_port = port;
    k->c.user_id = 1000;
    k->c.process_id = 4242;
    k->c.process_path = (char *)(uintptr_t)path;
    k->c.process_cwd = (char *)(uintptr_t) "/home/u";
    if (args != NULL) {
        k->args[0] = (char *)(uintptr_t)args;
        k->c.process_args = k->args;
        k->c.n_process_args = 1;
    }
    protocol__connection__process_checksums_entry__init(&k->md5);
    k->md5.key = (char *)(uintptr_t) "process.hash.md5";
    k->md5.value = (char *)(uintptr_t) "";
    k->sums[0] = &k->md5;
    k->c.process_checksums = k->sums;
    k->c.n_process_checksums = 1;
}

static const struct ks_combo_item *item(const struct ks_combo *c, enum ks_field f, int nth)
{
    for (size_t i = 0; i < c->len; i++) {
        if (c->items[i].field == f && nth-- == 0)
            return &c->items[i];
    }
    return NULL;
}

TEST(combos)
{
    struct conn k;
    conn_init(&k, "/usr/bin/curl", "curl https://www.example.com", "93.184.216.34",
              "www.example.com", 443);
    struct ks_combo what = {0}, ip = {0};
    CHECK(ks_prompt_fill_combos(&k.c, "1000 (u)", &aliases, &what, &ip) == 0);
    static const char *const want[] = {
        "from this executable", "from this command line", "to port 443",
        "to 93.184.216.34", "from user 1000 (u)", "from this PID",
        "to 93.184.216.0/24", "to 93.184.0.0/16", "to 93.0.0.0/8",
        "www.example.com", "to *.example.com",
        "to 93.*", "to 93.184.*", "to 93.184.216.*",
    };
    CHECK_INT_EQ(what.len, sizeof(want) / sizeof(want[0]));
    for (size_t i = 0; i < what.len; i++)
        CHECK_STR_EQ(what.items[i].text, want[i]);
    static const char *const want_ip[] = {
        "www.example.com", "to *.example.com", "to 93.184.216.34", "to 93.*",
        "to 93.184.*", "to 93.184.216.*", "to 93.184.216.0/24", "to 93.184.0.0/16",
        "to 93.0.0.0/8",
    };
    CHECK_INT_EQ(ip.len, sizeof(want_ip) / sizeof(want_ip[0]));
    for (size_t i = 0; i < ip.len; i++)
        CHECK_STR_EQ(ip.items[i].text, want_ip[i]);
    ks_combo_free(&what);
    ks_combo_free(&ip);

    /* IPv6, an alias, no host */
    conn_init(&k, "/usr/bin/ssh", "ssh h", "fd00:1:2:3::5", "", 22);
    CHECK(ks_prompt_fill_combos(&k.c, "1000 (u)", &aliases, &what, &ip) == 0);
    CHECK_STR_EQ(what.items[6].text, "to LAN");
    CHECK_STR_EQ(what.items[7].text, "to fd00:1:2:3::/64");
    CHECK_STR_EQ(what.items[8].text, "to fd00:1:2:3::5/128");
    CHECK_INT_EQ(what.len, 9);
    CHECK_STR_EQ(ip.items[0].text, "to fd00:1:2:3::5");
    ks_combo_free(&what);
    ks_combo_free(&ip);

    /* appimage and snap entries */
    conn_init(&k, "/tmp/.mount_Foo1a2b/usr/bin/app.bin", "app", "1.2.3.4", "", 80);
    CHECK(ks_prompt_fill_combos(&k.c, "", &aliases, &what, &ip) == 0);
    CHECK_STR_EQ(what.items[6].text, "from /tmp/.mount_Foo1a2*/app.bin");
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 0, "app", "app"), 6);
    ks_combo_free(&what);
    ks_combo_free(&ip);
    conn_init(&k, "/snap/firefox/4793/usr/lib/firefox/firefox", "firefox", "1.2.3.4", "", 443);
    CHECK(ks_prompt_fill_combos(&k.c, "", &aliases, &what, &ip) == 0);
    CHECK_STR_EQ(what.items[6].text, "from /snap/firefox/*/usr/lib/firefox/firefox");
    ks_combo_free(&what);
    ks_combo_free(&ip);
}

TEST(default_target)
{
    struct conn k;
    struct ks_combo what = {0}, ip = {0};
    conn_init(&k, "/usr/bin/curl", "curl x", "1.2.3.4", "", 80);
    CHECK(ks_prompt_fill_combos(&k.c, "", &aliases, &what, &ip) == 0);
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 1, "curl", "curl x"), 1);
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 1, "curl", ""), 2);
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 1, "", "curl x"), 2);
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 99, "curl", "curl x"), -1);
    k.c.process_id = 0;
    CHECK_INT_EQ(ks_prompt_default_target(&what, &k.c, 1, "curl", "curl x"), 2);
    ks_combo_free(&what);
    ks_combo_free(&ip);
}

TEST(network_aliases)
{
    CHECK_STR_EQ(ks_py_aliases_get(&aliases, "192.168.7.1"), "LAN");
    CHECK_STR_EQ(ks_py_aliases_get(&aliases, "127.0.0.1"), "LAN");
    CHECK_STR_EQ(ks_py_aliases_get(&aliases, "::1"), "LAN"); /* Python takes "::1" */
    CHECK_STR_EQ(ks_py_aliases_get(&aliases, "239.1.1.1"), "MULTICAST");
    CHECK(ks_py_aliases_get(&aliases, "8.8.8.8") == NULL);
    CHECK(ks_py_aliases_get(&aliases, "not an ip") == NULL);

    /* a network with host bits set ends the search (ValueError) */
    struct ks_py_aliases a;
    const char j[] = "{\"A\": [\"10.0.0.1/8\"], \"B\": [\"8.8.8.0/24\"]}";
    CHECK(ks_py_aliases_parse(&a, j, sizeof(j) - 1) == 0);
    CHECK(ks_py_aliases_get(&a, "8.8.8.8") == NULL);
    ks_py_aliases_free(&a);
    const char j2[] = "{\"B\": [\"8.8.8.0/24\"], \"A\": [\"10.0.0.1/8\"]}";
    CHECK(ks_py_aliases_parse(&a, j2, sizeof(j2) - 1) == 0);
    CHECK_STR_EQ(ks_py_aliases_get(&a, "8.8.8.8"), "B");
    ks_py_aliases_free(&a);
}

/* builds a rule for `what` (the n-th entry with that field) */
static Protocol__Rule *build(struct ks_arena *a, struct conn *k, enum ks_field f, int nth,
                             int action, int duration, bool dst_ip, bool dst_port, bool uid,
                             struct ks_rulesdb *db, struct ks_combo *what, struct ks_combo *ip)
{
    ks_combo_free(what);
    ks_combo_free(ip);
    if (ks_prompt_fill_combos(&k->c, "1000 (u)", &aliases, what, ip) < 0)
        return NULL;
    struct ks_prompt_choice ch = {
        .action_idx = action,
        .duration_idx = duration,
        .what = item(what, f, nth),
        .what_ip = &ip->items[0],
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .user_id = uid,
    };
    return ks_prompt_build_rule(a, &k->c, &ch, &aliases, db, "unix:/local", 1700000000);
}

TEST(rules)
{
    struct ks_rulesdb db;
    ks_rulesdb_init(&db);
    struct ks_arena a = {0};
    struct ks_combo what = {0}, ip = {0};
    struct conn k;
    conn_init(&k, "/usr/bin/curl", "curl -s http://www.example.com/x", "93.184.216.34",
              "www.example.com", 80);

    Protocol__Rule *r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 1, 8, false, false, false, &db,
                              &what, &ip);
    CHECK(r != NULL);
    CHECK_STR_EQ(r->name, "allow-always-simple-usr-bin-curl");
    CHECK_STR_EQ(r->action, "allow");
    CHECK_STR_EQ(r->duration, "always");
    CHECK_STR_EQ(r->operator_->type, "simple");
    CHECK_STR_EQ(r->operator_->operand, "process.path");
    CHECK_STR_EQ(r->operator_->data, "/usr/bin/curl");
    CHECK_INT_EQ(r->operator_->n_list, 0);
    CHECK(r->enabled);
    CHECK_INT_EQ(r->created, 1700000000);

    /* the same rule again: exists() checks the name before the extras */
    const char *row[KS_RF_COUNT] = {
        [KS_RF_NODE] = "unix:/local", [KS_RF_NAME] = "allow-always-simple-usr-bin-curl",
        [KS_RF_ACTION] = "allow", [KS_RF_DURATION] = "always", [KS_RF_OP_TYPE] = "simple",
        [KS_RF_OP_OPERAND] = "process.path", [KS_RF_OP_DATA] = "/usr/bin/curl",
        [KS_RF_ENABLED] = "True",
    };
    CHECK(ks_rulesdb_add_row(&db, row) == 0);
    r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->name, "allow-always-simple-usr-bin-curl"); /* exists: kept */
    r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 0, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->name, "deny-always-simple-usr-bin-curl"); /* free name */
    row[KS_RF_ACTION] = "deny"; /* same name, other action: not the same rule */
    row[KS_RF_NAME] = "deny-always-simple-usr-bin-curl";
    row[KS_RF_OP_DATA] = "/usr/bin/wget";
    CHECK(ks_rulesdb_add_row(&db, row) == 0);
    r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 0, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->name, "deny-always-simple-usr-bin-curl-0");

    /* advanced checks: a list, named after everything, the main operator last */
    r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 0, 6, true, true, true, &db, &what, &ip);
    CHECK_STR_EQ(r->name, "deny-12h-list-usr-bin-curl-www-example-com-80-1000");
    CHECK_STR_EQ(r->operator_->type, "list");
    CHECK_STR_EQ(r->operator_->operand, "list");
    CHECK_STR_EQ(r->operator_->data,
                 "[{\"type\": \"simple\", \"operand\": \"dest.host\", \"data\": "
                 "\"www.example.com\"}, {\"type\": \"simple\", \"operand\": \"dest.port\", "
                 "\"data\": \"80\"}, {\"type\": \"simple\", \"operand\": \"user.id\", \"data\": "
                 "\"1000\"}, {\"type\": \"simple\", \"operand\": \"process.path\", \"data\": "
                 "\"/usr/bin/curl\"}]");
    CHECK_INT_EQ(r->operator_->n_list, 4);
    CHECK_STR_EQ(r->operator_->list[3]->data, "/usr/bin/curl");
    CHECK(!r->operator_->list[0]->sensitive);

    /* a checkbox for what's already the target: still a list, of one */
    r = build(&a, &k, KS_FIELD_DST_PORT, 0, 1, 0, false, true, false, &db, &what, &ip);
    CHECK_STR_EQ(r->name, "allow-once-list-80");
    CHECK_INT_EQ(r->operator_->n_list, 1);

    /* regexps */
    r = build(&a, &k, KS_FIELD_REGEX_HOST, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->type, "regexp");
    CHECK_STR_EQ(r->operator_->operand, "dest.host");
    CHECK_STR_EQ(r->operator_->data, "^(|.*\\.)example\\.com$");
    CHECK_STR_EQ(r->name, "allow-always-simple-example-com");
    r = build(&a, &k, KS_FIELD_REGEX_IP, 1, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->data, "93\\.184\\..*");
    CHECK_STR_EQ(r->operator_->operand, "dest.ip");
    r = build(&a, &k, KS_FIELD_DST_NETWORK, 1, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->type, "network");
    CHECK_STR_EQ(r->operator_->data, "93.184.0.0/16");
    r = build(&a, &k, KS_FIELD_DST_HOST, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->data, "www.example.com");

    /* the command line: absolute, so it's enough on its own */
    k.args[0] = (char *)(uintptr_t) "/usr/bin/curl -s x";
    r = build(&a, &k, KS_FIELD_PROC_ARGS, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->type, "simple");
    CHECK_STR_EQ(r->operator_->operand, "process.command");
    CHECK_STR_EQ(r->operator_->data, "/usr/bin/curl -s x");
    /* relative: the binary too */
    k.args[0] = (char *)(uintptr_t) "curl -s x";
    r = build(&a, &k, KS_FIELD_PROC_ARGS, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->type, "list");
    CHECK_STR_EQ(r->name, "allow-always-simple-curl-s-x");
    CHECK_STR_EQ(r->operator_->list[0]->operand, "process.path");
    CHECK_STR_EQ(r->operator_->list[1]->operand, "process.command");

    /* a network with an alias also filters by the binary */
    conn_init(&k, "/usr/bin/smbclient", "smbclient", "192.168.1.10", "", 445);
    r = build(&a, &k, KS_FIELD_DST_NETWORK, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(what.items[6].text, "to LAN");
    CHECK_STR_EQ(r->name, "allow-always-simple-lan-smbclient");
    CHECK_STR_EQ(r->operator_->type, "list");
    CHECK_STR_EQ(r->operator_->data,
                 "[{\"type\": \"simple\", \"operand\": \"process.path\", \"data\": "
                 "\"/usr/bin/smbclient\"}, {\"type\": \"network\", \"operand\": "
                 "\"dest.network\", \"data\": \"LAN\"}]");

    /* appimage and snap regexps */
    conn_init(&k, "/tmp/.mount_Foo1a2b/usr/bin/app", "app", "1.2.3.4", "", 80);
    r = build(&a, &k, KS_FIELD_APPIMAGE, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->data, "^/tmp/\\.mount_Foo1a2[0-9A-Za-z]+\\/.*app$");
    conn_init(&k, "/snap/firefox/4793/usr/lib/firefox/firefox", "firefox", "1.2.3.4", "", 80);
    r = build(&a, &k, KS_FIELD_SNAP, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK_STR_EQ(r->operator_->data,
                 "^\\/snap\\/firefox\\/[0-9]+\\/usr\\/lib\\/firefox\\/firefox$");

    /* an empty operator: no rule */
    conn_init(&k, "", NULL, "1.2.3.4", "", 80);
    r = build(&a, &k, KS_FIELD_PROC_PATH, 0, 1, 8, false, false, false, &db, &what, &ip);
    CHECK(r == NULL);

    ks_arena_free(&a);
    ks_combo_free(&what);
    ks_combo_free(&ip);
    ks_rulesdb_free(&db);
}

TEST(messages)
{
    struct conn k;
    conn_init(&k, "/usr/bin/curl", "curl", "1.2.3.4", "a<b>.com", 443);
    char *m = ks_prompt_message(true, "unix:/local", "", "curl", &k.c);
    CHECK_STR_EQ(m, "<b>curl</b> is connecting to <b>a&lt;b&gt;.com</b> on TCP port 443");
    free(m);
    k.c.dst_port = 0;
    k.c.protocol = (char *)(uintptr_t) "icmp";
    m = ks_prompt_message(false, "ipv4:10.1.1.1", "host", "ping", &k.c);
    CHECK_STR_EQ(m, "<b>Remote</b> process <b>ping</b> running on <b>10.1.1.1 (host)</b> is "
                    "connecting to <b>a&lt;b&gt;.com</b>, ICMP");
    free(m);
    k.c.dst_port = 53;
    k.c.protocol = (char *)(uintptr_t) "udp";
    k.c.dst_host = (char *)(uintptr_t) "x.org";
    m = ks_prompt_message(true, "unix:/local", "", "systemd-resolved", &k.c);
    CHECK_STR_EQ(m, "<b>systemd-resolved</b> is attempting to resolve <b>x.org</b> via "
                    "1.2.3.4, UDP port 53");
    free(m);

    /* labels */
    k.args[0] = (char *)(uintptr_t) "curl";
    char *l = ks_prompt_path_label("curl", "curl", &k.c);
    CHECK_STR_EQ(l, "/usr/bin/curl");
    free(l);
    l = ks_prompt_path_label("Curl app", "curl", &k.c);
    CHECK_STR_EQ(l, "(/usr/bin/curl)");
    free(l);
    k.args[0] = (char *)(uintptr_t) "/usr/bin/curl";
    CHECK(ks_prompt_path_label("curl", "/usr/bin/curl", &k.c) == NULL);
    CHECK(ks_prompt_args_label("AMule", "amule") == NULL);
    l = ks_prompt_args_label("curl", "curl -s\x01x");
    CHECK_STR_EQ(l, "curl -sx");
    free(l);
    char *t = ks_prompt_truncate("\xc3\xa1" "bcdef", 3);
    CHECK_STR_EQ(t, "\xc3\xa1" "bc...");
    free(t);
}

TEST(rulesdb)
{
    struct ks_rulesdb db;
    ks_rulesdb_init(&db);
    /* add_rules(): the operator list goes as MessageToJson renders it */
    Protocol__Operator o1 = PROTOCOL__OPERATOR__INIT, o2 = PROTOCOL__OPERATOR__INIT,
                       op = PROTOCOL__OPERATOR__INIT;
    o1.type = (char *)(uintptr_t) "simple";
    o1.operand = (char *)(uintptr_t) "process.path";
    o1.data = (char *)(uintptr_t) "/usr/bin/x\xc3\xa9";
    o2.type = (char *)(uintptr_t) "regexp";
    o2.operand = (char *)(uintptr_t) "dest.host";
    o2.data = (char *)(uintptr_t) "";
    o2.sensitive = 1;
    Protocol__Operator *list[2] = {&o1, &o2};
    op.type = (char *)(uintptr_t) "list";
    op.operand = (char *)(uintptr_t) "list";
    op.data = (char *)(uintptr_t) "";
    op.list = list;
    op.n_list = 2;
    Protocol__Rule r = PROTOCOL__RULE__INIT;
    r.name = (char *)(uintptr_t) "r1";
    r.action = (char *)(uintptr_t) "deny";
    r.duration = (char *)(uintptr_t) "always";
    r.enabled = 1;
    r.operator_ = &op;
    r.created = 0;
    Protocol__Rule *rules[1] = {&r};
    CHECK(ks_rulesdb_add_pb(&db, "unix:/local", rules, 1) == 0);
    const struct ks_ui_rule *row = ks_rulesdb_get(&db, "r1", "unix:/local");
    CHECK(row != NULL);
    CHECK_STR_EQ(row->f[KS_RF_OP_DATA],
                 "[{\"type\": \"simple\", \"operand\": \"process.path\", \"data\": "
                 "\"/usr/bin/x\\u00e9\"}, {\"type\": \"regexp\", \"operand\": \"dest.host\", "
                 "\"sensitive\": true}]");
    CHECK_STR_EQ(row->f[KS_RF_ENABLED], "True");
    CHECK_STR_EQ(row->f[KS_RF_PRECEDENCE], "False");

    /* and back (Rule.new_from_records) */
    struct ks_arena a = {0};
    Protocol__Rule *back = ks_rulesdb_to_pb(&a, row);
    CHECK(back != NULL);
    CHECK_STR_EQ(back->operator_->data, "");
    CHECK_INT_EQ(back->operator_->n_list, 2);
    CHECK_STR_EQ(back->operator_->list[0]->data, "/usr/bin/x\xc3\xa9");
    CHECK(back->operator_->list[1]->sensitive);
    ks_arena_free(&a);

    /* LIKE */
    CHECK(ks_sql_like("%/USR/bin%", "x /usr/BIN/y"));
    CHECK(ks_sql_like("a_c", "a\xc3\xa9" "c"));
    CHECK(!ks_sql_like("%abc", "ab"));
    size_t idx[4];
    CHECK_INT_EQ(ks_rulesdb_find_like(&db, "unix:/local", KS_RF_OP_DATA, "/usr/bin", idx, 4), 1);
    CHECK_INT_EQ(ks_rulesdb_find_like(&db, "other", KS_RF_OP_DATA, "/usr/bin", idx, 4), 0);

    /* duration filter: rules with these durations aren't kept */
    ks_rulesdb_set_duration_filter(&db, true, 2);
    CHECK(ks_rulesdb_duration_filtered(&db, "once"));
    CHECK(ks_rulesdb_duration_filtered(&db, "30s"));
    CHECK(!ks_rulesdb_duration_filtered(&db, "5m"));
    r.duration = (char *)(uintptr_t) "30s";
    r.name = (char *)(uintptr_t) "r2";
    CHECK(ks_rulesdb_add_pb(&db, "unix:/local", rules, 1) == 0);
    CHECK(ks_rulesdb_get(&db, "r2", NULL) == NULL);
    ks_rulesdb_set_duration_filter(&db, false, 2);
    CHECK(!ks_rulesdb_duration_filtered(&db, "once"));

    ks_rulesdb_disable(&db, "unix:/local", "r1");
    CHECK_STR_EQ(ks_rulesdb_get(&db, "r1", NULL)->f[KS_RF_ENABLED], "False");
    ks_rulesdb_delete(&db, "r1", "elsewhere");
    CHECK(ks_rulesdb_get(&db, "r1", NULL) != NULL);
    ks_rulesdb_delete(&db, "r1", NULL);
    CHECK(ks_rulesdb_get(&db, "r1", NULL) == NULL);
    ks_rulesdb_free(&db);
}

TEST(checksums)
{
    struct ks_rulesdb db;
    ks_rulesdb_init(&db);
    struct conn k;
    conn_init(&k, "/usr/bin/curl", "curl", "1.2.3.4", "", 80);
    k.md5.value = (char *)(uintptr_t) "aaaa";
    const char *row[KS_RF_COUNT] = {
        [KS_RF_NODE] = "unix:/local", [KS_RF_ENABLED] = "True", [KS_RF_ACTION] = "allow",
        [KS_RF_DURATION] = "always", [KS_RF_OP_TYPE] = "list", [KS_RF_OP_OPERAND] = "list",
        [KS_RF_OP_DATA] = "[{\"type\": \"simple\", \"operand\": \"process.hash.md5\", \"data\": "
                          "\"bbbb\"}, {\"type\": \"simple\", \"operand\": \"process.path\", "
                          "\"data\": \"/usr/bin/curl\"}]",
    };
    row[KS_RF_NAME] = "first";
    CHECK(ks_rulesdb_add_row(&db, row) == 0);
    char *names[4];
    size_t n;
    char *expected;
    /* the first match is skipped, as upstream does */
    CHECK(!ks_prompt_checksum_mismatch(&db, "unix:/local", &k.c, names, 4, &n, &expected));
    CHECK_INT_EQ(n, 0);
    free(expected);
    row[KS_RF_NAME] = "second";
    CHECK(ks_rulesdb_add_row(&db, row) == 0);
    CHECK(ks_prompt_checksum_mismatch(&db, "unix:/local", &k.c, names, 4, &n, &expected));
    CHECK_INT_EQ(n, 1);
    CHECK_STR_EQ(names[0], "second");
    CHECK_STR_EQ(expected, "['bbbb']");
    free(names[0]);
    free(expected);

    struct ks_arena a = {0};
    Protocol__Rule *r = ks_prompt_checksum_update(&a, &db, "unix:/local", "second", &k.c);
    CHECK(r != NULL);
    CHECK_STR_EQ(r->operator_->list[0]->data, "aaaa");
    CHECK_STR_HAS(ks_rulesdb_get(&db, "second", NULL)->f[KS_RF_OP_DATA], "\"aaaa\"");
    CHECK(ks_prompt_checksum_update(&a, &db, "unix:/local", "nope", &k.c) == NULL);
    ks_arena_free(&a);
    ks_rulesdb_free(&db);
}

TEST(pyjson)
{
    const char in[] = "{\"b\": [1, 2.5, -0.0001, 1e20, true, null, \"\\u00e9\\ud83d\\ude00\\n\"],"
                      " \"a\": {\"x\": \"\\\"/\"}, \"n\": 30}";
    char err[128];
    cJSON *j = ks_json_parse(in, sizeof(in) - 1, err, sizeof(err));
    CHECK(j != NULL);
    char *s = ks_pyjson_dumps(j);
    CHECK_STR_EQ(s, "{\"b\": [1, 2.5, -0.0001, 1e+20, true, null, \"\\u00e9\\ud83d\\ude00\\n\"], "
                    "\"a\": {\"x\": \"\\\"/\"}, \"n\": 30}");
    free(s);
    cJSON_Delete(j);
}

TEST(service_helpers)
{
    CHECK_INT_EQ(ks_ui_duration_seconds("30s"), 30);
    CHECK_INT_EQ(ks_ui_duration_seconds("5m"), 300);
    CHECK_INT_EQ(ks_ui_duration_seconds("12h"), 43200);
    CHECK_INT_EQ(ks_ui_duration_seconds("1h30m"), 5400);
    CHECK_INT_EQ(ks_ui_duration_seconds("always"), 0);
    CHECK_INT_EQ(ks_ui_duration_seconds("until restart"), 0);
    CHECK_INT_EQ(ks_ui_duration_seconds("10ms"), 0); /* invalid unit "ms" */
    CHECK(ks_ui_versions_differ("1.8.0", "1.6.5"));
    CHECK(ks_ui_versions_differ("1.8.0", "2.8.0"));
    CHECK(!ks_ui_versions_differ("1.8.0", "1.8.3"));
    CHECK(!ks_ui_versions_differ("1.8.0", "0.0.1+os1.8.0")); /* not x.y.z: an exception */
}

int main(void)
{
    if (ks_py_aliases_parse(&aliases, (const char *)ks_res_network_aliases_json,
                            ks_res_network_aliases_json_len) < 0)
        return 1;
    RUN(combos);
    RUN(default_target);
    RUN(network_aliases);
    RUN(rules);
    RUN(messages);
    RUN(rulesdb);
    RUN(checksums);
    RUN(pyjson);
    RUN(service_helpers);
    ks_py_aliases_free(&aliases);
    return harness_report();
}
