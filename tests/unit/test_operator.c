/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Operator tests. The first group ports upstream's
 * daemon/rule/operator_test.go case by case; the rest is a table covering
 * every operand and type, including the edge cases phase 1 asks for.
 */
#include "daemon/rules/rule.h"

#include <net/if.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/rules/aliases.h"
#include "tests/harness.h"

#define LISTS KS_FIXTURES_DIR "/upstream/rules/lists"

/* Upstream's test connection. */
static const char *const proc_args[] = {"-rules-path", "/etc/opensnitchd/rules/"};
static struct ks_process proc;
static struct ks_conn conn;

static void restore_connection(void)
{
    memset(&proc, 0, sizeof(proc));
    proc.pid = 12345;
    proc.path = "/usr/bin/opensnitchd";
    proc.args = proc_args;
    proc.nargs = 2;

    memset(&conn, 0, sizeof(conn));
    conn.protocol = "TCP";
    conn.src_port = 66666;
    ks_ip_parse("192.168.1.111", &conn.src_ip);
    ks_ip_parse("185.53.178.14", &conn.dst_ip);
    conn.dst_port = 443;
    conn.dst_host = "opensnitch.io";
    conn.process = &proc;
    conn.uid = 666;
}

/* Builds an operator the way NewOperator does (uncompiled). */
static struct ks_operator *new_op(const char *type, bool sensitive,
                                  const char *operand, const char *data)
{
    struct ks_operator *o = calloc(1, sizeof(*o));
    o->type = strdup(type);
    o->sensitive = sensitive;
    o->operand = strdup(operand);
    o->data = strdup(data);
    return o;
}

static void free_op(struct ks_operator *o)
{
    ks_operator_clear(o);
    free(o);
}

static int compile(struct ks_operator *o, const struct ks_rules_env *env)
{
    char err[256];
    return ks_operator_compile(o, env, err, sizeof(err));
}

/* opList.List = unmarshalListData(data); compileListOperators(). */
static int set_list(struct ks_operator *o, const char *json)
{
    char err[256];
    for (size_t i = 0; i < o->list.len; i++)
        ks_operator_clear(KS_ARRAY_ITEM(o->list, struct ks_operator, i));
    free(o->list.items);
    if (ks_operator_list_parse(json, &o->list, err, sizeof(err)) < 0)
        return -1;
    for (size_t i = 0; i < o->list.len; i++)
        if (ks_operator_compile(KS_ARRAY_ITEM(o->list, struct ks_operator, i),
                                NULL, err, sizeof(err)) < 0)
            return -1;
    return 0;
}

/* ---- ported from operator_test.go -------------------------------------- */

TEST(upstream_simple)
{
    restore_connection();
    struct ks_operator *o = new_op("simple", false, "true", "");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, NULL, false));
    free_op(o);

    o = new_op("simple", false, "process.id", "12345");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", false, "process.path", "/usr/bin/opensnitchd");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    o->sensitive = true;
    proc.path = "/usr/bin/OpenSnitchd";
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    restore_connection();
    o = new_op("simple", false, "dest.host", "opensnitch.io");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    conn.dst_host = "www.opensnitch.io";
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", true, "dest.host", "OpEnsNitCh.io");
    CHECK(compile(o, NULL) == 0);
    conn.dst_host = "OpEnsNitCh.io";
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", false, "process.command",
               "-rules-path /etc/opensnitchd/rules/");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", false, "dest.ip", "185.53.178.14");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", false, "user.id", "666");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(upstream_network)
{
    restore_connection();
    struct ks_operator *o = new_op("network", false, "dest.network", "185.53.178.14/24");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("network", false, "dest.network", "8.8.8.8/24");
    CHECK(compile(o, NULL) == 0);
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(upstream_regexp)
{
    restore_connection();
    struct ks_operator *o = new_op("regexp", false, "protocol", "^TCP$");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("regexp", false, "protocol", "^TC(P$");
    CHECK(compile(o, NULL) == -1);
    free_op(o);

    proc.path = "/tmp/cUrL";
    o = new_op("regexp", true, "process.path", "^/tmp/cUrL$");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    proc.path = "/tmp/curl";
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("regexp", false, "process.path", "^/tmp/cUrL$");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    /* Insensitive regexps are lowercased in place, as upstream does. */
    CHECK_STR_EQ(o->data, "^/tmp/curl$");
    free_op(o);

    restore_connection();
    conn.dst_host = "";
    o = new_op("regexp", true, "dest.host", "^$");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);

    o = new_op("simple", true, "dest.host", "");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(upstream_list)
{
    restore_connection();
    const char *data = "[{\"type\": \"simple\", \"operand\": \"dest.ip\", \"data\": "
                       "\"185.53.178.14\", \"sensitive\": false}, {\"type\": \"simple\", "
                       "\"operand\": \"dest.port\", \"data\": \"443\", \"sensitive\": false}]";
    struct ks_operator *o = new_op("list", false, "protocol", data);
    CHECK(compile(o, NULL) == 0);
    CHECK_STR_EQ(o->operand, "list"); /* Compile rewrites the operand */
    CHECK(set_list(o, o->data) == 0);
    CHECK(ks_operator_match(o, &conn, false));

    CHECK(set_list(o, "[{\"type\": \"regexp\", \"operand\": \"process.path\", \"data\": "
                      "\"^/usr/bin/.*\", \"sensitive\": false},{\"type\": \"simple\", "
                      "\"operand\": \"dest.ip\", \"data\": \"185.53.178.14\", \"sensitive\": "
                      "false}, {\"type\": \"simple\", \"operand\": \"dest.port\", \"data\": "
                      "\"443\", \"sensitive\": false}]") == 0);
    CHECK(ks_operator_match(o, &conn, false));

    /* The items' own "sensitive" counts, not the list's. */
    CHECK(set_list(o, "[{\"type\": \"regexp\", \"operand\": \"process.path\", \"data\": "
                      "\"^/usr/BiN/.*\", \"sensitive\": false},{\"type\": \"simple\", "
                      "\"operand\": \"dest.ip\", \"data\": \"185.53.178.14\", \"sensitive\": "
                      "false}, {\"type\": \"simple\", \"operand\": \"dest.port\", \"data\": "
                      "\"443\", \"sensitive\": false}]") == 0);
    proc.path = "/usr/BiN/opensnitchd";
    o->sensitive = true;
    CHECK(ks_operator_match(o, &conn, false));
    o->sensitive = false;
    proc.path = "/USR/BiN/opensnitchd";
    CHECK(ks_operator_match(o, &conn, false));
    proc.path = "/USR/bin/opensnitchd";
    CHECK(ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(upstream_lists)
{
    restore_connection();
    /* lists.domains: 4 lines, 1 comment, 1 duplicate -> 2 domains. */
    struct ks_operator *o = new_op("lists", false, "lists.domains", LISTS "/domains/");
    CHECK(compile(o, NULL) == 0);
    CHECK_INT_EQ(ks_operator_lists_count(o), 2);
    CHECK(ks_operator_match(o, &conn, false));
    ks_operator_reset(o); /* StopMonitoringLists + ClearLists */
    CHECK_INT_EQ(ks_operator_lists_count(o), 0);
    free_op(o);

    static const struct {
        const char *operand, *dir;
    } lists[] = {
        {"lists.ips", LISTS "/ips/"},
        {"lists.nets", LISTS "/nets/"},
        {"lists.domains", LISTS "/domains/"},
        {"lists.domains_regexp", LISTS "/regexp/"},
    };
    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
        char data[512];
        snprintf(data, sizeof(data),
                 "[{\"type\": \"simple\", \"operand\": \"user.id\", \"data\": \"666\", "
                 "\"sensitive\": false}, {\"type\": \"lists\", \"operand\": \"%s\", "
                 "\"data\": \"%s\", \"sensitive\": false}]",
                 lists[i].operand, lists[i].dir);
        o = new_op("list", false, "list", data);
        CHECK(compile(o, NULL) == 0);
        CHECK(set_list(o, data) == 0);
        struct ks_operator *sub = KS_ARRAY_ITEM(o->list, struct ks_operator, 1);
        CHECK_MSG(ks_operator_lists_count(sub) == 2, "%s: %zu entries",
                  lists[i].operand, ks_operator_lists_count(sub));
        CHECK_MSG(ks_operator_match(o, &conn, false), "%s doesn't match",
                  lists[i].operand);
        free_op(o);
    }
}

/* ---- every operand ------------------------------------------------------ */

static const char *const args_with_spaces[] = {"/usr/bin/curl", "-s", "https://x"};
static const struct ks_env_var env[] = {{"HOME", "/home/u"}, {"LANG", "C.UTF-8"}};
static struct ks_process parent2 = {.pid = 1, .path = "/sbin/init"};
static struct ks_process parent1 = {.pid = 900, .path = "/usr/bin/bash",
                                    .parent = &parent2};

static void rich_connection(void)
{
    restore_connection();
    proc.parent = &parent1;
    proc.args = args_with_spaces;
    proc.nargs = 3;
    proc.env = env;
    proc.nenv = 2;
    proc.checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    conn.iface_in = 0;
    conn.iface_out = (int)if_nametoindex("lo");
    ks_ip_parse("2001:db8::10", &conn.src_ip);
}

static const struct {
    const char *type, *operand, *data;
    bool sensitive;
    int want; /* 1 match, 0 no match, -1 compile error */
} table[] = {
    {"simple", "true", "", false, 1},
    {"network", "true", "", false, -1},  /* empty data: CIDR error */
    {"simple", "process.id", "12345", false, 1},
    {"simple", "process.id", "1234", false, 0},
    {"simple", "process.path", "/USR/BIN/OPENSNITCHD", false, 1},
    {"simple", "process.path", "/USR/BIN/OPENSNITCHD", true, 0},
    {"simple", "process.parent.path", "/sbin/init", false, 1},
    {"simple", "process.parent.path", "/usr/bin/bash", false, 1},
    {"simple", "process.parent.path", "/usr/bin/opensnitchd", false, 0},
    {"regexp", "process.parent.path", "^/usr/", false, 1},
    {"simple", "process.command", "/usr/bin/curl -s https://x", false, 1},
    {"regexp", "process.command", "\\s-s\\s", false, 1},
    {"simple", "process.env.HOME", "/home/u", false, 1},
    {"simple", "process.env. HOME ", "/home/u", false, 1}, /* name is trimmed */
    {"simple", "process.env.MISSING", "", false, 1},       /* absent = "" */
    {"simple", "process.env.MISSING", "x", false, 0},
    {"simple", "user.id", "666", false, 1},
    {"simple", "user.id", "0", false, 0},
    {"simple", "user.name", "root", false, 0},              /* uid 666 */
    {"simple", "user.name", "no-such-user-kisnitch", false, -1},
    {"simple", "source.ip", "2001:db8::10", false, 1},
    {"simple", "source.port", "66666", false, 1},
    {"simple", "dest.ip", "185.53.178.14", false, 1},
    {"simple", "dest.host", "OPENSNITCH.IO", false, 1},
    {"simple", "dest.port", "443", false, 1},
    {"simple", "dest.port", "0443", false, 0},
    {"simple", "protocol", "tcp", false, 1},
    {"simple", "protocol", "tcp", true, 0},
    {"simple", "iface.in", "lo", false, 0},  /* index 0: no interface */
    {"simple", "iface.out", "lo", false, 1},
    {"regexp", "iface.out", "^l", false, 1},
    {"simple", "unknown.operand", "x", false, 0},
    {"bogus", "process.path", "x", false, -1},
    {"complex", "process.path", "x", false, -1},
    /* networks */
    {"network", "dest.network", "185.53.0.0/16", false, 1},
    {"network", "dest.network", "185.53.178.14", false, -1}, /* no prefix */
    {"network", "dest.network", "", false, -1},
    {"network", "source.network", "2001:db8::/32", false, 1},
    {"network", "source.network", "2001:db9::/32", false, 0},
    {"network", "source.network", "0.0.0.0/0", false, 0},
    {"network", "dest.network", "::ffff:185.53.178.0/120", false, 1},
    {"network", "dest.network", "LAN", false, 0},      /* alias */
    {"network", "source.network", "LAN", false, 0},
    {"network", "dest.network", "PUBLIC", false, 1},   /* test alias */
    /* type/operand combinations upstream panics on: no match here */
    {"network", "dest.ip", "185.53.178.0/24", false, 0},
    {"simple", "dest.network", "185.53.178.14", false, 0},
    {"regexp", "dest.network", ".*", false, 0},
    {"lists", "dest.ip", LISTS "/ips/", false, -1},     /* unknown lists operand */
    /* hashes */
    {"simple", "process.hash.md5", "d41d8cd98f00b204e9800998ecf8427e", false, 1},
    {"simple", "process.hash.md5", "00000000000000000000000000000000", false, 0},
    {"simple", "process.hash.sha1", "d41d8cd98f00b204e9800998ecf8427e", false, 1},
    {"lists", "lists.hash.md5", LISTS "/ips/", false, 0},
    /* lists */
    {"lists", "lists.domains", LISTS "/domains/", false, 1},
    {"lists", "lists.domains", LISTS "/nonexistent/", false, 0},
    {"lists", "lists.domains", "", false, -1},
    {"lists", "lists.ips", LISTS "/ips/", false, 1},
    {"lists", "lists.nets", LISTS "/nets/", false, 1},
    {"lists", "lists.domains_regexp", LISTS "/regexp/", false, 1},
    /* regexps */
    {"regexp", "dest.host", "^opensnitch\\.io$", false, 1},
    {"regexp", "dest.host", "^OPENSNITCH\\.IO$", true, 0},
    {"regexp", "dest.host", "^OPENSNITCH\\.IO$", false, 1},
    {"regexp", "dest.host", "(?=x)", false, -1},
    {"regexp", "dest.host", "", false, 1},
    /* Lowercased to \d before compiling (as upstream), and the path has
     * no digits: no match, although \D would match. */
    {"regexp", "process.path", "\\D", false, 0},
};

TEST(every_operand)
{
    struct ks_aliases aliases = {0};
    char err[256];
    const char *json = "{\"LAN\": [\"10.0.0.0/8\", \"192.168.0.0/16\", \"::1\"], "
                       "\"PUBLIC\": [\"185.53.0.0/16\"]}";
    CHECK(ks_aliases_parse(&aliases, json, strlen(json), err, sizeof(err)) == 0);
    struct ks_rules_env renv = {NULL, &aliases};

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        rich_connection();
        struct ks_operator *o = new_op(table[i].type, table[i].sensitive,
                                       table[i].operand, table[i].data);
        int rc = ks_operator_compile(o, &renv, err, sizeof(err));
        int got = rc < 0 ? -1 : ks_operator_match(o, &conn, true);
        CHECK_MSG(got == table[i].want, "%s %s '%s'%s: got %d, want %d (%s)",
                  table[i].type, table[i].operand, table[i].data,
                  table[i].sensitive ? " (sensitive)" : "", got, table[i].want,
                  rc < 0 ? err : "compiled");
        free_op(o);
    }
    ks_aliases_free(&aliases);
}

TEST(hash_operands_without_checksums)
{
    rich_connection();
    struct ks_operator *o = new_op("simple", false, "process.hash.md5", "ffff");
    CHECK(compile(o, NULL) == 0);
    /* Checksums disabled: always a match. */
    CHECK(ks_operator_match(o, &conn, false));
    CHECK(!ks_operator_match(o, &conn, true));
    /* No checksum computed for the process: a match too. */
    proc.checksum_md5 = NULL;
    CHECK(ks_operator_match(o, &conn, true));
    /* An empty checksum fakes a match (hashCmp). */
    proc.checksum_md5 = "";
    CHECK(ks_operator_match(o, &conn, true));
    free_op(o);
}

TEST(user_name_is_resolved_to_uid)
{
    rich_connection();
    struct passwd *pw = getpwuid(getuid());
    CHECK(pw != NULL);
    struct ks_operator *o = new_op("simple", false, "user.name", pw->pw_name);
    CHECK(compile(o, NULL) == 0);
    char uid[16];
    snprintf(uid, sizeof(uid), "%u", (unsigned)getuid());
    CHECK_STR_EQ(o->data, uid); /* Data now holds the UID, as upstream */
    conn.uid = (int)getuid();
    CHECK(ks_operator_match(o, &conn, false));
    conn.uid = (int)getuid() + 1;
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(lists_edge_cases)
{
    rich_connection();
    /* An empty list matches everything (listMatch starts at true). */
    struct ks_operator *o = new_op("list", false, "list", "");
    CHECK(compile(o, NULL) == 0);
    CHECK(ks_operator_match(o, &conn, false));
    CHECK(ks_operator_match(o, NULL, false));
    /* One failing item fails the list. */
    CHECK(set_list(o, "[{\"type\":\"simple\",\"operand\":\"dest.port\",\"data\":\"443\"},"
                      "{\"type\":\"simple\",\"operand\":\"dest.port\",\"data\":\"80\"}]") == 0);
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    /* Domain lists don't match an empty host, and compare lowercased. */
    o = new_op("lists", false, "lists.domains", LISTS "/domains/");
    CHECK(compile(o, NULL) == 0);
    conn.dst_host = "";
    CHECK(!ks_operator_match(o, &conn, false));
    conn.dst_host = "WWW.TEST.ORG";
    CHECK(ks_operator_match(o, &conn, false));
    o->sensitive = true;
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    /* An item whose regexp failed to compile never matches (found by
     * fuzzing; the loader rejects such rules anyway). */
    o = new_op("list", false, "list", "");
    CHECK(compile(o, NULL) == 0);
    CHECK(set_list(o, "[{\"type\":\"regexp\",\"operand\":\"process.path\","
                      "\"data\":\"(\"}]") == -1);
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);

    /* Nested lists: upstream only compiles one level (and then panics);
     * the inner items just don't match here. */
    o = new_op("list", false, "list", "");
    CHECK(compile(o, NULL) == 0);
    CHECK(set_list(o, "[{\"type\":\"list\",\"operand\":\"list\",\"list\":"
                      "[{\"type\":\"simple\",\"operand\":\"dest.port\",\"data\":\"443\"}]}]")
          == 0);
    CHECK(!ks_operator_match(o, &conn, false));
    free_op(o);
}

TEST(lists_files)
{
    char dir[] = "/tmp/kisnitch-lists-XXXXXX";
    char path[128];
    CHECK(mkdtemp(dir) != NULL);

    snprintf(path, sizeof(path), "%s/hosts.txt", dir);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fputs("# comment\n"
          "0.0.0.0 ads.example\n"
          "127.0.0.1 tracker.example\r\n"
          "0.0.0.0 localhost\n"
          "127.0.0.1\n"                       /* upstream panics on this one */
          "0.0.0.0\tTabbed.example\n"
          "1.2.3.4 ignored.example\n"
          "0.0.0.0 ads.example\n", f);
    fclose(f);
    snprintf(path, sizeof(path), "%s/.hidden.txt", dir);
    f = fopen(path, "w");
    fputs("0.0.0.0 hidden.example\n", f);
    fclose(f);
    snprintf(path, sizeof(path), "%s/noext", dir);
    f = fopen(path, "w");
    fputs("0.0.0.0 noext.example\n", f);
    fclose(f);

    struct ks_operator *o = new_op("lists", true, "lists.domains", dir);
    CHECK(compile(o, NULL) == 0);
    CHECK_INT_EQ(ks_operator_lists_count(o), 3);
    restore_connection();
    const char *yes[] = {"ads.example", "tracker.example", "Tabbed.example"};
    const char *no[] = {"localhost", "ignored.example", "hidden.example",
                        "noext.example", "tabbed.example"};
    for (size_t i = 0; i < 3; i++) {
        conn.dst_host = yes[i];
        CHECK_MSG(ks_operator_match(o, &conn, false), "%s", yes[i]);
    }
    for (size_t i = 0; i < 5; i++) {
        conn.dst_host = no[i];
        CHECK_MSG(!ks_operator_match(o, &conn, false), "%s", no[i]);
    }

    /* The monitor re-reads the lists when files are added. */
    snprintf(path, sizeof(path), "%s/more.list", dir);
    f = fopen(path, "w");
    fputs("0.0.0.0 new.example\n", f);
    fclose(f);
    ks_operator_lists_poll(o);
    CHECK_INT_EQ(ks_operator_lists_count(o), 4);
    conn.dst_host = "new.example";
    CHECK(ks_operator_match(o, &conn, false));
    unlink(path);
    ks_operator_lists_poll(o);
    CHECK_INT_EQ(ks_operator_lists_count(o), 3);
    free_op(o);

    const char *rm[] = {"hosts.txt", ".hidden.txt", "noext"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, rm[i]);
        unlink(path);
    }
    rmdir(dir);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(upstream_simple);
    RUN(upstream_network);
    RUN(upstream_regexp);
    RUN(upstream_list);
    RUN(upstream_lists);
    RUN(every_operand);
    RUN(hash_operands_without_checksums);
    RUN(user_name_is_resolved_to_uid);
    RUN(lists_edge_cases);
    RUN(lists_files);
    return harness_report();
}
