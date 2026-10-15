/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/rulesops.c: what the rules menu does to the table and to the nodes.
 */
#include "ui/rulesops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/pb_util.h"
#include "ui/db.h"
#include "tests/harness.h"

static struct ks_db *db;
static struct ks_rulesdb rules;
static struct ks_nodes nodes;

static int replies;
static void on_reply(const char *addr, const Protocol__NotificationReply *r, void *ud)
{
    (void)addr;
    (void)r;
    (void)ud;
    replies++;
}

static void add_node(const char *peer)
{
    Protocol__ClientConfig c = PROTOCOL__CLIENT_CONFIG__INIT;
    size_t len;
    uint8_t *buf = ks_pb_pack(&c.base, &len);
    Protocol__ClientConfig *cfg =
        (Protocol__ClientConfig *)ks_pb_unpack(&protocol__client_config__descriptor, buf, len);
    free(buf);
    ks_nodes_add(&nodes, peer, cfg);
}

static void setup(void)
{
    char err[128];
    setenv("TZ", "UTC", 1);
    tzset();
    db = ks_db_open(NULL, false, err, sizeof(err));
    ks_rulesdb_init(&rules);
    ks_rulesdb_attach(&rules, db);
    ks_nodes_init(&nodes);
    add_node("unix:");
    add_node("ipv4:10.0.0.9:5000");
    replies = 0;
    const char *v[KS_RF_COUNT] = {"t", "unix:/local", "r1", "True", "False", "allow", "always",
                                  "simple", "False", "process.path", "/usr/bin/curl", "",
                                  "False", "2023-11-14 22:13:20"};
    ks_rulesdb_add_row(&rules, v);
}

static void teardown(void)
{
    ks_nodes_free(&nodes);
    ks_rulesdb_free(&rules);
    ks_db_close(db);
}

/* the i-th notification queued for the node, unpacked */
static Protocol__Notification *queued(const char *addr, size_t i)
{
    struct ks_node *n = ks_nodes_get(&nodes, addr);
    if (n == NULL || i >= n->nqueue)
        return NULL;
    return (Protocol__Notification *)ks_pb_unpack(&protocol__notification__descriptor,
                                                    n->queue[i].buf, n->queue[i].len);
}

static const char *cell(const char *name, enum ks_rule_field f)
{
    const struct ks_ui_rule *r = ks_rulesdb_get(&rules, name, "unix:/local");
    return r ? r->f[f] : "<none>";
}

static char *sql_text(const char *sql)
{
    static char buf[128];
    sqlite3_stmt *st;
    buf[0] = '\0';
    if (sqlite3_prepare_v2(ks_db_handle(db), sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(buf, sizeof(buf), "%s", (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    return buf;
}

TEST(change_action_and_duration)
{
    setup();
    CHECK(ks_rops_change_field(&rules, &nodes, "unix:/local", "r1", KS_RF_ACTION, "deny",
                               on_reply, NULL));
    CHECK_STR_EQ(cell("r1", KS_RF_ACTION), "deny");
    CHECK_STR_EQ(sql_text("SELECT action FROM rules WHERE name='r1'"), "deny");
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__CHANGE_RULE);
    CHECK_INT_EQ((int)n->n_rules, 1);
    CHECK_STR_EQ(n->rules[0]->name, "r1");
    CHECK_STR_EQ(n->rules[0]->action, "deny");
    CHECK_STR_EQ(n->rules[0]->duration, "always");
    CHECK_STR_EQ(n->rules[0]->operator_->data, "/usr/bin/curl");
    CHECK_INT_EQ((long)n->rules[0]->created, 1700000000);
    protobuf_c_message_free_unpacked(&n->base, NULL);

    CHECK(ks_rops_change_field(&rules, &nodes, "unix:/local", "r1", KS_RF_DURATION, "5m",
                               on_reply, NULL));
    CHECK_STR_EQ(sql_text("SELECT duration FROM rules WHERE name='r1'"), "5m");
    n = queued("unix:/local", 1);
    CHECK_STR_EQ(n->rules[0]->duration, "5m");
    CHECK_STR_EQ(n->rules[0]->action, "deny");
    protobuf_c_message_free_unpacked(&n->base, NULL);

    CHECK(!ks_rops_change_field(&rules, &nodes, "unix:/local", "nope", KS_RF_ACTION, "deny",
                                on_reply, NULL));
    CHECK(!ks_rops_change_field(&rules, &nodes, "unix:/local", "r1", KS_RF_NAME, "x", on_reply,
                                NULL));
    teardown();
}

TEST(enable_disable)
{
    setup();
    CHECK(ks_rops_enable(&rules, &nodes, "unix:/local", "r1", "True", on_reply, NULL));
    CHECK_STR_EQ(cell("r1", KS_RF_ENABLED), "False");
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__DISABLE_RULE);
    protobuf_c_message_free_unpacked(&n->base, NULL);
    CHECK(ks_rops_enable(&rules, &nodes, "unix:/local", "r1", "False", on_reply, NULL));
    CHECK_STR_EQ(cell("r1", KS_RF_ENABLED), "True");
    n = queued("unix:/local", 1);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__ENABLE_RULE);
    protobuf_c_message_free_unpacked(&n->base, NULL);
    teardown();
}

TEST(duplicate_names)
{
    setup();
    CHECK(ks_rops_duplicate(&rules, &nodes, "unix:/local", "r1", on_reply, NULL));
    CHECK_STR_EQ(cell("r1-duplicated-0", KS_RF_ACTION), "allow");
    CHECK(ks_rops_duplicate(&rules, &nodes, "unix:/local", "r1", on_reply, NULL));
    CHECK_STR_EQ(cell("r1-duplicated-1", KS_RF_ACTION), "allow");
    /* a duplicate of a duplicate starts from the original's name */
    CHECK(ks_rops_duplicate(&rules, &nodes, "unix:/local", "r1-duplicated-0", on_reply, NULL));
    CHECK_STR_EQ(cell("r1-duplicated-2", KS_RF_ACTION), "allow");
    CHECK_INT_EQ((int)ks_db_count(db, "rules"), 4);
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__CHANGE_RULE);
    CHECK_STR_EQ(n->rules[0]->name, "r1-duplicated-0");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    teardown();
}

TEST(apply_to_other_node)
{
    setup();
    CHECK(ks_rops_apply_to_node(&rules, &nodes, "r1", "ipv4:10.0.0.9", on_reply, NULL));
    CHECK(ks_rulesdb_get(&rules, "r1", "ipv4:10.0.0.9") != NULL);
    CHECK_INT_EQ((int)ks_db_count(db, "rules"), 2);
    Protocol__Notification *n = queued("ipv4:10.0.0.9", 0);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__CHANGE_RULE);
    CHECK_STR_EQ(n->rules[0]->name, "r1");
    protobuf_c_message_free_unpacked(&n->base, NULL);
    CHECK(!ks_rops_apply_to_node(&rules, &nodes, "nope", "ipv4:10.0.0.9", on_reply, NULL));
    teardown();
}

TEST(delete_rule)
{
    setup();
    CHECK(ks_rops_delete(&rules, &nodes, "r1", "unix:/local", on_reply, NULL));
    CHECK_INT_EQ((int)ks_db_count(db, "rules"), 0);
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__DELETE_RULE);
    CHECK_STR_EQ(n->rules[0]->name, "r1");
    CHECK_STR_EQ(n->rules[0]->action, "");
    CHECK_STR_EQ(n->rules[0]->operator_->type, "");
    CHECK_INT_EQ(n->rules[0]->enabled, 0);
    protobuf_c_message_free_unpacked(&n->base, NULL);
    /* to a node that isn't connected: the error comes through the callback */
    CHECK(ks_rops_delete(&rules, &nodes, "r1", "ipv4:1.2.3.4", on_reply, NULL));
    CHECK_INT_EQ(replies, 1);
    teardown();
}

TEST(json_and_export)
{
    setup();
    char *j = ks_rops_rule_json(&rules, "unix:/local", "r1");
    CHECK(j != NULL);
    CHECK_STR_EQ(j, "{\n"
                    "    \"created\": \"2023-11-14T22:13:20.000000Z\",\n"
                    "    \"name\": \"r1\",\n"
                    "    \"enabled\": true,\n"
                    "    \"action\": \"allow\",\n"
                    "    \"duration\": \"always\",\n"
                    "    \"operator\": {\n"
                    "        \"type\": \"simple\",\n"
                    "        \"operand\": \"process.path\",\n"
                    "        \"data\": \"/usr/bin/curl\"\n"
                    "    }\n"
                    "}");
    free(j);
    CHECK(ks_rops_rule_json(&rules, "unix:/local", "nope") == NULL);

    const char *v[KS_RF_COUNT] = {
        "t", "unix:/local", "lst", "True", "True", "deny", "1h", "list", "False", "list",
        ("[{\"type\": \"simple\", \"operand\": \"dest.port\", \"data\": \"443\", \"sensitive\": true},"
         " {\"type\": \"regexp\", \"operand\": \"dest.host\", \"data\": \"caf\\u00e9\"}]"),
        "a rule", "True", "2023-11-14 22:13:20"};
    ks_rulesdb_add_row(&rules, v);
    j = ks_rops_rule_json(&rules, "unix:/local", "lst");
    CHECK(j != NULL);
    CHECK_STR_HAS(j, "        \"type\": \"list\",\n        \"operand\": \"list\",\n"
                     "        \"list\": [\n            {\n                \"type\": \"simple\",\n");
    CHECK_STR_HAS(j, "\"sensitive\": true\n            },\n");
    CHECK_STR_HAS(j, "\"data\": \"caf\\u00e9\"");
    CHECK_STR_HAS(j, "\"description\": \"a rule\",\n    \"enabled\": true,\n    \"precedence\": true,\n"
                     "    \"nolog\": true,");
    free(j);

    char dir[] = "/tmp/ks-test-export-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    CHECK(ks_rops_export(&rules, "unix:/local", "r1", dir));
    char path[128];
    snprintf(path, sizeof(path), "%s/unix-local/r1.json", dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    char buf[64] = "";
    if (f != NULL) {
        CHECK(fgets(buf, sizeof(buf), f) != NULL);
        fclose(f);
    }
    CHECK_STR_EQ(buf, "{\n");
    CHECK(ks_rops_export(&rules, "unix:/local", "r1", dir)); /* the directory exists already */
    CHECK(!ks_rops_export(&rules, "unix:/local", "nope", dir));
    unlink(path);
    snprintf(path, sizeof(path), "%s/unix-local", dir);
    rmdir(path);
    rmdir(dir);
    teardown();
}

TEST(import_export_roundtrip)
{
    setup();
    const char *v[KS_RF_COUNT] = {
        "t", "unix:/local", "lst", "True", "False", "deny", "1h", "list", "False", "list",
        "[{\"type\": \"simple\", \"operand\": \"dest.port\", \"data\": \"443\", \"sensitive\": true}]",
        "a rule", "False", "2023-11-14 22:13:20"};
    ks_rulesdb_add_row(&rules, v);
    char dir[] = "/tmp/ks-test-import-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char sub[128];
    snprintf(sub, sizeof(sub), "%s/unix-local", dir);
    CHECK(ks_rops_export_all(&rules, "unix:/local", dir));
    ks_rulesdb_delete(&rules, "r1", NULL);
    ks_rulesdb_delete(&rules, "lst", NULL);
    CHECK_INT_EQ((int)ks_db_count(db, "rules"), 0);

    /* the export of a whole node has a directory per node: importing the
     * node's directory reads its files */
    CHECK_INT_EQ(ks_rops_import(&rules, &nodes, "unix:/local", sub, on_reply, NULL), 2);
    CHECK_INT_EQ((int)ks_db_count(db, "rules"), 4); /* in the table of both nodes */
    CHECK_STR_EQ(cell("r1", KS_RF_OP_DATA), "/usr/bin/curl");
    CHECK_STR_EQ(cell("r1", KS_RF_CREATED), "2023-11-14 22:13:20");
    CHECK_STR_EQ(cell("lst", KS_RF_DESCRIPTION), "a rule");
    CHECK_STR_EQ(cell("lst", KS_RF_OP_TYPE), "list");
    CHECK_STR_HAS(cell("lst", KS_RF_OP_DATA), "\"operand\": \"dest.port\"");
    CHECK(ks_rulesdb_get(&rules, "r1", "ipv4:10.0.0.9") != NULL);
    Protocol__Notification *n = queued("unix:/local", 0);
    CHECK(n != NULL);
    CHECK_INT_EQ(n->type, PROTOCOL__ACTION__CHANGE_RULE);
    CHECK_INT_EQ((int)n->n_rules, 2);
    protobuf_c_message_free_unpacked(&n->base, NULL);

    /* a directory in the directory: open() fails, the import is refused */
    CHECK_INT_EQ(ks_rops_import(&rules, &nodes, "unix:/local", dir, on_reply, NULL), -1);
    CHECK_INT_EQ(ks_rops_import(&rules, &nodes, "unix:/local", "/nonexistent", on_reply, NULL), -1);
    /* the old timestamp form of "created", and what isn't a rule */
    char path[160];
    snprintf(path, sizeof(path), "%s/old.json", sub);
    FILE *f = fopen(path, "w");
    fputs("{\"name\": \"old\", \"created\": \"1700000000\", \"enabled\": true, "
          "\"unknownField\": 1, \"operator\": {\"type\": \"simple\", \"operand\": \"user.id\", "
          "\"data\": \"0\"}}", f);
    fclose(f);
    struct ks_arena a = {0};
    Protocol__Rule **list;
    size_t cnt;
    CHECK(ks_rops_import_parse(&a, sub, &list, &cnt));
    CHECK_INT_EQ((int)cnt, 3);
    bool found = false;
    for (size_t i = 0; i < cnt; i++) {
        if (strcmp(list[i]->name, "old") == 0) {
            found = true;
            CHECK_INT_EQ((long)list[i]->created, 1700000000);
            CHECK_INT_EQ(list[i]->enabled, 1);
        }
    }
    CHECK(found);
    ks_arena_free(&a);
    snprintf(path, sizeof(path), "%s/bad.json", sub);
    f = fopen(path, "w");
    fputs("{\"name\": 5}", f);
    fclose(f);
    CHECK(!ks_rops_import_parse(&a, sub, &list, &cnt));
    ks_arena_free(&a);

    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    CHECK_INT_EQ(system(cmd), 0);
    teardown();
}

int main(void)
{
    RUN(change_action_and_duration);
    RUN(enable_disable);
    RUN(duplicate_names);
    RUN(apply_to_other_node);
    RUN(delete_rule);
    RUN(json_and_export);
    RUN(import_export_roundtrip);
    return harness_report();
}
