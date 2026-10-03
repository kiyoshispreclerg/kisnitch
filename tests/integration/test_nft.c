/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * nftables interception rules (daemon/fw/nft.c), in a network namespace:
 * what gets installed (checked with the nft tool), cleanup on stop and
 * after a crash, and the rules checker putting them back.
 */
#include "tests/integration/netns.h"

#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/fw/fw.h"
#include "daemon/fw/nft.h"
#include "tests/harness.h"

static char out[16384];

static int nft(const char *args)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nft %s 2>&1", args);
    return ks_test_sh(cmd, out, sizeof(out));
}

/* Runs the loop until the rules are loaded or `ms` pass. */
static bool wait_rules(struct ks_evloop *loop, struct ks_nft *n, int ms)
{
    int64_t end = ks_evloop_now(loop) + (int64_t)ms * 1000000;
    while (ks_evloop_now(loop) < end) {
        ks_evloop_run_once(loop, 50);
        if (ks_nft_count_rules(n, KS_NFT_INTERCEPTION_KEY) == 3 && ks_nft_are_rules_loaded(n))
            return true;
    }
    return false;
}

TEST(installs_upstream_rules)
{
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_nft *n = ks_nft_new(loop);
    ks_nft_init(n, 0, KS_FW_DEFAULT_CONFIG_FILE, "10s", true);
    CHECK(ks_nft_is_running(n));
    CHECK(ks_nft_are_rules_loaded(n));
    CHECK_INT_EQ(ks_nft_count_rules(n, KS_NFT_INTERCEPTION_KEY), 3);

    /* The same rules upstream adds, as the nft tool shows them. */
    CHECK(nft("list ruleset") == 0);
    CHECK_STR_HAS(out, "table inet opensnitch {");
    CHECK_STR_HAS(out, "chain filter_input {");
    CHECK_STR_HAS(out, "type filter hook input priority filter; policy accept;");
    CHECK_STR_HAS(out, "udp sport 53 queue flags bypass to 0");
    CHECK_STR_HAS(out, "chain mangle_output {");
    CHECK_STR_HAS(out, "type route hook output priority mangle; policy accept;");
    CHECK_STR_HAS(out, "meta l4proto != tcp ct state related,new queue flags bypass to 0");
    /* nft >= 1.0 prints "tcp flags syn / fin,syn,rst,ack", older versions
     * "tcp flags & (fin | syn | rst | ack) == syn". */
    CHECK_MSG(strstr(out, "tcp flags syn / fin,syn,rst,ack queue flags bypass to 0") ||
                  strstr(out, "tcp flags & (fin | syn | rst | ack) == syn queue flags bypass to 0"),
              "no SYN rule in:\n%s", out);

    ks_nft_stop(n);
    CHECK(!ks_nft_is_running(n));
    CHECK_INT_EQ(ks_nft_count_rules(n, KS_NFT_INTERCEPTION_KEY), 0);
    CHECK_INT_EQ(ks_nft_table_exists(n, KS_NFT_TABLE_OPENSNITCH), 0);
    CHECK(nft("list ruleset") == 0);
    CHECK(strstr(out, "opensnitch") == NULL);
    ks_nft_free(n);
    ks_evloop_free(loop);
}

TEST(queue_num_and_no_bypass)
{
    struct ks_nft *n = ks_nft_new(NULL);
    ks_nft_init(n, 7, KS_FW_DEFAULT_CONFIG_FILE, "0s", false);
    CHECK(ks_nft_are_rules_loaded(n));
    CHECK(nft("list chain inet opensnitch mangle_output") == 0);
    CHECK_STR_HAS(out, "queue to 7");
    CHECK(strstr(out, "bypass") == NULL);
    CHECK_INT_EQ(ks_nft_check_interval(n), 0);
    ks_nft_stop(n);
    ks_nft_free(n);
}

TEST(cleans_up_after_a_crash)
{
    /* A daemon that died without cleaning up... */
    struct ks_nft *a = ks_nft_new(NULL);
    ks_nft_init(a, 0, "", "0s", true);
    ks_nft_free(a);
    CHECK(nft("list table inet opensnitch") == 0);

    /* ...leaves no duplicates behind when the next one starts. */
    struct ks_nft *b = ks_nft_new(NULL);
    ks_nft_init(b, 0, "", "0s", true);
    CHECK_INT_EQ(ks_nft_count_rules(b, KS_NFT_INTERCEPTION_KEY), 3);
    CHECK(ks_nft_are_rules_loaded(b));
    ks_nft_stop(b);
    CHECK_INT_EQ(ks_nft_table_exists(b, KS_NFT_TABLE_OPENSNITCH), 0);
    ks_nft_free(b);
}

TEST(checker_reinstalls_after_flush)
{
    struct ks_evloop *loop = ks_evloop_new();
    struct ks_nft *n = ks_nft_new(loop);
    ks_nft_init(n, 0, "", "200ms", true);
    CHECK(ks_nft_are_rules_loaded(n));

    CHECK(nft("flush ruleset") == 0);
    CHECK(!ks_nft_are_rules_loaded(n));
    /* checker (200ms) + reload delay (500ms) */
    CHECK(wait_rules(loop, n, 3000));

    /* A rule after ours in mangle_output: ours must be last, so it's
     * reloaded too. */
    CHECK(nft("add rule inet opensnitch mangle_output counter") == 0);
    CHECK(!ks_nft_are_rules_loaded(n));
    CHECK(wait_rules(loop, n, 3000));
    CHECK(nft("list chain inet opensnitch mangle_output") == 0);
    char *counter = strstr(out, "counter");
    char *syn = strstr(out, "tcp flags");
    CHECK(counter != NULL && syn != NULL && counter < syn);

    /* Stopping also stops the checker. */
    ks_nft_stop(n);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_nft_free(n);
    ks_evloop_free(loop);
}

TEST(other_tables_are_left_alone)
{
    CHECK(nft("add table ip filter") == 0);
    CHECK(nft("add chain ip filter output '{ type filter hook output priority 0; }'") == 0);
    CHECK(nft("add rule ip filter output counter") == 0);

    struct ks_nft *n = ks_nft_new(NULL);
    ks_nft_init(n, 0, "", "0s", true);
    ks_nft_stop(n);
    CHECK(nft("list table ip filter") == 0);
    CHECK_STR_HAS(out, "counter");
    CHECK_INT_EQ(ks_nft_table_exists(n, KS_NFT_TABLE_OPENSNITCH), 0);
    ks_nft_free(n);
    CHECK(nft("delete table ip filter") == 0);
}

TEST(upstream_keeps_table_if_inet_has_rules)
{
    /* nonSystemRules() counts the rules of every table with our name *or*
     * our family, so another inet table with rules keeps our (empty) table
     * around after stopping. Reproduced from upstream. */
    CHECK(nft("add table inet other") == 0);
    CHECK(nft("add chain inet other c") == 0);
    CHECK(nft("add rule inet other c counter") == 0);

    struct ks_nft *n = ks_nft_new(NULL);
    ks_nft_init(n, 0, "", "0s", true);
    ks_nft_stop(n);
    CHECK_INT_EQ(ks_nft_count_rules(n, KS_NFT_INTERCEPTION_KEY), 0);
    CHECK(nft("list table inet opensnitch") == 0);
    CHECK(strstr(out, "chain") == NULL);
    ks_nft_free(n);
    CHECK(nft("delete table inet other") == 0);
    CHECK(nft("delete table inet opensnitch") == 0);
}

TEST(fw_facade)
{
    struct ks_fw fw;
    CHECK(ks_fw_create(&fw, NULL) == 0);
    CHECK(ks_fw_init(&fw, "iptables", "", "0s", true, 0) == 0); /* falls back */
    CHECK(ks_fw_is_running(&fw));
    CHECK_STR_EQ(ks_fw_name(&fw), "nftables");
    CHECK(ks_fw_disable_interception(&fw) == 0);
    CHECK(nft("list ruleset") == 0);
    CHECK(strstr(out, "queue") == NULL);
    CHECK(ks_fw_enable_interception(&fw) == 0);
    CHECK(nft("list ruleset") == 0);
    CHECK_STR_HAS(out, "queue");
    CHECK(ks_fw_reload(&fw, "nftables", "", "0s", false, 3) == 0);
    CHECK(nft("list ruleset") == 0);
    CHECK_STR_HAS(out, "queue to 3");
    ks_fw_stop(&fw);
    CHECK(!ks_fw_is_running(&fw));
    ks_fw_destroy(&fw);
}

/* Each test starts from an empty ruleset, whatever the previous one left. */
#define RUN_CLEAN(name)                                                      \
    do {                                                                     \
        nft("flush ruleset");                                                \
        RUN(name);                                                           \
    } while (0)

int main(void)
{
    if (ks_test_enter_netns() < 0)
        return 0;
    if (ks_test_sh("nft list ruleset", NULL, 0) < 0) {
        fprintf(stderr, "SKIP: the nft tool is missing or can't talk to the kernel\n");
        return 0;
    }
    ks_log_set_level(KS_LOG_ERROR);
    RUN_CLEAN(installs_upstream_rules);
    RUN_CLEAN(queue_num_and_no_bypass);
    RUN_CLEAN(cleans_up_after_a_crash);
    RUN_CLEAN(checker_reinstalls_after_flush);
    RUN_CLEAN(other_tables_are_left_alone);
    RUN_CLEAN(upstream_keeps_table_if_inet_has_rules);
    RUN_CLEAN(fw_facade);
    return harness_report();
}
