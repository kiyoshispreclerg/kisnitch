/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verdicts on queued packets (daemon/intercept.c), without a real queue:
 * packets are built by hand for real sockets of this process and of a
 * child, so the process lookup is the real one.
 *
 * Run as `test_intercept --child-connect <port>`, the binary connects to
 * 127.0.0.1:<port> and waits (the child of the rule tests).
 */
#define _XOPEN_SOURCE 700 /* realpath() */
#include "daemon/intercept.h"

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/procmon/procmon.h"
#include "daemon/rules/loader.h"
#include "tests/harness.h"

static char self_exe[PATH_MAX];

static unsigned local_port(int fd)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    return getsockname(fd, (struct sockaddr *)&a, &l) == 0 ? ntohs(a.sin_port) : 0;
}

static unsigned peer_port(int fd)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    return getpeername(fd, (struct sockaddr *)&a, &l) == 0 ? ntohs(a.sin_port) : 0;
}

static int listen_lo(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 8) < 0)
        return -1;
    return fd;
}

static int connect_lo(unsigned port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
        return -1;
    return fd;
}

/* An IPv4 packet 127.0.0.1:sport -> 127.0.0.1:dport (TCP SYN, or UDP with
 * a 4-byte payload). */
struct pkt {
    uint8_t b[64];
    size_t len;
};

static struct pkt make_pkt(uint8_t proto, unsigned sport, unsigned dport)
{
    struct pkt p = {{0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, proto, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1},
                    20};
    uint8_t *t = p.b + 20;
    t[0] = (uint8_t)(sport >> 8);
    t[1] = (uint8_t)sport;
    t[2] = (uint8_t)(dport >> 8);
    t[3] = (uint8_t)dport;
    if (proto == IPPROTO_TCP) {
        t[12] = 0x50;
        t[13] = 0x02;
        p.len += 20;
    } else {
        t[5] = 12; /* UDP length */
        memcpy(t + 8, "abcd", 4);
        p.len += 12;
    }
    p.b[3] = (uint8_t)p.len;
    return p;
}

static struct ks_verdict decide(struct ks_intercept *ic, const struct pkt *p, uint32_t mark)
{
    struct ks_nfq_packet q = {.id = 1, .mark = mark, .uid = KS_NFQ_NO_UID,
                              .data = p->b, .len = p->len};
    struct ks_verdict v = {99, 99};
    ks_intercept_packet(ic, &q, &v);
    return v;
}

static struct ks_rule *rule(const char *name, const char *action, bool enabled,
                            const char *operand, const char *data)
{
    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = (char *)"simple";
    op.operand = (char *)operand;
    op.data = (char *)data;
    return ks_rule_create(name, "", enabled, false, false, action, "until restart", &op);
}

static void add(struct ks_loader *l, struct ks_rule *r)
{
    char err[256];
    if (ks_loader_add(l, r, false, err, sizeof(err)) < 0)
        fprintf(stderr, "  add rule: %s\n", err);
}

TEST(own_connections_are_accepted)
{
    struct ks_loader *l = ks_loader_new(NULL, NULL, false);
    add(l, rule("deny-all", KS_ACTION_DENY, true, KS_OP_TRUE, ""));
    struct ks_intercept ic;
    ks_intercept_init(&ic, l);
    ks_intercept_set_default_action(&ic, KS_ACTION_DENY);

    int srv = listen_lo();
    int c = connect_lo(local_port(srv));
    CHECK(srv >= 0 && c >= 0);
    struct pkt p = make_pkt(IPPROTO_TCP, local_port(c), local_port(srv));
    struct ks_verdict v = decide(&ic, &p, 0x10);
    CHECK_INT_EQ(v.verdict, KS_NF_ACCEPT);
    CHECK_INT_EQ(v.mark, 0); /* SetVerdict(): the mark is reset */
    close(c);
    close(srv);
    ks_loader_free(l);
}

TEST(dns_responses_are_accepted)
{
    struct ks_intercept ic;
    ks_intercept_init(&ic, NULL);
    ks_intercept_set_default_action(&ic, KS_ACTION_DENY);
    struct pkt p = make_pkt(IPPROTO_UDP, 53, 40000);
    struct ks_verdict v = decide(&ic, &p, 0x42);
    CHECK_INT_EQ(v.verdict, KS_NF_ACCEPT);
    CHECK_INT_EQ(v.mark, 0x42);

    /* Without a payload there's no DNS layer: a normal (unknown)
     * connection, so the default action. */
    p.b[20 + 5] = 8;
    p.len = 28;
    p.b[3] = 28;
    v = decide(&ic, &p, 0x42);
    CHECK_INT_EQ(v.verdict, KS_NF_DROP);
}

TEST(no_connection_gets_the_default_action)
{
    struct ks_intercept ic;
    ks_intercept_init(&ic, NULL);
    struct pkt junk = {{0x45, 0, 0, 10}, 10}; /* too short */
    struct pkt nobody = make_pkt(IPPROTO_TCP, 1, 2); /* no such socket */

    struct ks_verdict v = decide(&ic, &junk, 7); /* "allow" by default */
    CHECK_INT_EQ(v.verdict, KS_NF_ACCEPT);
    CHECK_INT_EQ(v.mark, 7);
    v = decide(&ic, &nobody, 7);
    CHECK_INT_EQ(v.verdict, KS_NF_ACCEPT);

    ks_intercept_set_default_action(&ic, ""); /* empty: unchanged */
    CHECK_STR_EQ(ic.default_action, "allow");
    ks_intercept_set_default_action(&ic, KS_ACTION_REJECT);
    v = decide(&ic, &junk, 7);
    CHECK_INT_EQ(v.verdict, KS_NF_DROP);
    CHECK_INT_EQ(v.mark, 0);
    ks_intercept_set_default_action(&ic, "anything else");
    v = decide(&ic, &nobody, 7);
    CHECK_INT_EQ(v.verdict, KS_NF_DROP);
}

TEST(ipv6_disabled)
{
    struct ks_intercept ic;
    ks_intercept_init(&ic, NULL);
    ic.ipv6_enabled = false;
    ks_intercept_set_default_action(&ic, KS_ACTION_DENY);
    struct pkt p = {{0x60, 0, 0, 0, 0, 20, 6, 64}, 60};
    p.b[24] = 0x01; /* source port 1 */
    struct ks_verdict v = decide(&ic, &p, 0);
    CHECK_INT_EQ(v.verdict, KS_NF_DROP);
}

TEST(rules_decide_a_childs_connection)
{
    int srv = listen_lo();
    CHECK(srv >= 0);
    char port[16];
    snprintf(port, sizeof(port), "%u", local_port(srv));
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        execl(self_exe, self_exe, "--child-connect", port, (char *)NULL);
        _exit(127);
    }
    int acc = accept(srv, NULL, NULL);
    char ready;
    bool connected = acc >= 0 && read(acc, &ready, 1) == 1;
    struct pkt p = make_pkt(IPPROTO_TCP, peer_port(acc), local_port(srv));

    struct ks_loader *l = ks_loader_new(NULL, NULL, false);
    struct ks_intercept ic;
    ks_intercept_init(&ic, l);
    ks_intercept_set_default_action(&ic, KS_ACTION_ALLOW);
    struct ks_verdict v1, v2, v3, v4;

    /* deny, against the default "allow" */
    add(l, rule("000-child", KS_ACTION_DENY, true, KS_OP_PROCESS_PATH, self_exe));
    v1 = decide(&ic, &p, 5);
    /* a disabled rule never matches: the default action */
    add(l, rule("001-off", KS_ACTION_DENY, false, KS_OP_TRUE, ""));
    ks_loader_delete(l, "000-child", NULL, 0);
    v2 = decide(&ic, &p, 5);
    /* allow, against the default "deny" */
    ks_intercept_set_default_action(&ic, KS_ACTION_DENY);
    add(l, rule("002-child", KS_ACTION_ALLOW, true, KS_OP_PROCESS_PATH, self_exe));
    v3 = decide(&ic, &p, 5);
    /* a rule for another program: the default action */
    ks_loader_delete(l, "002-child", NULL, 0);
    add(l, rule("003-other", KS_ACTION_ALLOW, true, KS_OP_PROCESS_PATH, "/bin/false"));
    v4 = decide(&ic, &p, 5);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (acc >= 0)
        close(acc);
    close(srv);
    ks_loader_free(l);

    CHECK(connected);
    CHECK_INT_EQ(v1.verdict, KS_NF_DROP);
    CHECK_INT_EQ(v2.verdict, KS_NF_ACCEPT);
    CHECK_INT_EQ(v2.mark, 5);
    CHECK_INT_EQ(v3.verdict, KS_NF_ACCEPT);
    CHECK_INT_EQ(v3.mark, 5); /* SetVerdictAndMark(): the packet's mark */
    CHECK_INT_EQ(v4.verdict, KS_NF_DROP);
}

static int child_connect(const char *port)
{
    int fd = connect_lo((unsigned)atoi(port));
    if (fd < 0 || write(fd, "r", 1) != 1)
        return 1;
    pause();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--child-connect") == 0)
        return child_connect(argv[2]);
    if (realpath("/proc/self/exe", self_exe) == NULL) {
        perror("realpath");
        return 1;
    }
    ks_log_set_level(KS_LOG_FATAL + 1);
    ks_procmon_init(NULL);

    RUN(own_connections_are_accepted);
    RUN(dns_responses_are_accepted);
    RUN(no_connection_gets_the_default_action);
    RUN(ipv6_disabled);
    /* Under valgrind the child is valgrind itself (see test_procmon.c). */
    if (getenv("KS_TEST_VALGRIND") == NULL)
        RUN(rules_decide_a_childs_connection);
    ks_procmon_end();
    return harness_report();
}
