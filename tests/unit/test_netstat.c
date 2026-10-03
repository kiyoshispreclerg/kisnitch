/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * netstat (/proc/net files) and sock_diag tests: fixture files for the parser,
 * and live sockets of this process for both lookups.
 */
#include "daemon/netstat.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/sockdiag.h"
#include "tests/harness.h"

#define PROC KS_FIXTURES_DIR "/proc"

static const char *ipstr(const struct ks_ip *ip)
{
    static char buf[KS_IP_STRLEN];
    ks_ip_string(ip, buf, sizeof(buf));
    return buf;
}

TEST(parse_tcp_fixture)
{
    struct ks_netstat_entry *e;
    size_t n;
    CHECK(ks_netstat_parse_file("tcp", PROC "/tcp", &e, &n) == 0);
    CHECK_INT_EQ(n, 4); /* header skipped, the garbage line too */

    CHECK_STR_EQ(e[0].proto, "tcp");
    CHECK_STR_EQ(ipstr(&e[0].src_ip), "127.0.0.1");
    CHECK_INT_EQ(e[0].src_ip.len, 4);
    CHECK_INT_EQ(e[0].src_port, 5037);
    CHECK_STR_EQ(ipstr(&e[0].dst_ip), "0.0.0.0");
    CHECK_INT_EQ(e[0].dst_port, 0);
    CHECK_INT_EQ(e[0].uid, 1000);
    CHECK_INT_EQ(e[0].inode, 16475915);

    /* 9 hex digits: upstream keeps the low 32 bits. Inodes above 2^31. */
    CHECK_STR_EQ(ipstr(&e[1].src_ip), "192.168.1.106");
    CHECK_INT_EQ(e[1].src_port, 47344);
    CHECK_STR_EQ(ipstr(&e[1].dst_ip), "118.89.22.196");
    CHECK_INT_EQ(e[1].inode, 4294967295LL);

    CHECK_INT_EQ(e[2].uid, 0);
    CHECK_INT_EQ(e[2].inode, 0);
    CHECK_INT_EQ(e[3].uid, 4294967294LL);
    CHECK_INT_EQ(e[3].dst_port, 54321);
    free(e);
}

TEST(parse_tcp6_fixture)
{
    struct ks_netstat_entry *e;
    size_t n;
    CHECK(ks_netstat_parse_file("tcp6", PROC "/tcp6", &e, &n) == 0);
    CHECK_INT_EQ(n, 4);
    /* All zeros: m == 0, so upstream returns a 4-byte 0.0.0.0. */
    CHECK_INT_EQ(e[0].src_ip.len, 4);
    CHECK_STR_EQ(ipstr(&e[0].src_ip), "0.0.0.0");
    CHECK_INT_EQ(e[0].src_port, 4455);
    CHECK_STR_EQ(ipstr(&e[1].src_ip), "127.0.0.1"); /* ::ffff:127.0.0.1 */
    CHECK_INT_EQ(e[1].src_ip.len, 16);
    CHECK_INT_EQ(e[1].dst_port, 80);
    CHECK_STR_EQ(ipstr(&e[2].src_ip), "2001:db8::1");
    CHECK_STR_EQ(ipstr(&e[2].dst_ip), "2001:db8::2");
    CHECK_INT_EQ(e[2].inode, 666);
    /* 2001:db8:: has a zero low half: upstream reads it as 0.0.0.0. */
    CHECK_STR_EQ(ipstr(&e[3].src_ip), "0.0.0.0");
    CHECK_STR_EQ(ipstr(&e[3].dst_ip), "::1");
    free(e);
}

TEST(parse_packet_fixture)
{
    struct ks_netstat_entry e;
    CHECK(ks_netstat_parse_packet_line(
              "0000000000000000 2      2    0000   0     0 0      0      44138", &e) == 0);
    CHECK_INT_EQ(e.iface, 0);
    CHECK_INT_EQ(e.uid, 0);
    CHECK_INT_EQ(e.inode, 44138);
    CHECK(ks_netstat_parse_packet_line(
              "ffff90b72f893800 3      3    0003   3     1 0      1000   257944535", &e) == 0);
    CHECK_INT_EQ(e.iface, 3);
    CHECK_INT_EQ(e.uid, 1000);
    CHECK_INT_EQ(e.inode, 257944535);
    /* Two-digit interface indexes don't fit upstream's pattern. */
    CHECK(ks_netstat_parse_packet_line(
              "ffff90b72f893800 3      3    0003   12    1 0      1000   1", &e) == -1);
}

TEST(unparseable_lines)
{
    struct ks_netstat_entry e;
    CHECK(ks_netstat_parse_line("tcp", "", &e) == -1);
    CHECK(ks_netstat_parse_line("tcp", "garbage", &e) == -1);
    /* No trailing fields after the inode: upstream's ".+" needs one. */
    CHECK(ks_netstat_parse_line("tcp", "0: 0100007F:13AD 00000000:0000 0A "
                                       "00000000:00000000 00:00000000 00000000 "
                                       "1000 0 123", &e) == -1);
    /* uid overflowing int64: upstream exits, we skip the line. */
    CHECK(ks_netstat_parse_line("tcp", "0: 0100007F:13AD 00000000:0000 0A "
                                       "00000000:00000000 00:00000000 00000000 "
                                       "99999999999999999999 0 123 1", &e) == -1);
    struct ks_netstat_entry *list;
    size_t n;
    CHECK(ks_netstat_parse_file("tcp", PROC "/nonexistent", &list, &n) == -1);
    CHECK(list == NULL && n == 0);
}

/* Connected TCP pair on loopback; returns the client fd and fills ports. */
static int tcp_pair(int family, int *server, int *accepted, unsigned *cport,
                    unsigned *sport)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sl = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        sl = sizeof(*a);
    }
    *server = socket(family, SOCK_STREAM, 0);
    if (*server < 0 || bind(*server, (struct sockaddr *)&ss, sl) < 0 ||
        listen(*server, 1) < 0 || getsockname(*server, (struct sockaddr *)&ss, &sl) < 0)
        return -1;
    int c = socket(family, SOCK_STREAM, 0);
    if (c < 0 || connect(c, (struct sockaddr *)&ss, sl) < 0)
        return -1;
    *accepted = accept(*server, NULL, NULL);
    *sport = family == AF_INET ? ntohs(((struct sockaddr_in *)&ss)->sin_port)
                               : ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    if (getsockname(c, (struct sockaddr *)&ss, &sl) < 0)
        return -1;
    *cport = family == AF_INET ? ntohs(((struct sockaddr_in *)&ss)->sin_port)
                               : ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    return c;
}

static int64_t fd_inode(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 ? (int64_t)st.st_ino : -1;
}

TEST(live_tcp_lookups)
{
    int srv, acc;
    unsigned cport, sport;
    int c = tcp_pair(AF_INET, &srv, &acc, &cport, &sport);
    CHECK(c >= 0);
    struct ks_ip lo;
    CHECK(ks_ip_parse("127.0.0.1", &lo) == 0);

    /* /proc/net/tcp */
    struct ks_netstat_entry e;
    CHECK(ks_netstat_find("tcp", &lo, cport, &lo, sport, &e));
    CHECK_INT_EQ(e.inode, fd_inode(c));
    CHECK_INT_EQ(e.uid, getuid());

    /* sock_diag */
    int64_t uid, inodes[8];
    size_t n = ks_socket_info("tcp", &lo, cport, &lo, sport, &uid, inodes, 8);
    CHECK_INT_EQ(n, 1);
    CHECK_INT_EQ(inodes[0], fd_inode(c));
    CHECK_INT_EQ(uid, getuid());

    struct ks_sock s;
    CHECK(ks_sock_find_by_inode((uint32_t)fd_inode(c), &s) == 0);
    CHECK_INT_EQ(s.sport, cport);
    CHECK_INT_EQ(s.dport, sport);

    /* Unknown connection: not found, uid and inode -1. */
    CHECK(!ks_netstat_find("tcp", &lo, 1, &lo, 2, &e));
    CHECK_INT_EQ(e.inode, -1);
    CHECK_INT_EQ(e.uid, -1);
    close(c);
    close(acc);
    close(srv);
}

TEST(live_udp_lookups)
{
    int srv = socket(AF_INET, SOCK_DGRAM, 0), c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    socklen_t sl = sizeof(a);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(srv >= 0 && c >= 0);
    CHECK(bind(srv, (struct sockaddr *)&a, sl) == 0);
    CHECK(getsockname(srv, (struct sockaddr *)&a, &sl) == 0);
    unsigned sport = ntohs(a.sin_port);
    CHECK(connect(c, (struct sockaddr *)&a, sl) == 0);
    CHECK(getsockname(c, (struct sockaddr *)&a, &sl) == 0);
    unsigned cport = ntohs(a.sin_port);

    struct ks_ip lo;
    ks_ip_parse("127.0.0.1", &lo);
    struct ks_netstat_entry e;
    CHECK(ks_netstat_find("udp", &lo, cport, &lo, sport, &e));
    CHECK_INT_EQ(e.inode, fd_inode(c));

    int64_t uid, inodes[8];
    size_t n = ks_socket_info("udp", &lo, cport, &lo, sport, &uid, inodes, 8);
    CHECK_INT_EQ(n, 1);
    CHECK_INT_EQ(inodes[0], fd_inode(c));

    /* An unconnected socket sending a broadcast-like packet: the kernel
     * shows 0.0.0.0 as destination, and upstream takes it anyway. */
    struct ks_ip bcast;
    ks_ip_parse("192.0.2.255", &bcast);
    n = ks_socket_info("udp", &lo, sport, &bcast, 9, &uid, inodes, 8);
    CHECK_INT_EQ(n, 1);
    CHECK_INT_EQ(inodes[0], fd_inode(srv));
    close(c);
    close(srv);
}

TEST(live_tcp6_lookups)
{
    int srv, acc;
    unsigned cport, sport;
    int c = tcp_pair(AF_INET6, &srv, &acc, &cport, &sport);
    if (c < 0) {
        fprintf(stderr, "  (no IPv6 loopback, skipped)\n");
        return;
    }
    struct ks_ip lo;
    ks_ip_parse("::1", &lo);
    struct ks_netstat_entry e;
    /* Found in tcp6 even when asked for "tcp" (the fallback). */
    CHECK(ks_netstat_find("tcp", &lo, cport, &lo, sport, &e) == ks_ipv6_enabled());
    if (ks_ipv6_enabled()) {
        CHECK_STR_EQ(e.proto, "tcp6");
        CHECK_INT_EQ(e.inode, fd_inode(c));
    }
    int64_t uid, inodes[8];
    size_t n = ks_socket_info("tcp6", &lo, cport, &lo, sport, &uid, inodes, 8);
    CHECK_INT_EQ(n, 1);
    CHECK_INT_EQ(inodes[0], fd_inode(c));
    close(c);
    close(acc);
    close(srv);
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(parse_tcp_fixture);
    RUN(parse_tcp6_fixture);
    RUN(parse_packet_fixture);
    RUN(unparseable_lines);
    RUN(live_tcp_lookups);
    RUN(live_udp_lookups);
    RUN(live_tcp6_lookups);
    return harness_report();
}
