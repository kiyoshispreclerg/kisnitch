/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Integration tests run in a network namespace of their own, so they never
 * touch the host's network: as root, a new network namespace; otherwise a
 * user namespace (mapping us to root) plus a network namespace, where the
 * kernel allows it. Call ks_test_enter_netns() first thing in main(),
 * before any thread exists.
 */
#ifndef KS_TESTS_INTEGRATION_NETNS_H
#define KS_TESTS_INTEGRATION_NETNS_H

#define _GNU_SOURCE /* unshare() */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int netns_write_file_(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n == (ssize_t)strlen(s) ? 0 : -1;
}

/* Brings the loopback interface up. */
static int netns_lo_up_(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "lo");
    int ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret == 0) {
        ifr.ifr_flags |= IFF_UP;
        ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);
    return ret;
}

/* Returns 0 inside a fresh network namespace with "lo" up, or -1 (with a
 * message on stderr) if namespaces aren't available: the caller skips. */
static int ks_test_enter_netns(void)
{
    if (getenv("KS_TEST_IN_NETNS") != NULL) /* already isolated by the runner */
        return netns_lo_up_();
    if (geteuid() == 0) {
        if (unshare(CLONE_NEWNET) < 0) {
            fprintf(stderr, "SKIP: unshare(CLONE_NEWNET): %s\n", strerror(errno));
            return -1;
        }
    } else {
        uid_t uid = geteuid();
        gid_t gid = getegid();
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            fprintf(stderr, "SKIP: no root and no unprivileged user namespaces (%s)\n",
                    strerror(errno));
            return -1;
        }
        char map[64];
        snprintf(map, sizeof(map), "0 %u 1", (unsigned)uid);
        if (netns_write_file_("/proc/self/setgroups", "deny") < 0 ||
            netns_write_file_("/proc/self/uid_map", map) < 0)
            return -1;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned)gid);
        if (netns_write_file_("/proc/self/gid_map", map) < 0)
            return -1;
    }
    setenv("KS_TEST_IN_NETNS", "1", 1);
    return netns_lo_up_();
}

/* Runs a shell command (inside our namespace) and returns its output, at
 * most `len` - 1 bytes. -1 if it can't run or exits with an error. */
static int ks_test_sh(const char *cmd, char *out, size_t len)
{
    FILE *p = popen(cmd, "r");
    if (p == NULL)
        return -1;
    size_t n = 0;
    if (out != NULL && len > 0) {
        n = fread(out, 1, len - 1, p);
        out[n] = '\0';
    } else {
        char sink[256];
        while (fread(sink, 1, sizeof(sink), p) > 0)
            ;
    }
    int st = pclose(p);
    return st == 0 ? 0 : -1;
}

#endif
