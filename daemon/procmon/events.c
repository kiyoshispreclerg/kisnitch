/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/netlink/procmon/procmon.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _GNU_SOURCE /* setns() */
#include "daemon/procmon/events.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/procmon/procmon.h"

#define RESTART_DELAY_NS 1000000000LL

static struct {
    struct ks_evloop *loop;
    int fd;
    struct ks_timer *restart;
    bool running;
} ev = {NULL, -1, NULL, false};

static void on_readable(int fd, uint32_t events, void *data);

/* Opens the connector socket in PID 1's network namespace, as upstream
 * (the connector only works there), and subscribes. */
static int open_socket(void)
{
    int self_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    int init_ns = open("/proc/1/ns/net", O_RDONLY | O_CLOEXEC);
    bool switched = false;
    if (self_ns < 0 || init_ns < 0) {
        ks_warning("unable to start netlink.ProcEventMonitor (0): %s", strerror(errno));
        goto fail;
    }
    if (setns(init_ns, CLONE_NEWNET) < 0) {
        ks_warning("unable to start netlink.ProcEventMonitor (1): %s", strerror(errno));
        goto fail;
    }
    switched = true;

    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    NETLINK_CONNECTOR);
    if (setns(self_ns, CLONE_NEWNET) < 0)
        ks_error("could not return to our network namespace: %s", strerror(errno));
    switched = false;
    if (fd < 0)
        goto fail_errno;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        goto fail_errno;
    }

    /* nlmsghdr + cn_msg + proc_cn_mcast_op, built in a buffer (cn_msg ends
     * in a flexible array). */
    union {
        struct nlmsghdr nh; /* alignment */
        char buf[NLMSG_SPACE(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op))];
    } u;
    memset(&u, 0, sizeof(u));
    u.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
    u.nh.nlmsg_type = NLMSG_DONE;
    u.nh.nlmsg_pid = (uint32_t)getpid();
    struct cn_msg *cn = NLMSG_DATA(&u.nh);
    cn->id.idx = CN_IDX_PROC;
    cn->id.val = CN_VAL_PROC;
    cn->len = sizeof(enum proc_cn_mcast_op);
    enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
    memcpy(cn->data, &op, sizeof(op));
    if (send(fd, u.buf, u.nh.nlmsg_len, 0) < 0) {
        close(fd);
        goto fail_errno;
    }
    close(self_ns);
    close(init_ns);
    return fd;

fail_errno:
    ks_warning("unable to start netlink.ProcEventMonitor (2): %s", strerror(errno));
fail:
    if (switched && setns(self_ns, CLONE_NEWNET) < 0)
        ks_error("could not return to our network namespace: %s", strerror(errno));
    if (self_ns >= 0)
        close(self_ns);
    if (init_ns >= 0)
        close(init_ns);
    return -1;
}

int ks_proc_events_handle(const void *buf, size_t len)
{
    int seen = 0;
    const struct nlmsghdr *nh = buf;
    size_t rem = len;
    /* NLMSG_OK/NEXT want a signed length type. */
    for (int l = (int)(rem > INT32_MAX ? INT32_MAX : rem); NLMSG_OK(nh, (unsigned)l);
         nh = NLMSG_NEXT(nh, l)) {
        if (nh->nlmsg_type == NLMSG_NOOP || nh->nlmsg_type == NLMSG_ERROR)
            continue;
        if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct cn_msg)))
            continue;
        const struct cn_msg *cn = NLMSG_DATA(nh);
        if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC)
            continue;
        size_t avail = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct cn_msg));
        if (cn->len > avail || cn->len < offsetof(struct proc_event, event_data))
            continue;
        struct proc_event pe;
        memset(&pe, 0, sizeof(pe));
        memcpy(&pe, cn->data, cn->len < sizeof(pe) ? cn->len : sizeof(pe));
        if (pe.what == PROC_EVENT_EXEC) {
            ks_procmon_on_exec((int)pe.event_data.exec.process_pid,
                               (int)pe.event_data.exec.process_tgid);
            seen++;
        } else if (pe.what == PROC_EVENT_EXIT) {
            ks_procmon_on_exit((int)pe.event_data.exit.process_pid);
            seen++;
        }
    }
    return seen;
}

static void close_socket(void)
{
    if (ev.fd >= 0) {
        ks_evloop_del_fd(ev.loop, ev.fd);
        close(ev.fd);
        ev.fd = -1;
    }
}

static void on_restart(void *data)
{
    (void)data;
    ev.restart = NULL;
    ks_info("reinitiating ProcEventMonitor");
    ev.fd = open_socket();
    if (ev.fd < 0 || ks_evloop_add_fd(ev.loop, ev.fd, EPOLLIN, on_readable, NULL) < 0) {
        close_socket();
        ev.running = false;
        return;
    }
    ev.running = true;
}

static void on_readable(int fd, uint32_t events, void *data)
{
    (void)events;
    (void)data;
    union {
        struct nlmsghdr nh;
        char buf[8192];
    } u;
    for (;;) {
        ssize_t n = recv(fd, u.buf, sizeof(u.buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                return;
            /* ENOBUFS after a stop or a suspend: start over in a second. */
            ks_error("ProcEventMonitor error: %s", strerror(errno));
            close_socket();
            ev.restart = ks_evloop_add_timer(ev.loop, RESTART_DELAY_NS, 0, on_restart, NULL);
            return;
        }
        if (n == 0)
            return;
        ks_proc_events_handle(u.buf, (size_t)n);
    }
}

int ks_proc_events_start(struct ks_evloop *loop)
{
    if (ev.running)
        return 0;
    ev.loop = loop;
    ev.fd = open_socket();
    if (ev.fd < 0)
        return -1;
    if (ks_evloop_add_fd(loop, ev.fd, EPOLLIN, on_readable, NULL) < 0) {
        close(ev.fd);
        ev.fd = -1;
        return -1;
    }
    ks_info("ProcEventMonitor started");
    ev.running = true;
    return 0;
}

void ks_proc_events_stop(void)
{
    if (ev.restart != NULL) {
        ks_evloop_cancel_timer(ev.loop, ev.restart);
        ev.restart = NULL;
    }
    close_socket();
    if (ev.running)
        ks_debug("netlink.ProcEventsMonitor stopped");
    ev.running = false;
}

bool ks_proc_events_running(void)
{
    return ev.running;
}
