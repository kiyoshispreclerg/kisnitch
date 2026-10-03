/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/netfilter/queue.go, queue.h and packet.go.
 *
 * Upstream reads the queue in a goroutine and hands packets to 16 workers
 * through channels; here the queue's fd is one more source of the event
 * loop (docs/PORTING.md section 4).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/queue.h"

/* glibc's netinet/in.h must come before the kernel headers */
#include <netinet/in.h>

#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/evloop.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* Packets handled per wakeup, so other sources of the loop get a turn. */
#define BATCH_PACKETS 64

struct ks_queue {
    struct ks_evloop *loop;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    uint16_t num;
    bool uid_flag;
    ks_queue_cb cb;
    void *data;
    char *buf;
};

/* nf_callback */
static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
                       void *arg)
{
    (void)qh;
    (void)nfmsg;
    struct ks_queue *q = arg;
    struct ks_nfq_packet p;
    memset(&p, 0, sizeof(p));

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == NULL)
        return 0;
    p.id = ntohl(ph->packet_id);
    p.indev = nfq_get_indev(nfa);
    p.outdev = nfq_get_outdev(nfa);
    p.mark = nfq_get_nfmark(nfa);
    unsigned char *payload = NULL;
    int size = nfq_get_payload(nfa, &payload);
    p.uid = KS_NFQ_NO_UID;
    if (q->uid_flag)
        nfq_get_uid(nfa, &p.uid);

    if (size <= 0) {
        /* go_callback would index an empty slice; accept it instead. */
        ks_queue_verdict(q, p.id, KS_NF_ACCEPT, 0);
        return 0;
    }
    p.data = payload;
    p.len = (size_t)size;
    q->cb(q, &p, q->data);
    return 0;
}

static void on_readable(int fd, uint32_t events, void *data)
{
    (void)events;
    struct ks_queue *q = data;
    for (int i = 0; i < BATCH_PACKETS; i++) {
        ssize_t n = recv(fd, q->buf, KS_NFQ_PACKET_SIZE + 4096, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                ks_error("Terminating, unable to receive packet due to errno=%d", errno);
            return;
        }
        nfq_handle_packet(q->h, q->buf, (int)n);
    }
}

/* create() */
static int create(struct ks_queue *q, uint16_t num, char *err, size_t errlen)
{
    int ret;
    q->h = nfq_open();
    if (q->h == NULL) {
        snprintf(err, errlen, "Error opening Queue handle: %s", strerror(errno));
        return -1;
    }
    if ((ret = nfq_unbind_pf(q->h, AF_INET)) < 0) {
        snprintf(err, errlen,
                 "Error %d unbinding existing q handler from AF_INET protocol family: %s%s",
                 ret, strerror(errno),
                 errno == EINVAL ? "\nRestarting your computer may help to solve this error "
                                   "(see issues: #323 and #912 for more information)"
                                 : "");
        return -1;
    }
    if ((ret = nfq_unbind_pf(q->h, AF_INET6)) < 0) {
        snprintf(err, errlen,
                 "Error (%d) unbinding existing q handler from AF_INET6 protocol family: %s",
                 ret, strerror(errno));
        return -1;
    }
    if ((ret = nfq_bind_pf(q->h, AF_INET)) < 0) {
        snprintf(err, errlen, "Error (%d) binding to AF_INET protocol family: %s", ret,
                 strerror(errno));
        return -1;
    }
    if ((ret = nfq_bind_pf(q->h, AF_INET6)) < 0) {
        snprintf(err, errlen, "Error (%d) binding to AF_INET6 protocol family: %s", ret,
                 strerror(errno));
        return -1;
    }
    q->qh = nfq_create_queue(q->h, num, nf_callback, q);
    if (q->qh == NULL) {
        snprintf(err, errlen, "Error binding to queue: %s", strerror(errno));
        return -1;
    }
    /* configure_uid_if_available */
    if (nfq_set_queue_flags(q->qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID) != 0)
        ks_warning("UID not available on this kernel/libnetfilter_queue");
    else
        q->uid_flag = true;
    return 0;
}

/* setup() */
static int setup(struct ks_queue *q, char *err, size_t errlen)
{
    if (nfq_set_queue_maxlen(q->qh, KS_NFQ_QUEUE_SIZE) < 0) {
        snprintf(err, errlen, "Unable to set max packets in queue: %s", strerror(errno));
        return -1;
    }
    if (nfq_set_mode(q->qh, NFQNL_COPY_PACKET, KS_NFQ_PACKET_SIZE) < 0) {
        snprintf(err, errlen, "Unable to set packets copy mode: %s", strerror(errno));
        return -1;
    }
    q->fd = nfq_fd(q->h);
    /* Upstream checks for < 0, which an unsigned result never is. */
    nfnl_rcvbufsiz(nfq_nfnlh(q->h), KS_NFQ_QUEUE_SIZE * KS_NFQ_PACKET_SIZE);
    int opt = 1;
    setsockopt(q->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(opt));
    return 0;
}

uint16_t ks_queue_num(const struct ks_queue *q)
{
    return q->num;
}

struct ks_queue *ks_queue_new(struct ks_evloop *loop, uint16_t num, ks_queue_cb cb,
                              void *data, char *err, size_t errlen)
{
    if (errlen > 0)
        err[0] = '\0';
    struct ks_queue *q = calloc(1, sizeof(*q));
    if (q == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    q->loop = loop;
    q->num = num;
    q->cb = cb;
    q->data = data;
    q->fd = -1;
    q->buf = malloc(KS_NFQ_PACKET_SIZE + 4096);
    if (q->buf == NULL) {
        snprintf(err, errlen, "out of memory");
        free(q);
        return NULL;
    }
    if (create(q, num, err, errlen) < 0 || setup(q, err, errlen) < 0 ||
        ks_evloop_add_fd(loop, q->fd, EPOLLIN, on_readable, q) < 0) {
        if (q->fd >= 0 && err[0] == '\0')
            snprintf(err, errlen, "Unable to watch the queue's fd");
        q->fd = -1;
        ks_queue_free(q);
        return NULL;
    }
    return q;
}

void ks_queue_free(struct ks_queue *q)
{
    if (q == NULL)
        return;
    if (q->fd >= 0)
        ks_evloop_del_fd(q->loop, q->fd);
    if (q->qh != NULL && nfq_destroy_queue(q->qh) != 0)
        ks_warning("Queue.destroy() idx=%u, nfq_destroy_queue() not closed", q->num);
    if (q->h != NULL && nfq_close(q->h) != 0)
        ks_warning("Queue.destroy() idx=%u, nfq_close() not closed", q->num);
    free(q->buf);
    free(q);
}

int ks_queue_verdict(struct ks_queue *q, uint32_t id, uint32_t verdict, uint32_t mark)
{
    return nfq_set_verdict2(q->qh, id, verdict, mark, 0, NULL);
}
