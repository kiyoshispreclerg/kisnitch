/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A netfilter queue read from the event loop. Port of upstream
 * daemon/netfilter/queue.go, queue.h and packet.go.
 *
 * Each packet is handed to the callback, which gives the verdict with
 * ks_queue_verdict(). The kernel holds the packet until then, so a verdict
 * may also come later (phase 5 asks the UI), as long as the queue lives.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_queue owns its netlink handles and its fd watcher on
 * the loop (which must outlive it). struct ks_nfq_packet and its data are
 * valid only during the callback.
 */
#ifndef KS_DAEMON_QUEUE_H
#define KS_DAEMON_QUEUE_H

#include <stddef.h>
#include <stdint.h>

struct ks_evloop;
struct ks_queue;

/* Verdicts (NF_DROP, NF_ACCEPT...). */
#define KS_NF_DROP 0u
#define KS_NF_ACCEPT 1u

/* NF_DEFAULT_QUEUE_SIZE, NF_DEFAULT_PACKET_SIZE */
#define KS_NFQ_QUEUE_SIZE 4096u
#define KS_NFQ_PACKET_SIZE 4096u

#define KS_NFQ_NO_UID 0xffffffffu

/* netfilter.Packet: what go_callback gets. */
struct ks_nfq_packet {
    uint32_t id;        /* packet id, for the verdict */
    uint32_t mark;      /* Mark */
    uint32_t uid;       /* UID (KS_NFQ_NO_UID if the kernel didn't say) */
    uint32_t indev;     /* IfaceInIdx */
    uint32_t outdev;    /* IfaceOutIdx */
    const uint8_t *data;
    size_t len;
};

typedef void (*ks_queue_cb)(struct ks_queue *q, const struct ks_nfq_packet *p, void *data);

/* NewQueue: binds queue `num` and starts reading it on `loop`. NULL on
 * error, with the reason in `err`. */
struct ks_queue *ks_queue_new(struct ks_evloop *loop, uint16_t num, ks_queue_cb cb,
                              void *data, char *err, size_t errlen);
/* Close: unbinds and frees the queue. Packets without a verdict are
 * dropped by the kernel. */
void ks_queue_free(struct ks_queue *q);

uint16_t ks_queue_num(const struct ks_queue *q);

/* nfq_set_verdict2(). Like upstream, the mark is always sent: SetVerdict()
 * is a verdict with mark 0, SetVerdictAndMark() keeps the packet's. */
int ks_queue_verdict(struct ks_queue *q, uint32_t id, uint32_t verdict, uint32_t mark);

#endif
