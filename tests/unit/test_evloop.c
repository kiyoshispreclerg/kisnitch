/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/evloop.h"

#include <sys/epoll.h>
#include <unistd.h>

#include "tests/harness.h"

static int64_t fake_now;

static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

static char order[16];
static size_t norder;

static void record(void *data)
{
    if (norder < sizeof(order) - 1)
        order[norder++] = *(const char *)data;
}

TEST(timers_fire_in_deadline_order)
{
    struct ks_evloop *loop = ks_evloop_new();
    CHECK(loop != NULL);
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1000;
    norder = 0;
    memset(order, 0, sizeof(order));

    ks_evloop_add_timer(loop, 30, 0, record, "c");
    ks_evloop_add_timer(loop, 10, 0, record, "a");
    ks_evloop_add_timer(loop, 20, 0, record, "b");
    ks_evloop_add_timer(loop, 20, 0, record, "B"); /* same deadline: FIFO */
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 4);

    fake_now = 1009;
    CHECK_INT_EQ(ks_evloop_fire_due(loop), 0);
    fake_now = 1020;
    CHECK_INT_EQ(ks_evloop_fire_due(loop), 3);
    CHECK_STR_EQ(order, "abB");
    fake_now = 5000;
    CHECK_INT_EQ(ks_evloop_fire_due(loop), 1);
    CHECK_STR_EQ(order, "abBc");
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
}

struct self_cancel {
    struct ks_evloop *loop;
    struct ks_timer *t;
    int runs;
};

static void cancel_self(void *data)
{
    struct self_cancel *sc = data;
    if (++sc->runs == 3)
        ks_evloop_cancel_timer(sc->loop, sc->t);
}

TEST(repeating_timer_and_self_cancel)
{
    struct ks_evloop *loop = ks_evloop_new();
    CHECK(loop != NULL);
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 0;
    struct self_cancel sc = {loop, NULL, 0};
    sc.t = ks_evloop_add_timer(loop, 100, 100, cancel_self, &sc);
    for (int i = 1; i <= 10; i++) {
        fake_now = i * 100;
        ks_evloop_fire_due(loop);
    }
    CHECK_INT_EQ(sc.runs, 3);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);

    /* Cancelling a pending timer. */
    struct ks_timer *t = ks_evloop_add_timer(loop, 10, 0, record, "x");
    ks_evloop_cancel_timer(loop, t);
    CHECK_INT_EQ(ks_evloop_timer_count(loop), 0);
    ks_evloop_free(loop);
}

static void stop_loop(void *data)
{
    ks_evloop_stop(data);
}

static int reads;

static void on_readable(int fd, uint32_t events, void *data)
{
    char c;
    (void)data;
    if ((events & EPOLLIN) && read(fd, &c, 1) == 1)
        reads++;
}

TEST(real_timer_and_fd)
{
    struct ks_evloop *loop = ks_evloop_new();
    int p[2];
    CHECK(loop != NULL);
    CHECK(pipe(p) == 0);
    reads = 0;
    CHECK(ks_evloop_add_fd(loop, p[0], EPOLLIN, on_readable, NULL) == 0);
    CHECK(write(p[1], "xy", 2) == 2);

    int64_t start = ks_evloop_now(loop);
    ks_evloop_add_timer(loop, 50 * 1000000, 0, stop_loop, loop);
    CHECK(ks_evloop_run(loop) == 0);
    int64_t elapsed = ks_evloop_now(loop) - start;
    CHECK_MSG(elapsed >= 50 * 1000000, "stopped after %lld ns", (long long)elapsed);
    CHECK_INT_EQ(reads, 2);

    ks_evloop_del_fd(loop, p[0]);
    CHECK(write(p[1], "z", 1) == 1);
    CHECK_INT_EQ(ks_evloop_run_once(loop, 10), 0);
    close(p[0]);
    close(p[1]);
    ks_evloop_free(loop);
}

int main(void)
{
    RUN(timers_fire_in_deadline_order);
    RUN(repeating_timer_and_self_cancel);
    RUN(real_timer_and_fd);
    return harness_report();
}
