/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Process monitor tests, including phase 2's acceptance criteria:
 *  - a TCP and a UDP socket of this process resolve to our PID;
 *  - a child (fork + exec) resolves to its path and its parent (us);
 *  - the cache doesn't grow without bounds over 10 000 short processes.
 * Also ports upstream's procmon/{process,find,cache,cache_events}_test.go.
 *
 * Run as `test_procmon --child-connect <port>`, the binary connects to
 * 127.0.0.1:<port> and waits: that's the child of the fork + exec test.
 */
#define _XOPEN_SOURCE 700 /* realpath() */
#include "daemon/procmon/procmon.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common/hash.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/procmon/events.h"
#include "daemon/rules/loader.h"
#include "tests/harness.h"

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define KS_HAS_ASAN 1
#endif
#endif
#ifndef KS_HAS_ASAN
#define KS_HAS_ASAN 0
#endif

static char self_exe[PATH_MAX];
static int64_t fake_now;

static int64_t fake_clock(void *ctx)
{
    (void)ctx;
    return fake_now;
}

/* A fresh procmon on a loop with a fake clock. */
static struct ks_evloop *setup(void)
{
    struct ks_evloop *loop = ks_evloop_new();
    ks_evloop_set_clock(loop, fake_clock, NULL);
    fake_now = 1000000000LL;
    ks_procmon_cache_reset();
    ks_procmon_cache_init(loop);
    return loop;
}

static void teardown(struct ks_evloop *loop)
{
    ks_procmon_cache_reset();
    ks_evloop_free(loop);
}

static void advance(struct ks_evloop *loop, int64_t ns)
{
    fake_now += ns;
    ks_evloop_fire_due(loop);
}

static int64_t fd_inode(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 ? (int64_t)st.st_ino : -1;
}

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

static int listen_lo(int type)
{
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
        (type == SOCK_STREAM && listen(fd, 8) < 0))
        return -1;
    return fd;
}

static int connect_lo(int type, unsigned port)
{
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
        return -1;
    return fd;
}

static size_t rss_kb(void)
{
    char err[64];
    size_t len;
    char *s = ks_read_file("/proc/self/status", 1 << 16, &len, err, sizeof(err));
    const char *v = s ? strstr(s, "VmRSS:") : NULL;
    size_t kb = v ? strtoul(v + 6, NULL, 10) : 0;
    free(s);
    return kb;
}

/* ---- acceptance: our own sockets ---------------------------------------- */

TEST(own_tcp_and_udp_sockets_resolve_to_our_pid)
{
    struct ks_evloop *loop = setup();
    struct ks_ip lo;
    ks_ip_parse("127.0.0.1", &lo);

    int srv = listen_lo(SOCK_STREAM);
    CHECK(srv >= 0);
    int c = connect_lo(SOCK_STREAM, local_port(srv));
    int acc = accept(srv, NULL, NULL);
    CHECK(c >= 0 && acc >= 0);

    struct ks_procmon_result r;
    CHECK(ks_procmon_resolve("tcp", &lo, local_port(c), &lo, local_port(srv),
                             0xffffffffu, false, &r) == 0);
    CHECK_INT_EQ(r.pid, getpid());
    CHECK_INT_EQ(r.inode, fd_inode(c));
    CHECK(r.proc != NULL && r.proc->pid == getpid());
    ks_procmon_result_clear(&r);
    /* The second time it comes from the inode cache. */
    CHECK(ks_inodes_len() >= 1);
    CHECK(ks_procmon_resolve("tcp", &lo, local_port(c), &lo, local_port(srv),
                             1234, false, &r) == 0);
    CHECK_INT_EQ(r.pid, getpid());
    ks_procmon_result_clear(&r);

    /* The /proc/net route (used when netlink finds nothing). */
    int64_t inode;
    CHECK(ks_procmon_inode_from_netstat("tcp", &lo, local_port(c), &lo,
                                        local_port(srv), &inode));
    CHECK_INT_EQ(inode, fd_inode(c));
    CHECK_INT_EQ(ks_procmon_lookup_pid_in_proc("/proc/", "socket:[0]", "k"), -1);
    char expect[48];
    snprintf(expect, sizeof(expect), "socket:[%lld]", (long long)inode);
    CHECK_INT_EQ(ks_procmon_lookup_pid_in_proc("/proc/", expect, "k2"), getpid());

    int us = listen_lo(SOCK_DGRAM);
    int uc = connect_lo(SOCK_DGRAM, local_port(us));
    CHECK(us >= 0 && uc >= 0);
    CHECK(ks_procmon_resolve("udp", &lo, local_port(uc), &lo, local_port(us),
                             0xffffffffu, false, &r) == 0);
    CHECK_INT_EQ(r.pid, getpid());
    CHECK_INT_EQ(r.inode, fd_inode(uc));
    ks_procmon_result_clear(&r);

    /* Unknown connection: no process (upstream drops it), or an empty one
     * when intercepting unknown connections. */
    CHECK(ks_procmon_resolve("tcp", &lo, 1, &lo, 2, 0xffffffffu, false, &r) == -1);
    CHECK_INT_EQ(r.pid, -1);
    ks_procmon_result_clear(&r);
    CHECK(ks_procmon_resolve("tcp", &lo, 1, &lo, 2, 1000, true, &r) == 0);
    CHECK(r.proc != NULL && r.proc->pid == 0);
    CHECK_INT_EQ(r.uid, 1000);
    ks_procmon_result_clear(&r);

    close(c);
    close(acc);
    close(srv);
    close(uc);
    close(us);
    teardown(loop);
}

/* ---- acceptance: fork + exec -------------------------------------------- */

TEST(child_fork_exec_path_and_parent)
{
    struct ks_evloop *loop = setup();
    struct ks_ip lo;
    ks_ip_parse("127.0.0.1", &lo);
    int srv = listen_lo(SOCK_STREAM);
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
    CHECK(acc >= 0);
    char ready;
    CHECK(read(acc, &ready, 1) == 1); /* connected and waiting */

    struct ks_procmon_result r;
    int rc = ks_procmon_resolve("tcp", &lo, peer_port(acc), &lo, local_port(srv),
                                0xffffffffu, false, &r);
    /* Like upstream's FindProcess, resolving reads no parents; they come
     * from GetParent (done on exec events, or here by hand). */
    if (rc == 0) {
        CHECK(r.proc->parent == NULL);
        ks_proc_get_parent(r.proc);
        ks_proc_build_tree(r.proc);
    }
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    close(acc);
    close(srv);

    CHECK_INT_EQ(rc, 0);
    CHECK_INT_EQ(r.pid, child);
    CHECK_STR_EQ(r.proc->path, self_exe);
    CHECK(r.proc->nargs == 3);
    CHECK_STR_EQ(r.proc->args[1], "--child-connect");
    CHECK_STR_EQ(r.proc->args[2], port);
    CHECK(ks_proc_getenv(r.proc, "KS_TEST_MARKER") != NULL);

    /* The parent chain: us, then our parents up to init. */
    CHECK(r.proc->parent != NULL);
    CHECK_INT_EQ(r.proc->parent->pid, getpid());
    CHECK_STR_EQ(r.proc->parent->path, self_exe);
    CHECK(r.proc->ntree >= 3);
    CHECK_INT_EQ(r.proc->tree[0].pid, child);
    CHECK_INT_EQ(r.proc->tree[1].pid, getpid());
    CHECK_INT_EQ(r.proc->tree[r.proc->ntree - 1].pid, 1);
    /* What the rules see (process.parent.path walks this). */
    CHECK_STR_EQ(r.proc->view.path, self_exe);
    CHECK(r.proc->view.parent == &r.proc->parent->view);
    ks_procmon_result_clear(&r);
    teardown(loop);
}

TEST(exec_of_a_system_binary)
{
    struct ks_evloop *loop = setup();
    char sleep_path[PATH_MAX];
    if (realpath("/bin/sleep", sleep_path) == NULL) {
        fprintf(stderr, "  (no /bin/sleep, skipped)\n");
        teardown(loop);
        return;
    }
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(p[0]);
        fcntl(p[1], F_SETFD, FD_CLOEXEC);
        execl("/bin/sleep", "sleep", "30", (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    char b;
    CHECK(read(p[0], &b, 1) == 0); /* EOF once exec closed it */
    close(p[0]);

    struct ks_proc *proc = ks_procmon_find_process(child, false);
    CHECK(proc != NULL);
    CHECK_STR_EQ(proc->path, sleep_path);
    CHECK_STR_EQ(proc->comm, "sleep");
    CHECK(proc->nargs == 2);
    CHECK_STR_EQ(proc->args[1], "30");
    ks_proc_get_parent(proc);
    CHECK(proc->parent != NULL && proc->parent->pid == getpid());
    /* Cached: found again without reading /proc. */
    CHECK(ks_procmon_find_process(child, false) == proc);
    ks_proc_unref(proc);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    ks_proc_unref(proc);
    teardown(loop);
}

/* An exec event replaces the cached process of that PID. */
TEST(exec_event_replaces_the_cached_binary)
{
    struct ks_evloop *loop = setup();
    int go[2];
    CHECK(pipe(go) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char c;
        close(go[1]);
        if (read(go[0], &c, 1) != 1)
            _exit(1);
        execl("/bin/sleep", "sleep", "30", (char *)NULL);
        _exit(127);
    }
    close(go[0]);
    /* Before exec it's a copy of us. */
    struct ks_proc *before = ks_procmon_find_process(child, false);
    CHECK(before != NULL);
    CHECK_STR_EQ(before->path, self_exe);
    ks_proc_unref(before);

    CHECK(write(go[1], "x", 1) == 1);
    close(go[1]);
    char sleep_path[PATH_MAX];
    CHECK(realpath("/bin/sleep", sleep_path) != NULL);
    /* Wait for the exec to happen. */
    for (int i = 0; i < 200; i++) {
        char link[PATH_MAX], exe[64];
        snprintf(exe, sizeof(exe), "/proc/%d/exe", (int)child);
        ssize_t n = readlink(exe, link, sizeof(link) - 1);
        if (n > 0 && (link[n] = '\0', strcmp(link, sleep_path) == 0))
            break;
        nanosleep(&(struct timespec){0, 10000000}, NULL);
    }

    ks_procmon_on_exec(child, child);
    struct ks_proc *after = ks_procmon_find_process(child, false);
    CHECK(after != NULL);
    CHECK_STR_EQ(after->path, sleep_path);
    ks_proc_unref(after);

    /* Exit: dropped 2 s after the event, once it's really gone. */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    ks_procmon_on_exit(child);
    CHECK(ks_events_find(child) != NULL);
    advance(loop, KS_EVENTS_EXIT_DELAY_NS);
    CHECK(ks_events_find(child) == NULL);
    teardown(loop);
}

/* ---- acceptance: 10 000 short processes --------------------------------- */

TEST(cache_stays_bounded_with_many_short_processes)
{
    struct ks_evloop *loop = setup();
    int total = 10000, batch = 1000;
    size_t rss_start = 0, max_cached = 0;

    for (int i = 0; i < total; i++) {
        int p[2];
        CHECK(pipe(p) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            char c;
            close(p[1]);
            _exit(read(p[0], &c, 1) == 1 ? 0 : 1);
        }
        close(p[0]);
        struct ks_proc *proc = ks_procmon_find_process(child, false);
        CHECK_MSG(proc != NULL, "process %d not found", (int)child);
        ks_proc_unref(proc);
        CHECK(write(p[1], "x", 1) == 1);
        close(p[1]);
        waitpid(child, NULL, 0);
        ks_procmon_on_exit(child); /* the event root would get */

        if (ks_events_len() > max_cached)
            max_cached = ks_events_len();
        if ((i + 1) % batch == 0) {
            /* A batch takes "1 s"; the 10 s sweep and 2 s exit delays run. */
            advance(loop, KS_EVENTS_EXIT_DELAY_NS);
            advance(loop, KS_EVENTS_SWEEP_NS);
            if (i + 1 == batch)
                rss_start = rss_kb();
        }
    }
    advance(loop, KS_EVENTS_PID_TTL_NS + KS_EVENTS_SWEEP_NS);
    size_t rss_end = rss_kb();

    CHECK_INT_EQ(ks_events_len(), 0);
    CHECK_MSG(max_cached <= (size_t)batch, "cache peaked at %zu entries", max_cached);
#if !defined(__SANITIZE_ADDRESS__) && !KS_HAS_ASAN
    /* Some growth is allocator noise; 10 000 leaked processes would be
     * several MB. (ASan keeps freed memory in quarantine, so RSS means
     * nothing there; it checks for leaks itself.) */
    CHECK_MSG(rss_end <= rss_start + 2048, "RSS grew from %zu to %zu kB",
              rss_start, rss_end);
#endif
    fprintf(stderr, "  %d processes: cache peak %zu, RSS %zu -> %zu kB\n", total,
            max_cached, rss_start, rss_end);
    teardown(loop);
}

/* Without exit events (not root), the 10 s sweep drops dead processes
 * once they're 20 s old, as upstream. */
TEST(dead_processes_expire_without_exit_events)
{
    struct ks_evloop *loop = setup();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        pause();
        _exit(0);
    }
    struct ks_proc *proc = ks_procmon_find_process(child, false);
    CHECK(proc != NULL);
    ks_proc_unref(proc);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    advance(loop, KS_EVENTS_SWEEP_NS);
    CHECK(ks_events_find(child) != NULL); /* only 10 s old */
    advance(loop, KS_EVENTS_SWEEP_NS);
    CHECK(ks_events_find(child) == NULL);
    /* Alive processes stay, however old. */
    proc = ks_procmon_find_process(getppid(), false);
    if (proc != NULL) {
        ks_proc_unref(proc);
        advance(loop, 10 * KS_EVENTS_PID_TTL_NS);
        CHECK(ks_events_find(getppid()) != NULL);
    }
    teardown(loop);
}

/* ---- process.go ----------------------------------------------------------- */

TEST(process_details_of_ourselves)
{
    struct ks_proc *p = ks_proc_new_empty(getpid(), "fakeComm");
    CHECK(p != NULL);
    CHECK_STR_EQ(p->comm, "fakeComm");
    CHECK(ks_proc_read_path(p) == 0);
    CHECK_STR_EQ(p->path, self_exe);
    ks_proc_read_cwd(p);
    CHECK(p->cwd[0] == '/');
    ks_proc_read_cmdline(p);
    CHECK(p->nargs >= 1);
    ks_proc_read_ppid(p);
    CHECK_INT_EQ(p->ppid, getppid());
    CHECK(ks_proc_is_alive(p));
    /* Our own PID: GetDetails reads nothing, as upstream. */
    struct ks_proc *q = ks_proc_new_empty(getpid(), "");
    CHECK(ks_proc_get_details(q) == 0);
    CHECK_STR_EQ(q->path, "");
    ks_proc_unref(q);

    /* TestProcEnv */
    ks_proc_read_env_file(p, KS_FIXTURES_DIR "/upstream/proc-environ");
    static const char *const env[][2] = {
        {"EMPTY", ""},
        {"TEST1", "xxx=123"},
        {"TEST2", "xxx=123==456"},
        {"SSH_AGENT_PID", "4873"},
        {"XDG_CURRENT_DESKTOP", "i3"},
        {"USER", "opensnitch"},
        {"HOME", "/tmp"},
        {"XDG_DATA_DIRS", "/usr/share/gnome:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share"},
        {"DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"},
        {"LS_COLORS", "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;"},
    };
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
        CHECK_STR_EQ(ks_proc_getenv(p, env[i][0]), env[i][1]);
    CHECK(p->view.nenv == p->nenv);

    /* TestProcCleanPath */
    ks_proc_set_path(p, "/fake/path/binary (deleted)");
    CHECK_STR_EQ(p->path, "/fake/path/binary");
    ks_proc_set_path(p, "/proc/self/exe");
    CHECK(strncmp(p->path, "/proc", 5) != 0);
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/4", (int)getpid());
    ks_proc_set_path(p, fdpath);
    CHECK(strncmp(p->path, "/proc", 5) != 0);
    ks_proc_set_path(p, "./opensnitchd");
    CHECK(p->path[0] == '/');

    /* TestProcCleanArgs */
    ks_proc_set_path(p, "/proc/self/exe");
    free(p->args[0]);
    p->args[0] = strdup("/proc/self/exe");
    ks_proc_clean_args(p);
    CHECK(strcmp(p->args[0], "/proc/self/exe") != 0);
    ks_proc_unref(p);
}

TEST(process_that_does_not_exist)
{
    struct ks_proc *p = ks_proc_new_empty(INT_MAX - 7, "");
    CHECK(!ks_proc_is_alive(p));
    CHECK(ks_proc_get_details(p) == -1);
    ks_proc_unref(p);
    CHECK(ks_procmon_find_process(INT_MAX - 7, false) == NULL);
    struct ks_proc *e = ks_procmon_find_process(-1, true);
    CHECK(e != NULL && e->pid == 0);
    ks_proc_unref(e);
}

TEST(checksums)
{
    struct ks_evloop *loop = setup();
    char err[128], expect[33];
    size_t len;
    char *bin = ks_read_file(self_exe, 1u << 30, &len, err, sizeof(err));
    CHECK(bin != NULL);
    struct ks_md5 m;
    uint8_t d[16];
    ks_md5_init(&m);
    ks_md5_update(&m, bin, len);
    ks_md5_final(&m, d);
    ks_hex_encode(d, 16, expect);
    free(bin);

    /* The loader turns checksums on for the procmon (EnableChecksums). */
    struct ks_loader *l = ks_loader_new(NULL, NULL, false);
    ks_loader_enable_checksums(l, true);
    CHECK(ks_events_get_compute_checksums());

    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        pause();
        _exit(0);
    }
    struct ks_proc *p = ks_procmon_find_process(child, false);
    CHECK(p != NULL);
    CHECK_STR_EQ(p->checksum_md5, expect);
    CHECK(p->checksum_sha1 == NULL); /* only md5 is enabled by default */
    CHECK_STR_EQ(p->view.checksum_md5, expect);
    ks_proc_unref(p);

    ks_loader_enable_checksums(l, false);
    CHECK(ks_events_find(child)->checksum_md5 == NULL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    ks_loader_free(l);
    teardown(loop);
}

/* ---- find.go / cache.go --------------------------------------------------- */

TEST(upstream_find_and_cache_tests)
{
    struct ks_evloop *loop = setup();
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/", (int)getpid());

    size_t n;
    char **fds = ks_lookup_pid_descriptors(fd_path, &n);
    CHECK(fds != NULL && n > 0);
    ks_free_names(fds, n);
    /* TestLookupPidInProc: something holds /dev/null open (we do). */
    FILE *devnull = fopen("/dev/null", "r");
    CHECK(ks_procmon_lookup_pid_in_proc("/proc/", "/dev/null", "") != -1);

    /* TestCacheProcs */
    ks_procmon_cache_reset();
    ks_procmon_cache_init(loop);
    char *list[] = {"0", "1", "2"};
    ks_pids_add(fd_path, list, 3, getpid());
    CHECK_INT_EQ(ks_pids_len(), 1);
    ks_pids_add(fd_path, list, 3, getpid());
    CHECK_INT_EQ(ks_pids_len(), 1);
    ks_pids_add("/proc/2/fd", list, 3, 2);
    ks_pids_delete(2);
    CHECK_INT_EQ(ks_pids_len(), 1);
    int pos;
    CHECK_INT_EQ(ks_pids_get_pid("", "/dev/null", &pos), getpid());
    /* A dead process is dropped from the pids cache when searched. */
    ks_pids_add("/proc/2147483640/fd/", list, 3, 2147483640);
    CHECK_INT_EQ(ks_pids_get_pid("", "socket:[1]", &pos), -1);
    CHECK_INT_EQ(ks_pids_len(), 1);

    const char *key = "000000000127.0.0.144444127.0.0.153";
    ks_inodes_add(key, "", getpid());
    CHECK_INT_EQ(ks_inodes_get_pid(key), getpid());
    ks_inodes_delete_pid(getpid());
    CHECK_INT_EQ(ks_inodes_get_pid(key), -1);
    /* A stale fd link drops the entry, and the PID from the pids cache. */
    ks_inodes_add(key, "/proc/2147483640/fd/9", getpid());
    CHECK_INT_EQ(ks_inodes_get_pid(key), -1);
    CHECK_INT_EQ(ks_pids_len(), 0);
    /* Unused for more than 3 minutes: dropped by the cleanup. */
    ks_inodes_add(key, "", getpid());
    advance(loop, KS_INODES_CLEANUP_NS);
    CHECK_INT_EQ(ks_inodes_len(), 1);
    advance(loop, KS_INODES_CLEANUP_NS);
    advance(loop, KS_INODES_CLEANUP_NS);
    CHECK_INT_EQ(ks_inodes_len(), 0);
    fclose(devnull);
    teardown(loop);
}

/* TestCacheEvents: an alive process isn't deleted on exit events. */
TEST(upstream_cache_events_tests)
{
    struct ks_evloop *loop = setup();
    struct ks_proc *p = ks_proc_new_empty(getpid(), "");
    ks_proc_read_comm(p);
    ks_proc_read_path(p);
    ks_proc_read_cmdline(p);
    ks_proc_build_tree(p);
    ks_events_add(p);
    CHECK(ks_events_find(getpid()) == p);
    ks_events_delete(getpid());
    advance(loop, KS_EVENTS_EXIT_DELAY_NS);
    CHECK(ks_events_find(getpid()) == p);
    ks_proc_unref(p);

    /* TestCacheEvents2: a PID that doesn't exist goes away after the
     * delay. */
    struct ks_proc *fake = ks_proc_new_empty(2147483641, "");
    free(fake->path);
    fake->path = strdup("/tmp/1234");
    ks_events_add(fake);
    CHECK(ks_events_find(2147483641) == fake);
    ks_events_delete(2147483641);
    CHECK(ks_events_find(2147483641) != NULL);
    advance(loop, KS_EVENTS_EXIT_DELAY_NS);
    CHECK(ks_events_find(2147483641) == NULL);
    ks_proc_unref(fake);

    /* Items with an empty path aren't stored. */
    struct ks_proc *empty = ks_proc_new_empty(2147483642, "");
    ks_events_add(empty);
    CHECK(ks_events_find(2147483642) == NULL);
    ks_proc_unref(empty);
    teardown(loop);
}

/* ---- the events connector -------------------------------------------------- */

TEST(connector_messages)
{
    struct ks_evloop *loop = setup();
    /* As a normal user the kernel refuses the subscription. */
    int rc = ks_proc_events_start(loop);
    if (getuid() != 0)
        CHECK(rc == -1 && !ks_proc_events_running());
    ks_proc_events_stop();

    /* A hand-made exec message for a child. */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        pause();
        _exit(0);
    }
    union {
        struct nlmsghdr nh;
        char buf[256];
    } u;
    memset(&u, 0, sizeof(u));
    u.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event));
    u.nh.nlmsg_type = NLMSG_DONE;
    struct cn_msg *cn = NLMSG_DATA(&u.nh);
    cn->id.idx = CN_IDX_PROC;
    cn->id.val = CN_VAL_PROC;
    cn->len = sizeof(struct proc_event);
    struct proc_event pe;
    memset(&pe, 0, sizeof(pe));
    pe.what = PROC_EVENT_EXEC;
    pe.event_data.exec.process_pid = child;
    pe.event_data.exec.process_tgid = child;
    memcpy(cn->data, &pe, sizeof(pe));
    CHECK_INT_EQ(ks_proc_events_handle(u.buf, u.nh.nlmsg_len), 1);
    CHECK(ks_events_find(child) != NULL);
    CHECK_STR_EQ(ks_events_find(child)->path, self_exe);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    pe.what = PROC_EVENT_EXIT;
    pe.event_data.exit.process_pid = child;
    memcpy(cn->data, &pe, sizeof(pe));
    CHECK_INT_EQ(ks_proc_events_handle(u.buf, u.nh.nlmsg_len), 1);
    advance(loop, KS_EVENTS_EXIT_DELAY_NS);
    CHECK(ks_events_find(child) == NULL);

    /* Truncated or foreign messages are ignored. */
    CHECK_INT_EQ(ks_proc_events_handle(u.buf, 10), 0);
    cn->id.idx = 99;
    CHECK_INT_EQ(ks_proc_events_handle(u.buf, u.nh.nlmsg_len), 0);
    teardown(loop);
}

/* Under valgrind (`make valgrind` sets KS_TEST_VALGRIND) a forked child is
 * valgrind itself: its /proc/<pid>/exe, checksums and memory aren't ours,
 * and exec behaves differently. Tests that look at children through /proc
 * run natively and under ASan instead. */
static bool skip_child_tests(void)
{
    if (getenv("KS_TEST_VALGRIND") == NULL)
        return false;
    fprintf(stderr, "  (test inspecting child processes skipped under valgrind)\n");
    return true;
}

static int child_connect(const char *port)
{
    int fd = connect_lo(SOCK_STREAM, (unsigned)atoi(port));
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
    setenv("KS_TEST_MARKER", "1", 1); /* inherited by the exec'd child */
    ks_log_set_level(KS_LOG_FATAL + 1);

    RUN(own_tcp_and_udp_sockets_resolve_to_our_pid);
    if (!skip_child_tests())
        RUN(child_fork_exec_path_and_parent);
    if (!skip_child_tests())
        RUN(exec_of_a_system_binary);
    if (!skip_child_tests())
        RUN(exec_event_replaces_the_cached_binary);
    if (!skip_child_tests())
        RUN(cache_stays_bounded_with_many_short_processes);
    if (!skip_child_tests())
        RUN(dead_processes_expire_without_exit_events);
    RUN(process_details_of_ourselves);
    RUN(process_that_does_not_exist);
    if (!skip_child_tests())
        RUN(checksums);
    RUN(upstream_find_and_cache_tests);
    RUN(upstream_cache_events_tests);
    if (!skip_child_tests())
        RUN(connector_messages);
    return harness_report();
}
