/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/procmon/audit (client.go, parse.go). See audit.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _GNU_SOURCE /* SOCK_CLOEXEC */
#include "daemon/procmon/audit.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/rules/regex.h"

extern char **environ;

#define RULES_KEY "key=\"opensnitch\""
#define CLEANER_INTERVAL (5 * KS_MINUTE)
#define RECONNECT_WAIT (30 * KS_SECOND)
/* upstream's list has no bound; old events go every 5 minutes */
#define MAX_EVENTS 8192
#define LINE_MAX_LEN (1024 * 1024)

/* the syscalls of the rules: upstream's numbers are amd64's; elsewhere,
 * this architecture's */
#if defined(__x86_64__)
#define SYS_SOCKET_STR "syscall=41"
#define SYS_CONNECT_STR "syscall=42"
#define SYS_SOCKETPAIR_STR "syscall=53"
#define SYS_EXECVE_STR "syscall=59"
#define SYS_SOCKETCALL_STR "syscall=102"
#else
#define STR2(x) #x
#define STR(x) STR2(x)
#define SYS_SOCKET_STR "syscall=" STR(__NR_socket)
#define SYS_CONNECT_STR "syscall=" STR(__NR_connect)
#define SYS_SOCKETPAIR_STR "syscall=" STR(__NR_socketpair)
#define SYS_EXECVE_STR "syscall=" STR(__NR_execve)
#ifdef __NR_socketcall
#define SYS_SOCKETCALL_STR "syscall=" STR(__NR_socketcall)
#else
#define SYS_SOCKETCALL_STR "syscall=-1"
#endif
#endif

static struct ks_audit_event *events[MAX_EVENTS]; /* newest first */
static size_t nevents;
static bool new_event;
static struct ks_audit_event *net_event; /* the event being parsed (owned by `events`) */
static struct ks_regex *audit_re;
static char auditctl[256] = "auditctl";

/* the connection */
static struct ks_evloop *aloop;
static int afd = -1;
static char apath[108];
static char *abuf;
static size_t abuf_len;
static struct ks_timer *cleaner, *reconnect_timer;

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * KS_SECOND + ts.tv_nsec;
}

void ks_audit_set_auditctl(const char *path)
{
    snprintf(auditctl, sizeof(auditctl), "%s", path != NULL ? path : "auditctl");
}

/* ---- the list --------------------------------------------------------- */

size_t ks_audit_count(void)
{
    return nevents;
}

const struct ks_audit_event *ks_audit_event_at(size_t i)
{
    return i < nevents ? events[i] : NULL;
}

const struct ks_audit_event *ks_audit_event_by_pid(int pid)
{
    for (size_t i = 0; i < nevents; i++)
        if (events[i]->pid == pid)
            return events[i];
    return NULL;
}

static void remove_at(size_t i)
{
    if (events[i] == net_event)
        net_event = NULL; /* the rest of its records are dropped */
    free(events[i]);
    memmove(&events[i], &events[i + 1], (nevents - i - 1) * sizeof(*events));
    nevents--;
}

static int cmp_seen(const void *a, const void *b)
{
    const struct ks_audit_event *x = *(struct ks_audit_event *const *)a;
    const struct ks_audit_event *y = *(struct ks_audit_event *const *)b;
    return (x->last_seen < y->last_seen) - (x->last_seen > y->last_seen);
}

/* AddEvent: a known PID and syscall is refreshed (and the list sorted,
 * newest first); a new one goes on top */
static void add_event(struct ks_audit_event *ev)
{
    if (ev == NULL)
        return;
    size_t self = nevents; /* ev's own slot, if it's already listed */
    for (size_t i = 0; i < nevents; i++)
        if (events[i] == ev)
            self = i;
    for (size_t i = 0; i < nevents; i++) {
        if (events[i] == ev || events[i]->pid != ev->pid || events[i]->syscall != ev->syscall)
            continue;
        /* the same PID and syscall: replaced by the new event (the cmdline,
         * proctitle, is never filled, so upstream always replaces) */
        if (self < nevents) {
            remove_at(i); /* ev is listed already: drop the other one */
        } else {
            free(events[i]);
            events[i] = ev;
            self = i;
        }
        break;
    }
    ev->last_seen = now_ns();
    if (self < nevents) {
        qsort(events, nevents, sizeof(*events), cmp_seen);
        return;
    }
    if (nevents == MAX_EVENTS)
        remove_at(nevents - 1);
    memmove(&events[1], &events[0], nevents * sizeof(*events));
    events[0] = ev;
    nevents++;
}

void ks_audit_clean_old_events(void)
{
    int64_t now = now_ns();
    for (size_t n = nevents; n-- > 0;) {
        char dir[32];
        struct stat st;
        snprintf(dir, sizeof(dir), "/proc/%d", events[n]->pid);
        if ((now - events[n]->last_seen) / KS_MINUTE >= KS_AUDIT_MAX_EVENT_AGE_MIN ||
            stat(dir, &st) < 0)
            remove_at(n);
    }
}

void ks_audit_reset(void)
{
    while (nevents > 0)
        remove_at(nevents - 1);
    new_event = false;
    net_event = NULL;
}

/* ---- parse.go --------------------------------------------------------- */

/* decodeString: hex.DecodeString, or the string as is */
static void decode_string(const char *s, char *out, size_t len)
{
    size_t n = strlen(s);
    bool hex = n % 2 == 0;
    for (size_t i = 0; hex && i < n; i++) {
        char c = s[i];
        hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    if (!hex) {
        snprintf(out, len, "%s", s);
        return;
    }
    size_t o = 0;
    for (size_t i = 0; i + 1 < n && o + 1 < len; i += 2) {
        char b[3] = {s[i], s[i + 1], '\0'};
        out[o++] = (char)strtol(b, NULL, 16);
    }
    out[o] = '\0';
}

/* strings.Trim(decodeString(v), "\"") */
static void decode_trim(const char *v, char *out, size_t len)
{
    char tmp[4096];
    decode_string(v, tmp, sizeof(tmp));
    const char *s = tmp;
    size_t n = strlen(s);
    while (n > 0 && s[0] == '"') {
        s++;
        n--;
    }
    while (n > 0 && s[n - 1] == '"')
        n--;
    snprintf(out, len, "%.*s", (int)n, s);
}

/* strconv.Atoi, 0 on errors */
static int atoi_go(const char *s)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || errno != 0 || v > 2147483647L || v < -2147483648L)
        return 0;
    return (int)v;
}

struct field {
    char key[64];
    char value[4096];
};

/* extractFields: every key=value of the line; the last of a key wins */
static size_t extract_fields(const char *line, struct field *f, size_t max)
{
    if (audit_re == NULL) {
        char err[128];
        audit_re = ks_regex_compile_flags(
            "([a-zA-Z0-9\\-_]+)=([a-zA-Z0-9:'\\-\\/\\\"\\.\\,_\\(\\)]+)", KS_REGEX_CAPTURE, err,
            sizeof(err));
        if (audit_re == NULL)
            return 0;
    }
    size_t n = 0, len = strlen(line), pos = 0;
    long off[6];
    while (pos < len && ks_regex_find_submatch(audit_re, line + pos, len - pos, off, 3) == 3) {
        const char *k = line + pos + off[2], *v = line + pos + off[4];
        size_t kl = (size_t)(off[3] - off[2]), vl = (size_t)(off[5] - off[4]);
        size_t i;
        for (i = 0; i < n; i++)
            if (strlen(f[i].key) == kl && strncmp(f[i].key, k, kl) == 0)
                break;
        if (i == n && n < max)
            n++;
        if (i < max) {
            snprintf(f[i].key, sizeof(f[i].key), "%.*s", (int)kl, k);
            snprintf(f[i].value, sizeof(f[i].value), "%.*s", (int)vl, v);
        }
        pos += (size_t)off[1] > 0 ? (size_t)off[1] : 1;
    }
    return n;
}

/* populateEvent: NULL for a local socket (fam=local) */
static struct ks_audit_event *populate(struct ks_audit_event *ev, const struct field *f, size_t n)
{
    if (ev == NULL)
        return NULL;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(f[i].key, "fam") == 0 && strcmp(f[i].value, "local") == 0)
            return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        const char *k = f[i].key, *v = f[i].value;
        if (strcmp(k, "fam") == 0)
            snprintf(ev->net_family, sizeof(ev->net_family), "%s", v);
        else if (strcmp(k, "lport") == 0)
            ev->dst_port = atoi_go(v);
        else if (strcmp(k, "exe") == 0)
            decode_trim(v, ev->proc_path, sizeof(ev->proc_path));
        else if (strcmp(k, "comm") == 0)
            decode_trim(v, ev->proc_name, sizeof(ev->proc_name));
        else if (strcmp(k, "tty") == 0)
            snprintf(ev->tty, sizeof(ev->tty), "%s", v);
        else if (strcmp(k, "pid") == 0)
            ev->pid = atoi_go(v);
        else if (strcmp(k, "ppid") == 0)
            ev->ppid = atoi_go(v);
        else if (strcmp(k, "uid") == 0)
            ev->uid = atoi_go(v);
        else if (strcmp(k, "gid") == 0)
            ev->gid = atoi_go(v);
        else if (strcmp(k, "success") == 0)
            snprintf(ev->success, sizeof(ev->success), "%s", v);
        else if (strcmp(k, "cwd") == 0)
            decode_trim(v, ev->proc_dir, sizeof(ev->proc_dir));
        else if (strcmp(k, "inode") == 0)
            ev->inode = atoi_go(v);
        else if (strcmp(k, "dev") == 0)
            snprintf(ev->dev, sizeof(ev->dev), "%s", v);
        else if (strcmp(k, "mode") == 0)
            snprintf(ev->mode, sizeof(ev->mode), "%s", v);
        else if (strcmp(k, "ouid") == 0)
            ev->ouid = atoi_go(v);
        else if (strcmp(k, "ogid") == 0)
            ev->ogid = atoi_go(v);
        else if (strcmp(k, "syscall") == 0)
            ev->syscall = atoi_go(v);
        else if (strcmp(k, "exit") == 0)
            ev->exit = atoi_go(v);
        else if (strcmp(k, "type") == 0)
            snprintf(ev->event_type, sizeof(ev->event_type), "%s", v);
        else if (strcmp(k, "msg") == 0 && strlen(v) > 6) {
            /* audit(1234567890.123:456): -> timestamp and serial */
            const char *p = v + 6, *colon = strchr(p, ':');
            if (colon != NULL) {
                snprintf(ev->timestamp, sizeof(ev->timestamp), "%.*s", (int)(colon - p), p);
                const char *s = colon + 1, *e = strchr(s, ':');
                size_t sl = e != NULL ? (size_t)(e - s) : strlen(s);
                if (sl > 0)
                    snprintf(ev->serial, sizeof(ev->serial), "%.*s", (int)(sl - 1), s);
            }
        }
    }
    return ev;
}

void ks_audit_parse_line(const char *line)
{
    if (!new_event && strstr(line, RULES_KEY) == NULL)
        return;
    static struct field f[128];
    bool syscall = strstr(line, SYS_SOCKET_STR) != NULL || strstr(line, SYS_CONNECT_STR) != NULL ||
                   strstr(line, SYS_SOCKETPAIR_STR) != NULL ||
                   strstr(line, SYS_EXECVE_STR) != NULL ||
                   strstr(line, SYS_SOCKETCALL_STR) != NULL;
    if (syscall) {
        size_t n = extract_fields(line, f, 128);
        new_event = true;
        struct ks_audit_event *ev = calloc(1, sizeof(*ev));
        net_event = populate(ev, f, n);
        if (net_event == NULL)
            free(ev);
        add_event(net_event);
        return;
    }
    if (!new_event)
        return;
    if (strstr(line, "type=PROCTITLE") || strstr(line, "type=CWD") ||
        strstr(line, "type=EXECVE") || strstr(line, "type=PATH") ||
        strstr(line, "type=SOCKADDR")) {
        size_t n = extract_fields(line, f, 128);
        net_event = populate(net_event, f, n);
        add_event(net_event);
    } else if (strstr(line, "type=EOE")) {
        new_event = false;
        add_event(net_event);
    }
}

/* ---- client.go --------------------------------------------------------- */

/* core.Exec("auditctl", args): 0 if it ran and exited with 0 */
static int run_auditctl(char *const *args)
{
    char *argv[16];
    size_t n = 0;
    argv[n++] = auditctl;
    for (size_t i = 0; args[i] != NULL && n < 15; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    pid_t pid;
    int r = posix_spawnp(&pid, auditctl, &fa, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (r != 0) {
        errno = r;
        return -1;
    }
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

static void add_rules(void)
{
    char ppid[32], pid[32];
    snprintf(ppid, sizeof(ppid), "ppid!=%d", (int)getpid());
    snprintf(pid, sizeof(pid), "pid!=%d", (int)getpid());
    char *r64[] = {"-A", "exit,always", "-F", "arch=b64", "-F", ppid, "-F", pid,
                   "-S", "socket,connect", "-k", "opensnitch", NULL};
    char *r32[] = {"-A", "exit,always", "-F", "arch=b32", "-F", ppid, "-F", pid,
                   "-S", "socketcall", "-F", "a0=1", "-k", "opensnitch", NULL};
    int e64 = run_auditctl(r64), e32 = run_auditctl(r32);
    if (e64 < 0 || e32 < 0)
        ks_error("Error adding audit rule, err32=%s, err=%s", e32 < 0 ? "error" : "<nil>",
                 e64 < 0 ? "error" : "<nil>");
}

static void delete_rules(void)
{
    char *r[] = {"-D", "-k", "opensnitch", NULL};
    int e64 = run_auditctl(r), e32 = run_auditctl(r);
    if (e64 < 0 || e32 < 0)
        ks_error("Error deleting audit rules, err32=%s, err64=%s", e32 < 0 ? "error" : "<nil>",
                 e64 < 0 ? "error" : "<nil>");
}

static void on_read(int fd, uint32_t events_mask, void *data);

/* connect(): the rules, then the socket */
static int do_connect(char *err, size_t errlen)
{
    add_rules();
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", apath);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errlen, "dial unix %s: %s", apath, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (ks_evloop_add_fd(aloop, fd, EPOLLIN, on_read, NULL) < 0) {
        snprintf(err, errlen, "out of memory");
        close(fd);
        return -1;
    }
    afd = fd;
    abuf_len = 0;
    return 0;
}

static void close_conn(void)
{
    if (afd >= 0) {
        ks_evloop_del_fd(aloop, afd);
        close(afd);
        afd = -1;
    }
}

/* reconnect(): every 30 s until it works */
static void on_reconnect(void *data)
{
    (void)data;
    char err[256];
    if (do_connect(err, sizeof(err)) == 0) {
        ks_evloop_cancel_timer(aloop, reconnect_timer);
        reconnect_timer = NULL;
        ks_important("Auditd reconnected, continue reading");
    } else {
        delete_rules();
    }
}

static void lost(const char *why)
{
    ks_error("AuditReader: auditd stopped, reconnecting in 30s %s", why);
    close_conn();
    delete_rules();
    if (reconnect_timer == NULL)
        reconnect_timer =
            ks_evloop_add_timer(aloop, RECONNECT_WAIT, RECONNECT_WAIT, on_reconnect, NULL);
}

static void on_read(int fd, uint32_t events_mask, void *data)
{
    (void)events_mask;
    (void)data;
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return;
    if (n <= 0) {
        lost(n == 0 ? "EOF" : strerror(errno));
        return;
    }
    char *nb = realloc(abuf, abuf_len + (size_t)n + 1);
    if (nb == NULL)
        return;
    abuf = nb;
    memcpy(abuf + abuf_len, buf, (size_t)n);
    abuf_len += (size_t)n;
    abuf[abuf_len] = '\0';
    char *start = abuf, *nl;
    while ((nl = memchr(start, '\n', abuf_len - (size_t)(start - abuf))) != NULL) {
        *nl = '\0';
        if (nl > start && nl[-1] == '\r')
            nl[-1] = '\0';
        ks_audit_parse_line(start);
        start = nl + 1;
    }
    abuf_len -= (size_t)(start - abuf);
    memmove(abuf, start, abuf_len);
    if (abuf_len > LINE_MAX_LEN) /* a line that never ends */
        abuf_len = 0;
}

static void on_clean(void *data)
{
    (void)data;
    ks_audit_clean_old_events();
}

int ks_audit_start(struct ks_evloop *loop, const char *socket_path, char *err, size_t errlen)
{
    ks_debug("[audit] config loaded: {%s}", socket_path != NULL ? socket_path : "");
    aloop = loop;
    snprintf(apath, sizeof(apath), "%s", socket_path != NULL ? socket_path : "");
    if (do_connect(err, errlen) < 0) {
        ks_error("auditd Start() connection error %s", err);
        delete_rules();
        aloop = NULL;
        return -1;
    }
    cleaner = ks_evloop_add_timer(loop, CLEANER_INTERVAL, CLEANER_INTERVAL, on_clean, NULL);
    return 0;
}

void ks_audit_stop(void)
{
    if (aloop == NULL)
        return;
    close_conn();
    if (cleaner != NULL)
        ks_evloop_cancel_timer(aloop, cleaner);
    if (reconnect_timer != NULL)
        ks_evloop_cancel_timer(aloop, reconnect_timer);
    cleaner = reconnect_timer = NULL;
    delete_rules();
    free(abuf);
    abuf = NULL;
    abuf_len = 0;
    aloop = NULL;
}

bool ks_audit_running(void)
{
    return aloop != NULL;
}
