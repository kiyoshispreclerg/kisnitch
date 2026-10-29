/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/firewall/iptables/{iptables,rules,system,
 * monitor}.go and the rules checker of daemon/firewall/common/common.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/iptables.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/fw/nft.h"
#include "daemon/fw/sysfw.h"
#include "daemon/sockdiag.h"

extern char **environ;

#define MAX_ARGS 64
#define OUT_MAX (1024 * 1024)

/* SystemRule: a chain we added, by "<table>-opensnitch-filter-<hook>". */
struct sys_chain {
    char *key;
    char *table;
    char *chain;
};

struct ks_ipt {
    struct ks_evloop *loop;
    char bin[64], bin6[64];
    bool ipv6; /* core.IPv6Enabled */
    struct sys_chain *chains;
    size_t nchains;
    bool bypass_queue;
    uint16_t queue_num;
    int64_t check_interval;
    bool running;
    struct ks_timer *checker;
    struct ks_sysfw_conf conf;
    bool conf_ready;
    struct ks_fw_errors errors;
};

/* ---- core.Exec --------------------------------------------------------- */

/* Runs argv (looked up in PATH) and collects its combined output, trimmed
 * (core.Trim) if `out` isn't NULL. 0 if it exited with status 0. */
static int exec_cmd(char *const argv[], char **out)
{
    int pfd[2];
    if (pipe(pfd) < 0)
        return -1;
    fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);
    posix_spawnattr_init(&attr);
    /* the daemon blocks its signals for signalfd; the child shouldn't */
    sigset_t empty;
    sigemptyset(&empty);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDERR_FILENO);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    pid_t pid;
    int err = posix_spawnp(&pid, argv[0], &fa, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    close(pfd[1]);
    if (err != 0) {
        close(pfd[0]);
        errno = err;
        return -1;
    }
    char *buf = NULL;
    size_t len = 0, cap = 0;
    for (;;) {
        if (len + 4096 + 1 > cap && cap < OUT_MAX) {
            size_t ncap = cap ? cap * 2 : 8192;
            char *nb = realloc(buf, ncap);
            if (nb == NULL)
                break;
            buf = nb;
            cap = ncap;
        }
        char sink[4096];
        bool keep = buf != NULL && len + 4096 + 1 <= cap;
        ssize_t n = read(pfd[0], keep ? buf + len : sink, 4096);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (keep)
            len += (size_t)n;
    }
    close(pfd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (out != NULL && ok) {
        if (buf == NULL)
            buf = calloc(1, 1);
        else
            buf[len] = '\0';
        /* strings.Trim(s, "\r\n\t ") */
        if (buf != NULL) {
            size_t s = 0;
            while (buf[s] == '\r' || buf[s] == '\n' || buf[s] == '\t' || buf[s] == ' ')
                s++;
            size_t e = strlen(buf);
            while (e > s && (buf[e - 1] == '\r' || buf[e - 1] == '\n' || buf[e - 1] == '\t' ||
                             buf[e - 1] == ' '))
                e--;
            memmove(buf, buf + s, e - s);
            buf[e - s] = '\0';
        }
        *out = buf;
        buf = NULL;
    }
    free(buf);
    if (!ok) {
        errno = ECHILD;
        return -1;
    }
    return 0;
}

static int exec_args(const char *bin, const char *const *args, size_t nargs, char **out)
{
    char *argv[MAX_ARGS + 2];
    if (nargs > MAX_ARGS)
        return -1;
    argv[0] = (char *)bin;
    for (size_t i = 0; i < nargs; i++)
        argv[i + 1] = (char *)args[i];
    argv[nargs + 1] = NULL;
    return exec_cmd(argv, out);
}

bool ks_ipt_is_available(void)
{
    const char *args[] = {"-V"};
    return exec_args("iptables", args, 1, NULL) == 0;
}

/* ---- rules.go ------------------------------------------------------------ */

static void join_args(const char *action, const char *const *rule, size_t n, char *buf,
                      size_t len)
{
    size_t off = (size_t)snprintf(buf, len, "[%s", action);
    for (size_t i = 0; i < n && off < len; i++)
        off += (size_t)snprintf(buf + off, len - off, " %s", rule[i]);
    if (off < len)
        snprintf(buf + off, len - off, "]");
}

/* RunRule: `action` (or -D if !enable) on iptables and ip6tables. Returns
 * 0 if both worked; err4 and err6 tell which failed. */
static int run_rule(struct ks_ipt *ipt, const char *action, bool enable, bool log_error,
                    const char *const *rule, size_t n, bool *err4, bool *err6)
{
    const char *args[MAX_ARGS];
    if (n + 1 > MAX_ARGS)
        return -1;
    if (!enable)
        action = "-D";
    /* a trailing "" (QueueBypass off) makes iptables fail: drop it */
    if (n > 0 && rule[n - 1][0] == '\0')
        n--;
    args[0] = action;
    for (size_t i = 0; i < n; i++)
        args[i + 1] = rule[i];
    bool e4 = exec_args(ipt->bin, args, n + 1, NULL) < 0, e6 = false;
    char shown[1024];
    if (e4 && log_error) {
        join_args(action, rule, n, shown, sizeof(shown));
        ks_error("Error while running firewall rule, ipv4 err: exit status");
        ks_error("rule: %s", shown);
    }
    /* On some systems IPv6 is disabled */
    if (ipt->ipv6) {
        e6 = exec_args(ipt->bin6, args, n + 1, NULL) < 0;
        if (e6 && log_error) {
            join_args(action, rule, n, shown, sizeof(shown));
            ks_error("Error while running firewall rule, ipv6 err: exit status");
            ks_error("rule: %s", shown);
        }
    }
    if (err4 != NULL)
        *err4 = e4;
    if (err6 != NULL)
        *err6 = e6;
    return e4 || e6 ? -1 : 0;
}

#define RUN(ipt, action, enable, log, ...)                                              \
    do {                                                                                 \
        const char *a_[] = {__VA_ARGS__};                                                \
        run_rule(ipt, action, enable, log, a_, sizeof(a_) / sizeof(a_[0]), NULL, NULL);  \
    } while (0)

/* QueueDNSResponses */
static int queue_dns_responses(struct ks_ipt *ipt, bool enable, bool log_error)
{
    char num[8];
    snprintf(num, sizeof(num), "%u", ipt->queue_num);
    const char *rule[] = {"INPUT", "--protocol", "udp", "--sport", "53", "-j", "NFQUEUE",
                          "--queue-num", num, ipt->bypass_queue ? "--queue-bypass" : ""};
    return run_rule(ipt, "-I", enable, log_error, rule, sizeof(rule) / sizeof(rule[0]), NULL,
                    NULL);
}

/* QueueConnections */
static int queue_connections(struct ks_ipt *ipt, bool enable, bool log_error)
{
    char num[8];
    snprintf(num, sizeof(num), "%u", ipt->queue_num);
    const char *rule[] = {"OUTPUT",      "-t", "mangle",  "-m",  "conntrack", "--ctstate",
                          "NEW,RELATED", "-j", "NFQUEUE", "--queue-num", num,
                          ipt->bypass_queue ? "--queue-bypass" : ""};
    int ret = run_rule(ipt, "-A", enable, log_error, rule, sizeof(rule) / sizeof(rule[0]), NULL,
                       NULL);
    /* flush conntrack so that established connections go to the queue */
    if (enable)
        ks_conntrack_flush_table();
    return ret;
}

/* ---- system.go ----------------------------------------------------------- */

static struct sys_chain *find_chain(struct ks_ipt *ipt, const char *key)
{
    for (size_t i = 0; i < ipt->nchains; i++)
        if (strcmp(ipt->chains[i].key, key) == 0)
            return &ipt->chains[i];
    return NULL;
}

static void del_chain_entry(struct ks_ipt *ipt, const char *key)
{
    for (size_t i = 0; i < ipt->nchains; i++) {
        if (strcmp(ipt->chains[i].key, key) == 0) {
            free(ipt->chains[i].key);
            free(ipt->chains[i].table);
            free(ipt->chains[i].chain);
            ipt->chains[i] = ipt->chains[--ipt->nchains];
            return;
        }
    }
}

static const char *or_filter(const char *table)
{
    return table != NULL && table[0] != '\0' ? table : "filter";
}

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

/* CreateSystemRule */
static bool create_system_rule(struct ks_ipt *ipt, const struct ks_fw_rule *rule,
                               const char *table_, const char *chain, const char *hook)
{
    if (rule == NULL)
        return false;
    const char *table = or_filter(table_);
    if (hook == NULL || hook[0] == '\0')
        hook = nz(rule->chain);
    char name[512], key[1024];
    snprintf(name, sizeof(name), "%s-%s", KS_IPT_SYSTEM_RULE_PREFIX, hook);
    snprintf(key, sizeof(key), "%s-%s", table, name);
    if (find_chain(ipt, key) != NULL)
        return false;
    RUN(ipt, "-N", true, true, name, "-t", table);
    /* the jump at the top of the hook */
    const char *jump[] = {hook, "-t", table, "-j", name};
    if (run_rule(ipt, "-I", true, true, jump, 5, NULL, NULL) == 0) {
        struct sys_chain *v = realloc(ipt->chains, (ipt->nchains + 1) * sizeof(*v));
        if (v != NULL) {
            ipt->chains = v;
            struct sys_chain *c = &v[ipt->nchains];
            c->key = strdup(key);
            c->table = strdup(table);
            c->chain = strdup(nz(chain));
            if (c->key && c->table && c->chain) {
                ipt->nchains++;
            } else {
                free(c->key);
                free(c->table);
                free(c->chain);
            }
        }
    }
    return true;
}

/* Appends the space-separated words of `s` (strings.Split(s, " ")). */
static size_t split_words(char *s, const char **args, size_t n, size_t max)
{
    char *p = s;
    for (;;) {
        char *sp = strchr(p, ' ');
        if (n < max)
            args[n++] = p;
        if (sp == NULL)
            break;
        *sp = '\0';
        p = sp + 1;
    }
    return n;
}

/* AddSystemRule: always appended, whatever its Enabled says (upstream). */
static void add_system_rule(struct ks_ipt *ipt, const struct ks_fw_rule *rule,
                            const char *table_, const char *chain)
{
    if (rule == NULL)
        return;
    const char *table = or_filter(table_);
    char name[512];
    snprintf(name, sizeof(name), "%s-%s", KS_IPT_SYSTEM_RULE_PREFIX, nz(chain));
    char *parms = strdup(nz(rule->parameters));
    char *tparms = strdup(nz(rule->target_parameters));
    if (parms == NULL || tparms == NULL) {
        free(parms);
        free(tparms);
        return;
    }
    const char *args[MAX_ARGS];
    size_t n = 0;
    args[n++] = name;
    args[n++] = "-t";
    args[n++] = table;
    if (parms[0] != '\0')
        n = split_words(parms, args, n, MAX_ARGS - 4);
    args[n++] = "-j";
    args[n++] = nz(rule->target);
    if (tparms[0] != '\0')
        n = split_words(tparms, args, n, MAX_ARGS - 1);
    run_rule(ipt, "-A", true, true, args, n, NULL, NULL);
    free(parms);
    free(tparms);
}

/* ConfigureChainPolicy */
static void configure_chain_policy(struct ks_ipt *ipt, const char *table, const char *hook,
                                   const char *policy)
{
    char up[64];
    size_t i;
    for (i = 0; i + 1 < sizeof(up) && policy[i]; i++)
        up[i] = policy[i] >= 'a' && policy[i] <= 'z' ? (char)(policy[i] - 'a' + 'A')
                                                     : policy[i];
    up[i] = '\0';
    RUN(ipt, "-P", true, true, hook, up, "-t", table);
}

/* AddSystemRules */
static void add_system_rules(struct ks_ipt *ipt)
{
    const struct ks_sysfw *cfg = &ipt->conf.cfg;
    /* Version 0 has no Enabled field, so it'd be always false */
    if (!cfg->enabled && cfg->version > 0)
        return;
    for (size_t i = 0; i < cfg->system_rules.len; i++) {
        const struct ks_fw_chains_list *l = KS_SYSFW_RULES(cfg, i);
        if (l->rule != NULL) {
            create_system_rule(ipt, l->rule, l->rule->table, l->rule->chain, l->rule->chain);
            add_system_rule(ipt, l->rule, l->rule->table, l->rule->chain);
            continue;
        }
        for (size_t j = 0; j < l->chains.len; j++) {
            const struct ks_fw_chain *ch = KS_SYSFW_CHAIN(l, j);
            if (ch->hook[0] != '\0' && ch->type[0] != '\0')
                configure_chain_policy(ipt, ch->type, ch->hook, ch->policy);
        }
    }
}

/* Flush, unhook and delete one of our chains. */
static void del_system_chain(struct ks_ipt *ipt, const char *chain, const char *table,
                             const char *hook, bool log_errors)
{
    RUN(ipt, "-F", true, false, chain, "-t", table);
    RUN(ipt, "-D", false, log_errors, hook, "-t", table, "-j", chain);
    RUN(ipt, "-X", true, false, chain, "-t", table);
}

/* DeleteSystemRules: only the entries with a legacy Rule are visited. */
static void delete_system_rules(struct ks_ipt *ipt, bool force, bool log_errors)
{
    struct ks_sysfw *cfg = &ipt->conf.cfg;
    for (size_t i = 0; i < cfg->system_rules.len; i++) {
        struct ks_fw_chains_list *l = KS_SYSFW_RULES(cfg, i);
        if (l->rule == NULL)
            continue;
        char chain[512], key[1024];
        snprintf(chain, sizeof(chain), "%s-%s", KS_IPT_SYSTEM_RULE_PREFIX, nz(l->rule->chain));
        snprintf(key, sizeof(key), "%s-%s", nz(l->rule->table), chain);
        if (find_chain(ipt, key) == NULL && !force)
            continue;
        del_system_chain(ipt, chain, nz(l->rule->table), nz(l->rule->chain), log_errors);
        del_chain_entry(ipt, key);

        for (size_t j = 0; j < l->chains.len; j++) {
            struct ks_fw_chain *ch = KS_SYSFW_CHAIN(l, j);
            if (ch->table == NULL || ch->table[0] == '\0') {
                char *f = strdup("filter");
                if (f != NULL) {
                    free(ch->table);
                    ch->table = f;
                }
            }
            snprintf(chain, sizeof(chain), "%s-%s", KS_IPT_SYSTEM_RULE_PREFIX, nz(ch->hook));
            snprintf(key, sizeof(key), "%s-%s", nz(ch->type), chain);
            if (find_chain(ipt, key) == NULL && !force)
                continue;
            del_system_chain(ipt, chain, nz(ch->type), nz(ch->hook), log_errors);
            del_chain_entry(ipt, key);
        }
    }
}

/* ---- iptables.go ----------------------------------------------------- */

static void stop_checking_rules(struct ks_ipt *ipt)
{
    if (ipt->checker != NULL) {
        ks_evloop_cancel_timer(ipt->loop, ipt->checker);
        ipt->checker = NULL;
        ks_info("exit checking firewall rules");
    }
}

static void reload_rules_callback(void *data);

static void check_rules(void *data)
{
    struct ks_ipt *ipt = data;
    if (!ks_ipt_are_rules_loaded(ipt))
        reload_rules_callback(ipt);
}

/* NewRulesChecker */
static void new_rules_checker(struct ks_ipt *ipt)
{
    char ival[KS_DURATION_STRLEN];
    ks_format_duration(ipt->check_interval, ival, sizeof(ival));
    if (strcmp(ival, "0s") == 0) {
        ks_info("Fw rules checker disabled ...");
        return;
    }
    stop_checking_rules(ipt);
    if (ipt->loop == NULL)
        return;
    ks_info("Starting new fw checker every %s ...", ival);
    ipt->checker = ks_evloop_add_timer(ipt->loop, ipt->check_interval, ipt->check_interval,
                                       check_rules, ipt);
}

void ks_ipt_enable_interception(struct ks_ipt *ipt)
{
    if (queue_connections(ipt, true, true) < 0) {
        /* upstream exits here (log.Fatal) */
        ks_error("Error while running conntrack firewall rule");
    } else if (queue_dns_responses(ipt, true, true) < 0) {
        ks_error("Error while running DNS firewall rule");
    }
    new_rules_checker(ipt);
}

void ks_ipt_disable_interception(struct ks_ipt *ipt, bool log_errors)
{
    stop_checking_rules(ipt);
    queue_dns_responses(ipt, false, log_errors);
    queue_connections(ipt, false, log_errors);
}

void ks_ipt_clean_rules(struct ks_ipt *ipt, bool log_errors)
{
    ks_ipt_disable_interception(ipt, log_errors);
    delete_system_rules(ipt, true, log_errors);
}

/* regexRulesQuery `NFQUEUE.*ctstate NEW,RELATED.*NFQUEUE num.*` on one
 * line */
static bool has_queue_rule(const char *out)
{
    for (const char *line = out; line != NULL && *line;) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);
        char buf[1024];
        if (len >= sizeof(buf))
            len = sizeof(buf) - 1;
        memcpy(buf, line, len);
        buf[len] = '\0';
        const char *a = strstr(buf, "NFQUEUE");
        const char *b = a ? strstr(a + 7, "ctstate NEW,RELATED") : NULL;
        if (b != NULL && strstr(b + 19, "NFQUEUE num") != NULL)
            return true;
        line = eol ? eol + 1 : NULL;
    }
    return false;
}

bool ks_ipt_are_rules_loaded(struct ks_ipt *ipt)
{
    char *out4 = NULL, *out6 = NULL;
    const char *args[] = {"-n", "-L", "OUTPUT", "-t", "mangle"};
    if (exec_args("iptables", args, 5, &out4) < 0)
        return false;
    if (ipt->ipv6 && exec_args("ip6tables", args, 5, &out6) < 0) {
        free(out4);
        return false;
    }
    bool system_loaded = true;
    for (size_t i = 0; i < ipt->nchains && system_loaded; i++) {
        const struct sys_chain *c = &ipt->chains[i];
        const char *la[] = {"-n", "-L", c->chain, "-t", c->table};
        char *o = NULL;
        if (exec_args("iptables", la, 5, &o) == 0 &&
            strstr(o, KS_IPT_SYSTEM_RULE_PREFIX) == NULL)
            system_loaded = false;
        free(o);
        o = NULL;
        if (system_loaded && ipt->ipv6 && exec_args("ip6tables", la, 5, &o) == 0 &&
            strstr(o, KS_IPT_SYSTEM_RULE_PREFIX) == NULL)
            system_loaded = false;
        free(o);
    }
    bool result = has_queue_rule(out4) && system_loaded;
    if (ipt->ipv6)
        result = result && has_queue_rule(out6);
    free(out4);
    free(out6);
    return result;
}

/* reloadRulesCallback: the rules are missing, or the configuration
 * changed. */
static void reload_rules_callback(void *data)
{
    struct ks_ipt *ipt = data;
    ks_important("firewall rules changed, reloading");
    ks_ipt_clean_rules(ipt, false);
    add_system_rules(ipt);
    ks_ipt_enable_interception(ipt);
}

/* preloadConfCallback */
static void preload_conf_callback(void *data)
{
    struct ks_ipt *ipt = data;
    ks_info("iptables config changed, reloading");
    delete_system_rules(ipt, true, ks_log_get_level() == KS_LOG_DEBUG);
}

struct ks_ipt *ks_ipt_new(struct ks_evloop *loop)
{
    struct ks_ipt *ipt = calloc(1, sizeof(*ipt));
    if (ipt == NULL)
        return NULL;
    ipt->loop = loop;
    snprintf(ipt->bin, sizeof(ipt->bin), "iptables");
    snprintf(ipt->bin6, sizeof(ipt->bin6), "ip6tables");
    struct stat st;
    ipt->ipv6 = stat("/proc/sys/net/ipv6", &st) == 0;
    return ipt;
}

void ks_ipt_set_binaries(struct ks_ipt *ipt, const char *bin, const char *bin6)
{
    snprintf(ipt->bin, sizeof(ipt->bin), "%s", bin);
    snprintf(ipt->bin6, sizeof(ipt->bin6), "%s", bin6);
}

void ks_ipt_free(struct ks_ipt *ipt)
{
    if (ipt == NULL)
        return;
    stop_checking_rules(ipt);
    for (size_t i = 0; i < ipt->nchains; i++) {
        free(ipt->chains[i].key);
        free(ipt->chains[i].table);
        free(ipt->chains[i].chain);
    }
    free(ipt->chains);
    if (ipt->conf_ready)
        ks_sysfw_conf_destroy(&ipt->conf);
    ks_fw_errors_clear(&ipt->errors);
    free(ipt);
}

static void set_interval(struct ks_ipt *ipt, const char *interval)
{
    char err[256];
    int64_t ns;
    if (ks_parse_duration(interval, &ns, err, sizeof(err)) < 0) {
        char def[KS_DURATION_STRLEN];
        ks_format_duration(KS_FW_DEFAULT_CHECK_INTERVAL_NS, def, sizeof(def));
        ks_warning("Invalid rules checker interval (falling back to %s): %s", def, err);
        ns = KS_FW_DEFAULT_CHECK_INTERVAL_NS;
    } else if (ns < 0) {
        ks_warning("Invalid rules checker interval (%s), disabling the checker", interval);
        ns = 0;
    }
    ipt->check_interval = ns;
}

void ks_ipt_init(struct ks_ipt *ipt, uint16_t queue_num, const char *config_path,
                 const char *monitor_interval, bool bypass_queue)
{
    if (ipt->running)
        return;
    ipt->bypass_queue = bypass_queue;
    ipt->queue_num = queue_num;
    set_interval(ipt, monitor_interval);
    ks_fw_errors_clear(&ipt->errors);

    /* the configuration first, to know which rules to clean up */
    if (ipt->conf_ready)
        ks_sysfw_conf_destroy(&ipt->conf);
    ipt->conf_ready = ks_sysfw_conf_init(&ipt->conf, ipt->loop, config_path,
                                         preload_conf_callback, reload_rules_callback,
                                         ipt) == 0;
    if (ipt->conf_ready)
        ks_sysfw_conf_load(&ipt->conf, false);

    /* start from a clean state */
    ks_ipt_clean_rules(ipt, false);
    ks_ipt_enable_interception(ipt);
    add_system_rules(ipt);
    ipt->running = true;
}

void ks_ipt_stop(struct ks_ipt *ipt)
{
    ks_fw_errors_clear(&ipt->errors);
    if (!ipt->running)
        return;
    /* StopConfigWatcher: keep the configuration (Serialize, cleanup) */
    if (ipt->conf_ready) {
        struct ks_sysfw keep = ipt->conf.cfg;
        memset(&ipt->conf.cfg, 0, sizeof(ipt->conf.cfg));
        char *file = strdup(ipt->conf.file);
        ks_sysfw_conf_destroy(&ipt->conf);
        ipt->conf_ready = ks_sysfw_conf_init(&ipt->conf, NULL, file, preload_conf_callback,
                                             reload_rules_callback, ipt) == 0;
        free(file);
        ipt->conf.cfg = keep;
    }
    stop_checking_rules(ipt);
    ks_ipt_clean_rules(ipt, ks_log_get_level() == KS_LOG_DEBUG);
    ipt->running = false;
}

bool ks_ipt_is_running(const struct ks_ipt *ipt)
{
    return ipt != NULL && ipt->running;
}

struct _Protocol__SysFirewall *ks_ipt_serialize(struct ks_ipt *ipt, struct ks_arena *a)
{
    return ks_sysfw_to_pb(a, &ipt->conf.cfg);
}

int ks_ipt_save_configuration(struct ks_ipt *ipt, const char *raw, size_t len)
{
    return ipt->conf_ready ? ks_sysfw_conf_save(&ipt->conf, raw, len) : -1;
}

struct ks_fw_errors *ks_ipt_errors(struct ks_ipt *ipt)
{
    return &ipt->errors;
}

const struct ks_sysfw *ks_ipt_sysfw(const struct ks_ipt *ipt)
{
    return &ipt->conf.cfg;
}
