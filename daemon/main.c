/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * kisnitchd entry point. Port of upstream daemon/main.go.
 *
 * Parses the command line, sets up logging, loads the configuration, the
 * network aliases and the rules, starts the process monitor and the
 * firewall, and answers the packets of the netfilter queue until a signal
 * arrives. The UI client arrives in phase 5.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/config.h"
#include "daemon/dns/cache.h"
#include "daemon/dns/resolved.h"
#include "daemon/evloop.h"
#include "daemon/fw/fw.h"
#include "daemon/intercept.h"
#include "daemon/procmon/procmon.h"
#include "daemon/queue.h"
#include "daemon/rules/aliases.h"
#include "daemon/rules/loader.h"
#include "daemon/sockdiag.h"

#define KS_NAME "kisnitchd"

/* Command line options. Names and defaults as upstream main.go; the ones not
 * listed here are added together with the feature they control. */
static struct {
    bool show_version;
    const char *config_file;
    const char *rules_path;
    const char *procmon_method;
    int queue_num;
    const char *fw_config_file;
    bool no_live_reload;
    const char *log_file;
    bool log_utc;
    bool log_micro;
    bool debug, warning, important, errorlog;
} opt = {
    .config_file = KS_CONFIG_DEFAULT_FILE,
    .rules_path = "",
    .procmon_method = "",
    .fw_config_file = "",
    .log_file = "",
    .log_utc = true,
};

enum flag_kind { FLAG_BOOL, FLAG_STRING, FLAG_INT };

static const struct flag {
    const char *name;
    enum flag_kind kind;
    void *ptr;
    const char *usage;
} flags[] = {
    {"version", FLAG_BOOL, &opt.show_version, "Show daemon version of this executable and exit."},
    {"config-file", FLAG_STRING, &opt.config_file, "Path to the daemon configuration file."},
    {"process-monitor-method", FLAG_STRING, &opt.procmon_method, "Options: audit, ebpf, proc (default)"},
    {"queue-num", FLAG_INT, &opt.queue_num, "Netfilter queue number."},
    {"rules-path", FLAG_STRING, &opt.rules_path, "Path to load JSON rules from."},
    {"fw-config-file", FLAG_STRING, &opt.fw_config_file, "Path to the system fw configuration file."},
    {"no-live-reload", FLAG_BOOL, &opt.no_live_reload, "Disable rules live reloading."},
    {"log-file", FLAG_STRING, &opt.log_file, "Write logs to this file instead of the standard output."},
    {"log-utc", FLAG_BOOL, &opt.log_utc, "Write logs output with UTC timezone (enabled by default)."},
    {"log-micro", FLAG_BOOL, &opt.log_micro, "Write logs output with microsecond timestamp (disabled by default)."},
    {"debug", FLAG_BOOL, &opt.debug, "Enable debug level logs."},
    {"warning", FLAG_BOOL, &opt.warning, "Enable warning level logs."},
    {"important", FLAG_BOOL, &opt.important, "Enable important level logs."},
    {"error", FLAG_BOOL, &opt.errorlog, "Enable error level logs."},
};
#define N_FLAGS (sizeof(flags) / sizeof(flags[0]))

static void usage(FILE *out, const char *argv0)
{
    fprintf(out, "Usage of %s:\n", argv0);
    for (size_t i = 0; i < N_FLAGS; i++)
        fprintf(out, "  -%s%s\n    \t%s\n", flags[i].name,
                flags[i].kind == FLAG_STRING ? " string" :
                flags[i].kind == FLAG_INT ? " int" : "", flags[i].usage);
}

/* Parses booleans the way Go's strconv.ParseBool does. */
static int parse_bool(const char *s, bool *out)
{
    static const char *const yes[] = {"1", "t", "T", "TRUE", "true", "True"};
    static const char *const no[] = {"0", "f", "F", "FALSE", "false", "False"};
    for (size_t i = 0; i < 6; i++) {
        if (strcmp(s, yes[i]) == 0) { *out = true; return 0; }
        if (strcmp(s, no[i]) == 0) { *out = false; return 0; }
    }
    return -1;
}

/* Parses integers the way Go's flag package does (strconv.ParseInt with
 * base 0, into an int). */
static int parse_int(const char *s, int *out)
{
    char *end;
    errno = 0;
    long long v = strtoll(s, &end, 0);
    if (*s == '\0' || *end != '\0' || errno != 0 || v < INT_MIN || v > INT_MAX)
        return -1;
    *out = (int)v;
    return 0;
}

/* Same syntax as Go's flag package: -name, --name, -name=value, and
 * "-name value" for non-boolean flags. Parsing stops at "--" or at the first
 * non-flag argument. Exits with status 2 on errors, like Go. */
static void parse_flags(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0')
            return;
        arg++;
        if (*arg == '-') {
            arg++;
            if (*arg == '\0')
                return; /* "--" terminates the flags */
        }

        const char *eq = strchr(arg, '=');
        size_t name_len = eq != NULL ? (size_t)(eq - arg) : strlen(arg);
        const struct flag *f = NULL;
        for (size_t j = 0; j < N_FLAGS; j++)
            if (strlen(flags[j].name) == name_len &&
                strncmp(flags[j].name, arg, name_len) == 0)
                f = &flags[j];
        if (f == NULL) {
            fprintf(stderr, "flag provided but not defined: -%.*s\n",
                    (int)name_len, arg);
            usage(stderr, argv[0]);
            exit(2);
        }

        if (f->kind == FLAG_BOOL) {
            bool v = true;
            if (eq != NULL && parse_bool(eq + 1, &v) < 0) {
                fprintf(stderr, "invalid boolean value \"%s\" for -%s\n",
                        eq + 1, f->name);
                usage(stderr, argv[0]);
                exit(2);
            }
            *(bool *)f->ptr = v;
            continue;
        }
        const char *val;
        if (eq != NULL) {
            val = eq + 1;
        } else if (i + 1 < argc) {
            val = argv[++i];
        } else {
            fprintf(stderr, "flag needs an argument: -%s\n", f->name);
            usage(stderr, argv[0]);
            exit(2);
        }
        if (f->kind == FLAG_STRING) {
            *(const char **)f->ptr = val;
        } else if (parse_int(val, (int *)f->ptr) < 0) {
            fprintf(stderr, "invalid value \"%s\" for flag -%s: parse error\n", val,
                    f->name);
            usage(stderr, argv[0]);
            exit(2);
        }
    }
}

/* main.go setupLogging(). */
static void setup_logging(void)
{
    if (opt.debug)
        ks_log_set_level(KS_LOG_DEBUG);
    else if (opt.warning)
        ks_log_set_level(KS_LOG_WARNING);
    else if (opt.important)
        ks_log_set_level(KS_LOG_IMPORTANT);
    else if (opt.errorlog)
        ks_log_set_level(KS_LOG_ERROR);
    else
        ks_log_set_level(KS_LOG_INFO);

    ks_log_set_utc(opt.log_utc);
    ks_log_set_micro(opt.log_micro);

    const char *file = opt.log_file[0] != '\0' ? opt.log_file : KS_LOG_STDOUT_FILE;
    ks_log_close();
    if (ks_log_open_file(file) < 0)
        ks_error("Error opening user defined log: %s", file);
}

/* main.go overwriteLogging(). */
static bool overwrite_logging(void)
{
    return opt.debug || opt.warning || opt.important || opt.errorlog ||
           opt.log_file[0] != '\0' || opt.log_micro;
}

/* The logging part of ui/config_utils.go reloadConfiguration(). */
static void apply_log_config(const struct ks_config *cfg)
{
    if (cfg->log_level.set)
        ks_log_set_level(cfg->log_level.value);
    ks_log_set_utc(cfg->log_utc);
    ks_log_set_micro(cfg->log_micro);
    if (cfg->server.log_file[0] != '\0') {
        ks_debug("[config] using config.server.logfile: %s", cfg->server.log_file);
        ks_log_close();
        ks_log_open_file(cfg->server.log_file);
    }
}

/* State the signal and packet handlers reach. */
static struct {
    struct ks_evloop *loop;
    struct ks_intercept intercept;
    int sigfd;
} d = {.sigfd = -1};

/* Go's names for the signals setupSignals() listens to. */
static const char *signal_name(int sig)
{
    switch (sig) {
    case SIGHUP:
        return "hangup";
    case SIGINT:
        return "interrupt";
    case SIGQUIT:
        return "quit";
    case SIGTERM:
        return "terminated";
    }
    return "signal";
}

static void on_alarm(int sig)
{
    (void)sig;
    static const char msg[] = "[REVIEW] closing due to timeout\n";
    ssize_t n = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)n;
    _exit(0);
}

/* setupSignals(): the first signal starts the shutdown, which must finish
 * within 10 seconds. */
static void on_signal(int fd, uint32_t events, void *data)
{
    (void)events;
    (void)data;
    struct signalfd_siginfo si;
    if (read(fd, &si, sizeof(si)) != (ssize_t)sizeof(si))
        return;
    ks_important("Got signal: %s", signal_name((int)si.ssi_signo));
    signal(SIGALRM, on_alarm);
    alarm(10);
    ks_evloop_del_fd(d.loop, fd);
    ks_evloop_stop(d.loop);
}

static int setup_signals(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
        return -1;
    d.sigfd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
    if (d.sigfd < 0)
        return -1;
    return ks_evloop_add_fd(d.loop, d.sigfd, EPOLLIN, on_signal, NULL);
}

/* worker() -> onPacket() */
static void on_packet(struct ks_queue *q, const struct ks_nfq_packet *p, void *data)
{
    (void)data;
    struct ks_verdict v;
    ks_intercept_packet(&d.intercept, p, &v);
    ks_queue_verdict(q, p->id, v.verdict, v.mark);
}

/* The firewall part of ui/config_utils.go reloadConfiguration() on the
 * first load, when the previous configuration is empty. */
static void start_firewall(struct ks_fw *fw, const struct ks_config *cfg)
{
    const struct ks_fw_options *o = &cfg->fw_options;
    /* GetFirewallType() of the empty configuration is "iptables". */
    bool reload_fw = strcmp(cfg->firewall, KS_FW_IPTABLES) != 0 ||
                     o->config_path[0] != '\0' || o->queue_num != 0 ||
                     o->monitor_interval[0] != '\0' || o->queue_bypass;
    if (reload_fw) {
        ks_debug("[config] reloading config.firewall");
        ks_fw_reload(fw, cfg->firewall, o->config_path, o->monitor_interval,
                     o->queue_bypass, o->queue_num);
    } else {
        ks_debug("[config] config.firewall not changed");
    }
    /* The process monitor method is always (re)loaded the first time. */
    if (cfg->internal.flush_conns_on_start) {
        ks_debug("[config] flushing established connections");
        ks_flush_connections();
    } else {
        ks_debug("[config] not flushing established connections");
    }
}

int main(int argc, char **argv)
{
    parse_flags(argc, argv);

    if (opt.show_version) {
        printf("%s\n", KS_VERSION);
        return 0;
    }

    setup_logging();
    ks_important("Starting %s v%s", KS_NAME, KS_VERSION);

    char err[1024];
    struct ks_aliases aliases = {0};
    if (ks_aliases_load(&aliases, KS_ALIASES_DEFAULT_FILE, err, sizeof(err)) < 0)
        ks_warning("Error loading network aliases: %s", err);
    ks_info("Loading network aliases from %s ...", KS_ALIASES_DEFAULT_FILE);

    if (opt.config_file[0] == '\0')
        ks_fatal("Configuration file cannot be empty");

    struct ks_config cfg;
    if (ks_config_load(opt.config_file, &cfg, err, sizeof(err)) < 0)
        ks_fatal("%s", err);
    ks_info("Loading configuration file %s ...", opt.config_file);

    if (cfg.rules.path[0] == '\0') {
        free(cfg.rules.path);
        cfg.rules.path = strdup(KS_RULES_DEFAULT_PATH);
        if (cfg.rules.path == NULL)
            ks_fatal("out of memory");
    }

    d.loop = ks_evloop_new();
    struct ks_loader *rules =
        d.loop ? ks_loader_new(d.loop, &aliases, !opt.no_live_reload) : NULL;
    struct ks_fw fw = {0};
    if (rules == NULL || ks_fw_create(&fw, d.loop) < 0) {
        ks_log(KS_LOG_FATAL, "Error creating the event loop or the rules loader");
        return 1;
    }
    if (setup_signals() < 0)
        ks_fatal("Error setting up signal handling: %s", strerror(errno));

    /* ui.NewClient() -> loadDiskConfiguration() -> reloadConfiguration() */
    apply_log_config(&cfg);
    ks_intercept_init(&d.intercept, rules);
    ks_intercept_set_default_action(&d.intercept, cfg.default_action);
    d.intercept.intercept_unknown = cfg.intercept_unknown;
    ks_info("Loading rules from %s ...", cfg.rules.path);
    ks_loader_enable_checksums(rules, cfg.rules.enable_checksums);
    if (ks_loader_reload(rules, cfg.rules.path, err, sizeof(err)) < 0)
        ks_warning("%s", err);
    ks_procmon_init(d.loop);
    start_firewall(&fw, &cfg);

    /* Default expected queue from the cli is 0. If it's greater than 0,
     * overwrite the config value. */
    uint16_t qnum = cfg.fw_options.queue_num;
    if (opt.queue_num > 0 && (uint16_t)opt.queue_num != cfg.fw_options.queue_num)
        qnum = (uint16_t)opt.queue_num;
    ks_info("Using queue number %u ...", qnum);

    /* setupQueues(). The repeat queue (qnum + 1) is only used to ask the
     * UI: phase 5. */
    struct ks_queue *queue = ks_queue_new(d.loop, qnum, on_packet, NULL, err, sizeof(err));
    if (queue == NULL) {
        ks_warning("Is opensnitchd already running?");
        ks_fw_stop(&fw);
        ks_fatal("Error creating queue #%u: %s", qnum, err);
    }
    ks_info("Listening on queue number %u ...", qnum);

    /* Command line options take precedence over the configuration file. */
    if (overwrite_logging())
        setup_logging();
    if (opt.fw_config_file[0] != '\0') {
        ks_info("Reloading fw rules from %s, queue %u ...", opt.fw_config_file, qnum);
        ks_fw_reload(&fw, cfg.firewall, opt.fw_config_file,
                     cfg.fw_options.monitor_interval, cfg.fw_options.queue_bypass, qnum);
    }
    ks_info("Using system fw configuration %s ...", opt.fw_config_file);
    if (opt.rules_path[0] != '\0') {
        ks_info("Reloading rules from %s ...", opt.rules_path);
        if (ks_loader_reload(rules, opt.rules_path, err, sizeof(err)) < 0)
            ks_fatal("Error loading rules path %s", opt.rules_path);
    }

    /* monitor.ReconfigureMonitorMethod: the command line wins. Only "proc"
     * exists so far; the others fall back to it, as upstream does when they
     * fail to start. */
    const char *method = opt.procmon_method[0] ? opt.procmon_method : cfg.proc_monitor_method;
    if (method[0] != '\0' && strcmp(method, KS_PROCMON_METHOD_PROC) != 0)
        ks_warning("error starting %s monitor method: not implemented yet", method);

    ks_debug("Configuration: DefaultAction=%s DefaultDuration=%s "
             "ProcMonitorMethod=%s Firewall=%s Server.Address=%s",
             cfg.default_action, cfg.default_duration, cfg.proc_monitor_method,
             cfg.firewall, cfg.server.address);
    size_t n = ks_loader_num_rules(rules);
    ks_info("%zu rules loaded from %s", n, ks_loader_path(rules));
    for (size_t i = 0; i < n; i++) {
        char desc[1024];
        ks_rule_describe(ks_loader_rule_at(rules, i), desc, sizeof(desc));
        ks_debug("  %s", desc);
    }

    /* The ebpf DNS listener (dns.ListenerEbpf) comes with phase 9. */
    struct ks_resolved *resolved = ks_resolved_start(d.loop, KS_RESOLVED_SOCKET);

    ks_info("Running on netfilter queue #%d ...", opt.queue_num);
    ks_evloop_run(d.loop);

    /* doCleanup(). Upstream never closes the resolved monitor here (the
     * variable it closes is shadowed in initSystemdResolvedMonitor). */
    ks_info("Cleaning up ...");
    ks_fw_stop(&fw);
    ks_procmon_end();
    ks_resolved_stop(resolved);
    ks_queue_free(queue);

    ks_fw_destroy(&fw);
    ks_dns_cache_reset();
    ks_loader_free(rules);
    if (d.sigfd >= 0)
        close(d.sigfd);
    ks_evloop_free(d.loop);
    ks_aliases_free(&aliases);
    ks_config_free(&cfg);
    ks_log_close();
    return 0;
}
