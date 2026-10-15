/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the logic of upstream ui/opensnitch/dialogs/ruleseditor.py
 * (_save_rule, _load_rule, _load_rule_operator, _comma_to_regexp,
 * _regexp_to_comma, _is_regex, _is_valid_regex, set_fields_from_connection).
 * See rulegen.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/rulegen.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <glib.h>
#include <pcre2.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "ui/slug.h"

/* ---- constants ------------------------------------------------------------ */

/* classA_net, classB_net, classC_net, others_net, multinets of the dialog */
#define CLASS_A "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
#define CLASS_B                                                                               \
    "172\\.1[6-9]\\.\\d+\\.\\d+|172\\.2[0-9]\\.\\d+\\.\\d+|172\\.3[0-1]+\\.\\d{1,3}\\.\\d{1,3}"
#define CLASS_C "192\\.168\\.\\d{1,3}\\.\\d{1,3}"
#define OTHERS "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|169\\.254\\.\\d{1,3}\\.\\d{1,3}"
#define MULTINETS "2[32][23459]\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"

const char *const KS_RULE_MULTICAST_RANGE = "^(" MULTINETS ")$";
const char *const KS_RULE_LAN_RANGES =
    "^(" OTHERS "|" CLASS_C "|" CLASS_B "|" CLASS_A "|::1|f[cde].*::.*)$";

#define OP_PROTOCOL "protocol"
#define OP_PROC_PATH "process.path"
#define OP_PROC_COMMAND "process.command"
#define OP_PROC_ID "process.id"
#define OP_MD5 "process.hash.md5"
#define OP_USER_ID "user.id"
#define OP_IFACE_OUT "iface.out"
#define OP_SRC_IP "source.ip"
#define OP_SRC_NET "source.network"
#define OP_SRC_PORT "source.port"
#define OP_DST_IP "dest.ip"
#define OP_DST_NET "dest.network"
#define OP_DST_HOST "dest.host"
#define OP_DST_PORT "dest.port"
#define OP_LIST_DOMAINS "lists.domains"
#define OP_LIST_DOMAINS_RE "lists.domains_regexp"
#define OP_LIST_IPS "lists.ips"
#define OP_LIST_NETS "lists.nets"

#define T_LIST "list"
#define T_LISTS "lists"
#define T_SIMPLE "simple"
#define T_REGEXP "regexp"
#define T_NETWORK "network"

static const char *const durations[] = {"once", "30s", "5m", "15m", "30m", "1h", "12h",
                                        "until restart", "always"};

const char *ks_rform_duration_name(int idx)
{
    return idx >= 0 && idx < 8 ? durations[idx] : "always";
}

int ks_rform_duration_index(const char *d)
{
    for (int i = 0; i < 8; i++) {
        if (strcmp(d, durations[i]) == 0)
            return i;
    }
    return 8;
}

/* ---- the form --------------------------------------------------------------- */

static struct ks_rcheck *checks(struct ks_rform *f, size_t *n)
{
    *n = 16;
    return &f->proto; /* the 16 checks are contiguous, in the order of the struct */
}

void ks_rform_set(struct ks_rcheck *c, const char *text)
{
    char *t = g_strdup(text != NULL ? text : "");
    g_free(c->text);
    c->text = t;
}

void ks_rform_set_name(struct ks_rform *f, const char *name)
{
    char *t = g_strdup(name != NULL ? name : "");
    g_free(f->name);
    f->name = t;
}

void ks_rform_set_desc(struct ks_rform *f, const char *desc)
{
    char *t = g_strdup(desc != NULL ? desc : "");
    g_free(f->desc);
    f->desc = t;
}

/* _reset_state(): the texts and checks; the checkboxes for enabled, priority, log and
 * case-sensitivity keep their state, as the widgets do upstream */
void ks_rform_reset(struct ks_rform *f)
{
    size_t n;
    struct ks_rcheck *c = checks(f, &n);
    for (size_t i = 0; i < n; i++) {
        c[i].on = false;
        ks_rform_set(&c[i], "");
    }
    f->proc_regexp = false;
    f->cmdline_regexp = false;
    ks_rform_set_name(f, "");
    ks_rform_set_desc(f, "");
    f->action = KS_RACTION_DENY;
    f->duration = 0;
}

void ks_rform_init(struct ks_rform *f)
{
    memset(f, 0, sizeof(*f));
    ks_rform_reset(f);
}

void ks_rform_free(struct ks_rform *f)
{
    g_free(f->name);
    g_free(f->desc);
    size_t n;
    struct ks_rcheck *c = checks(f, &n);
    for (size_t i = 0; i < n; i++)
        g_free(c[i].text);
    memset(f, 0, sizeof(*f));
}

/* ---- regular expressions ------------------------------------------------------ */

bool ks_rule_is_regex(const char *text)
{
    /* charset="\\*{[|^?$" */
    return strpbrk(text, "\\*{[|^?$") != NULL;
}

/* What PCRE2 takes and Python's `re` (3.11 to 3.13) refuses, or the other way: the
 * escapes Python has no meaning for (any ASCII letter not in its list is "bad escape"),
 * (?<name>...) and (?|...), (?'name'...). Quantifiers above 65535 and \N{NAME} are fine
 * for Python and not for PCRE2: those are taken as valid. Returns a copy of the pattern
 * for PCRE2 (with each \N{...} as "x"), or NULL if Python refuses it. */
static char *python_view(const char *re)
{
    GString *g = g_string_new(NULL);
    bool in_class = false;
    for (const char *p = re; *p; p++) {
        if (*p == '\\') {
            char c = p[1];
            if (c == '\0') {
                g_string_free(g, TRUE);
                return NULL; /* bad escape (end of pattern) */
            }
            if (c == 'N' && p[2] == '{') {
                const char *close = strchr(p + 3, '}');
                if (close == NULL) {
                    g_string_free(g, TRUE);
                    return NULL;
                }
                g_string_append_c(g, 'x');
                p = close;
                continue;
            }
            if (((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) &&
                strchr("abfnrtvxuUAbBdDsSwWZ", c) == NULL) {
                g_string_free(g, TRUE);
                return NULL;
            }
            g_string_append_c(g, '\\');
            g_string_append_c(g, c);
            p++;
            continue;
        }
        if (in_class) {
            if (*p == ']')
                in_class = false;
        } else if (*p == '[') {
            in_class = true;
            g_string_append_c(g, *p);
            if (p[1] == '^')
                g_string_append_c(g, *++p);
            if (p[1] == ']') /* a ']' first is a literal */
                g_string_append_c(g, *++p);
            continue;
        } else if (*p == '(' && p[1] == '?') {
            char c = p[2];
            if ((c == '<' && p[3] != '=' && p[3] != '!') || c == '|' || c == '\'') {
                g_string_free(g, TRUE);
                return NULL;
            }
            /* "global flags not at the start of the expression": an error from 3.11 on
             * (a warning before) */
            size_t k = strspn(p + 2, "aiLmsux");
            if (p != re && k > 0 && p[2 + k] == ')') {
                g_string_free(g, TRUE);
                return NULL;
            }
        }
        g_string_append_c(g, *p);
    }
    return g_string_free(g, FALSE);
}

bool ks_rule_valid_regex(const char *re, char *err, size_t errlen)
{
    char *view = python_view(re);
    if (view == NULL) {
        if (err != NULL)
            snprintf(err, errlen, "%s", "bad escape or unsupported group");
        return false;
    }
    int code;
    PCRE2_SIZE off;
    pcre2_code *p = pcre2_compile((PCRE2_SPTR)view, PCRE2_ZERO_TERMINATED, PCRE2_UTF | PCRE2_UCP,
                                  &code, &off, NULL);
    g_free(view);
    if (p == NULL) {
        if (code == PCRE2_ERROR_QUANTIFIER_TOO_BIG)
            return true; /* Python allows repeats PCRE2 doesn't */
        if (err != NULL) {
            PCRE2_UCHAR msg[160];
            pcre2_get_error_message(code, msg, sizeof(msg));
            snprintf(err, errlen, "%s at position %zu", (const char *)msg, (size_t)off);
        }
        return false;
    }
    pcre2_code_free(p);
    return true;
}

static bool py_int(const char *s)
{
    /* int(s): an optional sign and digits (underscores between digits too) */
    if (*s == '+' || *s == '-')
        s++;
    if (*s == '\0')
        return false;
    bool prev_digit = false;
    for (; *s; s++) {
        if (*s >= '0' && *s <= '9')
            prev_digit = true;
        else if (*s == '_' && prev_digit && s[1] >= '0' && s[1] <= '9')
            prev_digit = false;
        else
            return false;
    }
    return true;
}

bool ks_rule_comma_to_regexp(const char *text, bool ints, char *out, size_t outlen)
{
    /* text.replace(" ", "").split(",") */
    GString *clean = g_string_new(NULL);
    for (const char *p = text; *p; p++) {
        if (*p != ' ')
            g_string_append_c(clean, *p);
    }
    /* "".split(",") is [""] in Python, [] in GLib */
    char **parts = clean->len == 0 ? g_strsplit("x", ",", -1) : g_strsplit(clean->str, ",", -1);
    if (clean->len == 0) {
        g_free(parts[0]);
        parts[0] = g_strdup("");
    }
    g_string_free(clean, TRUE);
    GString *re = g_string_new("^(");
    bool ok = true;
    for (char **p = parts; *p != NULL && ok; p++) {
        if (ints && !py_int(*p)) {
            snprintf(out, outlen, "%s", "Invalid text");
            ok = false;
        } else if ((*p)[0] == '\0') {
            snprintf(out, outlen, "%s", "Invalid text");
            ok = false;
        } else {
            g_string_append_printf(re, "%s|", *p);
        }
    }
    g_strfreev(parts);
    if (ok) {
        g_string_truncate(re, re->len - 1); /* removesuffix("|") */
        g_string_append(re, ")$");
        if (!ks_rule_valid_regex(re->str, NULL, 0)) {
            snprintf(out, outlen, "%s", "regexp error (report it)");
            ok = false;
        } else {
            snprintf(out, outlen, "%s", re->str);
        }
    }
    g_string_free(re, TRUE);
    return ok;
}

int ks_rule_regexp_to_comma(const char *text, bool ints, char *out, size_t outlen)
{
    /* re.search(r'\^\(([\d|]+)\)\$') or r'\^\(([.\-\w|]+)\)\$' */
    const char *pat = ints ? "\\^\\(([\\d|]+)\\)\\$" : "\\^\\(([.\\-\\w|]+)\\)\\$";
    int code;
    PCRE2_SIZE off;
    pcre2_code *p = pcre2_compile((PCRE2_SPTR)pat, PCRE2_ZERO_TERMINATED, PCRE2_UTF | PCRE2_UCP,
                                  &code, &off, NULL);
    if (p == NULL)
        return 0;
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(p, NULL);
    int rc = pcre2_match(p, (PCRE2_SPTR)text, PCRE2_ZERO_TERMINATED, 0, 0, md, NULL);
    int ret = 0;
    if (rc >= 2) {
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        char *grp = g_strndup(text + ov[2], ov[3] - ov[2]);
        char **parts = g_strsplit(grp, "|", -1);
        bool ok = true;
        for (char **q = parts; *q != NULL && ok; q++) {
            if (ints && !py_int(*q)) {
                snprintf(out, outlen, "Error parsing regexp to comma: invalid literal for int() "
                                      "with base 10: '%s'", *q);
                ok = false;
            }
        }
        if (ok) {
            char *joined = g_strjoinv(",", parts);
            snprintf(out, outlen, "%s", joined);
            g_free(joined);
            ret = 1;
        } else {
            ret = -1;
        }
        g_strfreev(parts);
        g_free(grp);
    }
    pcre2_match_data_free(md);
    pcre2_code_free(p);
    return ret;
}

/* ---- _save_rule() ---------------------------------------------------------------- */

struct rd {
    const char *type, *operand;
    char *data;
    bool sensitive;
};

struct gen {
    struct ks_arena *a;
    const struct ks_rform *f;
    const struct ks_py_aliases *aliases;
    /* self.rule.operator, as the code mutates it while building */
    const char *op_type, *op_operand;
    char *op_data;
    struct rd rd[16];
    size_t n;
    char *err;
    size_t errlen;
};

static bool fail(struct gen *g, const char *msg)
{
    snprintf(g->err, g->errlen, "%s", msg);
    return false;
}

static char *dup(struct gen *g, const char *s)
{
    return ks_arena_strdup(g->a, s);
}

static struct rd *add(struct gen *g, const char *type, const char *operand, const char *data)
{
    struct rd *r = &g->rd[g->n++];
    r->type = type;
    r->operand = operand;
    r->data = dup(g, data);
    r->sensitive = g->f->sensitive;
    return r;
}

static const char *lower(struct gen *g, const char *s)
{
    char *l = g_utf8_strdown(s, -1);
    char *d = dup(g, l);
    g_free(l);
    return d;
}

/* the shape shared by protocol, interface, ports and host: a regexp if the
 * text looks like one, or a comma separated list turned into one */
static bool listish(struct gen *g, struct rd *r, const char *text, bool ints, const char *re_err,
                    bool lowercase)
{
    if (ks_rule_is_regex(text)) {
        r->type = T_REGEXP;
        if (!ks_rule_valid_regex(text, NULL, 0))
            return fail(g, re_err);
    } else if (strchr(text, ',') != NULL) {
        char res[512];
        if (ks_rule_comma_to_regexp(lowercase ? lower(g, text) : text, ints, res, sizeof(res))) {
            r->type = T_REGEXP;
            r->data = dup(g, res);
        } else {
            return fail(g, res);
        }
    }
    return true;
}

static bool is_alias(const struct ks_py_aliases *al, const char *name)
{
    for (size_t i = 0; al != NULL && i < al->len; i++) {
        if (strcmp(al->items[i].name, name) == 0)
            return true;
    }
    return false;
}

/* srcIPCheck and dstIPCheck, which are the same but for the aliases */
static bool ip_block(struct gen *g, const char *text, bool dst)
{
    const char *op_ip = dst ? OP_DST_IP : OP_SRC_IP;
    const char *op_net = dst ? OP_DST_NET : OP_SRC_NET;
    const char *re_err = dst ? "Dst IP regexp error" : "Source IP regexp error";
    char *t = dup(g, text);
    if (dst && is_alias(g->aliases, text)) {
        g->op_type = T_NETWORK;
        g->op_operand = OP_DST_NET;
        g->op_data = t;
    } else if (strcmp(t, KS_RULE_LAN_LABEL) == 0) {
        g->op_operand = op_ip;
        g->op_type = T_REGEXP;
        t = dup(g, KS_RULE_LAN_RANGES);
    } else if (strcmp(t, KS_RULE_MULTICAST_LABEL) == 0) {
        g->op_operand = op_ip;
        g->op_type = T_REGEXP;
        t = dup(g, KS_RULE_MULTICAST_RANGE);
    } else {
        if (ks_py_ip_valid(text)) {
            g->op_operand = op_ip;
            g->op_type = T_SIMPLE;
        } else {
            g->op_operand = op_net;
            g->op_type = T_NETWORK;
        }
        if (ks_rule_is_regex(t)) {
            g->op_operand = op_ip;
            g->op_type = T_REGEXP;
            if (!ks_rule_valid_regex(text, NULL, 0))
                return fail(g, re_err);
        } else if (strchr(t, ',') != NULL) {
            char res[512];
            if (!ks_rule_comma_to_regexp(t, false, res, sizeof(res)))
                return fail(g, res);
            g->op_operand = op_ip;
            g->op_type = T_REGEXP;
            t = dup(g, res);
        }
    }
    add(g, g->op_type, g->op_operand, t);
    return true;
}

static bool is_local_dir(struct gen *g, const char *text, const char *empty_msg)
{
    if (text[0] == '\0')
        return fail(g, empty_msg);
    if (g->f->node_is_local && !g->f->apply_all) {
        struct stat st;
        if (stat(text, &st) != 0 || !S_ISDIR(st.st_mode))
            return fail(g, "Lists field must be a directory");
    }
    return true;
}

static bool list_block(struct gen *g, const struct ks_rcheck *c, const char *operand)
{
    if (!is_local_dir(g, c->text, "Lists field cannot be empty"))
        return false;
    g->op_type = T_LISTS;
    g->op_operand = operand;
    add(g, T_LISTS, operand, c->text);
    g->op_data = dup(g, "");
    return true;
}

bool ks_rform_to_rule(const struct ks_rform *f, const struct ks_py_aliases *aliases,
                      struct ks_arena *a, Protocol__Rule **out, char *err, size_t errlen)
{
    struct gen g = {.a = a, .f = f, .aliases = aliases, .op_type = T_SIMPLE, .op_operand = "",
                    .err = err, .errlen = errlen};
    g.op_data = dup(&g, "");
    err[0] = '\0';
    const char *text;

    if (f->proto.on) {
        text = f->proto.text;
        if (text[0] == '\0')
            return fail(&g, "protocol can not be empty, or uncheck it");
        g.op_operand = OP_PROTOCOL;
        g.op_data = dup(&g, text);
        struct rd *r = add(&g, T_SIMPLE, OP_PROTOCOL, lower(&g, text));
        if (!listish(&g, r, text, false, "Protocol regexp error", true))
            return false;
    }
    if (f->proc.on) {
        if (f->proc.text[0] == '\0')
            return fail(&g, "process path can not be empty");
        g.op_operand = OP_PROC_PATH;
        g.op_data = dup(&g, f->proc.text);
        struct rd *r = add(&g, T_SIMPLE, OP_PROC_PATH, f->proc.text);
        if (f->proc_regexp) {
            r->type = T_REGEXP;
            if (!ks_rule_valid_regex(f->proc.text, NULL, 0))
                return fail(&g, "Process path regexp error");
        }
    }
    if (f->cmdline.on) {
        if (f->cmdline.text[0] == '\0')
            return fail(&g, "command line can not be empty");
        g.op_operand = OP_PROC_COMMAND;
        g.op_data = dup(&g, f->cmdline.text);
        struct rd *r = add(&g, T_SIMPLE, OP_PROC_COMMAND, f->cmdline.text);
        if (f->cmdline_regexp) {
            r->type = T_REGEXP;
            if (!ks_rule_valid_regex(f->cmdline.text, NULL, 0))
                return fail(&g, "Command line regexp error");
        }
    }
    if (f->iface.on) {
        if (f->iface.text[0] == '\0')
            return fail(&g, "Network interface can not be empty");
        g.op_operand = OP_IFACE_OUT;
        g.op_data = dup(&g, f->iface.text);
        struct rd *r = add(&g, T_SIMPLE, OP_IFACE_OUT, f->iface.text);
        if (!listish(&g, r, f->iface.text, false, "Network interface regexp error", false))
            return false;
    }
    if (f->srcport.on) {
        if (f->srcport.text[0] == '\0')
            return fail(&g, "Source port can not be empty");
        g.op_operand = OP_SRC_PORT;
        g.op_data = dup(&g, f->srcport.text);
        struct rd *r = add(&g, T_SIMPLE, OP_SRC_PORT, f->srcport.text);
        if (!listish(&g, r, f->srcport.text, true, "Source port regexp error", false))
            return false;
    }
    if (f->dstport.on) {
        if (f->dstport.text[0] == '\0')
            return fail(&g, "Dest port can not be empty");
        g.op_operand = OP_DST_PORT;
        g.op_data = dup(&g, f->dstport.text);
        struct rd *r = add(&g, T_SIMPLE, OP_DST_PORT, f->dstport.text);
        if (!listish(&g, r, f->dstport.text, true, "Dst port regexp error", false))
            return false;
    }
    if (f->dsthost.on) {
        if (f->dsthost.text[0] == '\0')
            return fail(&g, "Dest host can not be empty");
        g.op_operand = OP_DST_HOST;
        g.op_data = dup(&g, f->dsthost.text);
        struct rd *r = add(&g, T_SIMPLE, OP_DST_HOST, f->dsthost.text);
        if (!listish(&g, r, f->dsthost.text, false, "Dst host regexp error", false))
            return false;
    }
    if (f->srcip.on) {
        if (f->srcip.text[0] == '\0')
            return fail(&g, "Source IP/Network can not be empty");
        if (!ip_block(&g, f->srcip.text, false))
            return false;
    }
    if (f->dstip.on) {
        if (f->dstip.text[0] == '\0')
            return fail(&g, "Dest IP/Network can not be empty");
        if (!ip_block(&g, f->dstip.text, true))
            return false;
    }
    if (f->uid.on) {
        const char *uid_type = T_SIMPLE;
        char *uid = dup(&g, f->uid.text);
        if (uid[0] == '\0')
            return fail(&g, "User ID can not be empty");
        /* "user (uid)" is looked up by the name; a lone token must be a number */
        char **tok = g_strsplit(f->uid.text, " ", -1);
        bool parsed;
        if (tok[1] == NULL) {
            parsed = py_int(tok[0]);
        } else {
            struct passwd pw, *res = NULL;
            char buf[1024];
            parsed = getpwnam_r(tok[0], &pw, buf, sizeof(buf), &res) == 0 && res != NULL;
            if (parsed)
                uid = ks_arena_printf(a, "%u", (unsigned)pw.pw_uid);
        }
        g_strfreev(tok);
        if (!parsed) {
            if (ks_rule_is_regex(f->uid.text)) {
                uid_type = T_REGEXP;
                if (!ks_rule_valid_regex(f->uid.text, NULL, 0))
                    return fail(&g, "User ID regexp error");
            } else {
                return fail(&g, "Invalid UID, it must be a digit.");
            }
        }
        g.op_operand = OP_USER_ID;
        g.op_data = dup(&g, f->uid.text);
        add(&g, uid_type, OP_USER_ID, uid);
    }
    if (f->pid.on) {
        if (f->pid.text[0] == '\0')
            return fail(&g, "PID field can not be empty");
        g.op_operand = OP_PROC_ID;
        g.op_data = dup(&g, f->pid.text);
        struct rd *r = add(&g, T_SIMPLE, OP_PROC_ID, f->pid.text);
        if (ks_rule_is_regex(f->pid.text)) {
            r->type = T_REGEXP;
            if (!ks_rule_valid_regex(f->pid.text, NULL, 0))
                return fail(&g, "PID field regexp error");
        }
    }
    if (f->lists.on && !list_block(&g, &f->lists, OP_LIST_DOMAINS))
        return false;
    if (f->lists_regexp.on && !list_block(&g, &f->lists_regexp, OP_LIST_DOMAINS_RE))
        return false;
    if (f->lists_nets.on && !list_block(&g, &f->lists_nets, OP_LIST_NETS))
        return false;
    if (f->lists_ips.on && !list_block(&g, &f->lists_ips, OP_LIST_IPS))
        return false;
    if (f->md5.on) {
        if (f->md5.text[0] == '\0')
            return fail(&g, "md5 line cannot be empty");
        const char *low = lower(&g, f->md5.text);
        g.op_operand = OP_MD5;
        g.op_data = dup(&g, low);
        struct rd *r = add(&g, T_SIMPLE, OP_MD5, low);
        r->sensitive = false;
        if (ks_rule_is_regex(f->md5.text)) {
            r->type = T_REGEXP;
            /* upstream validates the PID line here, not this one */
            if (!ks_rule_valid_regex(f->pid.text, NULL, 0))
                return fail(&g, "md5 field regexp error");
        }
    }

    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    Protocol__Operator *op = ks_arena_alloc(a, sizeof(*op));
    if (r == NULL || op == NULL)
        return fail(&g, "out of memory");
    protocol__rule__init(r);
    protocol__operator__init(op);
    r->operator_ = op;
    r->created = (int64_t)time(NULL);
    r->name = dup(&g, f->name);
    r->description = dup(&g, f->desc);
    r->enabled = f->enabled;
    r->precedence = f->precedence;
    r->nolog = f->nolog;
    r->action = dup(&g, f->action == KS_RACTION_ALLOW    ? "allow"
                        : f->action == KS_RACTION_REJECT ? "reject"
                                                         : "deny");
    r->duration = dup(&g, ks_rform_duration_name(f->duration));
    op->sensitive = f->sensitive;

    if (g.n >= 2) {
        op->type = dup(&g, T_LIST);
        op->operand = dup(&g, T_LIST);
        op->data = dup(&g, "");
        Protocol__Operator **items = ks_arena_calloc(a, g.n, sizeof(*items));
        if (items == NULL)
            return fail(&g, "out of memory");
        for (size_t i = 0; i < g.n; i++) {
            Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
            if (o == NULL)
                return fail(&g, "out of memory");
            protocol__operator__init(o);
            o->type = dup(&g, g.rd[i].type);
            o->operand = dup(&g, g.rd[i].operand);
            o->data = g.rd[i].data;
            o->sensitive = g.rd[i].sensitive;
            items[i] = o;
        }
        op->list = items;
        op->n_list = g.n;
    } else if (g.n == 1) {
        const char *type = g.op_type;
        const char *data = g.rd[0].data;
        if (f->proc_regexp || f->cmdline_regexp)
            type = T_REGEXP;
        else if (!f->proc.on && !f->cmdline.on && ks_rule_is_regex(data))
            type = T_REGEXP;
        op->type = dup(&g, type);
        op->operand = dup(&g, g.rd[0].operand);
        op->data = dup(&g, data);
    } else {
        return fail(&g, "Select at least one field.");
    }

    if (f->name[0] == '\0') {
        char *raw = g_strdup_printf("%s %s %s", r->action, op->type, op->data);
        char *slug = ks_slugify(raw);
        r->name = dup(&g, slug != NULL ? slug : "");
        free(slug);
        g_free(raw);
    }
    if (a->failed)
        return fail(&g, "out of memory");
    *out = r;
    return true;
}

/* ---- loading ------------------------------------------------------------------------ */

static void load_list(struct ks_rform *f, struct ks_rcheck *c, const char *text, bool ints,
                      bool upper, char *err, size_t errlen)
{
    char buf[512];
    c->on = true;
    int rc = ks_rule_regexp_to_comma(text, ints, buf, sizeof(buf));
    if (rc < 0)
        snprintf(err, errlen, "%s", buf);
    if (rc == 1) {
        ks_rform_set(c, buf);
    } else {
        ks_rform_set(c, text);
    }
    if (upper) {
        char *u = g_utf8_strup(c->text, -1);
        ks_rform_set(c, u);
        g_free(u);
    }
    (void)f;
}

static void load_ip(struct ks_rform *f, struct ks_rcheck *c, const char *data, char *err,
                    size_t errlen)
{
    c->on = true;
    if (strcmp(data, KS_RULE_LAN_RANGES) == 0)
        ks_rform_set(c, KS_RULE_LAN_LABEL);
    else if (strcmp(data, KS_RULE_MULTICAST_RANGE) == 0)
        ks_rform_set(c, KS_RULE_MULTICAST_LABEL);
    else
        load_list(f, c, data, false, false, err, errlen);
}

static void load_operator(struct ks_rform *f, const Protocol__Operator *o, char *err, size_t errlen)
{
    const char *operand = o->operand != NULL ? o->operand : "";
    const char *data = o->data != NULL ? o->data : "";
    const char *type = o->type != NULL ? o->type : "";
    f->sensitive = o->sensitive;
    if (strcmp(operand, OP_PROTOCOL) == 0) {
        load_list(f, &f->proto, data, false, true, err, errlen);
    } else if (strcmp(operand, OP_PROC_PATH) == 0) {
        f->proc.on = true;
        ks_rform_set(&f->proc, data);
        f->proc_regexp = strcmp(type, T_REGEXP) == 0;
    } else if (strcmp(operand, OP_PROC_COMMAND) == 0) {
        f->cmdline.on = true;
        ks_rform_set(&f->cmdline, data);
        f->cmdline_regexp = strcmp(type, T_REGEXP) == 0;
    } else if (strcmp(operand, OP_USER_ID) == 0) {
        f->uid.on = true;
        ks_rform_set(&f->uid, data);
    } else if (strcmp(operand, OP_PROC_ID) == 0) {
        f->pid.on = true;
        ks_rform_set(&f->pid, data);
    } else if (strcmp(operand, OP_IFACE_OUT) == 0) {
        load_list(f, &f->iface, data, false, false, err, errlen);
    } else if (strcmp(operand, OP_SRC_PORT) == 0) {
        load_list(f, &f->srcport, data, true, false, err, errlen);
    } else if (strcmp(operand, OP_DST_PORT) == 0) {
        load_list(f, &f->dstport, data, true, false, err, errlen);
    } else if (strcmp(operand, OP_SRC_IP) == 0 || strcmp(operand, OP_SRC_NET) == 0) {
        load_ip(f, &f->srcip, data, err, errlen);
    } else if (strcmp(operand, OP_DST_IP) == 0 || strcmp(operand, OP_DST_NET) == 0) {
        load_ip(f, &f->dstip, data, err, errlen);
    } else if (strcmp(operand, OP_DST_HOST) == 0) {
        load_list(f, &f->dsthost, data, false, false, err, errlen);
    } else if (strcmp(operand, OP_LIST_DOMAINS) == 0) {
        f->lists.on = true;
        ks_rform_set(&f->lists, data);
    } else if (strcmp(operand, OP_LIST_DOMAINS_RE) == 0) {
        f->lists_regexp.on = true;
        ks_rform_set(&f->lists_regexp, data);
    } else if (strcmp(operand, OP_LIST_IPS) == 0) {
        f->lists_ips.on = true;
        ks_rform_set(&f->lists_ips, data);
    } else if (strcmp(operand, OP_LIST_NETS) == 0) {
        f->lists_nets.on = true;
        ks_rform_set(&f->lists_nets, data);
    } else if (strcmp(operand, OP_MD5) == 0) {
        f->md5.on = true;
        ks_rform_set(&f->md5, data);
    }
}

void ks_rform_load_rule(struct ks_rform *f, const Protocol__Rule *r, char *err, size_t errlen)
{
    err[0] = '\0';
    ks_rform_set_name(f, r->name);
    ks_rform_set_desc(f, r->description);
    f->enabled = r->enabled;
    f->precedence = r->precedence;
    f->nolog = r->nolog;
    const char *action = r->action != NULL ? r->action : "";
    /* the radio keeps its state if the action is none of the three */
    if (strcmp(action, "deny") == 0)
        f->action = KS_RACTION_DENY;
    else if (strcmp(action, "allow") == 0)
        f->action = KS_RACTION_ALLOW;
    else if (strcmp(action, "reject") == 0)
        f->action = KS_RACTION_REJECT;
    f->duration = ks_rform_duration_index(r->duration != NULL ? r->duration : "");
    const Protocol__Operator *op = r->operator_;
    if (op == NULL)
        return;
    if (strcmp(op->type != NULL ? op->type : "", T_LIST) != 0) {
        load_operator(f, op, err, errlen);
    } else {
        for (size_t i = 0; i < op->n_list; i++)
            load_operator(f, op->list[i], err, errlen);
    }
}

void ks_rform_from_connection(struct ks_rform *f, const char *protocol, const char *src_ip,
                              const char *src_port, const char *dst_ip, const char *dst_host,
                              const char *dst_port, const char *uid, const char *pid,
                              const char *process, const char *cmdline)
{
    char *up = g_utf8_strup(protocol, -1);
    ks_rform_set(&f->proto, up);
    g_free(up);
    ks_rform_set(&f->srcip, src_ip);
    ks_rform_set(&f->dstip, dst_ip);
    ks_rform_set(&f->dsthost, dst_host);
    ks_rform_set(&f->dstport, dst_port);
    ks_rform_set(&f->srcport, src_port);
    ks_rform_set(&f->uid, uid);
    ks_rform_set(&f->pid, pid);
    ks_rform_set(&f->proc, process);
    ks_rform_set(&f->cmdline, cmdline);
}
