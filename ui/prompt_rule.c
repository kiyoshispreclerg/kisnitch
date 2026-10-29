/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the logic of upstream ui/opensnitch/dialogs/prompt/
 * (__init__.py, _utils.py, _details.py, _checksums.py) and
 * ui/opensnitch/utils/network_aliases/network_aliases.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2024 Nolan Carouge (network aliases).
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/prompt_rule.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "common/json_util.h"
#include "common/unicode.h"
#include "ui/pyjson.h"
#include "ui/slug.h"
#include "ui/i18n.h"

const char *const ks_durations[KS_DURATION_COUNT] = {
    "once", "30s", "5m", "15m", "30m", "1h", "12h", "until restart", "always",
};
const char *const ks_duration_labels[KS_DURATION_COUNT] = {
    N_("once"), "30s", "5m", "15m", "30m", "1h", "12h", N_("until reboot"), N_("forever"),
};

#define MD5_KEY "process.hash.md5"

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

const char *ks_prompt_duration(int idx)
{
    /* anything else is "always" */
    if (idx < 0 || idx >= KS_DURATION_COUNT)
        return ks_durations[KS_DURATION_COUNT - 1];
    return ks_durations[idx];
}

const char *ks_prompt_action(int idx)
{
    if (idx == 0)
        return "deny";
    if (idx == 2)
        return "reject";
    return "allow";
}

/* ---- combos ------------------------------------------------------------ */

void ks_combo_free(struct ks_combo *c)
{
    for (size_t i = 0; i < c->len; i++)
        free(c->items[i].text);
    free(c->items);
    memset(c, 0, sizeof(*c));
}

int ks_combo_find(const struct ks_combo *c, enum ks_field field)
{
    for (size_t i = 0; i < c->len; i++) {
        if (c->items[i].field == field)
            return (int)i;
    }
    return -1;
}

/* Adds pre + arg + post. */
static int combo_add(struct ks_combo *c, enum ks_field field, const char *pre, const char *arg,
                     const char *post)
{
    if (c->len == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 16;
        struct ks_combo_item *n = realloc(c->items, ncap * sizeof(*n));
        if (n == NULL)
            return -1;
        c->items = n;
        c->cap = ncap;
    }
    pre = pre[0] != '\0' ? _(pre) : pre;
    size_t lp = strlen(pre), la = strlen(nz(arg)), lq = strlen(nz(post));
    char *text = malloc(lp + la + lq + 1);
    if (text == NULL)
        return -1;
    memcpy(text, pre, lp);
    memcpy(text + lp, nz(arg), la);
    memcpy(text + lp + la, nz(post), lq + 1);
    c->items[c->len++] = (struct ks_combo_item){text, field, false};
    return 0;
}

/* ---- strings ----------------------------------------------------------- */

/* The first `n` characters (code points) of `s`. malloc'd. */
static char *cp_prefix(const char *s, size_t n)
{
    size_t len = strlen(s), i = 0;
    for (size_t k = 0; k < n && i < len; k++) {
        uint32_t r;
        size_t l = ks_utf8_decode(s + i, len - i, &r);
        i += l ? l : 1;
    }
    return strndup(s, i);
}

static size_t cp_len(const char *s)
{
    size_t len = strlen(s), i = 0, n = 0;
    while (i < len) {
        uint32_t r;
        size_t l = ks_utf8_decode(s + i, len - i, &r);
        i += l ? l : 1;
        n++;
    }
    return n;
}

char *ks_prompt_truncate(const char *text, size_t max)
{
    if (cp_len(text) <= max)
        return strdup(text);
    char *p = cp_prefix(text, max);
    if (p == NULL)
        return NULL;
    size_t l = strlen(p);
    char *out = realloc(p, l + 4);
    if (out == NULL) {
        free(p);
        return NULL;
    }
    memcpy(out + l, "...", 4);
    return out;
}

static bool printable(uint32_t r)
{
    /* str.isprintable(): no control (Cc), format (Cf), separators other
     * than the space (Zl, Zp, Zs) nor unassigned/surrogate characters.
     * This covers the ones that show up in process names and arguments. */
    if (r < 0x20 || (r >= 0x7f && r <= 0xa0) || r == 0xad)
        return false;
    if ((r >= 0x2000 && r <= 0x200f) || (r >= 0x2028 && r <= 0x202f) ||
        (r >= 0x205f && r <= 0x206f) || r == 0x1680 || r == 0x3000 || r == 0xfeff ||
        (r >= 0xfff9 && r <= 0xfffb) || (r >= 0xd800 && r <= 0xdfff))
        return false;
    return true;
}

void ks_prompt_printable(char *text)
{
    size_t len = strlen(text), i = 0, o = 0;
    while (i < len) {
        uint32_t r;
        size_t l = ks_utf8_decode(text + i, len - i, &r);
        if (l == 0)
            l = 1;
        if (printable(r)) {
            memmove(text + o, text + i, l);
            o += l;
        }
        i += l;
    }
    text[o] = '\0';
}

char *ks_markup_escape(const char *s)
{
    struct ks_pybuf b = {0};
    ks_pybuf_add(&b, "", 0);
    for (; *s; s++) {
        switch (*s) {
        case '<': ks_pybuf_adds(&b, "&lt;"); break;
        case '>': ks_pybuf_adds(&b, "&gt;"); break;
        case '&': ks_pybuf_adds(&b, "&amp;"); break;
        case '"': ks_pybuf_adds(&b, "&quot;"); break;
        case '\'': ks_pybuf_adds(&b, "&#39;"); break;
        default: ks_pybuf_add(&b, s, 1);
        }
    }
    return ks_pybuf_finish(&b);
}

static char *basename_of(const char *path)
{
    const char *s = strrchr(path, '/');
    return strdup(s ? s + 1 : path);
}

/* os.path.dirname() */
static char *dirname_of(const char *path)
{
    const char *s = strrchr(path, '/');
    if (s == NULL)
        return strdup("");
    size_t n = (size_t)(s - path) + 1;
    /* strip trailing slashes unless it's all slashes */
    size_t k = n;
    while (k > 0 && path[k - 1] == '/')
        k--;
    return strndup(path, k > 0 ? k : n);
}

/* s.replace(from, to) for single characters into strings. malloc'd. */
static char *replace_char(const char *s, char from, const char *to)
{
    struct ks_pybuf b = {0};
    ks_pybuf_add(&b, "", 0);
    for (; *s; s++) {
        if (*s == from)
            ks_pybuf_adds(&b, to);
        else
            ks_pybuf_add(&b, s, 1);
    }
    return ks_pybuf_finish(&b);
}

/* The last space-separated word of `s` (comboText.split(' ')[-1]). */
static const char *last_word(const char *s)
{
    const char *sp = strrchr(s, ' ');
    return sp ? sp + 1 : s;
}

/* " ".join(con.process_args) */
static char *join_args(const Protocol__Connection *con)
{
    struct ks_pybuf b = {0};
    ks_pybuf_add(&b, "", 0);
    for (size_t i = 0; i < con->n_process_args; i++) {
        if (i > 0)
            ks_pybuf_add(&b, " ", 1);
        ks_pybuf_adds(&b, nz(con->process_args[i]));
    }
    return ks_pybuf_finish(&b);
}

const char *ks_prompt_md5(const Protocol__Connection *con)
{
    for (size_t i = 0; i < con->n_process_checksums; i++) {
        const Protocol__Connection__ProcessChecksumsEntry *e = con->process_checksums[i];
        if (strcmp(nz(e->key), MD5_KEY) == 0)
            return nz(e->value);
    }
    return "";
}

/* ---- network aliases --------------------------------------------------- */

void ks_py_aliases_free(struct ks_py_aliases *a)
{
    for (size_t i = 0; i < a->len; i++) {
        for (size_t j = 0; j < a->items[i].nnets; j++)
            free(a->items[i].nets[j].text);
        free(a->items[i].nets);
        free(a->items[i].name);
    }
    free(a->items);
    memset(a, 0, sizeof(*a));
}

int ks_py_aliases_parse(struct ks_py_aliases *a, const char *json, size_t len)
{
    char err[128];
    memset(a, 0, sizeof(*a));
    cJSON *j = ks_json_parse(json, len, err, sizeof(err));
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        return -1;
    }
    size_t n = (size_t)cJSON_GetArraySize(j);
    a->items = calloc(n ? n : 1, sizeof(*a->items));
    if (a->items == NULL) {
        cJSON_Delete(j);
        return -1;
    }
    const cJSON *it;
    cJSON_ArrayForEach(it, j)
    {
        struct ks_py_alias *al = &a->items[a->len++];
        al->name = strdup(it->string);
        size_t m = cJSON_IsArray(it) ? (size_t)cJSON_GetArraySize(it) : 0;
        al->nets = calloc(m ? m : 1, sizeof(*al->nets));
        if (al->name == NULL || al->nets == NULL)
            goto oom;
        const cJSON *net;
        cJSON_ArrayForEach(net, it)
        {
            if (!cJSON_IsString(net))
                continue;
            if ((al->nets[al->nnets].text = strdup(net->valuestring)) == NULL)
                goto oom;
            al->nnets++;
        }
    }
    cJSON_Delete(j);
    return 0;
oom:
    cJSON_Delete(j);
    ks_py_aliases_free(a);
    return -1;
}

/* ipaddress.ip_address(): the 16 bytes and whether it's IPv4. */
static bool py_ip(const char *s, struct ks_ip *ip, bool *v4)
{
    if (ks_ip_parse(s, ip) < 0)
        return false;
    *v4 = strchr(s, ':') == NULL;
    return true;
}

bool ks_py_ip_valid(const char *s)
{
    struct ks_ip ip;
    bool v4;
    /* IPv6 may carry a scope id ("fe80::1%eth0", Python 3.9): non-empty,
     * without "%" or "/" */
    const char *pct = strchr(s, '%');
    if (pct != NULL) {
        if (strchr(s, ':') == NULL || pct[1] == '\0' || strchr(pct + 1, '%') != NULL ||
            strchr(pct + 1, '/') != NULL)
            return false;
        char addr[64];
        size_t al = (size_t)(pct - s);
        if (al >= sizeof(addr))
            return false;
        memcpy(addr, s, al);
        addr[al] = '\0';
        return py_ip(addr, &ip, &v4);
    }
    return py_ip(s, &ip, &v4);
}

/* ipaddress.ip_network(s) (strict): -1 on ValueError. */
static int py_network(const char *s, uint8_t net[16], int *bits, bool *v4)
{
    char addr[64];
    const char *slash = strchr(s, '/');
    size_t al = slash ? (size_t)(slash - s) : strlen(s);
    if (al >= sizeof(addr))
        return -1;
    memcpy(addr, s, al);
    addr[al] = '\0';
    struct ks_ip ip;
    if (!py_ip(addr, &ip, v4))
        return -1;
    int max = *v4 ? 32 : 128;
    *bits = max;
    if (slash) {
        char *end;
        long b = strtol(slash + 1, &end, 10);
        if (slash[1] == '\0' || *end != '\0' || b < 0 || b > max)
            return -1;
        *bits = (int)b;
    }
    const uint8_t *bytes = *v4 ? ip.b + 12 : ip.b;
    int nb = *v4 ? 4 : 16;
    memcpy(net, bytes, (size_t)nb);
    for (int i = *bits; i < nb * 8; i++) {
        if (net[i / 8] & (0x80 >> (i % 8)))
            return -1; /* has host bits set */
    }
    return 0;
}

const char *ks_py_aliases_get(const struct ks_py_aliases *a, const char *ip)
{
    struct ks_ip addr;
    bool v4;
    if (!py_ip(ip, &addr, &v4))
        return NULL;
    const uint8_t *b = v4 ? addr.b + 12 : addr.b;
    for (size_t i = 0; i < a->len; i++) {
        for (size_t j = 0; j < a->items[i].nnets; j++) {
            uint8_t net[16];
            int bits;
            bool nv4;
            if (py_network(a->items[i].nets[j].text, net, &bits, &nv4) < 0)
                return NULL;
            if (nv4 != v4)
                continue;
            bool in = true;
            for (int k = 0; k < bits && in; k++) {
                uint8_t m = (uint8_t)(0x80 >> (k % 8));
                in = (b[k / 8] & m) == (net[k / 8] & m);
            }
            if (in)
                return a->items[i].name;
        }
    }
    return NULL;
}

/* str(ip_network(ip + "/" + bits, strict=False)) */
static int network_text(const char *ip, int bits, char *buf, size_t len)
{
    struct ks_ip addr;
    bool v4;
    if (!py_ip(ip, &addr, &v4))
        return -1;
    int nb = v4 ? 4 : 16;
    uint8_t *b = v4 ? addr.b + 12 : addr.b;
    for (int i = bits; i < nb * 8; i++)
        b[i / 8] &= (uint8_t)~(0x80 >> (i % 8));
    char s[KS_IP_STRLEN];
    if (v4) {
        snprintf(s, sizeof(s), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    } else {
        struct ks_ip n = {.len = 16};
        memcpy(n.b, b, 16);
        ks_ip_string(&n, s, sizeof(s));
    }
    snprintf(buf, len, "%s/%d", s, bits);
    return 0;
}

/* ---- the pop-up's combos ----------------------------------------------- */

char *ks_prompt_uid_text(const Protocol__Connection *con, bool is_local)
{
    char buf[512];
    if (is_local) {
        struct passwd pw, *res = NULL;
        char tmp[1024];
        if (getpwuid_r((uid_t)con->user_id, &pw, tmp, sizeof(tmp), &res) != 0 || res == NULL)
            return strdup("");
        snprintf(buf, sizeof(buf), "%u (%s)", con->user_id, pw.pw_name);
    } else {
        snprintf(buf, sizeof(buf), "%u", con->user_id);
    }
    return strdup(buf);
}

static int add_dst_networks(struct ks_combo *c, const char *dst_ip,
                            const struct ks_py_aliases *aliases)
{
    const char *alias = aliases ? ks_py_aliases_get(aliases, dst_ip) : NULL;
    if (alias != NULL && combo_add(c, KS_FIELD_DST_NETWORK, N_("to "), alias, "") < 0)
        return -1;
    struct ks_ip ip;
    bool v4;
    if (!py_ip(dst_ip, &ip, &v4))
        return 0; /* upstream raises here; nothing more is added */
    static const int bits4[] = {24, 16, 8}, bits6[] = {64, 128};
    const int *bits = v4 ? bits4 : bits6;
    size_t n = v4 ? 3 : 2;
    for (size_t i = 0; i < n; i++) {
        char net[80];
        if (network_text(dst_ip, bits[i], net, sizeof(net)) == 0 &&
            combo_add(c, KS_FIELD_DST_NETWORK, N_("to "), net, "") < 0)
            return -1;
    }
    return 0;
}

static int add_dsthost(struct ks_combo *what, struct ks_combo *ipc, const char *host)
{
    if (combo_add(what, KS_FIELD_DST_HOST, "", host, "") < 0 ||
        combo_add(ipc, KS_FIELD_DST_HOST, "", host, "") < 0)
        return -1;
    /* parts = dst_host.split('.')[1:]; for i in range(0, nparts - 1) */
    const char *parts[256];
    size_t nparts = 0;
    for (const char *p = strchr(host, '.'); p != NULL && nparts < 256; p = strchr(p + 1, '.'))
        parts[nparts++] = p + 1;
    for (size_t i = 0; i + 1 < nparts; i++) {
        if (combo_add(what, KS_FIELD_REGEX_HOST, N_("to *."), parts[i], "") < 0 ||
            combo_add(ipc, KS_FIELD_REGEX_HOST, N_("to *."), parts[i], "") < 0)
            return -1;
    }
    return 0;
}

static int add_ip_regexp(struct ks_combo *what, struct ks_combo *ipc, const char *dst_ip)
{
    if (combo_add(ipc, KS_FIELD_DST_IP, N_("to "), dst_ip, "") < 0)
        return -1;
    /* parts = dst_ip.split('.'); for i in range(1, nparts): parts[:i] */
    for (const char *p = strchr(dst_ip, '.'); p != NULL; p = strchr(p + 1, '.')) {
        char *prefix = strndup(dst_ip, (size_t)(p - dst_ip));
        if (prefix == NULL)
            return -1;
        int rc = combo_add(what, KS_FIELD_REGEX_IP, N_("to "), prefix, ".*");
        if (rc == 0)
            rc = combo_add(ipc, KS_FIELD_REGEX_IP, N_("to "), prefix, ".*");
        free(prefix);
        if (rc < 0)
            return -1;
    }
    return 0;
}

/* path.split('/') */
static size_t split_path(const char *path, const char **parts, size_t *lens, size_t max)
{
    size_t n = 0;
    const char *s = path;
    while (n < max) {
        const char *e = strchr(s, '/');
        parts[n] = s;
        lens[n] = e ? (size_t)(e - s) : strlen(s);
        n++;
        if (e == NULL)
            break;
        s = e + 1;
    }
    return n;
}

/* sep.join(parts[from:]) */
static char *join_parts(const char **parts, const size_t *lens, size_t n, size_t from,
                        const char *sep)
{
    struct ks_pybuf b = {0};
    ks_pybuf_add(&b, "", 0);
    for (size_t i = from; i < n; i++) {
        if (i > from)
            ks_pybuf_adds(&b, sep);
        ks_pybuf_add(&b, parts[i], lens[i]);
    }
    return ks_pybuf_finish(&b);
}

int ks_prompt_fill_combos(const Protocol__Connection *con, const char *uid_text,
                          const struct ks_py_aliases *aliases, struct ks_combo *what,
                          struct ks_combo *ipc)
{
    char port[16], pid[16];
    snprintf(port, sizeof(port), "%u", con->dst_port);
    snprintf(pid, sizeof(pid), "%u", con->process_id);
    const char *path = nz(con->process_path), *dst_ip = nz(con->dst_ip),
               *dst_host = nz(con->dst_host);

    /* the order must match the default target of the preferences */
    if (combo_add(what, KS_FIELD_PROC_PATH, N_("from this executable"), NULL, NULL) < 0 ||
        combo_add(what, KS_FIELD_PROC_ARGS, N_("from this command line"), NULL, NULL) < 0 ||
        combo_add(what, KS_FIELD_DST_PORT, N_("to port "), port, "") < 0 ||
        combo_add(what, KS_FIELD_DST_IP, N_("to "), dst_ip, "") < 0 ||
        combo_add(what, KS_FIELD_USER_ID, N_("from user "), uid_text, "") < 0 ||
        combo_add(what, KS_FIELD_PROC_ID, N_("from this PID"), NULL, NULL) < 0)
        return -1;
    /* process_id and user_id are unsigned: the "< 0" checks that disable
     * entries 0 and 4 never hold */

    if (strncmp(path, KS_APPIMAGE_PREFIX, strlen(KS_APPIMAGE_PREFIX)) == 0) {
        char *bin = basename_of(path), *dir = dirname_of(path);
        char *pre = dir ? cp_prefix(dir, strlen(KS_APPIMAGE_PREFIX) + 6) : NULL;
        int rc = -1;
        if (bin != NULL && pre != NULL) {
            size_t l = strlen(pre) + strlen(bin) + 16;
            char *text = malloc(l);
            if (text != NULL) {
                snprintf(text, l, "from %s*/%s", pre, bin);
                rc = combo_add(what, KS_FIELD_APPIMAGE, "", text, "");
                free(text);
            }
        }
        free(bin);
        free(dir);
        free(pre);
        if (rc < 0)
            return -1;
    } else if (strncmp(path, KS_SNAP_PREFIX, strlen(KS_SNAP_PREFIX)) == 0) {
        const char *parts[512];
        size_t lens[512];
        size_t n = split_path(path, parts, lens, 512);
        /* upstream raises IndexError (and shows nothing) with fewer parts */
        if (n >= 3) {
            char *app = strndup(parts[2], lens[2]);
            char *app_path = join_parts(parts, lens, n, 4, "/");
            int rc = -1;
            if (app != NULL && app_path != NULL) {
                size_t l = strlen(app) + strlen(app_path) + 32;
                char *text = malloc(l);
                if (text != NULL) {
                    snprintf(text, l, "from %s/%s/*/%s", KS_SNAP_PREFIX, app, app_path);
                    rc = combo_add(what, KS_FIELD_SNAP, "", text, "");
                    free(text);
                }
            }
            free(app);
            free(app_path);
            if (rc < 0)
                return -1;
        }
    }
    if (add_dst_networks(what, dst_ip, aliases) < 0)
        return -1;
    if (dst_host[0] != '\0' && strcmp(dst_host, dst_ip) != 0 &&
        add_dsthost(what, ipc, dst_host) < 0)
        return -1;
    if (add_ip_regexp(what, ipc, dst_ip) < 0)
        return -1;
    return add_dst_networks(ipc, dst_ip, aliases);
}

int ks_prompt_default_target(const struct ks_combo *what, const Protocol__Connection *con,
                             int cfg_target, const char *app_name, const char *app_args)
{
    const char *path = nz(con->process_path);
    int idx = -1;
    if (strncmp(path, KS_APPIMAGE_PREFIX, strlen(KS_APPIMAGE_PREFIX)) == 0)
        idx = ks_combo_find(what, KS_FIELD_APPIMAGE);
    else if (strncmp(path, KS_SNAP_PREFIX, strlen(KS_SNAP_PREFIX)) == 0)
        idx = ks_combo_find(what, KS_FIELD_SNAP);
    if (idx != -1)
        return idx;
    if (con->process_id > 0 && nz(app_name)[0] != '\0' && nz(app_args)[0] != '\0')
        idx = cfg_target;
    else
        idx = 2;
    /* QComboBox.setCurrentIndex() with an invalid index selects nothing */
    return (idx >= 0 && (size_t)idx < what->len) ? idx : -1;
}

/* ---- texts ------------------------------------------------------------- */

static char *upper(const char *s)
{
    char *u = strdup(nz(s));
    for (char *p = u; p && *p; p++) {
        if (*p >= 'a' && *p <= 'z')
            *p = (char)(*p - 32);
    }
    return u;
}

char *ks_prompt_message(bool is_local, const char *node, const char *hostname,
                        const char *app_name, const Protocol__Connection *con)
{
    struct ks_pybuf b = {0};
    char *name = ks_prompt_truncate(nz(app_name), 64);
    char *ename = name ? ks_markup_escape(name) : NULL;
    const char *host = nz(con->dst_host)[0] ? con->dst_host : nz(con->dst_ip);
    char *ehost = ks_markup_escape(host), *eip = ks_markup_escape(nz(con->dst_ip));
    char *proto = upper(con->protocol);
    char *eproto = proto ? ks_markup_escape(proto) : NULL;
    char port[16];
    snprintf(port, sizeof(port), "%u", con->dst_port);
    free(name);
    free(proto);
    if (ename == NULL || ehost == NULL || eip == NULL || eproto == NULL)
        goto out;

    if (!is_local) {
        const char *colon = strchr(nz(node), ':');
        const char *addr = colon ? colon + 1 : "";
        const char *end = strchr(addr, ':');
        char *a = end ? strndup(addr, (size_t)(end - addr)) : strdup(addr);
        char *ea = a ? ks_markup_escape(a) : NULL;
        char *eh = ks_markup_escape(nz(hostname));
        free(a);
        if (ea == NULL || eh == NULL) {
            free(ea);
            free(eh);
            goto out;
        }
        ks_pybuf_adds(&b, "<b>Remote</b> process <b>");
        ks_pybuf_adds(&b, ename);
        ks_pybuf_adds(&b, "</b> running on <b>");
        ks_pybuf_adds(&b, ea);
        ks_pybuf_adds(&b, " (");
        ks_pybuf_adds(&b, eh);
        ks_pybuf_adds(&b, ")</b>");
        free(ea);
        free(eh);
    } else {
        ks_pybuf_adds(&b, "<b>");
        ks_pybuf_adds(&b, ename);
        ks_pybuf_adds(&b, "</b>");
    }
    ks_pybuf_adds(&b, " ");
    if (con->dst_port == 53 && strcmp(nz(con->dst_ip), nz(con->dst_host)) != 0 &&
        nz(con->dst_host)[0] != '\0') {
        ks_pybuf_adds(&b, "is attempting to resolve <b>");
        ks_pybuf_adds(&b, ehost);
        ks_pybuf_adds(&b, "</b> via ");
        ks_pybuf_adds(&b, eip);
        ks_pybuf_adds(&b, ", ");
        ks_pybuf_adds(&b, eproto);
        ks_pybuf_adds(&b, " port ");
        ks_pybuf_adds(&b, port);
    } else if (con->dst_port == 0) {
        /* icmp: no port */
        ks_pybuf_adds(&b, "is connecting to <b>");
        ks_pybuf_adds(&b, ehost);
        ks_pybuf_adds(&b, "</b>, ");
        ks_pybuf_adds(&b, eproto);
    } else {
        ks_pybuf_adds(&b, "is connecting to <b>");
        ks_pybuf_adds(&b, ehost);
        ks_pybuf_adds(&b, "</b> on ");
        ks_pybuf_adds(&b, eproto);
        ks_pybuf_adds(&b, " port ");
        ks_pybuf_adds(&b, port);
    }
out:
    free(ename);
    free(ehost);
    free(eip);
    free(eproto);
    if (b.s == NULL)
        b.oom = true;
    return ks_pybuf_finish(&b);
}

static bool args_contain(const Protocol__Connection *con, const char *s)
{
    for (size_t i = 0; i < con->n_process_args; i++) {
        if (strcmp(nz(con->process_args[i]), s) == 0)
            return true;
    }
    return false;
}

/* app_name.lower() == app_args (ASCII lowercase is enough for the
 * comparison of a name with a command line) */
static bool lower_equals(const char *name, const char *args)
{
    char *l = ks_str_to_lower(nz(name));
    bool eq = l != NULL && strcmp(l, nz(args)) == 0;
    free(l);
    return eq;
}

char *ks_prompt_path_label(const char *app_name, const char *app_args,
                           const Protocol__Connection *con)
{
    const char *path = nz(con->process_path);
    char *text = NULL;
    if (path[0] != '\0' && con->n_process_args >= 1 && !args_contain(con, path)) {
        if (lower_equals(app_name, app_args)) {
            text = ks_prompt_truncate(path, 64);
        } else {
            size_t l = strlen(path) + 3;
            char *p = malloc(l);
            if (p != NULL) {
                snprintf(p, l, "(%s)", path);
                text = ks_prompt_truncate(p, 64);
                free(p);
            }
        }
    } else if (path[0] != '\0' && con->n_process_args == 0) {
        text = ks_prompt_truncate(path, 64);
    } else {
        return NULL;
    }
    if (text != NULL)
        ks_prompt_printable(text);
    return text;
}

char *ks_prompt_args_label(const char *app_name, const char *app_args)
{
    if (lower_equals(app_name, app_args))
        return NULL;
    char *t = ks_prompt_truncate(nz(app_args), 256);
    if (t != NULL)
        ks_prompt_printable(t);
    return t;
}

char *ks_prompt_details(const Protocol__Connection *con)
{
    struct ks_pybuf b = {0};
    char tmp[64];
    char *proto = upper(con->protocol), *args = join_args(con);
    ks_pybuf_adds(&b, nz(proto));
    /* sic: upstream prints src_port:src_ip */
    snprintf(tmp, sizeof(tmp), " %u:", con->src_port);
    ks_pybuf_adds(&b, tmp);
    ks_pybuf_adds(&b, nz(con->src_ip));
    ks_pybuf_adds(&b, " -> ");
    ks_pybuf_adds(&b, nz(con->dst_ip));
    snprintf(tmp, sizeof(tmp), ":%u\n\n", con->dst_port);
    ks_pybuf_adds(&b, tmp);
    ks_pybuf_adds(&b, "Path:      ");
    ks_pybuf_adds(&b, nz(con->process_path));
    ks_pybuf_adds(&b, "\nCmdline:  ");
    ks_pybuf_adds(&b, nz(args));
    ks_pybuf_adds(&b, "\nCWD:       ");
    ks_pybuf_adds(&b, nz(con->process_cwd));
    ks_pybuf_adds(&b, "\nMD5:       ");
    ks_pybuf_adds(&b, ks_prompt_md5(con));
    snprintf(tmp, sizeof(tmp), "\nUID:         %u\nPID:         %u\n\nProcess tree:\n",
             con->user_id, con->process_id);
    ks_pybuf_adds(&b, tmp);
    /* con.process_tree.reverse(): the oldest ancestor first */
    size_t indent = 1;
    for (size_t i = con->n_process_tree; i > 0; i--) {
        const Protocol__StringInt *p = con->process_tree[i - 1];
        snprintf(tmp, sizeof(tmp), "│%u\t", p->value);
        ks_pybuf_adds(&b, tmp);
        for (size_t s = 0; s < indent; s++)
            ks_pybuf_add(&b, " ", 1);
        if (i != con->n_process_tree)
            ks_pybuf_adds(&b, "\\_ ");
        ks_pybuf_adds(&b, nz(p->key));
        ks_pybuf_adds(&b, "\n");
        indent += 4;
    }
    ks_pybuf_adds(&b, "\nEnvironment variables:\n");
    for (size_t i = 0; i < con->n_process_env; i++) {
        ks_pybuf_adds(&b, nz(con->process_env[i]->key));
        ks_pybuf_adds(&b, "=");
        ks_pybuf_adds(&b, nz(con->process_env[i]->value));
        ks_pybuf_adds(&b, "\n");
    }
    free(proto);
    free(args);
    return ks_pybuf_finish(&b);
}

/* ---- the rule ---------------------------------------------------------- */

struct op3 {
    const char *type, *operand;
    char *data; /* in the arena */
};

/* _utils.get_combo_operator(); false if upstream gets None. */
static bool combo_operator(struct ks_arena *a, const struct ks_combo_item *it,
                           const Protocol__Connection *con, struct op3 *o)
{
    char tmp[32];
    const char *path = nz(con->process_path);
    if (it == NULL)
        return false;
    const char *text = it->text;
    o->type = "simple";
    switch (it->field) {
    case KS_FIELD_PROC_PATH:
        o->operand = "process.path";
        o->data = ks_arena_strdup(a, path);
        return true;
    case KS_FIELD_PROC_ARGS: {
        if (con->n_process_args == 0 || nz(con->process_args[0])[0] == '\0') {
            o->operand = "process.path";
            o->data = ks_arena_strdup(a, path);
            return true;
        }
        char *args = join_args(con);
        o->operand = "process.command";
        o->data = ks_arena_strdup(a, nz(args));
        free(args);
        return true;
    }
    case KS_FIELD_PROC_ID:
        snprintf(tmp, sizeof(tmp), "%u", con->process_id);
        o->operand = "process.id";
        o->data = ks_arena_strdup(a, tmp);
        return true;
    case KS_FIELD_USER_ID:
        snprintf(tmp, sizeof(tmp), "%u", con->user_id);
        o->operand = "user.id";
        o->data = ks_arena_strdup(a, tmp);
        return true;
    case KS_FIELD_DST_PORT:
        snprintf(tmp, sizeof(tmp), "%u", con->dst_port);
        o->operand = "dest.port";
        o->data = ks_arena_strdup(a, tmp);
        return true;
    case KS_FIELD_DST_IP:
        o->operand = "dest.ip";
        o->data = ks_arena_strdup(a, nz(con->dst_ip));
        return true;
    case KS_FIELD_DST_HOST:
        o->operand = "dest.host";
        o->data = ks_arena_strdup(a, text);
        return true;
    case KS_FIELD_DST_NETWORK:
        /* "to x.x.x.0/24" -> "x.x.x.0/24" */
        o->type = "network";
        o->operand = "dest.network";
        o->data = ks_arena_strdup(a, last_word(text));
        return true;
    case KS_FIELD_REGEX_HOST: {
        /* "to *.example.com" -> ^(|.*\.)example\.com$ */
        char *esc = replace_char(last_word(text), '.', "\\.");
        char *nostar = esc ? replace_char(esc, '*', "") : NULL;
        free(esc);
        if (nostar == NULL)
            return false;
        const char *rest = strlen(nostar) >= 2 ? nostar + 2 : "";
        o->type = "regexp";
        o->operand = "dest.host";
        o->data = ks_arena_printf(a, "^(|.*\\.)%s$", rest);
        free(nostar);
        return true;
    }
    case KS_FIELD_REGEX_IP: {
        char *esc = replace_char(last_word(text), '.', "\\.");
        char *star = esc ? replace_char(esc, '*', ".*") : NULL;
        free(esc);
        if (star == NULL)
            return false;
        o->type = "regexp";
        o->operand = "dest.ip";
        o->data = ks_arena_strdup(a, star);
        free(star);
        return true;
    }
    case KS_FIELD_APPIMAGE: {
        char *bin = basename_of(path), *dir = dirname_of(path);
        char *esc = dir ? replace_char(dir, '.', "\\.") : NULL;
        char *pre = esc ? cp_prefix(esc, strlen(KS_APPIMAGE_PREFIX) + 7) : NULL;
        bool ok = bin != NULL && pre != NULL;
        if (ok) {
            o->type = "regexp";
            o->operand = "process.path";
            o->data = ks_arena_printf(a, "^%s[0-9A-Za-z]+\\/.*%s$", pre, bin);
        }
        free(bin);
        free(dir);
        free(esc);
        free(pre);
        return ok;
    }
    case KS_FIELD_SNAP: {
        const char *parts[512];
        size_t lens[512];
        size_t n = split_path(path, parts, lens, 512);
        if (n < 3)
            return false; /* IndexError upstream */
        char *app_path = join_parts(parts, lens, n, 4, "\\/");
        if (app_path == NULL)
            return false;
        o->type = "regexp";
        o->operand = "process.path";
        o->data = ks_arena_printf(a, "^\\/%.*s\\/%.*s\\/[0-9]+\\/%s$", (int)lens[1], parts[1],
                                  (int)lens[2], parts[2], app_path);
        free(app_path);
        return true;
    }
    }
    return false;
}

/* slugify("%s %s" % (a, b)) */
static char *slug2(const char *a, const char *b)
{
    size_t l = strlen(a) + strlen(b) + 2;
    char *t = malloc(l);
    if (t == NULL)
        return NULL;
    snprintf(t, l, "%s %s", a, b);
    char *s = ks_slugify(t);
    free(t);
    return s;
}

/* name = slugify(name + " " + extra), replacing `*name`. */
static int slug_append(char **name, const char *extra)
{
    char *s = slug2(*name, extra);
    if (s == NULL)
        return -1;
    free(*name);
    *name = s;
    return 0;
}

/* _utils.get_rule_name() */
static char *rule_name(const char *action, const char *duration, const char *data, bool is_list)
{
    char *s = slug2(action, duration);
    if (s == NULL)
        return NULL;
    size_t l = strlen(s) + 8;
    char *t = malloc(l);
    if (t == NULL) {
        free(s);
        return NULL;
    }
    snprintf(t, l, "%s-%s", s, is_list ? "list" : "simple");
    free(s);
    char *r = slug2(t, data);
    free(t);
    if (r != NULL && strlen(r) > 128)
        r[128] = '\0'; /* [:128], ASCII after slugify */
    return r;
}

#define MAX_OPS 8

Protocol__Rule *ks_prompt_build_rule(struct ks_arena *a, const Protocol__Connection *con,
                                     const struct ks_prompt_choice *ch,
                                     const struct ks_py_aliases *aliases,
                                     const struct ks_rulesdb *db, const char *peer,
                                     int64_t now)
{
    Protocol__Rule *r = ks_arena_alloc(a, sizeof(*r));
    Protocol__Operator *op = ks_arena_alloc(a, sizeof(*op));
    if (r == NULL || op == NULL)
        return NULL;
    protocol__rule__init(r);
    protocol__operator__init(op);
    r->operator_ = op;
    r->created = now;
    r->enabled = 1;
    r->duration = (char *)(uintptr_t)ks_prompt_duration(ch->duration_idx);
    r->action = (char *)(uintptr_t)ks_prompt_action(ch->action_idx);

    struct op3 main;
    if (!combo_operator(a, ch->what, con, &main) || main.data == NULL)
        return NULL;
    op->type = (char *)(uintptr_t)main.type;
    op->operand = (char *)(uintptr_t)main.operand;
    op->data = main.data;
    if (main.data[0] == '\0')
        return NULL; /* "Invalid rule, discarding" */

    bool checks = ch->user_id || ch->dst_port || ch->dst_ip || ch->checksum;
    char *temp_name = rule_name(r->action, r->duration, op->data, checks);
    if (temp_name == NULL)
        return NULL;
    r->name = ks_arena_strdup(a, temp_name);

    struct op3 data[MAX_OPS];
    size_t ndata = 0;
    bool alias_selected = false;
    enum ks_field what = ch->what->field;
    char tmp[32];

    if (what == KS_FIELD_DST_NETWORK && aliases != NULL &&
        ks_py_aliases_get(aliases, nz(con->dst_ip)) != NULL) {
        data[ndata++] = (struct op3){"simple", "process.path",
                                     ks_arena_strdup(a, nz(con->process_path))};
        char *base = basename_of(nz(con->process_path));
        if (base == NULL || slug_append(&temp_name, base) < 0) {
            free(base);
            goto fail;
        }
        free(base);
        alias_selected = true;
    }
    if (ch->dst_ip && what != KS_FIELD_DST_IP) {
        struct op3 o;
        if (!combo_operator(a, ch->what_ip, con, &o) || o.data == NULL)
            goto fail; /* TypeError upstream */
        data[ndata++] = o;
        if (slug_append(&temp_name, o.data) < 0)
            goto fail;
    }
    if (ch->dst_port && what != KS_FIELD_DST_PORT) {
        snprintf(tmp, sizeof(tmp), "%u", con->dst_port);
        data[ndata++] = (struct op3){"simple", "dest.port", ks_arena_strdup(a, tmp)};
        if (slug_append(&temp_name, tmp) < 0)
            goto fail;
    }
    if (ch->user_id && what != KS_FIELD_USER_ID) {
        snprintf(tmp, sizeof(tmp), "%u", con->user_id);
        data[ndata++] = (struct op3){"simple", "user.id", ks_arena_strdup(a, tmp)};
        if (slug_append(&temp_name, tmp) < 0)
            goto fail;
    }
    if (ch->checksum && nz(ch->checksum_text)[0] != '\0') {
        data[ndata++] =
            (struct op3){"simple", "process.hash.md5", ks_arena_strdup(a, ch->checksum_text)};
        if (slug_append(&temp_name, "process.hash.md5") < 0)
            goto fail;
    }

    bool is_list = checks;
    /* filtering by a command line that doesn't start with an absolute path
     * (or that runs from /proc) also filters by the binary */
    if (strcmp(op->operand, "process.command") == 0) {
        char *args = join_args(con);
        if (args == NULL)
            goto fail;
        char *sp = strchr(args, ' ');
        if (sp)
            *sp = '\0';
        if (args[0] != '/' || strncmp(args, "/proc", 5) == 0) {
            is_list = true;
            data[ndata++] = (struct op3){"simple", "process.path",
                                         ks_arena_strdup(a, nz(con->process_path))};
        }
        free(args);
    }

    if (is_list || alias_selected) {
        data[ndata++] = (struct op3){op->type, op->operand, op->data};
        struct ks_pybuf j = {0};
        ks_pybuf_adds(&j, "[");
        Protocol__Operator **items = ks_arena_calloc(a, ndata, sizeof(*items));
        if (items == NULL)
            goto fail;
        for (size_t i = 0; i < ndata; i++) {
            if (i > 0)
                ks_pybuf_adds(&j, ", ");
            ks_pybuf_adds(&j, "{\"type\": ");
            ks_pybuf_add_json_str(&j, data[i].type);
            ks_pybuf_adds(&j, ", \"operand\": ");
            ks_pybuf_add_json_str(&j, data[i].operand);
            ks_pybuf_adds(&j, ", \"data\": ");
            ks_pybuf_add_json_str(&j, nz(data[i].data));
            ks_pybuf_adds(&j, "}");
            Protocol__Operator *o = ks_arena_alloc(a, sizeof(*o));
            if (o == NULL)
                break;
            protocol__operator__init(o);
            o->type = (char *)(uintptr_t)data[i].type;
            o->operand = (char *)(uintptr_t)data[i].operand;
            o->data = data[i].data ? data[i].data : (char *)(uintptr_t) "";
            items[i] = o;
        }
        ks_pybuf_adds(&j, "]");
        char *js = ks_pybuf_finish(&j);
        if (js == NULL)
            goto fail;
        op->data = ks_arena_strdup(a, js);
        free(js);
        op->type = (char *)(uintptr_t) "list";
        op->operand = (char *)(uintptr_t) "list";
        op->list = items;
        op->n_list = ndata;
    }

    if (!ks_rulesdb_exists(db, peer, r)) {
        char *unique = ks_rulesdb_new_unique_name(db, temp_name, peer);
        if (unique == NULL)
            goto fail;
        r->name = ks_arena_strdup(a, unique);
        free(unique);
    }
    free(temp_name);
    return a->failed ? NULL : r;
fail:
    free(temp_name);
    return NULL;
}

/* ---- checksums --------------------------------------------------------- */

bool ks_prompt_checksum_mismatch(const struct ks_rulesdb *db, const char *peer,
                                 const Protocol__Connection *con, char **names, size_t max,
                                 size_t *nnames, char **expected)
{
    *nnames = 0;
    *expected = NULL;
    size_t idx[256];
    size_t n = ks_rulesdb_find_like(db, peer, KS_RF_OP_DATA, nz(con->process_path), idx, 256);
    const char *md5 = ks_prompt_md5(con);
    bool valid = true;
    struct ks_pybuf exp = {0};
    ks_pybuf_adds(&exp, "[");
    /* records.first() and then records.next(): the first match is
     * skipped */
    for (size_t k = 1; k < n; k++) {
        const struct ks_ui_rule *row = &db->rows[idx[k]];
        if (strcmp(row->f[KS_RF_ENABLED], "True") != 0)
            continue;
        if (*nnames < max)
            names[(*nnames)++] = strdup(row->f[KS_RF_NAME]);
        /* _checksums.verify() */
        if (strcmp(row->f[KS_RF_OP_TYPE], "list") != 0 || md5[0] == '\0')
            continue;
        struct ks_arena a = {0};
        Protocol__Rule *r = ks_rulesdb_to_pb(&a, row);
        for (size_t i = 0; r != NULL && i < r->operator_->n_list; i++) {
            const Protocol__Operator *o = r->operator_->list[i];
            if (strcmp(o->type, "simple") == 0 && strcmp(o->operand, MD5_KEY) == 0 &&
                strcmp(o->data, md5) != 0) {
                if (!valid)
                    ks_pybuf_adds(&exp, ", ");
                ks_pybuf_adds(&exp, "'");
                ks_pybuf_adds(&exp, o->data);
                ks_pybuf_adds(&exp, "'");
                valid = false;
                break;
            }
        }
        ks_arena_free(&a);
    }
    ks_pybuf_adds(&exp, "]");
    *expected = ks_pybuf_finish(&exp);
    return !valid;
}

Protocol__Rule *ks_prompt_checksum_update(struct ks_arena *a, struct ks_rulesdb *db,
                                          const char *peer, const char *name,
                                          const Protocol__Connection *con)
{
    const struct ks_ui_rule *row = ks_rulesdb_get(db, name, peer);
    if (row == NULL)
        return NULL;
    Protocol__Rule *r = ks_rulesdb_to_pb(a, row);
    if (r == NULL)
        return NULL;
    const char *md5 = ks_prompt_md5(con);
    Protocol__Operator *op = r->operator_;
    if (strcmp(op->type, "list") != 0) {
        if (strcmp(op->operand, MD5_KEY) == 0)
            op->data = ks_arena_strdup(a, md5);
    } else {
        for (size_t i = 0; i < op->n_list; i++) {
            if (strcmp(op->list[i]->operand, MD5_KEY) == 0) {
                op->list[i]->data = ks_arena_strdup(a, md5);
                break;
            }
        }
    }
    Protocol__Rule *one[1] = {r};
    if (ks_rulesdb_add_pb(db, peer, one, 1) < 0)
        return NULL;
    return r;
}
