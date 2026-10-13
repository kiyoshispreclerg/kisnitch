/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The parser follows Go 1.23's src/regexp/syntax/parse.go (Perl flags),
 * Copyright 2011 The Go Authors (BSD-3-Clause).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define PCRE2_CODE_UNIT_WIDTH 8
#include "daemon/rules/regex.h"

#include <pcre2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/unicode.h"

/* Same limit as Go's maxNestingDepth (syntax.ErrNestingDepth). */
#define MAX_DEPTH 1000
/* Go's repeat count limit. */
#define MAX_REPEAT 1000
/* Backtracking budget per match. Rule subjects are short (paths, hosts,
 * command lines); this only stops pathological patterns. */
#define MATCH_LIMIT 1000000

struct ks_regex {
    pcre2_code *code;
    pcre2_match_data *md;
    pcre2_match_context *mctx;
};

/* ---- output buffer ---------------------------------------------------- */

struct out {
    char *p;
    size_t len, cap;
    bool oom;
};

static void put(struct out *o, const char *s, size_t n)
{
    if (o->oom)
        return;
    if (o->len + n + 1 > o->cap) {
        size_t cap = o->cap ? o->cap * 2 : 64;
        while (cap < o->len + n + 1)
            cap *= 2;
        char *np = realloc(o->p, cap);
        if (np == NULL) {
            o->oom = true;
            return;
        }
        o->p = np;
        o->cap = cap;
    }
    memcpy(o->p + o->len, s, n);
    o->len += n;
    o->p[o->len] = '\0';
}

static void puts_(struct out *o, const char *s)
{
    put(o, s, strlen(s));
}

static void put_rune(struct out *o, uint32_t r)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "\\x{%x}", (unsigned)r);
    puts_(o, buf);
}

/* ---- parser state ----------------------------------------------------- */

struct frame {
    long need;      /* max repeat "need" in this group so far */
    long last_need; /* need of the last atom */
    bool has_atom;  /* a quantifier has something to apply to */
};

struct tr {
    const char *s; /* pattern */
    size_t n;
    size_t i;
    struct out out;
    char *err;
    size_t errlen;
    struct frame frames[MAX_DEPTH + 1];
    int depth;
    bool last_repeat;
};

static int fail(struct tr *t, const char *code, size_t from, size_t to)
{
    if (to > t->n)
        to = t->n;
    snprintf(t->err, t->errlen, "error parsing regexp: %s: `%.*s`", code,
             (int)(to - from), t->s + from);
    return -1;
}

#define ERR_ESCAPE "invalid escape sequence"
#define ERR_CLASS_RANGE "invalid character class range"
#define ERR_MISSING_BRACKET "missing closing ]"
#define ERR_MISSING_PAREN "missing closing )"
#define ERR_UNEXPECTED_PAREN "unexpected )"
#define ERR_REPEAT_ARG "missing argument to repetition operator"
#define ERR_REPEAT_OP "invalid nested repetition operator"
#define ERR_REPEAT_SIZE "invalid repeat count"
#define ERR_PERL_OP "invalid or unsupported Perl syntax"
#define ERR_NAMED_CAPTURE "invalid named capture"
#define ERR_UTF8 "invalid UTF-8"
#define ERR_NESTING "expression nests too deeply"

/* Decodes the rune at t->i; fails on invalid UTF-8 (checkUTF8/nextRune). */
static int next_rune(struct tr *t, size_t at, uint32_t *r, size_t *w)
{
    *w = ks_utf8_decode(t->s + at, t->n - at, r);
    if (*r == KS_RUNE_ERROR && *w == 1)
        return fail(t, ERR_UTF8, at, t->n);
    return 0;
}

static int unhex(uint32_t c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

static bool is_alnum(uint32_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

static bool is_word(char c)
{
    return is_alnum((unsigned char)c) || c == '_';
}

/* parseEscape: a single-character escape at t->i (which points at '\').
 * Returns the rune and advances t->i. */
static int parse_escape(struct tr *t, uint32_t *out)
{
    size_t start = t->i;
    size_t p = t->i + 1;
    if (p >= t->n)
        return fail(t, "trailing backslash at end of expression", start, t->n);

    uint32_t c;
    size_t w;
    if (next_rune(t, p, &c, &w) < 0)
        return -1;
    p += w;

    switch (c) {
    case '1': case '2': case '3': case '4': case '5': case '6': case '7':
        /* Single non-zero digit is a backreference; not supported. */
        if (p >= t->n || t->s[p] < '0' || t->s[p] > '7')
            break;
        /* fall through */
    case '0': {
        uint32_t r = c - '0';
        for (int k = 1; k < 3; k++) {
            if (p >= t->n || t->s[p] < '0' || t->s[p] > '7')
                break;
            r = r * 8 + (uint32_t)(t->s[p] - '0');
            p++;
        }
        *out = r;
        t->i = p;
        return 0;
    }
    case 'x': {
        if (p >= t->n)
            break;
        if (next_rune(t, p, &c, &w) < 0)
            return -1;
        p += w;
        if (c == '{') {
            int nhex = 0;
            uint32_t r = 0;
            for (;;) {
                if (p >= t->n)
                    return fail(t, ERR_ESCAPE, start, p);
                if (next_rune(t, p, &c, &w) < 0)
                    return -1;
                p += w;
                if (c == '}')
                    break;
                int v = unhex(c);
                if (v < 0)
                    return fail(t, ERR_ESCAPE, start, p);
                r = r * 16 + (uint32_t)v;
                if (r > 0x10FFFF)
                    return fail(t, ERR_ESCAPE, start, p);
                nhex++;
            }
            if (nhex == 0)
                return fail(t, ERR_ESCAPE, start, p);
            *out = r;
            t->i = p;
            return 0;
        }
        int x = unhex(c);
        if (p >= t->n)
            return fail(t, ERR_ESCAPE, start, p);
        if (next_rune(t, p, &c, &w) < 0)
            return -1;
        p += w;
        int y = unhex(c);
        if (x < 0 || y < 0)
            break;
        *out = (uint32_t)(x * 16 + y);
        t->i = p;
        return 0;
    }
    case 'a': *out = 7; t->i = p; return 0;
    case 'f': *out = '\f'; t->i = p; return 0;
    case 'n': *out = '\n'; t->i = p; return 0;
    case 'r': *out = '\r'; t->i = p; return 0;
    case 't': *out = '\t'; t->i = p; return 0;
    case 'v': *out = '\v'; t->i = p; return 0;
    default:
        if (c < 0x80 && !is_alnum(c)) {
            /* Escaped punctuation is a literal. */
            *out = c;
            t->i = p;
            return 0;
        }
        break;
    }
    return fail(t, ERR_ESCAPE, start, p);
}

/* Emits a literal rune so PCRE2 reads it literally. */
static void emit_literal(struct tr *t, uint32_t r)
{
    if (r >= 0xD800 && r <= 0xDFFF) {
        /* A surrogate can't occur in a decoded Go string: never matches. */
        puts_(&t->out, "(?!)");
    } else if (r < 0x80 && is_alnum(r)) {
        char c = (char)r;
        put(&t->out, &c, 1);
    } else {
        put_rune(&t->out, r);
    }
}

/* Perl class escapes \d \D \s \S \w \W (parsePerlClassEscape). `in_class`
 * selects the form usable inside brackets. Returns 1 if consumed. */
static int perl_class(struct tr *t, bool in_class)
{
    if (t->i + 1 >= t->n || t->s[t->i] != '\\')
        return 0;
    char c = t->s[t->i + 1];
    const char *rep = NULL;
    switch (c) {
    case 'd': rep = "\\d"; break;
    case 'D': rep = "\\D"; break;
    case 'w': rep = "\\w"; break;
    case 'W': rep = "\\W"; break;
    /* Go's \s is [\t\n\f\r ]; PCRE2's also has \v. */
    case 's': rep = in_class ? "\\t\\n\\f\\r " : "[\\t\\n\\f\\r ]"; break;
    case 'S':
        rep = in_class ? "\\x{0}-\\x{8}\\x{b}\\x{e}-\\x{1f}\\x{21}-\\x{10ffff}"
                       : "[^\\t\\n\\f\\r ]";
        break;
    default:
        return 0;
    }
    puts_(&t->out, rep);
    t->i += 2;
    return 1;
}

/* Go 1.23's unicode.Categories and unicode.Scripts (Unicode 15.0), the
 * names regexp/syntax accepts in \\p{...}. Sorted for bsearch. */
static const char *const unicode_names[] = {
    "Adlam", "Ahom", "Anatolian_Hieroglyphs", "Arabic", "Armenian",
    "Avestan", "Balinese", "Bamum", "Bassa_Vah", "Batak", "Bengali",
    "Bhaiksuki", "Bopomofo", "Brahmi", "Braille", "Buginese", "Buhid", "C",
    "Canadian_Aboriginal", "Carian", "Caucasian_Albanian", "Cc", "Cf",
    "Chakma", "Cham", "Cherokee", "Chorasmian", "Co", "Common", "Coptic",
    "Cs", "Cuneiform", "Cypriot", "Cypro_Minoan", "Cyrillic", "Deseret",
    "Devanagari", "Dives_Akuru", "Dogra", "Duployan", "Egyptian_Hieroglyphs",
    "Elbasan", "Elymaic", "Ethiopic", "Georgian", "Glagolitic", "Gothic",
    "Grantha", "Greek", "Gujarati", "Gunjala_Gondi", "Gurmukhi", "Han",
    "Hangul", "Hanifi_Rohingya", "Hanunoo", "Hatran", "Hebrew", "Hiragana",
    "Imperial_Aramaic", "Inherited", "Inscriptional_Pahlavi",
    "Inscriptional_Parthian", "Javanese", "Kaithi", "Kannada", "Katakana",
    "Kawi", "Kayah_Li", "Kharoshthi", "Khitan_Small_Script", "Khmer",
    "Khojki", "Khudawadi", "L", "Lao", "Latin", "Lepcha", "Limbu",
    "Linear_A", "Linear_B", "Lisu", "Ll", "Lm", "Lo", "Lt", "Lu", "Lycian",
    "Lydian", "M", "Mahajani", "Makasar", "Malayalam", "Mandaic",
    "Manichaean", "Marchen", "Masaram_Gondi", "Mc", "Me", "Medefaidrin",
    "Meetei_Mayek", "Mende_Kikakui", "Meroitic_Cursive",
    "Meroitic_Hieroglyphs", "Miao", "Mn", "Modi", "Mongolian", "Mro",
    "Multani", "Myanmar", "N", "Nabataean", "Nag_Mundari", "Nandinagari",
    "Nd", "New_Tai_Lue", "Newa", "Nko", "Nl", "No", "Nushu",
    "Nyiakeng_Puachue_Hmong", "Ogham", "Ol_Chiki", "Old_Hungarian",
    "Old_Italic", "Old_North_Arabian", "Old_Permic", "Old_Persian",
    "Old_Sogdian", "Old_South_Arabian", "Old_Turkic", "Old_Uyghur", "Oriya",
    "Osage", "Osmanya", "P", "Pahawh_Hmong", "Palmyrene", "Pau_Cin_Hau",
    "Pc", "Pd", "Pe", "Pf", "Phags_Pa", "Phoenician", "Pi", "Po", "Ps",
    "Psalter_Pahlavi", "Rejang", "Runic", "S", "Samaritan", "Saurashtra",
    "Sc", "Sharada", "Shavian", "Siddham", "SignWriting", "Sinhala", "Sk",
    "Sm", "So", "Sogdian", "Sora_Sompeng", "Soyombo", "Sundanese",
    "Syloti_Nagri", "Syriac", "Tagalog", "Tagbanwa", "Tai_Le", "Tai_Tham",
    "Tai_Viet", "Takri", "Tamil", "Tangsa", "Tangut", "Telugu", "Thaana",
    "Thai", "Tibetan", "Tifinagh", "Tirhuta", "Toto", "Ugaritic", "Vai",
    "Vithkuqi", "Wancho", "Warang_Citi", "Yezidi", "Yi", "Z",
    "Zanabazar_Square", "Zl", "Zp", "Zs",
};

static int cmp_name(const void *key, const void *elem)
{
    return strcmp(key, *(const char *const *)elem);
}

static bool known_unicode_name(const char *name)
{
    return bsearch(name, unicode_names, sizeof(unicode_names) / sizeof(unicode_names[0]),
                   sizeof(unicode_names[0]), cmp_name) != NULL;
}

/* Unicode classes \pL, \p{Greek}, \p{^Greek}, \PL (parseUnicodeClass).
 * Names must be in Go's tables; PCRE2 knows the same categories and
 * scripts (one built with Unicode < 15 lacks Kawi and Nag_Mundari, and then
 * rejects them).
 * Returns 1 if consumed (2 if it emitted nothing), 0 if not a \p escape,
 * -1 on error. */
static int unicode_class(struct tr *t, bool in_class)
{
    size_t start = t->i;
    if (t->i + 1 >= t->n || t->s[t->i] != '\\' ||
        (t->s[t->i + 1] != 'p' && t->s[t->i + 1] != 'P'))
        return 0;
    char sign = t->s[t->i + 1];
    size_t p = t->i + 2;
    if (p >= t->n)
        return fail(t, ERR_CLASS_RANGE, start, p);

    uint32_t c;
    size_t w;
    if (next_rune(t, p, &c, &w) < 0)
        return -1;
    char name[64];
    bool neg = false;
    if (c != '{') {
        /* Single-letter name. */
        if (c >= 0x80 || !is_alnum(c))
            return fail(t, ERR_CLASS_RANGE, start, p + w);
        name[0] = (char)c;
        name[1] = '\0';
        p += w;
    } else {
        const char *end = memchr(t->s + p, '}', t->n - p);
        if (end == NULL)
            return fail(t, ERR_CLASS_RANGE, start, t->n);
        size_t from = p + 1, to = (size_t)(end - t->s);
        if (from < to && t->s[from] == '^') {
            neg = true;
            from++;
        }
        if (from == to || to - from >= sizeof(name))
            return fail(t, ERR_CLASS_RANGE, start, to + 1);
        for (size_t k = from; k < to; k++)
            if (!is_word(t->s[k]))
                return fail(t, ERR_CLASS_RANGE, start, to + 1);
        memcpy(name, t->s + from, to - from);
        name[to - from] = '\0';
        p = to + 1;
    }
    if (sign == 'P')
        neg = !neg;
    if (strcmp(name, "Any") != 0 && !known_unicode_name(name))
        return fail(t, ERR_CLASS_RANGE, start, p);
    t->i = p;
    /* Go's "Any" is every rune; PCRE2 calls it "Any" too, but spell it out
     * so the negation inside a class is simply "nothing". */
    if (strcmp(name, "Any") == 0) {
        if (neg) {
            if (in_class)
                return 2;
            puts_(&t->out, "(?!)");
        } else {
            puts_(&t->out, in_class ? "\\x{0}-\\x{10ffff}" : "[\\x{0}-\\x{10ffff}]");
        }
        return 1;
    }
    puts_(&t->out, neg ? "\\P{" : "\\p{");
    puts_(&t->out, name);
    puts_(&t->out, "}");
    return 1;
}

static const char *const posix_names[] = {
    "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph",
    "lower", "print", "punct", "space", "upper", "word", "xdigit",
};

/* parseClass: t->i points at '['. */
static int parse_class(struct tr *t)
{
    size_t start = t->i;
    size_t out_start = t->out.len;
    size_t items = 0;
    bool negated = false;
    t->i++;
    put(&t->out, "[", 1);
    if (t->i < t->n && t->s[t->i] == '^') {
        put(&t->out, "^", 1);
        negated = true;
        t->i++;
    }
    bool first = true;
    for (;;) {
        if (t->i >= t->n)
            return fail(t, ERR_MISSING_BRACKET, start, t->n);
        if (t->s[t->i] == ']' && !first)
            break;
        first = false;

        /* POSIX [:alnum:] */
        if (t->n - t->i > 2 && t->s[t->i] == '[' && t->s[t->i + 1] == ':') {
            const char *end = NULL;
            for (size_t k = t->i + 2; k + 1 < t->n; k++)
                if (t->s[k] == ':' && t->s[k + 1] == ']') {
                    end = t->s + k;
                    break;
                }
            if (end != NULL) {
                size_t from = t->i + 2, to = (size_t)(end - t->s);
                bool neg = from < to && t->s[from] == '^';
                if (neg)
                    from++;
                bool known = false;
                for (size_t k = 0; k < sizeof(posix_names) / sizeof(posix_names[0]); k++)
                    if (strlen(posix_names[k]) == to - from &&
                        memcmp(posix_names[k], t->s + from, to - from) == 0)
                        known = true;
                if (!known)
                    return fail(t, ERR_CLASS_RANGE, t->i, to + 2);
                puts_(&t->out, neg ? "[:^" : "[:");
                put(&t->out, t->s + from, to - from);
                puts_(&t->out, ":]");
                t->i = to + 2;
                items++;
                continue;
            }
        }

        int u = unicode_class(t, true);
        if (u < 0)
            return -1;
        if (u > 0) {
            items += u == 1;
            continue;
        }
        if (perl_class(t, true)) {
            items++;
            continue;
        }

        /* Single character or range. */
        size_t rng = t->i;
        uint32_t lo, hi;
        if (t->s[t->i] == '\\') {
            if (parse_escape(t, &lo) < 0)
                return -1;
        } else {
            size_t w;
            if (next_rune(t, t->i, &lo, &w) < 0)
                return -1;
            t->i += w;
        }
        hi = lo;
        /* [a-] means (a|-), so check for a final ]. */
        if (t->n - t->i >= 2 && t->s[t->i] == '-' && t->s[t->i + 1] != ']') {
            t->i++;
            if (t->i >= t->n)
                return fail(t, ERR_MISSING_BRACKET, start, t->n);
            if (t->s[t->i] == '\\') {
                if (parse_escape(t, &hi) < 0)
                    return -1;
            } else {
                size_t w;
                if (next_rune(t, t->i, &hi, &w) < 0)
                    return -1;
                t->i += w;
            }
            if (hi < lo)
                return fail(t, ERR_CLASS_RANGE, rng, t->i);
        }
        /* Surrogates never occur in decoded text; skip them. */
        if (lo >= 0xD800 && hi <= 0xDFFF)
            continue;
        if (lo >= 0xD800 && lo <= 0xDFFF)
            lo = 0xE000;
        if (hi >= 0xD800 && hi <= 0xDFFF)
            hi = 0xD7FF;
        put_rune(&t->out, lo);
        if (hi != lo) {
            put(&t->out, "-", 1);
            put_rune(&t->out, hi);
        }
        items++;
    }
    t->i++; /* ] */
    if (items == 0 && !t->out.oom) {
        /* Only surrogates or \P{Any}: matches nothing (or, negated,
         * anything). PCRE2 has no empty class, so spell it out. */
        t->out.len = out_start;
        t->out.p[out_start] = '\0';
        puts_(&t->out, negated ? "[\\x{0}-\\x{10ffff}]" : "(?!)");
        return 0;
    }
    put(&t->out, "]", 1);
    return 0;
}

/* Called after emitting an atom (anything a quantifier may follow). */
static void atom(struct tr *t, long need)
{
    struct frame *f = &t->frames[t->depth];
    f->has_atom = true;
    f->last_need = need;
    if (need > f->need)
        f->need = need;
}

/* parseRepeat for "{": returns true and min/max (max -1 = unbounded, min -1
 * = too big) if s[i..] is a valid repeat, advancing *end past '}'. */
static bool parse_repeat_braces(const struct tr *t, size_t i, long *min,
                                long *max, size_t *end)
{
    /* parseInt: digits without leading zeros; too-big values become -1. */
    size_t p = i + 1;
    long v[2] = {0, 0};
    int which = 0;
    for (;;) {
        if (p >= t->n || t->s[p] < '0' || t->s[p] > '9')
            return false;
        if (p + 1 < t->n && t->s[p] == '0' && t->s[p + 1] >= '0' &&
            t->s[p + 1] <= '9')
            return false;
        long n = 0;
        while (p < t->n && t->s[p] >= '0' && t->s[p] <= '9') {
            if (n >= 0) {
                if (n >= 100000000)
                    n = -1;
                else
                    n = n * 10 + (t->s[p] - '0');
            }
            p++;
        }
        v[which] = n;
        if (p >= t->n)
            return false;
        if (which == 0 && t->s[p] == ',') {
            p++;
            if (p >= t->n)
                return false;
            if (t->s[p] == '}') {
                *min = v[0];
                *max = -1;
                *end = p + 1;
                return true;
            }
            which = 1;
            continue;
        }
        if (t->s[p] != '}')
            return false;
        *min = v[0];
        *max = which == 0 ? v[0] : v[1];
        if (which == 1 && v[1] < 0)
            *min = -1; /* max too big */
        *end = p + 1;
        return true;
    }
}

/* repeat(): applies a quantifier to the last atom. */
static int repeat(struct tr *t, size_t before, size_t after, long min,
                  long max, bool braces)
{
    struct frame *f = &t->frames[t->depth];

    bool lazy = after < t->n && t->s[after] == '?';
    if (lazy)
        after++;
    if (t->last_repeat)
        return fail(t, ERR_REPEAT_OP, before, after);
    if (!f->has_atom)
        return fail(t, ERR_REPEAT_ARG, before, after);

    if (braces) {
        /* repeatIsValid: nested repeat counts multiply up to 1000. */
        long m = max;
        long need;
        if (m == 0)
            need = 0;
        else {
            if (m < 0)
                m = min;
            need = m > 0 ? m * (f->last_need > 1 ? f->last_need : 1)
                         : f->last_need;
        }
        if ((min >= 2 || max >= 2) && need > MAX_REPEAT)
            return fail(t, ERR_REPEAT_SIZE, before, after);
        f->last_need = need > MAX_REPEAT ? MAX_REPEAT + 1 : need;
        if (f->last_need > f->need)
            f->need = f->last_need;
        char buf[48];
        if (max < 0)
            snprintf(buf, sizeof(buf), "{%ld,}", min);
        else if (max == min)
            snprintf(buf, sizeof(buf), "{%ld}", min);
        else
            snprintf(buf, sizeof(buf), "{%ld,%ld}", min, max);
        puts_(&t->out, buf);
    } else {
        put(&t->out, t->s + before, 1);
    }
    if (lazy)
        put(&t->out, "?", 1);
    t->i = after;
    t->last_repeat = true;
    return 0;
}

static int open_group(struct tr *t, size_t at)
{
    if (t->depth >= MAX_DEPTH)
        return fail(t, ERR_NESTING, at, t->n);
    t->depth++;
    memset(&t->frames[t->depth], 0, sizeof(t->frames[t->depth]));
    return 0;
}

/* parsePerlFlags: t->i points at "(?". */
static int perl_flags(struct tr *t)
{
    size_t start = t->i;
    const char *s = t->s + t->i;
    size_t rem = t->n - t->i;

    bool with_p = rem > 4 && s[2] == 'P' && s[3] == '<';
    bool with_name = rem > 3 && s[2] == '<';
    if (with_p || with_name) {
        size_t name_at = with_p ? 4 : 3;
        const char *end = memchr(s, '>', rem);
        if (end == NULL) {
            for (size_t k = t->i; k < t->n;) {
                uint32_t r;
                size_t w;
                if (next_rune(t, k, &r, &w) < 0)
                    return -1;
                k += w;
            }
            return fail(t, ERR_NAMED_CAPTURE, start, t->n);
        }
        size_t name_len = (size_t)(end - s) - name_at;
        size_t cap_end = (size_t)(end - t->s) + 1;
        for (size_t k = 0; k < name_len;) {
            uint32_t r;
            size_t w;
            if (next_rune(t, t->i + name_at + k, &r, &w) < 0)
                return -1;
            k += w;
        }
        if (name_len == 0)
            return fail(t, ERR_NAMED_CAPTURE, start, cap_end);
        for (size_t k = 0; k < name_len; k++)
            if (!is_word(s[name_at + k]))
                return fail(t, ERR_NAMED_CAPTURE, start, cap_end);
        /* Names don't matter for matching: a plain group. Go accepts
         * repeated names ((?P<n>a)(?P<n>b)), so there is nothing to track. */
        put(&t->out, "(", 1);
        t->i = cap_end;
        return open_group(t, start);
    }

    /* Flags: [imsU]*(-[imsU]+)? followed by ':' or ')'. */
    size_t p = 2;
    int sign = 1;
    bool saw_flag = false;
    while (p < rem) {
        char c = s[p++];
        switch (c) {
        case 'i': case 'm': case 's': case 'U':
            saw_flag = true;
            continue;
        case '-':
            if (sign < 0)
                goto bad;
            sign = -1;
            saw_flag = false;
            continue;
        case ':':
        case ')':
            if (sign < 0 && !saw_flag)
                goto bad;
            put(&t->out, s, p);
            t->i += p;
            if (c == ':')
                return open_group(t, start);
            /* A bare flag group isn't an atom: (?i)* is an error. */
            t->frames[t->depth].has_atom = false;
            return 0;
        default:
            goto bad;
        }
    }
bad:
    /* Report non-UTF-8 like Go does (nextRune fails first). */
    for (size_t k = t->i; k < t->i + p && k < t->n;) {
        uint32_t r;
        size_t w;
        if (next_rune(t, k, &r, &w) < 0)
            return -1;
        k += w;
    }
    return fail(t, ERR_PERL_OP, start, t->i + p);
}

static int translate(struct tr *t)
{
    while (t->i < t->n) {
        bool was_repeat = false;
        char c = t->s[t->i];
        size_t at = t->i;

        switch (c) {
        case '(':
            if (t->i + 1 < t->n && t->s[t->i + 1] == '?') {
                if (perl_flags(t) < 0)
                    return -1;
                break;
            }
            put(&t->out, "(", 1);
            t->i++;
            if (open_group(t, at) < 0)
                return -1;
            break;
        case '|':
            put(&t->out, "|", 1);
            t->i++;
            t->frames[t->depth].has_atom = false;
            break;
        case ')': {
            if (t->depth == 0)
                return fail(t, ERR_UNEXPECTED_PAREN, 0, t->n);
            long need = t->frames[t->depth].need;
            t->depth--;
            put(&t->out, ")", 1);
            t->i++;
            atom(t, need);
            break;
        }
        /* Zero-width assertions are wrapped in a group so that, like in Go,
         * they can take a quantifier. */
        case '^':
            puts_(&t->out, "(?:^)");
            t->i++;
            atom(t, 0);
            break;
        case '$':
            puts_(&t->out, "(?:$)");
            t->i++;
            atom(t, 0);
            break;
        case '.':
            put(&t->out, ".", 1);
            t->i++;
            atom(t, 0);
            break;
        case '[':
            if (parse_class(t) < 0)
                return -1;
            atom(t, 0);
            break;
        case '*':
        case '+':
        case '?':
            if (repeat(t, at, at + 1, 0, 0, false) < 0)
                return -1;
            was_repeat = true;
            break;
        case '{': {
            long min, max;
            size_t end;
            if (!parse_repeat_braces(t, at, &min, &max, &end)) {
                /* Not a valid repeat: '{' is a literal. */
                puts_(&t->out, "\\{");
                t->i++;
                atom(t, 0);
                break;
            }
            if (min < 0 || min > MAX_REPEAT || max > MAX_REPEAT ||
                (max >= 0 && min > max))
                return fail(t, ERR_REPEAT_SIZE, at, end);
            if (repeat(t, at, end, min, max, true) < 0)
                return -1;
            was_repeat = true;
            break;
        }
        case '\\': {
            if (t->i + 1 < t->n) {
                char e = t->s[t->i + 1];
                const char *assert = NULL;
                switch (e) {
                case 'A': assert = "(?:\\A)"; break;
                case 'z': assert = "(?:\\z)"; break;
                case 'b': assert = "(?:\\b)"; break;
                case 'B': assert = "(?:\\B)"; break;
                case 'C':
                    return fail(t, ERR_ESCAPE, at, at + 2);
                case 'Q': {
                    /* \Q...\E: everything up to \E (or the end) is literal. */
                    size_t p = t->i + 2;
                    size_t stop = t->n; /* where the literal text ends */
                    size_t next = stop;   /* where parsing resumes */
                    for (size_t k = p; k + 1 < t->n; k++)
                        if (t->s[k] == '\\' && t->s[k + 1] == 'E') {
                            stop = k;
                            next = k + 2;
                            break;
                        }
                    while (p < stop) {
                        uint32_t r;
                        size_t w;
                        if (next_rune(t, p, &r, &w) < 0)
                            return -1;
                        if (p + w > stop) /* rune cut by \E */
                            return fail(t, ERR_UTF8, p, t->n);
                        /* Each literal is its own atom. */
                        t->last_repeat = false;
                        emit_literal(t, r);
                        atom(t, 0);
                        p += w;
                    }
                    t->i = next;
                    if (stop == p) /* nothing was quoted, or it all was */
                        t->last_repeat = false;
                    continue;
                }
                default:
                    break;
                }
                if (assert != NULL) {
                    puts_(&t->out, assert);
                    t->i += 2;
                    atom(t, 0);
                    break;
                }
            }
            int u = unicode_class(t, false);
            if (u < 0)
                return -1;
            if (u > 0) {
                atom(t, 0);
                break;
            }
            if (perl_class(t, false)) {
                atom(t, 0);
                break;
            }
            uint32_t r;
            if (parse_escape(t, &r) < 0)
                return -1;
            emit_literal(t, r);
            atom(t, 0);
            break;
        }
        default: {
            uint32_t r;
            size_t w;
            if (next_rune(t, t->i, &r, &w) < 0)
                return -1;
            if (r < 0x80 && !is_alnum(r))
                put_rune(&t->out, r);
            else
                put(&t->out, t->s + t->i, w);
            t->i += w;
            atom(t, 0);
            break;
        }
        }
        t->last_repeat = was_repeat;
    }
    if (t->depth > 0)
        return fail(t, ERR_MISSING_PAREN, 0, t->n);
    return 0;
}

char *ks_regex_translate(const char *pattern, char *err, size_t errlen)
{
    struct tr *t = calloc(1, sizeof(*t));
    if (t == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    t->s = pattern;
    t->n = strlen(pattern);
    t->err = err;
    t->errlen = errlen;
    put(&t->out, "", 0);

    int ret = translate(t);
    if (ret == 0 && t->out.oom) {
        snprintf(err, errlen, "out of memory");
        ret = -1;
    }
    char *out = t->out.p;
    free(t);
    if (ret < 0) {
        free(out);
        return NULL;
    }
    return out;
}

struct ks_regex *ks_regex_compile(const char *pattern, char *err, size_t errlen)
{
    return ks_regex_compile_flags(pattern, 0, err, errlen);
}

struct ks_regex *ks_regex_compile_flags(const char *pattern, int flags, char *err,
                                        size_t errlen)
{
    char *pcre = ks_regex_translate(pattern, err, errlen);
    if (pcre == NULL)
        return NULL;

    struct ks_regex *re = calloc(1, sizeof(*re));
    pcre2_compile_context *cctx = pcre2_compile_context_create(NULL);
    if (re == NULL || cctx == NULL) {
        snprintf(err, errlen, "out of memory");
        goto fail;
    }
    pcre2_set_newline(cctx, PCRE2_NEWLINE_LF);
    pcre2_set_parens_nest_limit(cctx, MAX_DEPTH + 10);

    int code;
    PCRE2_SIZE off;
    re->code = pcre2_compile((PCRE2_SPTR)pcre, PCRE2_ZERO_TERMINATED,
                             PCRE2_UTF | PCRE2_DOLLAR_ENDONLY |
                                 PCRE2_ALT_CIRCUMFLEX | PCRE2_NEVER_BACKSLASH_C |
                                 ((flags & KS_REGEX_CAPTURE) ? 0 : PCRE2_NO_AUTO_CAPTURE),
                             &code, &off, cctx);
    if (re->code == NULL) {
        char msg[160];
        pcre2_get_error_message(code, (PCRE2_UCHAR *)msg, sizeof(msg));
        snprintf(err, errlen, "error parsing regexp: %s: `%s`", msg, pattern);
        goto fail;
    }
    re->md = (flags & KS_REGEX_CAPTURE)
                 ? pcre2_match_data_create_from_pattern(re->code, NULL)
                 : pcre2_match_data_create(1, NULL);
    re->mctx = pcre2_match_context_create(NULL);
    if (re->md == NULL || re->mctx == NULL) {
        snprintf(err, errlen, "out of memory");
        goto fail;
    }
    pcre2_set_match_limit(re->mctx, MATCH_LIMIT);
    pcre2_compile_context_free(cctx);
    free(pcre);
    return re;

fail:
    pcre2_compile_context_free(cctx);
    ks_regex_free(re);
    free(pcre);
    return NULL;
}

int ks_regex_match(struct ks_regex *re, const char *subject)
{
    /* Go reads each invalid UTF-8 byte as U+FFFD; give PCRE2 the same. */
    size_t len = strlen(subject);
    char *clean = NULL;
    if (!ks_utf8_valid(subject, len) &&
        (clean = ks_utf8_sanitize(subject, len, &len)) == NULL)
        return 0;
    const char *s = clean != NULL ? clean : subject;

    int rc = pcre2_match(re->code, (PCRE2_SPTR)s, len, 0, 0, re->md, re->mctx);
    free(clean);
    return rc >= 0 ? 1 : 0;
}

int ks_regex_find_submatch(struct ks_regex *re, const char *subject, size_t len,
                           long *offsets, int max_groups)
{
    if (!ks_utf8_valid(subject, len))
        return -1;
    int rc = pcre2_match(re->code, (PCRE2_SPTR)subject, len, 0, 0, re->md,
                         re->mctx);
    if (rc < 0)
        return 0;
    /* rc == 0: more groups than the match data holds (can't happen with
     * match data created from the pattern). */
    uint32_t pairs = pcre2_get_ovector_count(re->md);
    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(re->md);
    int n = (int)pairs < max_groups ? (int)pairs : max_groups;
    for (int i = 0; i < n; i++) {
        bool unset = ov[2 * i] == PCRE2_UNSET || i >= (rc ? rc : (int)pairs);
        offsets[2 * i] = unset ? -1 : (long)ov[2 * i];
        offsets[2 * i + 1] = unset ? -1 : (long)ov[2 * i + 1];
    }
    return n;
}

void ks_regex_free(struct ks_regex *re)
{
    if (re == NULL)
        return;
    pcre2_match_data_free(re->md);
    pcre2_match_context_free(re->mctx);
    pcre2_code_free(re->code);
    free(re);
}
