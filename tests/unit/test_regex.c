/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Go's regexp accepts/rejects these patterns and matches these subjects
 * (checked against Go's regexp/syntax rules; the differential test in
 * tests/diff/ runs them through Go itself).
 */
#include "daemon/rules/regex.h"

#include <stdlib.h>
#include <time.h>

#include "tests/harness.h"

static const char *const go_valid[] = {
    "", "|", "()", "a|", "^TCP$", "^/usr/bin/.*", "a{2,5}", "a{1000}",
    "a{0,1000}", "a{2,}", "(a|b)+", "(?i)abc", "(?i:abc)", "(?i-s:a.)",
    "(?P<name>x)", "(?<name>x)", "(?P<n>a)(?P<n>b)", "(?P<1a>x)", "[[:alpha:]]+", "[[:^space:]]",
    "[^a-z]", "\\pL", "\\p{Greek}", "\\PL", "\\p{^Greek}", "\\p{Any}",
    "[\\p{Lu}\\d]", "\\p{Old_Italic}", "\\pS", "\\p{Zs}", "\\x41", "\\x{263a}", "\\Q.*+?\\E", "\\Q", "\\0", "\\012",
    "\\12", "\\17", "a*?", "a+?", "a??", "a{2}?", "(?s).", "(?m)^a$", "[]a]",
    "[a-]", "[-a]", "\\.", "\\-", "\\ ", "a{", "a{,3}", "a{01}", "a{1,2",
    "x{2}{", "^*", "$+", "\\b*", "(?i)", "(?)", "\\b\\B\\A\\z",
    "\\d\\D\\s\\S\\w\\W", "[\\d\\s]", "(?U)a+", "(a{10}){100}",
    "\xc3\xa9t\xc3\xa9", "[\xc3\xa0-\xc3\xbf]", "\\a\\f\\t\\n\\r\\v",
    "((((a))))", "[[]", "[a[]", "a]", "a}", "#", "\\#", "[\\[\\]]",
};

static const char *const go_invalid[] = {
    "^TC(P$", "/opt/((.*)google/chrome/chrome", "^(/di(rmngr)$", "a)", ")",
    "a**", "a*+", "a++", "a?*", "a{2}*", "a*{2}", "a*??", "a{1001}",
    "a{2,1}", "a{0,1001}", "(a{500}){3}", "((a{10}){10}){11}", "(?=a)",
    "(?!a)", "(?<=a)", "(?<!a)", "(?>a)", "(?#c)", "(?|a)", "(?P=n)",
    "(?P>n)", "(?x)a", "(?R)", "(?1)", "\\1", "\\7", "(a)\\1", "\\8", "\\9", "\\Z",
    "\\G", "\\K", "\\h", "\\e", "\\C", "\\c", "\\g1", "\\k<n>", "\\u0041",
    "\\N", "\\X", "\\R", "\\E", "[\\b]", "[\\A]", "[\\Q]", "[a", "[]",
    "[z-a]", "[[:foo:]]", "\\p", "\\p{", "\\p{}", "\\p{^}", "\\p\xc3\xa9",
    "\\ps", "[^\\Ps]", "\\p{greek}", "\\p{Klingon}", "\\p{L&}", "\\p{Xan}",
    "*a", "a|*", "(*)", "(?i)*", "+", "\\xZZ", "\\x", "\\x1", "\\x{}",
    "\\x{110000}", "\\x{12", "(?P<>a)", "(?P<a-b>x)",
    "(?P<n", "\xff", "a\xc3", "\\", "a\\", "(?i-)", "(?-)", "(?i--s)",
    "(?ii", "(?", "\\\xc3\xa9", "(*UTF)a",
};

TEST(accepts_what_go_accepts)
{
    for (size_t i = 0; i < sizeof(go_valid) / sizeof(go_valid[0]); i++) {
        char err[256] = "";
        struct ks_regex *re = ks_regex_compile(go_valid[i], err, sizeof(err));
        CHECK_MSG(re != NULL, "\"%s\" should compile: %s", go_valid[i], err);
        ks_regex_free(re);
    }
}

TEST(rejects_what_go_rejects)
{
    for (size_t i = 0; i < sizeof(go_invalid) / sizeof(go_invalid[0]); i++) {
        char err[256] = "";
        struct ks_regex *re = ks_regex_compile(go_invalid[i], err, sizeof(err));
        CHECK_MSG(re == NULL, "\"%s\" should be rejected", go_invalid[i]);
        CHECK_STR_HAS(err, "error parsing regexp: ");
    }
}

TEST(error_messages_name_the_problem)
{
    char err[256];
    CHECK(ks_regex_compile("^TC(P$", err, sizeof(err)) == NULL);
    CHECK_STR_EQ(err, "error parsing regexp: missing closing ): `^TC(P$`");
    CHECK(ks_regex_compile("a**", err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "invalid nested repetition operator");
    CHECK(ks_regex_compile("(?=a)", err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "invalid or unsupported Perl syntax: `(?=`");
    CHECK(ks_regex_compile("\\1", err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "invalid escape sequence: `\\1`");
    CHECK(ks_regex_compile("a{1001}", err, sizeof(err)) == NULL);
    CHECK_STR_HAS(err, "invalid repeat count: `{1001}`");
}

static const struct {
    const char *re, *subject;
    int want;
} matches[] = {
    {"^TCP$", "TCP", 1},
    {"^TCP$", "TCP\n", 0},            /* $ is end of text without (?m) */
    {"(?m)^TCP$", "x\nTCP\n", 1},
    {"(?m)^$", "a\n", 1},             /* empty line after the final \n */
    {"\\s", "\v", 0},                 /* Go's \s has no \v */
    {"\\s", "\t", 1},
    {"[\\s]", "\v", 0},
    {"\\S", "\v", 1},
    {"[\\S]", "\v", 1},
    {"[^\\S]", " ", 1},
    {"\\v", "\x0b", 1},               /* \v is VT, not a class */
    {"\\v", "\n", 0},
    {"a{01}", "a{01}", 1},            /* not a repeat in Go */
    {"a{01}", "a", 0},
    {"a{,3}", "a{,3}", 1},
    {"a{,3}", "aaa", 0},
    {"a{2}", "aa", 1},
    {"^a{2}$", "aaa", 0},
    {"\\12", "\n", 1},                /* octal */
    {"\\0", "", 0},
    {".", "\xff", 1},                 /* invalid byte = U+FFFD */
    {"^.$", "\xff", 1},
    {"\\x{fffd}", "\xff", 1},
    {"^..$", "\xc3\xa9\xff", 1},
    {"(?i)k", "\xe2\x84\xaa", 1},     /* Kelvin sign folds to k */
    {"(?i)OPENSNITCH", "opensnitch", 1},
    {"[^a]", "\n", 1},
    {".", "\n", 0},
    {"(?s).", "\n", 1},
    {"\\pL+", "\xe6\x97\xa5\xe6\x9c\xac", 1},
    {"\\p{Greek}", "\xce\xb1", 1},
    {"\\p{Greek}", "a", 0},
    {"\\p{Any}", "\n", 1},
    {"\\P{Any}", "a", 0},
    {"\\Qa.b\\E", "axb", 0},
    {"\\Qa.b\\E", "a.b", 1},
    {"\\Qa.b", "a.b", 1},
    {"x*", "", 1},
    {"\\bfoo\\b", "a foo b", 1},
    {"\\bfoo\\b", "afoob", 0},
    {"\\d", "\xd9\xa3", 0},           /* \d is ASCII only */
    {"\\w", "\xc3\xa9", 0},
    {"[[:^alpha:]]", "1", 1},
    {"[[:space:]]", "\v", 1},         /* POSIX space does include \v */
    {"[]a]", "]", 1},
    {"[a-]", "-", 1},
    {"[\xc3\xa0-\xc3\xbf]", "\xc3\xa9", 1},
    {"^*a", "a", 1},
    {"^/usr/bin/.*", "/usr/bin/curl", 1},
    {"^/usr/bin/.*", "/usr/sbin/curl", 0},
    {"a#b", "a#b", 1},
    {"a b", "a b", 1},
    {"(?U)a+", "aaa", 1},
    {"(?P<1a>x)y", "xy", 1},
    {"(?P<n>a)(?P<n>b)", "ab", 1},
    {"", "anything", 1},
};

TEST(matches_like_go)
{
    for (size_t i = 0; i < sizeof(matches) / sizeof(matches[0]); i++) {
        char err[256] = "";
        struct ks_regex *re = ks_regex_compile(matches[i].re, err, sizeof(err));
        CHECK_MSG(re != NULL, "\"%s\" should compile: %s", matches[i].re, err);
        int got = ks_regex_match(re, matches[i].subject);
        ks_regex_free(re);
        CHECK_MSG(got == matches[i].want, "/%s/ on \"%s\": got %d, want %d",
                  matches[i].re, matches[i].subject, got, matches[i].want);
    }
}

TEST(pathological_patterns_finish)
{
    char err[256];
    struct ks_regex *re = ks_regex_compile("(a+)+$", err, sizeof(err));
    CHECK(re != NULL);
    char subject[64];
    memset(subject, 'a', 40);
    subject[40] = '!';
    subject[41] = '\0';
    clock_t start = clock();
    CHECK_INT_EQ(ks_regex_match(re, subject), 0);
    CHECK_MSG(clock() - start < 5 * CLOCKS_PER_SEC, "took too long");
    ks_regex_free(re);
}

TEST(deep_nesting)
{
    /* Go allows 1000 levels of nesting; one more is an error. */
    char *p = malloc(2 * 1002 + 2);
    char err[256];
    CHECK(p != NULL);
    for (int depth = 1000; depth <= 1001; depth++) {
        memset(p, '(', (size_t)depth);
        p[depth] = 'a';
        memset(p + depth + 1, ')', (size_t)depth);
        p[2 * depth + 1] = '\0';
        struct ks_regex *re = ks_regex_compile(p, err, sizeof(err));
        if (depth == 1000) {
            CHECK_MSG(re != NULL, "depth 1000: %s", err);
            CHECK_INT_EQ(ks_regex_match(re, "a"), 1);
        } else {
            CHECK(re == NULL);
            CHECK_STR_HAS(err, "expression nests too deeply");
        }
        ks_regex_free(re);
    }
    free(p);
}

int main(void)
{
    RUN(accepts_what_go_accepts);
    RUN(rejects_what_go_rejects);
    RUN(error_messages_name_the_problem);
    RUN(matches_like_go);
    RUN(pathological_patterns_finish);
    RUN(deep_nesting);
    return harness_report();
}
