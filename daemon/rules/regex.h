/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Regular expressions with Go's regexp syntax and semantics, on top of PCRE2.
 *
 * Upstream compiles rule patterns with Go's regexp package (RE2 syntax). A Go
 * pattern is parsed here following regexp/syntax (Perl flags) and translated
 * to an equivalent PCRE2 pattern:
 *   - everything Go rejects is rejected: backreferences, lookaround, atomic
 *     groups, possessive or stacked quantifiers, \C \Z \G \K..., repeat counts
 *     over 1000 (also when nested), invalid UTF-8, bad group names;
 *   - constructs whose meaning differs are rewritten: \s and \S use Go's set
 *     [\t\n\f\r ], \v is the VT character, octal escapes, a '{' that Go reads
 *     as a literal, characters inside classes;
 *   - $ only matches at the very end without (?m), and (?m)^ also matches
 *     after a trailing newline, as in Go.
 * Subjects with invalid UTF-8 are matched as Go does, with each bad byte
 * read as U+FFFD.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a struct ks_regex owns the compiled code and its match data. Not
 * thread-safe: one regex must not be matched from two threads at once.
 */
#ifndef KS_DAEMON_RULES_REGEX_H
#define KS_DAEMON_RULES_REGEX_H

#include <stddef.h>

struct ks_regex;

/* Compiles a Go regexp. On error returns NULL and writes a message in Go's
 * style ("error parsing regexp: ...: `...`") to `err`. */
struct ks_regex *ks_regex_compile(const char *pattern, char *err, size_t errlen);

/* Returns 1 if `subject` matches anywhere, 0 if not. A match that hits the
 * PCRE2 backtracking limit counts as no match (Go's engine has no such
 * limit; see docs/UPSTREAM.md). */
int ks_regex_match(struct ks_regex *re, const char *subject);

void ks_regex_free(struct ks_regex *re);

/* Translation only (for tests and fuzzing). Returns a malloc'd PCRE2 pattern
 * or NULL with `err` filled. */
char *ks_regex_translate(const char *pattern, char *err, size_t errlen);

#endif
