/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * UTF-8 decoding and case mapping with the semantics of Go's unicode/utf8 and
 * strings packages, which upstream uses to compare rule data
 * (strings.EqualFold, strings.ToLower).
 *
 * Case mapping uses the C library's tables through a C.UTF-8 locale object
 * (towlower_l/towupper_l), which follow the Unicode simple case mappings like
 * Go does. If that locale isn't available only ASCII is mapped.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_COMMON_UNICODE_H
#define KS_COMMON_UNICODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KS_RUNE_ERROR 0xFFFDu

/* Decodes one rune from s[0..n), n > 0, like utf8.DecodeRuneInString:
 * invalid, overlong or surrogate encodings yield KS_RUNE_ERROR with width 1.
 * Returns the width in bytes. */
size_t ks_utf8_decode(const char *s, size_t n, uint32_t *rune);

/* Encodes `r` into buf (at least 4 bytes). Invalid runes encode as U+FFFD.
 * Returns the number of bytes written. */
size_t ks_utf8_encode(uint32_t r, char *buf);

/* Returns a malloc'd copy of s[0..n) with every invalid UTF-8 byte replaced
 * by U+FFFD, as Go does when decoding JSON strings or ranging over a
 * string; *out_len gets the new length. NULL on OOM. */
char *ks_utf8_sanitize(const char *s, size_t n, size_t *out_len);

/* True if s[0..n) is valid UTF-8 (Go's utf8.ValidString). */
bool ks_utf8_valid(const char *s, size_t n);

/* strings.ToLower: returns a malloc'd copy (NULL on OOM). Invalid UTF-8
 * bytes become U+FFFD, as Go's strings.Map does (ASCII-only input is copied
 * with only A-Z mapped). */
char *ks_str_to_lower(const char *s);

/* strings.EqualFold: equality under Unicode simple case folding. */
bool ks_str_equal_fold(const char *a, const char *b);

#endif
