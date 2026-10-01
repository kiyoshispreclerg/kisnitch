/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Durations.
 *
 * Upstream parses every textual interval (FwOptions.MonitorInterval, temporary
 * rule durations such as "30s" or "1h", task intervals, logger timeouts) with
 * Go's time.ParseDuration, so ks_parse_duration() reproduces it exactly,
 * including the accepted syntax, overflow limits and error texts.
 *
 * Rule durations add three keywords on top (upstream daemon/rule/rule.go):
 * "once", "until restart" and "always". Any other value is a temporary rule
 * whose lifetime is parsed with ks_parse_duration().
 */
#ifndef KS_COMMON_DURATION_H
#define KS_COMMON_DURATION_H

#include <stddef.h>
#include <stdint.h>

#define KS_NANOSECOND  INT64_C(1)
#define KS_MICROSECOND (INT64_C(1000) * KS_NANOSECOND)
#define KS_MILLISECOND (INT64_C(1000) * KS_MICROSECOND)
#define KS_SECOND      (INT64_C(1000) * KS_MILLISECOND)
#define KS_MINUTE      (INT64_C(60) * KS_SECOND)
#define KS_HOUR        (INT64_C(60) * KS_MINUTE)

/* Parses `s` (e.g. "300ms", "-1.5h", "2h45m") into nanoseconds.
 * Returns 0 on success. On failure returns -1 and, if `err` is not NULL,
 * writes a message identical to Go's error text into it. */
int ks_parse_duration(const char *s, int64_t *ns, char *err, size_t errlen);

/* Rule duration keywords, verbatim from upstream. */
#define KS_DURATION_ONCE    "once"
#define KS_DURATION_RESTART "until restart"
#define KS_DURATION_ALWAYS  "always"

enum ks_rule_duration {
    KS_RULE_ONCE,
    KS_RULE_UNTIL_RESTART,
    KS_RULE_ALWAYS,
    /* Anything else, as upstream's Loader.isTemporary(). The value may still
     * fail ks_parse_duration(), in which case upstream doesn't schedule the
     * rule's expiration. */
    KS_RULE_TEMPORARY,
};

enum ks_rule_duration ks_rule_duration_kind(const char *s);

#endif
