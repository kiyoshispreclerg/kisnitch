#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fills po/<locale>.po from the upstream Qt .ts files (ui/i18n/locales/).

The message ids are the ones in po/kisnitch.pot (the English texts marked with
_() / N_() in ui/*.c); a translation comes from the .ts message whose <source>
is the same text. Qt's contexts (the widget's class) don't exist in gettext,
so when a source has several translations the most common one wins.

  tools/ts2po.py [--pot po/kisnitch.pot] [--ts DIR] [--out po] [--report]

Not carried over: obsolete, vanished and unfinished messages, plural forms
(numerus), and messages with a Qt placeholder (%1...) whose id here doesn't
have the same number of %s. Qt's '&' mnemonics are dropped on both sides.

Copyright (C) 2026 the Kisnitch contributors.
"""
import argparse
import collections
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

# gettext directory name for each upstream locale (Qt's zh_Hans is zh_CN)
MIN_DONE = 10
RENAME = {"zh_Hans": "zh_CN"}

QT_ARG = re.compile(r"%(?:[1-9]|n)")
C_ARG = re.compile(r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z)?[sdiuxXfgc]")


def unamp(s):
    return re.sub(r"&(.)", r"\1", s.replace("&&", "\0")).replace("\0", "&")


def read_pot(path):
    """-> list of (msgid, [references], flags)"""
    out, cur = [], None
    refs, flags, msgid, mode = [], [], None, None
    for raw in open(path, encoding="utf-8").read().split("\n") + [""]:
        line = raw.rstrip()
        if line.startswith("#:"):
            refs += line[2:].split()
        elif line.startswith("#,"):
            flags += [f.strip() for f in line[2:].split(",")]
        elif line.startswith("msgid "):
            msgid, mode = [unquote(line[6:])], "id"
        elif line.startswith("msgstr "):
            mode = "str"
        elif line.startswith('"') and mode == "id":
            msgid.append(unquote(line))
        elif line == "":
            if msgid is not None and "".join(msgid) != "":
                out.append(("".join(msgid), refs, flags))
            refs, flags, msgid, mode = [], [], None, None
    return out


def unquote(s):
    s = s.strip()
    assert s.startswith('"') and s.endswith('"'), s
    return (s[1:-1].replace('\\n', '\n').replace('\\t', '\t')
            .replace('\\"', '"').replace('\\\\', '\\'))


def quote(s):
    return ('"' + s.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\t", "\\t") + '"')


def emit(tag, s):
    if "\n" in s[:-1]:
        parts = s.split("\n")
        lines = [parts[i] + "\n" for i in range(len(parts) - 1)]
        if parts[-1]:
            lines.append(parts[-1])
        return f'{tag} ""\n' + "\n".join(quote(l) for l in lines) + "\n"
    return f"{tag} {quote(s)}\n"


def read_ts(path):
    """-> (language, {source: Counter(translation)})"""
    root = ET.parse(path).getroot()
    tr = collections.defaultdict(collections.Counter)
    for m in root.iter("message"):
        if m.get("numerus") == "yes":
            continue
        src = m.findtext("source")
        t = m.find("translation")
        if src is None or t is None or t.get("type") in ("obsolete", "vanished", "unfinished"):
            continue
        text = t.text or ""
        if text.strip() == "":
            continue
        tr[unamp(src)][text] += 1
    return root.get("language"), tr


MNEMONIC = re.compile(r"^[^_]*_[^_]*$")


def mnemonic(text):
    """Qt's &File -> GTK's _File (&& is a literal &)."""
    return text.replace("&&", "\0").replace("&", "_").replace("\0", "&")


def adapt(msgid, src, text):
    """Qt %1 placeholders -> positional printf, only if the C id is all %s."""
    q = QT_ARG.findall(src)
    c = C_ARG.findall(msgid)
    if not q and not c:
        return text
    if len(q) != len(c) or any(a[-1] != "s" for a in c):
        return None
    if sorted(set(QT_ARG.findall(text))) != sorted(set(q)):
        return None
    return re.sub(r"%([1-9])", lambda m: "%" + m.group(1) + "$s", text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pot", default="po/kisnitch.pot")
    ap.add_argument("--ts", default="upstream/ui/i18n/locales")
    ap.add_argument("--out", default="po")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()

    pot = read_pot(a.pot)
    # lookup by source text and by the source with Qt args as %s
    for path in sorted(glob.glob(os.path.join(a.ts, "*", "*.ts"))):
        lang, tr = read_ts(path)
        code = RENAME.get(os.path.basename(os.path.dirname(path)),
                          os.path.basename(os.path.dirname(path)))
        by_norm = {}
        for src, c in tr.items():
            by_norm.setdefault(QT_ARG.sub("%s", src), (src, c))
        done = 0
        out = []
        out.append('# Translation of Kisnitch to %s, converted from the upstream\n'
                   '# Qt .ts by tools/ts2po.py. Don\'t edit by hand: send fixes to the\n'
                   '# OpenSnitch translations and run tools/update-po.sh.\n'
                   '# SPDX-License-Identifier: GPL-3.0-or-later\n'
                   'msgid ""\nmsgstr ""\n'
                   '"Project-Id-Version: kisnitch\\n"\n'
                   '"Language: %s\\n"\n'
                   '"MIME-Version: 1.0\\n"\n'
                   '"Content-Type: text/plain; charset=UTF-8\\n"\n'
                   '"Content-Transfer-Encoding: 8bit\\n"\n' % (code, code))
        for msgid, refs, flags in pot:
            gtk_mn = MNEMONIC.match(msgid) is not None
            key = msgid.replace("_", "") if gtk_mn else msgid
            hit = by_norm.get(QT_ARG.sub("%s", unamp(key)))
            text = None
            if hit:
                src, c = hit
                raw = c.most_common(1)[0][0]
                text = adapt(msgid, src, mnemonic(raw) if gtk_mn else unamp(raw))
                if text is not None and C_ARG.findall(msgid) == [] and QT_ARG.search(src):
                    text = None
            if text is not None and text != "":
                done += 1
            out.append("\n")
            if refs:
                out.append("#: " + " ".join(refs) + "\n")
            fl = [f for f in flags if f != "fuzzy"]
            if fl:
                out.append("#, " + ", ".join(fl) + "\n")
            out.append(emit("msgid", msgid))
            out.append(emit("msgstr", text or ""))
        if done < MIN_DONE:
            # upstream hasn't translated this language yet (all "unfinished")
            stale = os.path.join(a.out, code + ".po")
            if os.path.exists(stale):
                os.remove(stale)
            if a.report:
                print(f"{code:8} {done:4}/{len(pot)}  skipped (not translated upstream)")
            continue
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, code + ".po"), "w", encoding="utf-8") as f:
            f.write("".join(out))
        if a.report:
            print(f"{code:8} {done:4}/{len(pot)}  {100 * done // max(len(pot), 1)}%")


if __name__ == "__main__":
    sys.exit(main())
