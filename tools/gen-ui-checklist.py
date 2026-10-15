#!/usr/bin/env python3
"""Generates docs/UI-CHECKLIST.md from the upstream .ui files.

Every widget with a user-visible text (label, button, check, group box, tab,
menu action) or an input (entry, combo, spin, table...) is listed. A widget
counts as covered when its text appears in our sources (ui/*.c), or when
docs/ui-checklist-map.tsv says how it is covered / why it is not. The script
exits non-zero if any widget is left without an answer.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "upstream/ui/opensnitch/res")
FILES = ["stats", "preferences", "ruleseditor", "prompt", "process_details", "firewall", "firewall_rule"]
LAYOUT = {"QWidget", "QFrame", "QSpacerItem", "QScrollArea", "QSplitter", "QStackedWidget",
          "QGroupBox", "QDialog", "QMenu", "QStatusBar", "QMenuBar", "Line", "QToolBox"}
INPUTS = {"QLineEdit", "QComboBox", "QSpinBox", "QDoubleSpinBox", "QTableView", "QTableWidget",
          "QTreeView", "QPlainTextEdit", "QTextEdit", "QListWidget", "QSlider", "QProgressBar",
          "QCheckBox", "QRadioButton", "QPushButton", "QToolButton", "QLabel", "QTabWidget",
          "QGroupBox", "QAction", "QDateTimeEdit", "QTreeWidget", "QListView", "QCommandLinkButton"}


def prop_string(w, name):
    for p in w.findall("property"):
        if p.get("name") == name:
            s = p.find("string")
            if s is not None and s.text:
                return " ".join(s.text.split())
    return ""


def widgets(path):
    t = ET.parse(path).getroot()
    for w in t.iter("widget"):
        yield w.get("class"), w.get("name"), prop_string(w, "text") or prop_string(w, "title") or \
            prop_string(w, "windowTitle"), prop_string(w, "toolTip"), prop_string(w, "placeholderText")
    for a in t.iter("action"):
        yield "QAction", a.get("name"), prop_string(a, "text"), prop_string(a, "toolTip"), ""


def sources():
    s = ""
    for f in glob.glob(os.path.join(ROOT, "ui/*.c")) + glob.glob(os.path.join(ROOT, "ui/*.h")):
        s += open(f, encoding="utf-8", errors="replace").read()
    return s


def norm(t):
    return re.sub(r"[&:…\.]+", "", t).strip().lower()


def load_map():
    m = {}
    p = os.path.join(ROOT, "docs/ui-checklist-map.tsv")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            k, status, note = (line.rstrip("\n").split("\t") + ["", ""])[:3]
            m[k] = (status, note)
    return m


def main():
    src = norm(sources())
    m = load_map()
    out = ["# Checklist da UI", "",
           "Gerado por `tools/gen-ui-checklist.py` a partir de `upstream/ui/opensnitch/res/*.ui`.",
           "Um widget está *coberto* quando o texto dele aparece em `ui/*.c`, ou quando",
           "`docs/ui-checklist-map.tsv` diz como é coberto (ou por que não, e em que fase entra).", ""]
    missing = 0
    total = 0
    for f in FILES:
        rows = []
        for cls, name, text, tip, ph in widgets(os.path.join(UI, f + ".ui")):
            if cls in LAYOUT and not text:
                continue
            if cls not in INPUTS and not text:
                continue
            if cls == "QLabel" and not text:
                continue
            key = f + ":" + name
            if key in m:
                status, note = m[key]
            elif text and len(norm(text)) > 1 and norm(text) in src:
                status, note = "ok", "texto presente"
            elif cls in ("QLineEdit", "QComboBox", "QSpinBox", "QTableView", "QTreeView", "QTabWidget",
                         "QPlainTextEdit", "QTextEdit", "QProgressBar", "QListWidget") and not text:
                status, note = "ok?", "entrada sem texto"
            else:
                status, note = "FALTA", ""
                missing += 1
            total += 1
            rows.append((cls, name, text or tip or ph, status, note))
        out += ["## %s.ui" % f, "", "| widget | classe | texto | estado | nota |", "|---|---|---|---|---|"]
        for cls, name, text, status, note in rows:
            out.append("| `%s` | %s | %s | %s | %s |" % (name, cls, text.replace("|", "\\|"), status, note))
        out.append("")
    out += ["Total: %d widgets, %d sem resposta." % (total, missing), ""]
    open(os.path.join(ROOT, "docs/UI-CHECKLIST.md"), "w", encoding="utf-8").write("\n".join(out))
    print("%d widgets, %d sem resposta" % (total, missing))
    return 1 if missing else 0


sys.exit(main())
