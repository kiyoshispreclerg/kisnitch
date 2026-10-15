#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs upstream's rules editor (ui/opensnitch/dialogs/ruleseditor.py, 1.8.0)
# on the cases of cases.jsonl, without Qt: the widgets are small stand-ins
# (below). Everything that decides the rule is upstream's code:
# _save_rule(), _load_rule(), _load_rule_operator(), _comma_to_regexp(),
# _regexp_to_comma(), the LAN and multicast ranges.
#
#   upstream_ruleseditor.py <upstream ui dir> <dir with ui_pb2.py> <cases> <out>
#
# One JSON object per case. A "save" case has a form and gives the rule or
# the error; a "load" case has a rule and gives the form it fills.
# tests/diff/ks_rules_diff.c does the same with ui/rulegen.c.
import json
import os
import sys
import types

UI, PB, CASES, OUT = sys.argv[1:5]
sys.path.insert(0, PB)
sys.path.insert(0, UI)


class Sig:
    def __init__(self):
        self.cbs = []

    def connect(self, cb):
        self.cbs.append(cb)

    def emit(self, *a):
        for cb in list(self.cbs):
            cb(*a)


class pyqtSignal:
    def __init__(self, *types_):
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, owner):
        if obj is None:
            return self
        return obj.__dict__.setdefault("_sig_" + self.name, Sig())


def pyqtSlot(*a, **k):
    return lambda f: f


class Anything:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return Anything()

    def __call__(self, *a, **k):
        return Anything()

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False


class QObject:
    def __init__(self, *a, **k):
        pass


class Widget:
    def __init__(self):
        self._text = ""
        self._checked = False
        self._enabled = True
        self._visible = True
        self._sigs = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in ("clicked", "toggled", "activated", "currentIndexChanged"):
            return self._sigs.setdefault(name, Sig())
        return Anything()

    def setText(self, t):
        self._text = t

    def text(self):
        return self._text

    def setPlainText(self, t):
        self._text = t

    def toPlainText(self):
        return self._text

    def setChecked(self, c):
        self._checked = bool(c)

    def isChecked(self):
        return self._checked

    def setEnabled(self, e):
        self._enabled = bool(e)

    def setVisible(self, v):
        self._visible = bool(v)

    def setStyleSheet(self, s):
        pass


class Radio(Widget):
    group = []

    def setChecked(self, c):
        if c:
            for r in Radio.group:
                r._checked = False
        self._checked = bool(c)


class Combo(Widget):
    def __init__(self, texts=()):
        super().__init__()
        self.items = []
        self.cur = -1
        self.edit = ""
        for t in texts:
            self.addItem(t)

    def addItem(self, text, data=None):
        self.items.append([text, data])
        if self.cur == -1:
            self.cur = 0
            self.edit = text

    def addItems(self, texts):
        for t in texts:
            self.addItem(t)

    def clear(self):
        self.items = []
        self.cur = -1
        self.edit = ""

    def count(self):
        return len(self.items)

    def findText(self, t):
        for i, it in enumerate(self.items):
            if it[0] == t:
                return i
        return -1

    def findData(self, d):
        for i, it in enumerate(self.items):
            if it[1] == d:
                return i
        return -1

    def insertItem(self, i, t):
        self.items.insert(i, [t, None])

    def setCurrentIndex(self, i):
        self.cur = i if 0 <= i < len(self.items) else -1
        self.edit = self.items[self.cur][0] if self.cur >= 0 else ""

    def currentIndex(self):
        return self.cur

    def setCurrentText(self, t):
        # an editable combo: the text is what it shows, in the list or not
        self.edit = t
        for i, it in enumerate(self.items):
            if it[0] == t:
                self.cur = i

    def currentText(self):
        return self.edit

    def itemData(self, i):
        return self.items[i][1] if 0 <= i < len(self.items) else None

    def blockSignals(self, b):
        pass


class QDialog:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return Anything()


DURATIONS = ["once", "30s", "5m", "15m", "30m", "1h", "12h", "until reboot", "always"]
LINES = ["procLine", "cmdlineLine", "pidLine", "dstHostLine", "srcPortLine", "dstPortLine",
         "dstListsLine", "dstListRegexpLine", "dstListIPsLine", "dstListNetsLine",
         "dstRegexpListsLine", "md5Line", "ruleNameEdit", "ruleDescEdit"]
CHECKS = ["procCheck", "checkProcRegexp", "cmdlineCheck", "checkCmdlineRegexp", "uidCheck",
          "pidCheck", "protoCheck", "ifaceCheck", "srcPortCheck", "dstPortCheck", "srcIPCheck",
          "dstIPCheck", "dstHostCheck", "dstListsCheck", "dstListRegexpCheck",
          "dstListIPsCheck", "dstListNetsCheck", "md5Check", "sensitiveCheck", "nologCheck",
          "precedenceCheck", "enableCheck", "nodeApplyAllCheck"]
COMBOS = ["uidCombo", "ifaceCombo", "protoCombo", "srcIPCombo", "dstIPCombo", "nodesCombo"]


class Ui:
    def setupUi(self, dlg):
        for n in LINES:
            setattr(dlg, n, Widget())
        for n in CHECKS:
            setattr(dlg, n, Widget())
        for n in COMBOS:
            setattr(dlg, n, Combo())
        dlg.durationCombo = Combo(DURATIONS)
        Radio.group = [Radio(), Radio(), Radio()]
        dlg.actionDenyRadio, dlg.actionAllowRadio, dlg.actionRejectRadio = Radio.group
        dlg.actionDenyRadio._checked = True
        dlg.statusLabel = Widget()
        for n in ("buttonBox", "selectListButton", "selectListRegexpButton", "selectIPsListButton",
                  "selectNetsListButton", "tabWidget"):
            setattr(dlg, n, Widget())


def module(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


QtCore = module("PyQt6.QtCore", QObject=QObject, pyqtSignal=pyqtSignal, pyqtSlot=pyqtSlot,
                QSettings=Anything, QByteArray=bytes, QSize=Anything, Qt=Anything(),
                QEvent=Anything(), QCoreApplication=types.SimpleNamespace(
                    translate=lambda ctx, s, *a: s))
QtGui = module("PyQt6.QtGui", QTextCursor=Anything(), QCursor=Anything(), QIcon=Anything,
               QPixmap=Anything, QValidator=Anything, QDesktopServices=Anything())
QtWidgets = module("PyQt6.QtWidgets", QDialog=QDialog, QMenu=Anything, QWidget=QObject,
                   QMessageBox=Anything(), QDialogButtonBox=Anything())
uic = module("PyQt6.uic", loadUiType=lambda path: (Ui, object))
module("PyQt6", QtCore=QtCore, QtGui=QtGui, QtWidgets=QtWidgets, uic=uic)


class Database:
    _inst = None

    @staticmethod
    def instance():
        if Database._inst is None:
            Database._inst = Database()
        return Database._inst

    def __getattr__(self, name):
        return lambda *a, **k: True


real = os.path.join(UI, "opensnitch")
module("opensnitch.database", Database=Database, __path__=[os.path.join(real, "database")])


class Icons:
    @staticmethod
    def new(widget, name):
        return Anything()


class NetworkInterfaces:
    @staticmethod
    def list():
        return {}


class qvalidator:
    class RestrictChars:
        def __init__(self, *a):
            self.result = Sig()


module("opensnitch.utils", Icons=Icons, NetworkInterfaces=NetworkInterfaces, Message=Anything(),
       FileDialog=Anything(), qvalidator=qvalidator, Versions=Anything(),
       __path__=[os.path.join(real, "utils")])


class Nodes:
    local = True

    @staticmethod
    def instance():
        return Nodes()

    def is_local(self, addr):
        return Nodes.local

    def get(self):
        return {"unix:/local": {}}

    def get_node_hostname(self, n):
        return "host"


module("opensnitch.nodes", Nodes=Nodes)

import ui_pb2  # noqa: E402

module("opensnitch.proto", import_=lambda: (ui_pb2, None))

# the enums the dialog imports (database/enums.py is plain Python)
_stdout = sys.stdout
sys.stdout = sys.stderr
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("opensnitch.database.enums",
                                              os.path.join(real, "database", "enums.py"))
enums = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enums)
sys.modules["opensnitch.database.enums"] = enums
from opensnitch.config import Config  # noqa: E402
from opensnitch.dialogs.ruleseditor import RulesEditorDialog  # noqa: E402
from opensnitch.rules import Rule  # noqa: E402
sys.stdout = _stdout

TEXTS = {"proto": ("protoCheck", "protoCombo"), "iface": ("ifaceCheck", "ifaceCombo"),
         "srcip": ("srcIPCheck", "srcIPCombo"), "dstip": ("dstIPCheck", "dstIPCombo"),
         "uid": ("uidCheck", "uidCombo"), "proc": ("procCheck", "procLine"),
         "cmdline": ("cmdlineCheck", "cmdlineLine"), "pid": ("pidCheck", "pidLine"),
         "srcport": ("srcPortCheck", "srcPortLine"), "dstport": ("dstPortCheck", "dstPortLine"),
         "dsthost": ("dstHostCheck", "dstHostLine"), "lists": ("dstListsCheck", "dstListsLine"),
         "lists_regexp": ("dstListRegexpCheck", "dstRegexpListsLine"),
         "lists_ips": ("dstListIPsCheck", "dstListIPsLine"),
         "lists_nets": ("dstListNetsCheck", "dstListNetsLine"), "md5": ("md5Check", "md5Line")}


def set_text(w, t):
    if isinstance(w, Combo):
        w.setCurrentText(t)
    else:
        w.setText(t)


def fill(dlg, form):
    dlg.ruleNameEdit.setText(form.get("name", ""))
    dlg.ruleDescEdit.setPlainText(form.get("desc", ""))
    dlg.enableCheck.setChecked(form.get("enabled", False))
    dlg.precedenceCheck.setChecked(form.get("precedence", False))
    dlg.nologCheck.setChecked(form.get("nolog", False))
    dlg.sensitiveCheck.setChecked(form.get("sensitive", False))
    {0: dlg.actionDenyRadio, 1: dlg.actionAllowRadio, 2: dlg.actionRejectRadio}[
        form.get("action", 0)].setChecked(True)
    dlg.durationCombo.setCurrentIndex(form.get("duration", 0))
    for key, (chk, line) in TEXTS.items():
        c = form.get(key)
        if c is not None:
            getattr(dlg, chk).setChecked(c["on"])
            set_text(getattr(dlg, line), c["text"])
    dlg.checkProcRegexp.setChecked(form.get("proc_regexp", False))
    dlg.checkCmdlineRegexp.setChecked(form.get("cmdline_regexp", False))
    dlg.nodeApplyAllCheck.setChecked(form.get("apply_all", False))
    Nodes.local = form.get("node_is_local", True)


def dump_form(dlg):
    f = {"name": dlg.ruleNameEdit.text(), "desc": dlg.ruleDescEdit.toPlainText(),
         "enabled": dlg.enableCheck.isChecked(), "precedence": dlg.precedenceCheck.isChecked(),
         "nolog": dlg.nologCheck.isChecked(), "sensitive": dlg.sensitiveCheck.isChecked(),
         "action": 1 if dlg.actionAllowRadio.isChecked() else 2 if dlg.actionRejectRadio.isChecked() else 0,
         "duration": dlg.durationCombo.currentIndex(),
         "proc_regexp": dlg.checkProcRegexp.isChecked(),
         "cmdline_regexp": dlg.checkCmdlineRegexp.isChecked()}
    for key, (chk, line) in TEXTS.items():
        f[key] = {"on": getattr(dlg, chk).isChecked(),
                  "text": getattr(dlg, line).currentText() if isinstance(getattr(dlg, line), Combo)
                  else getattr(dlg, line).text()}
    return f


def rule_out(r):
    return {
        "name": r.name, "description": r.description, "enabled": r.enabled,
        "precedence": r.precedence, "nolog": r.nolog, "action": r.action,
        "duration": r.duration, "type": r.operator.type, "operand": r.operator.operand,
        "data": r.operator.data, "sensitive": r.operator.sensitive,
        "list": [{"type": o.type, "operand": o.operand, "data": o.data,
                  "sensitive": o.sensitive} for o in r.operator.list],
    }


def proto_rule(d):
    r = ui_pb2.Rule(name=d["name"], description=d.get("description", ""),
                    enabled=d.get("enabled", False), precedence=d.get("precedence", False),
                    nolog=d.get("nolog", False), action=d["action"], duration=d["duration"])
    r.operator.type = d["type"]
    r.operator.operand = d["operand"]
    r.operator.data = d["data"]
    r.operator.sensitive = d.get("sensitive", False)
    for o in d.get("list", []):
        r.operator.list.extend([ui_pb2.Operator(type=o["type"], operand=o["operand"],
                                                data=o["data"], sensitive=o.get("sensitive", False))])
    return r


def new_dialog():
    dlg = RulesEditorDialog.__new__(RulesEditorDialog)
    Ui().setupUi(dlg)
    dlg._nodes = Nodes()
    dlg._old_rule_name = None
    dlg._notifications_sent = {}
    dlg.WORK_MODE = RulesEditorDialog.ADD_RULE
    dlg.nodesCombo.addItem("unix:/local - host", "unix:/local")
    return dlg


def run(case):
    dlg = new_dialog()
    if case["kind"] == "save":
        fill(dlg, case["form"])
        dlg.statusLabel.setText("")
        ok, err = dlg._save_rule()
        out = {"id": case["id"], "ok": ok}
        if ok:
            out["rule"] = rule_out(dlg.rule)
        else:
            out["error"] = err
        return out
    if case["kind"] == "load":
        rule = proto_rule(case["rule"])
        dlg._reset_state()
        dlg.rule = rule
        dlg.statusLabel.setText("")
        dlg._load_rule(addr="unix:/local", rule=rule)
        return {"id": case["id"], "form": dump_form(dlg), "status": dlg.statusLabel.text()}
    if case["kind"] == "helpers":
        res = {"id": case["id"]}
        for k, t in case["comma_to_regexp"]:
            res["c2r:%s:%s" % (k, t)] = list(dlg._comma_to_regexp(t, int if k == "int" else str))
        for k, t in case["regexp_to_comma"]:
            res["r2c:%s:%s" % (k, t)] = list(dlg._regexp_to_comma(t, int if k == "int" else str))
        for t in case["is_regex"]:
            res["isre:%s" % t] = dlg._is_regex(t)
        return res
    raise SystemExit("unknown case kind")


def main():
    with open(CASES) as f, open(OUT, "w") as out:
        for line in f:
            if line.strip():
                out.write(json.dumps(run(json.loads(line)), sort_keys=True) + "\n")


main()
