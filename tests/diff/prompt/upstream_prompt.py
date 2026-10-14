#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs upstream's pop-up (ui/opensnitch/dialogs/prompt/__init__.py, 1.8.0,
# with its _utils, rules.py, nodes.py, config.py and network aliases) on
# the cases of cases.jsonl, without Qt: PyQt6, the SQLite database (through
# QtSql), the icons, the plugins and the .desktop parser are replaced by
# small stand-ins below. Everything that decides the rule is upstream's
# code: the combos, the defaults, _send_rule(), slugify, the rules table
# queries (run on Python's sqlite3 with the same SQL).
#
#   upstream_prompt.py <upstream ui dir> <dir with ui_pb2.py> <cases> <out>
#
# Writes one JSON object per case: the combo entries and the rule (or
# null). tests/diff/ks_prompt_diff.c writes the same for ui/prompt_rule.c.
import json
import os
import sqlite3
import sys
import types

UI, PB, CASES, OUT = sys.argv[1:5]
sys.path.insert(0, PB)
sys.path.insert(0, UI)

# ---- PyQt6 -----------------------------------------------------------------


class Sig:
    def __init__(self):
        self.cbs = []

    def connect(self, cb):
        self.cbs.append(cb)

    def emit(self, *a):
        for cb in list(self.cbs):
            cb(*a)


class pyqtSignal:  # a descriptor: one Sig per instance
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
    """Absorbs any call or attribute."""

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


SIGNALS = ("clicked", "toggled", "activated", "linkActivated", "triggered")


class Widget:
    def __init__(self):
        self._text = ""
        self._visible = True
        self._checked = False
        self._sigs = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in SIGNALS:
            return self._sigs.setdefault(name, Sig())
        return Anything()

    def setText(self, t):
        self._text = t

    def text(self):
        return self._text

    def setVisible(self, v):
        self._visible = bool(v)

    def isVisible(self):
        return self._visible

    def setChecked(self, c):
        self._checked = bool(c)

    def isChecked(self):
        return self._checked

    def toggle(self):
        self._checked = not self._checked
        self.toggled.emit(self._checked)

    def document(self):
        return Anything()


class Combo(Widget):
    def __init__(self, texts=()):
        super().__init__()
        self.items = []
        self.cur = -1
        for t in texts:
            self.addItem(t)

    def addItem(self, text, data=None):
        self.items.append([text, data])
        if self.cur == -1:
            self.cur = 0

    def addItems(self, texts):
        for t in texts:
            self.addItem(t)

    def clear(self):
        self.items = []
        self.cur = -1

    def count(self):
        return len(self.items)

    def setCurrentIndex(self, i):
        self.cur = i if 0 <= i < len(self.items) else -1

    def currentIndex(self):
        return self.cur

    def currentText(self):
        return self.items[self.cur][0] if self.cur >= 0 else ""

    def itemData(self, i):
        return self.items[i][1] if 0 <= i < len(self.items) else None

    def itemText(self, i):
        return self.items[i][0] if 0 <= i < len(self.items) else ""

    def findData(self, d):
        for i, it in enumerate(self.items):
            if it[1] == d:
                return i
        return -1

    def model(self):
        return Anything()


class QDialog:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return Anything()


DURATIONS = ["once", "30s", "5m", "15m", "30m", "1h", "12h", "until reboot", "forever"]


class Ui:
    def setupUi(self, dlg):
        for name in ("whatCombo", "whatIPCombo", "comboChecksumRule"):
            setattr(dlg, name, Combo())
        dlg.durationCombo = Combo(DURATIONS)
        for name in ("checkDstIP", "checkDstPort", "checkUserID", "checkSum", "checkAdvanced",
                     "appDescriptionLabel", "appPathLabel", "argsLabel", "appNameLabel",
                     "cwdLabel", "iconLabel", "messageLabel", "sourceIPLabel", "destIPLabel",
                     "destPortLabel", "destPortLabel_1", "uidLabel", "checksumLabel",
                     "checksumLabel_2", "stackedWidget", "connDetails", "cmdInfo", "cmdBack",
                     "cmdUpdateRule", "cmdUpdateRuleAll", "cmdBackChecksums",
                     "labelChecksumStatus", "labelChecksumNote", "actionButton",
                     "allowButton"):
            setattr(dlg, name, Widget())


SETTINGS = {}


class QSettings:
    def __init__(self, *a):
        pass

    def value(self, key, type=None, defaultValue=None):
        if key not in SETTINGS:
            return defaultValue
        v = SETTINGS[key]
        if type is bool:
            return v if isinstance(v, bool) else str(v).lower() not in ("", "0", "false")
        if type is int:
            return int(v)
        return v

    def contains(self, key):
        return key in SETTINGS

    def setValue(self, key, value):
        SETTINGS[key] = value

    def sync(self):
        pass


def module(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


QtCore = module("PyQt6.QtCore", QObject=QObject, pyqtSignal=pyqtSignal, pyqtSlot=pyqtSlot,
                QSettings=QSettings, QByteArray=bytes, QSize=Anything, Qt=Anything(),
                QEvent=Anything(), QCoreApplication=types.SimpleNamespace(
                    translate=lambda ctx, s: s))
QtGui = module("PyQt6.QtGui", QTextCursor=Anything(), QCursor=Anything(), QIcon=Anything,
               QPixmap=Anything)
QtWidgets = module("PyQt6.QtWidgets", QDialog=QDialog, QMenu=Anything, QWidget=QObject)
uic = module("PyQt6.uic", loadUiType=lambda path: (Ui, object))
module("PyQt6", QtCore=QtCore, QtGui=QtGui, QtWidgets=QtWidgets, uic=uic)

# ---- opensnitch modules that need Qt or the system -------------------------


class Query:
    """QSqlQuery over fetched rows."""

    def __init__(self, rows):
        self.rows = rows
        self.i = -1

    def next(self):
        self.i += 1
        return self.i < len(self.rows)

    def first(self):
        self.i = 0
        return len(self.rows) > 0

    def value(self, n):
        return self.rows[self.i][n]


class Database:
    _inst = None
    DB_IN_MEMORY = "file::memory:"
    DB_TYPE_MEMORY = 0
    DB_JRNL_WAL = False

    @staticmethod
    def instance():
        if Database._inst is None:
            Database._inst = Database()
        return Database._inst

    def __init__(self):
        self.reset()

    def reset(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("create table rules (time text, node text, name text, enabled text, "
                        "precedence text, action text, duration text, operator_type text, "
                        "operator_sensitive text, operator_operand text, operator_data text, "
                        "description text, nolog text, created text, UNIQUE(node, name))")

    def _q(self, sql, args):
        return Query(self.db.execute(sql, args).fetchall())

    def insert(self, table, fields, columns, update_field=None, update_values=None,
               action_on_conflict="REPLACE"):
        sql = "INSERT OR %s INTO %s %s VALUES(%s)" % (
            action_on_conflict, table, fields, ",".join("?" * len(columns)))
        self.db.execute(sql, columns)
        return True

    def rule_exists(self, rule, node_addr):
        q = self._q("SELECT node, name, action, duration, operator_type, operator_operand, "
                    "operator_data FROM rules WHERE name=? AND node=? AND action=? AND "
                    "duration=? AND operator_type=? AND operator_operand=? AND "
                    "operator_data=?", (rule.name, node_addr, rule.action, rule.duration,
                                        rule.operator.type, rule.operator.operand,
                                        rule.operator.data))
        if not q.next():
            return None
        return q

    def get_rule(self, rule_name, node_addr=None):
        if node_addr is None:
            return self._q("SELECT * FROM rules WHERE name=?", (rule_name,))
        return self._q("SELECT * FROM rules WHERE name=? AND node=?", (rule_name, node_addr))

    def get_rule_by_field(self, node_addr=None, field=None, value=None):
        sql = "SELECT * FROM rules WHERE {0} LIKE ?".format(field)
        args = ["%" + value + "%"]
        if node_addr is not None:
            sql += " AND node=?"
            args.append(node_addr)
        return self._q(sql, args)

    def __getattr__(self, name):
        return lambda *a, **k: True


real = os.path.join(UI, "opensnitch")
module("opensnitch.database", Database=Database, __path__=[os.path.join(real, "database")])


class Icons:
    @staticmethod
    def new(widget, name):
        return Anything()

    @staticmethod
    def get_by_appname(name):
        return Anything()


class NetworkInterfaces:
    def list(self):
        return {}


module("opensnitch.utils", Icons=Icons, NetworkInterfaces=NetworkInterfaces,
       Versions=Anything(), __path__=[os.path.join(real, "utils")])

APP = {}


class LinuxDesktopParser:
    def get_info_by_path(self, path, default_icon):
        return (APP["name"], default_icon, APP.get("description", ""), None)


module("opensnitch.desktop_parser", LinuxDesktopParser=LinuxDesktopParser)


class PluginBase:
    TYPE_POPUPS = "popups"
    TYPE_GLOBAL = "global"


module("opensnitch.plugins", PluginBase=PluginBase)


class Actions:
    @staticmethod
    def instance():
        return Actions()

    def getByType(self, t):
        return {}


module("opensnitch.actions", Actions=Actions)

import ui_pb2  # noqa: E402

module("opensnitch.proto", import_=lambda: (ui_pb2, None))

# network_aliases.py prints a line when it loads
_stdout = sys.stdout
sys.stdout = sys.stderr
from opensnitch.config import Config  # noqa: E402
from opensnitch.dialogs.prompt import PromptDialog  # noqa: E402
sys.stdout = _stdout

# ---- the cases -------------------------------------------------------------


def connection(c):
    con = ui_pb2.Connection(
        protocol=c.get("protocol", "tcp"), src_ip=c.get("src_ip", "10.0.0.2"),
        src_port=c.get("src_port", 40000), dst_ip=c["dst_ip"],
        dst_host=c.get("dst_host", ""), dst_port=c.get("dst_port", 0),
        user_id=c.get("user_id", 1000), process_id=c.get("process_id", 4242),
        process_path=c.get("process_path", ""), process_cwd=c.get("process_cwd", "/"),
        process_args=c.get("process_args", []))
    con.process_checksums["process.hash.md5"] = c.get("md5", "")
    return con


def rule_out(r):
    if r is None:
        return None
    return {
        "name": r.name, "action": r.action, "duration": r.duration, "enabled": r.enabled,
        "type": r.operator.type, "operand": r.operator.operand, "data": r.operator.data,
        "sensitive": r.operator.sensitive,
        "list": [{"type": o.type, "operand": o.operand, "data": o.data,
                  "sensitive": o.sensitive} for o in r.operator.list],
    }


def run(case, dlg):
    SETTINGS.clear()
    SETTINGS.update(case.get("settings", {}))
    Config.init()
    dlg._cfg = Config.get()
    Database.instance().reset()
    for r in case.get("rules", []):
        Database.instance().insert(
            "rules", "(time, node, name, description, enabled, precedence, nolog, action, "
            "duration, operator_type, operator_sensitive, operator_operand, operator_data, "
            "created)", ("", "unix:/local", r["name"], "", r.get("enabled", "True"), "False",
                         "False", r["action"], r["duration"], r["type"], "False", r["operand"],
                         r["data"], ""))
    APP.clear()
    APP["name"] = case.get("app_name", "")
    con = connection(case["con"])
    dlg._con = con
    dlg._local = case.get("local", True)
    dlg._peer = "unix:/local"
    dlg._hostname = ""
    dlg._ischeckAdvanceded = False
    dlg.checkAdvanced.setChecked(False)
    dlg._render_connection(con)

    ch = case.get("choice", {})
    if ch.get("what") is not None:
        dlg.whatCombo.setCurrentIndex(ch["what"])
    if ch.get("what_ip") is not None:
        dlg.whatIPCombo.setCurrentIndex(ch["what_ip"])
    if ch.get("duration") is not None:
        dlg.durationCombo.setCurrentIndex(ch["duration"])
    for key, w in (("dst_ip", dlg.checkDstIP), ("dst_port", dlg.checkDstPort),
                   ("uid", dlg.checkUserID), ("sum", dlg.checkSum)):
        if ch.get(key) is not None:
            w.setChecked(ch[key])
    action = ch.get("action", "timeout")
    if action == "none":
        pass
    elif action == "timeout":
        dlg._timeout_triggered = True
        dlg._send_rule()
    elif action == "deny_button":
        dlg._on_deny_btn_clicked(None)
    else:
        dlg._on_action_clicked({"deny": 0, "allow": 1, "reject": 2}[action])
    return {
        "id": case["id"],
        "what": [it[0] for it in dlg.whatCombo.items],
        "what_ip": [it[0] for it in dlg.whatIPCombo.items],
        "rule": rule_out(dlg._rule) if action != "none" else None,
    }


def main():
    Config.init()
    dlg = PromptDialog()
    with open(CASES) as f, open(OUT, "w") as out:
        for line in f:
            if not line.strip():
                continue
            case = json.loads(line)
            ch = case.get("choice", {})
            each = [k for k in ("what", "what_ip") if ch.get(k) == "each"]
            if not each:
                out.write(json.dumps(run(case, dlg), sort_keys=True) + "\n")
                continue
            k = each[0]
            probe = run(dict(case, choice=dict(ch, **{k: None, "action": "none"})), dlg)
            for i in range(len(probe[k])):
                c = dict(case, id="%s#%d" % (case["id"], i), choice=dict(ch, **{k: i}))
                out.write(json.dumps(run(c, dlg), sort_keys=True) + "\n")

main()
