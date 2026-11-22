#!/usr/bin/env python3
"""
Headless smoke/integration test for password_manager_gui.py.
Run with a virtual display:   xvfb-run -a python3 test_gui.py
(On a normal desktop just run `python3 test_gui.py`; a window will flash briefly.)
"""

import os
import shutil
import sys
import tempfile
import time
import types
from datetime import datetime, timedelta
from unittest import mock

import password_manager as pm
import password_manager_gui as gui

pm.PBKDF2_ITERATIONS = 1000        # keep the test fast
MASTER = "Gui-Test-Master-2026"
failures = []


def check(name, condition, detail=""):
    print(("PASS  " if condition else "FAIL  ") + name + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def pump(app, seconds=0.0):
    end = time.time() + seconds
    app.update()
    while time.time() < end:
        app.update()
        time.sleep(0.02)


tmp = tempfile.mkdtemp()
vault = os.path.join(tmp, "vault.json")
app = gui.App(vault_path=vault, auto_lock_seconds=3)
pump(app)

# ---- creating the vault ----------------------------------------------------
check("login screen shown, no session", app.session is None)
check("create rejects mismatch", app.attempt_create("aaaaaaaaaaaa", "bbbbbbbbbbbb")[0] is False)
check("create rejects short", app.attempt_create("short", "short")[0] is False)
check("create rejects common", app.attempt_create("password123", "password123")[0] is False)
ok, msg = app.attempt_create(MASTER, MASTER)
check("create + auto-unlock succeeds", ok and app.session is not None, msg)
pump(app)

# ---- entries ---------------------------------------------------------------
w1 = app.save_entry("Camera 7", "admin", "letmein", "lobby")
w2 = app.save_entry("Camera 8", "admin", "letmein", "")
w3 = app.save_entry("Q-SYS Core", "admin", "Hy7&cD3*fG6^jL1!", "rack 2")
check("common-password warning raised", any("common" in w for w in w1))
check("reuse warning raised", any("Camera 7" in w for w in w2))
check("strong password: no warnings", w3 == [])
app.refresh_tree()
check("tree lists 3 entries", len(app.tree.get_children()) == 3)

app.search_var.set("q-sys")
pump(app)
check("search filters list", app.tree.get_children() == ("Q-SYS Core",))
app.search_var.set("")
pump(app)

app.tree.selection_set("Q-SYS Core")
pump(app)
check("details show masked password", app.d_pw.get() == "********" and app.d_user.get() == "admin")
app.toggle_password()
check("show reveals password", app.d_pw.get() == "Hy7&cD3*fG6^jL1!")
app.toggle_password()
check("hide masks again", app.d_pw.get() == "********")

app.copy_password()
pump(app)
check("clipboard holds password", app.clipboard_get() == "Hy7&cD3*fG6^jL1!")
app.clear_clipboard()
pump(app)
check("clipboard cleared", app.clipboard_get() in ("", None))

app.save_entry("Q-SYS Core 2", "admin", "Hy7&cD3*fG6^jL1!", "renamed", old_site="Q-SYS Core")
check("rename removes old entry", "Q-SYS Core" not in app.session.entries and "Q-SYS Core 2" in app.session.entries)
app.remove_entry("Camera 8")
check("delete removes entry", "Camera 8" not in app.session.entries)
app.session.entries["Old Router"] = {"username": "root", "password": "Zq8#nW5$kT2@vB9!", "notes": "",
                                     "updated": (datetime.now() - timedelta(days=300)).isoformat(timespec="seconds")}
pm.persist_entries(app.session.fernet, app.session.entries)
app.refresh_tree()

# ---- audit window ----------------------------------------------------------
audit = gui.AuditWindow(app)
pump(app)
audit.run()
pump(app, 1.0)
rows = [audit.tree.item(i, "values") for i in audit.tree.get_children()]
check("audit lists findings", len(rows) >= 2, str(rows))
check("audit flags common password", any("common" in r[2].lower() for r in rows))
check("audit flags stale password", any(r[1] == "Old Router" and "not changed" in r[2] for r in rows))
check("audit summary text set", "scanned" in audit.summary.get(), audit.summary.get())
audit.destroy()

# ---- export / import -------------------------------------------------------
enc_path = os.path.join(tmp, "export.csv.enc")
app.wait_window = lambda w: None
with mock.patch.object(gui.messagebox, "askokcancel", return_value=True), \
     mock.patch.object(gui.simpledialog, "askstring", return_value=MASTER), \
     mock.patch.object(gui, "ChoiceDialog", lambda *a, **k: types.SimpleNamespace(result="enc")), \
     mock.patch.object(gui.filedialog, "asksaveasfilename", return_value=enc_path), \
     mock.patch.object(gui.messagebox, "showinfo"):
    app.export_flow()
check("encrypted export file written", os.path.exists(enc_path))
with open(enc_path, "rb") as fh:
    check("export is ciphertext", b"Camera 7" not in fh.read())

with mock.patch.object(gui.simpledialog, "askstring", return_value="not-the-master"), \
     mock.patch.object(gui.messagebox, "askokcancel", return_value=True), \
     mock.patch.object(gui.messagebox, "showerror") as err:
    app.export_flow()
check("export blocked on wrong master password", err.called)

with mock.patch.object(gui.messagebox, "showinfo"):
    stats = app.run_import(enc_path, "rename")
check("import with keep-both renames duplicates", stats and stats["renamed"] == 3, str(stats))
with mock.patch.object(gui.messagebox, "showerror") as err:
    app.run_import(vault, "skip")      # a JSON file is not a valid CSV import
check("importing a non-CSV is rejected cleanly", err.called)

# ---- change master password -----------------------------------------------
answers = iter([MASTER, "Brand-New-Master-77", "Brand-New-Master-77"])
with mock.patch.object(gui.simpledialog, "askstring", lambda *a, **k: next(answers)), \
     mock.patch.object(gui.messagebox, "showinfo"):
    app.change_master_flow()
check("change master re-keys vault", True)

# ---- locking ---------------------------------------------------------------
dialog = gui.EntryDialog(app, "Add entry")
pump(app)
app.lock("manual")
pump(app)
check("manual lock clears session", app.session is None)
check("lock closes open dialogs", not any(isinstance(w, gui.tk.Toplevel) for w in app.winfo_children()))
check("old master no longer works", app.attempt_unlock(MASTER)[0] is False)
ok, msg = app.attempt_unlock("Brand-New-Master-77")
check("new master unlocks, data intact", ok and "Camera 7" in app.session.entries and
      "Q-SYS Core 2" in app.session.entries, msg)

# ---- inactivity auto-lock --------------------------------------------------
pump(app)
app.session.last_activity -= 10            # pretend 10s of inactivity (limit is 3s)
app.tick()
pump(app)
check("inactivity timeout locks the vault", app.session is None)
check("lock reason logged", any(r["event"] == "session_lock" and "timeout" in r["detail"]
                                for r in pm.read_log(50)))

# ---- brute force through the GUI ------------------------------------------
results = [app.attempt_unlock("wrong")[1] for _ in range(5)]
check("GUI shows remaining attempts", "attempt(s) remaining" in results[0], results[0])
check("GUI enforces lockout", "locked" in results[4].lower(), results[4])
ok, msg = app.attempt_unlock("Brand-New-Master-77")
check("lockout blocks even the correct password", ok is False and "locked" in msg.lower(), msg)

app.on_close()
shutil.rmtree(tmp, ignore_errors=True)
print()
print("ALL GUI CHECKS PASSED" if not failures else f"{len(failures)} FAILED: {failures}")
sys.exit(1 if failures else 0)
