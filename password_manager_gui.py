#!/usr/bin/env python3
"""
Secure Password Manager - graphical interface (Tkinter)

A GUI front end for password_manager.py. All cryptography, rate limiting,
auditing, CSV handling and logging live in that module; this file only
provides the windows. Keep both files in the same folder.

Run:  python3 password_manager_gui.py [--vault path/to/vault.json]

Security behavior in the GUI:
  - Auto-lock after inactivity (countdown shown in the status bar); locking
    closes every dialog and drops the decrypted vault from memory.
  - Passwords are masked until you click Show.
  - Copied passwords are cleared from the clipboard after a delay.
  - Export and master-password changes require re-entering the master password.
"""

import argparse
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

import password_manager as pm

CLIPBOARD_CLEAR_MS = pm.CLIPBOARD_CLEAR_SECONDS * 1000
SEVERITY_COLORS = {"High": "#b00020", "Medium": "#b26a00", "Low": "#555555"}


# ---------------------------------------------------------------------------
# Small dialogs
# ---------------------------------------------------------------------------

class ChoiceDialog(tk.Toplevel):
    """Pick one option from a few radio buttons. .result is the chosen key or None."""

    def __init__(self, parent, title, prompt, choices, default=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None
        self.var = tk.StringVar(value=default or choices[0][0])
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=prompt, wraplength=360, justify="left").pack(anchor="w", pady=(0, 8))
        for key, label in choices:
            ttk.Radiobutton(frame, text=label, value=key, variable=self.var).pack(anchor="w", pady=2)
        buttons = ttk.Frame(frame)
        buttons.pack(anchor="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="OK", command=self._ok).pack(side="right")
        self.transient(parent)
        self.grab_set()

    def _ok(self):
        self.result = self.var.get()
        self.destroy()


class EntryDialog(tk.Toplevel):
    """Add / edit an entry. .result is a dict or None if cancelled."""

    def __init__(self, parent, title, site="", username="", password="", notes=""):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None

        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        self.site_var = tk.StringVar(value=site)
        self.user_var = tk.StringVar(value=username)
        self.pw_var = tk.StringVar(value=password)
        self.show_var = tk.BooleanVar(value=False)
        self.len_var = tk.IntVar(value=16)
        self.strength_var = tk.StringVar()

        ttk.Label(frame, text="Site / service").grid(row=0, column=0, sticky="w", pady=4)
        self.site_entry = ttk.Entry(frame, textvariable=self.site_var, width=38)
        self.site_entry.grid(row=0, column=1, columnspan=3, sticky="ew")

        ttk.Label(frame, text="Username").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.user_var).grid(row=1, column=1, columnspan=3, sticky="ew")

        ttk.Label(frame, text="Password").grid(row=2, column=0, sticky="w", pady=4)
        self.pw_entry = ttk.Entry(frame, textvariable=self.pw_var, show="*")
        self.pw_entry.grid(row=2, column=1, columnspan=2, sticky="ew")
        ttk.Checkbutton(frame, text="Show", variable=self.show_var,
                        command=self._toggle_show).grid(row=2, column=3, padx=(6, 0))

        ttk.Label(frame, text="Strength").grid(row=3, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.strength_var).grid(row=3, column=1, sticky="w")

        gen = ttk.Frame(frame)
        gen.grid(row=4, column=1, columnspan=3, sticky="w", pady=4)
        ttk.Button(gen, text="Generate", command=self._generate).pack(side="left")
        ttk.Label(gen, text="  length").pack(side="left")
        ttk.Spinbox(gen, from_=8, to=64, width=4, textvariable=self.len_var).pack(side="left")

        ttk.Label(frame, text="Notes").grid(row=5, column=0, sticky="nw", pady=4)
        self.notes_text = tk.Text(frame, width=38, height=4)
        self.notes_text.grid(row=5, column=1, columnspan=3, sticky="ew")
        self.notes_text.insert("1.0", notes)

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=4, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="Save", command=self._save).pack(side="right")

        self.pw_var.trace_add("write", lambda *_: self._update_strength())
        self._update_strength()
        self.transient(parent)
        self.grab_set()
        self.site_entry.focus_set()

    def _toggle_show(self):
        self.pw_entry.config(show="" if self.show_var.get() else "*")

    def _generate(self):
        try:
            length = int(self.len_var.get())
        except (tk.TclError, ValueError):
            length = 16
        self.pw_var.set(pm.generate_password(length))
        self.show_var.set(True)
        self._toggle_show()

    def _update_strength(self):
        pw = self.pw_var.get()
        text = pm.password_strength_score(pw) if pw else ""
        if pw and pm.is_common_password(pw):
            text += " (common password!)"
        self.strength_var.set(text)

    def _save(self):
        site, password = self.site_var.get().strip(), self.pw_var.get()
        if not site or not password:
            messagebox.showwarning("Missing information", "Site name and password are required.", parent=self)
            return
        self.result = {
            "site": site,
            "username": self.user_var.get().strip(),
            "password": password,
            "notes": self.notes_text.get("1.0", "end").strip(),
        }
        self.destroy()


class AuditWindow(tk.Toplevel):
    """Runs the vault audit (optionally with the online breach check) and lists findings."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Security audit")
        self.geometry("830x430")
        self.online_var = tk.BooleanVar(value=False)

        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill="x")
        ttk.Button(top, text="Run audit", command=self.run).pack(side="left")
        ttk.Checkbutton(
            top, variable=self.online_var,
            text="Also check Have I Been Pwned (sends only 5-character hash prefixes)",
        ).pack(side="left", padx=10)

        self.summary = tk.StringVar(value="Click 'Run audit' to scan every stored password.")
        ttk.Label(self, textvariable=self.summary, padding=(12, 0)).pack(anchor="w")

        columns = ("severity", "site", "issue")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for name, width in (("severity", 70), ("site", 240), ("issue", 450)):
            self.tree.heading(name, text=name.capitalize())
            self.tree.column(name, width=width, anchor="w")
        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)
        self.tree.pack(fill="both", expand=True, padx=12, pady=10)

    def run(self):
        if not self.app.session or self.app.session.locked:
            return
        entries = {k: dict(v) for k, v in self.app.session.entries.items()}
        online = self.online_var.get()
        result = {}
        self.summary.set("Checking breaches online..." if online else "Scanning...")

        def work():
            result["data"] = pm.audit_vault(entries, check_online=online)

        thread = threading.Thread(target=work, daemon=True)
        thread.start()

        def poll():
            try:
                if thread.is_alive():
                    self.after(100, poll)
                else:
                    findings, status = result["data"]
                    self.render(findings, status, len(entries))
            except tk.TclError:
                pass        # window closed (or vault locked) while the check was running

        poll()

    def render(self, findings, status, entry_count):
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self.tree.insert("", "end", values=(f["severity"], f["site"], f["issue"]), tags=(f["severity"],))
        s = pm.summarize_findings(findings)
        text = (f"{entry_count} entries scanned: {s['High']} high, {s['Medium']} medium, {s['Low']} low.")
        if not findings:
            text = f"{entry_count} entries scanned: no issues found."
        if status == "unavailable":
            text += "  (Breach service unreachable - online check skipped.)"
        self.summary.set(text)
        pm.log_event("vault_audit", "ok", f"{len(findings)} findings, online={status}")


class LogWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Activity log")
        self.geometry("760x400")
        columns = ("timestamp", "event", "outcome", "detail")
        tree = ttk.Treeview(self, columns=columns, show="headings")
        for name, width in (("timestamp", 150), ("event", 170), ("outcome", 80), ("detail", 300)):
            tree.heading(name, text=name.capitalize())
            tree.column(name, width=width, anchor="w")
        for row in reversed(pm.read_log(500)):
            tree.insert("", "end", values=(row["timestamp"], row["event"], row["outcome"], row["detail"]))
        tree.pack(fill="both", expand=True, padx=12, pady=12)
        ttk.Label(self, text=f"Log file: {pm.audit_log_path()}", padding=(12, 0, 12, 10)).pack(anchor="w")


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, vault_path=None, auto_lock_seconds=None):
        super().__init__()
        if vault_path:
            pm.VAULT_FILE = vault_path
        self.auto_lock_seconds = auto_lock_seconds or pm.SESSION_TIMEOUT_SECONDS
        self.session = None
        self._tick_job = None
        self._clip_job = None
        self._clip_text = None
        self._pw_visible = False

        self.title("Secure Password Manager")
        self.geometry("960x540")
        self.minsize(760, 440)
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        for sequence in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(sequence, self.touch, add="+")
        self.show_login()

    # ----- helpers ---------------------------------------------------------

    def _clear_container(self):
        for child in self.container.winfo_children():
            child.destroy()

    def _close_dialogs(self):
        for child in self.winfo_children():
            if isinstance(child, tk.Toplevel):
                child.destroy()

    def touch(self, _event=None):
        if self.session and not self.session.locked:
            self.session.touch()

    # ----- login / create --------------------------------------------------

    def show_login(self, message=""):
        self._clear_container()
        self.title("Secure Password Manager")
        creating = not pm.vault_exists()

        frame = ttk.Frame(self.container, padding=30)
        frame.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(frame, text="Secure Password Manager", font=("TkDefaultFont", 16, "bold")).pack(pady=(0, 4))
        ttk.Label(frame, text="Create your vault" if creating else "Vault locked - enter master password",
                  ).pack(pady=(0, 14))

        self.pw1 = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.login_status = tk.StringVar(value=message)

        ttk.Label(frame, text="Master password" if not creating else "Create master password").pack(anchor="w")
        e1 = ttk.Entry(frame, textvariable=self.pw1, show="*", width=34)
        e1.pack(pady=(2, 8))
        if creating:
            ttk.Label(frame, text="Confirm master password").pack(anchor="w")
            e2 = ttk.Entry(frame, textvariable=self.pw2, show="*", width=34)
            e2.pack(pady=(2, 8))
            e2.bind("<Return>", lambda _e: self._submit_login())
            ttk.Label(frame, text=f"At least {pm.MIN_MASTER_LENGTH} characters, not a common password.",
                      foreground="#555").pack(anchor="w")
        e1.bind("<Return>", lambda _e: self._submit_login())
        ttk.Button(frame, text="Create vault" if creating else "Unlock", command=self._submit_login).pack(pady=10)
        ttk.Label(frame, textvariable=self.login_status, foreground="#b00020", wraplength=300).pack()
        e1.focus_set()

    def _submit_login(self):
        if not pm.vault_exists():
            ok, msg = self.attempt_create(self.pw1.get(), self.pw2.get())
        else:
            ok, msg = self.attempt_unlock(self.pw1.get())
        if not ok:
            self.login_status.set(msg)
            self.pw1.set("")
            self.pw2.set("")

    def attempt_create(self, pw1, pw2):
        if pw1 != pw2:
            return False, "Passwords do not match."
        try:
            pm.create_vault(pw1)
        except ValueError as e:
            return False, str(e)
        return self.attempt_unlock(pw1)

    def attempt_unlock(self, password):
        try:
            fernet, entries = pm.unlock_vault(password)
        except ValueError as e:                 # wrong password or locked out
            return False, str(e)
        self.session = pm.Session(fernet, entries, timeout=self.auto_lock_seconds, auto_timer=False)
        self.show_main()
        return True, ""

    # ----- main screen -----------------------------------------------------

    def show_main(self):
        self._clear_container()
        self.title("Secure Password Manager - unlocked")

        bar = ttk.Frame(self.container, padding=(8, 8, 8, 4))
        bar.pack(fill="x")
        for text, command in (
            ("Add", self.add_entry), ("Security audit", self.open_audit),
            ("Import CSV", self.import_flow), ("Export CSV", self.export_flow),
            ("Change master password", self.change_master_flow), ("Activity log", self.open_log),
        ):
            ttk.Button(bar, text=text, command=command).pack(side="left", padx=2)
        ttk.Button(bar, text="Lock now", command=lambda: self.lock("manual")).pack(side="right", padx=2)

        self.status_var = tk.StringVar(value=f"{len(self.session.entries)} entries")
        ttk.Label(self.container, textvariable=self.status_var, anchor="w",
                  padding=(10, 4)).pack(fill="x", side="bottom")

        body = ttk.Frame(self.container, padding=8)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_tree())
        ttk.Entry(left, textvariable=self.search_var).pack(fill="x", pady=(0, 6))
        self.tree = ttk.Treeview(left, columns=("site", "username"), show="headings", selectmode="browse")
        self.tree.heading("site", text="Site / service")
        self.tree.heading("username", text="Username")
        self.tree.column("site", width=270)
        self.tree.column("username", width=110)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())

        right = ttk.LabelFrame(body, text="Details", padding=10)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)
        self.d_site, self.d_user = tk.StringVar(), tk.StringVar()
        self.d_pw, self.d_updated = tk.StringVar(), tk.StringVar()
        for row, (label, var) in enumerate((
            ("Site", self.d_site), ("Username", self.d_user),
            ("Password", self.d_pw), ("Updated", self.d_updated),
        )):
            ttk.Label(right, text=label).grid(row=row, column=0, sticky="w", pady=3)
            ttk.Label(right, textvariable=var).grid(row=row, column=1, sticky="w", padx=8)
        ttk.Label(right, text="Notes").grid(row=4, column=0, sticky="nw", pady=3)
        self.d_notes = tk.Text(right, height=5, width=30, state="disabled")
        self.d_notes.grid(row=4, column=1, sticky="ew", padx=8)

        actions = ttk.Frame(right)
        actions.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.show_btn = ttk.Button(actions, text="Show", command=self.toggle_password)
        self.show_btn.pack(side="left", padx=(0, 4))
        ttk.Button(actions, text="Copy password", command=self.copy_password).pack(side="left", padx=4)
        ttk.Button(actions, text="Edit", command=self.edit_entry).pack(side="left", padx=4)
        ttk.Button(actions, text="Delete", command=self.delete_entry).pack(side="left", padx=4)

        self.refresh_tree()
        self._schedule_tick()

    def update_status(self):
        if self.session and not self.session.locked and hasattr(self, "status_var"):
            self.status_var.set(f"{len(self.session.entries)} entries  |  "
                                f"auto-lock in {self.session.seconds_until_lock()}s")

    def refresh_tree(self, select=None):
        if not self.session or self.session.locked:
            return
        self.update_status()
        needle = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        self.tree.delete(*self.tree.get_children())
        for site in sorted(self.session.entries, key=str.lower):
            entry = self.session.entries[site]
            if needle and needle not in site.lower() and needle not in entry.get("username", "").lower():
                continue
            self.tree.insert("", "end", iid=site, values=(site, entry.get("username", "")))
        if select and self.tree.exists(select):
            self.tree.selection_set(select)
        self.show_details()

    def selected_site(self):
        selection = self.tree.selection()
        return selection[0] if selection else None

    def show_details(self):
        self._pw_visible = False
        if hasattr(self, "show_btn"):
            self.show_btn.config(text="Show")
        site = self.selected_site()
        entry = self.session.entries.get(site) if (self.session and site) else None
        self.d_site.set(site or "")
        self.d_user.set(entry["username"] if entry else "")
        self.d_pw.set("********" if entry else "")
        self.d_updated.set(entry.get("updated", "").replace("T", " ") if entry else "")
        self.d_notes.config(state="normal")
        self.d_notes.delete("1.0", "end")
        if entry:
            self.d_notes.insert("1.0", entry.get("notes", ""))
        self.d_notes.config(state="disabled")

    def toggle_password(self):
        site = self.selected_site()
        if not site:
            return
        self._pw_visible = not self._pw_visible
        self.d_pw.set(self.session.entries[site]["password"] if self._pw_visible else "********")
        self.show_btn.config(text="Hide" if self._pw_visible else "Show")
        if self._pw_visible:
            pm.log_event("view_password", "ok", site)

    # ----- entry operations ------------------------------------------------

    def save_entry(self, site, username, password, notes, old_site=None):
        """Store/replace an entry. Returns a list of warning strings (reuse, common password)."""
        entries = self.session.entries
        if old_site and old_site != site:
            entries.pop(old_site, None)
        entries[site] = {
            "username": username, "password": password, "notes": notes,
            "updated": datetime.now().isoformat(timespec="seconds"),
        }
        pm.persist_entries(self.session.fernet, entries)
        pm.log_event("edit_entry" if old_site else "add_entry", "ok", site)
        warnings = []
        if pm.is_common_password(password):
            warnings.append("This password is on the common-password list.")
        reused = [s for s, e in entries.items() if s != site and e["password"] == password]
        if reused:
            warnings.append("This password is also used for: " + ", ".join(reused))
        return warnings

    def remove_entry(self, site):
        self.session.entries.pop(site, None)
        pm.persist_entries(self.session.fernet, self.session.entries)
        pm.log_event("delete_entry", "ok", site)

    def add_entry(self):
        dialog = EntryDialog(self, "Add entry")
        self.wait_window(dialog)
        self._finish_entry_dialog(dialog.result, None)

    def edit_entry(self):
        site = self.selected_site()
        if not site:
            return
        e = self.session.entries[site]
        dialog = EntryDialog(self, "Edit entry", site, e["username"], e["password"], e.get("notes", ""))
        self.wait_window(dialog)
        self._finish_entry_dialog(dialog.result, site)

    def _finish_entry_dialog(self, result, old_site):
        if not result or not self.session or self.session.locked:
            return
        if (result["site"] in self.session.entries and result["site"] != old_site
                and not messagebox.askyesno("Overwrite?", f"'{result['site']}' already exists. Overwrite it?")):
            return
        warnings = self.save_entry(result["site"], result["username"], result["password"],
                                   result["notes"], old_site)
        self.refresh_tree(select=result["site"])
        if warnings:
            messagebox.showwarning("Password warning", "\n".join(warnings))

    def delete_entry(self):
        site = self.selected_site()
        if site and messagebox.askyesno("Delete entry", f"Delete '{site}'? This cannot be undone."):
            self.remove_entry(site)
            self.refresh_tree()

    # ----- clipboard -------------------------------------------------------

    def copy_password(self):
        site = self.selected_site()
        if not site:
            return
        self.copy_text(self.session.entries[site]["password"])
        pm.log_event("copy_password", "ok", site)
        self.status_var.set(f"Password copied - clipboard clears in {pm.CLIPBOARD_CLEAR_SECONDS}s.")

    def copy_text(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._clip_text = text
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(CLIPBOARD_CLEAR_MS, self.clear_clipboard)

    def clear_clipboard(self):
        if self._clip_job:
            try:
                self.after_cancel(self._clip_job)
            except tk.TclError:
                pass
            self._clip_job = None
        if self._clip_text is not None:
            try:
                if self.clipboard_get() == self._clip_text:     # don't clobber newer clipboard content
                    self.clipboard_clear()
                    self.clipboard_append("")
            except tk.TclError:
                pass
            self._clip_text = None

    # ----- security audit / log -------------------------------------------

    def open_audit(self):
        AuditWindow(self)

    def open_log(self):
        LogWindow(self)

    # ----- re-authentication, export, import, change master ----------------

    def reauthenticate(self):
        pw = simpledialog.askstring("Confirm identity", "Re-enter your master password:",
                                    show="*", parent=self)
        if pw is None:
            return False
        try:
            pm.unlock_vault(pw, purpose="reauth")
            return True
        except ValueError as e:
            messagebox.showerror("Not authorised", str(e), parent=self)
            return False

    def export_flow(self):
        if not messagebox.askokcancel("Export", "Exporting creates a file containing your passwords. Continue?"):
            return
        if not self.reauthenticate():
            return
        choice = ChoiceDialog(self, "Export format", "How should the file be saved?", [
            ("enc", "Encrypted (recommended) - only openable by this vault's master password"),
            ("plain", "Plaintext CSV - anyone with the file can read every password"),
        ])
        self.wait_window(choice)
        if not choice.result:
            return
        encrypted = choice.result == "enc"
        path = filedialog.asksaveasfilename(
            parent=self, title="Save export",
            defaultextension=".csv.enc" if encrypted else ".csv",
            initialfile="vault_export.csv.enc" if encrypted else "vault_export.csv")
        if not path:
            return
        pm.export_csv(self.session.entries, path, fernet=self.session.fernet if encrypted else None)
        note = "" if encrypted else "\n\nThis file is PLAINTEXT - delete it when you're done."
        messagebox.showinfo("Export complete", f"Exported {len(self.session.entries)} entries.{note}")

    def import_flow(self):
        path = filedialog.askopenfilename(parent=self, title="Choose a CSV to import",
                                          filetypes=[("CSV / encrypted export", "*.csv *.enc"), ("All files", "*.*")])
        if not path:
            return
        choice = ChoiceDialog(self, "Duplicates", "If a site already exists in the vault:", [
            ("skip", "Skip it (keep the existing entry)"),
            ("overwrite", "Overwrite it with the imported one"),
            ("rename", "Keep both (rename the imported one)"),
        ])
        self.wait_window(choice)
        if not choice.result:
            return
        self.run_import(path, choice.result)

    def run_import(self, path, on_conflict):
        try:
            stats = pm.import_csv(path, self.session.entries, fernet=self.session.fernet, on_conflict=on_conflict)
        except ValueError as e:
            messagebox.showerror("Import failed", str(e))
            return None
        pm.persist_entries(self.session.fernet, self.session.entries)
        self.refresh_tree()
        messagebox.showinfo("Import complete", ", ".join(f"{v} {k}" for k, v in stats.items()))
        return stats

    def change_master_flow(self):
        old = simpledialog.askstring("Change master password", "Current master password:", show="*", parent=self)
        if old is None:
            return
        new = simpledialog.askstring("Change master password", "New master password:", show="*", parent=self)
        if new is None:
            return
        confirm = simpledialog.askstring("Change master password", "Confirm new master password:",
                                         show="*", parent=self)
        if confirm != new:
            messagebox.showerror("Mismatch", "The new passwords do not match.")
            return
        try:
            self.session.fernet = pm.change_master_password(old, new, self.session.entries)
        except ValueError as e:
            messagebox.showerror("Could not change password", str(e))
            return
        messagebox.showinfo("Done", "Master password changed. The vault was re-encrypted with a new salt.")

    # ----- auto-lock -------------------------------------------------------

    def _schedule_tick(self):
        if self._tick_job:
            self.after_cancel(self._tick_job)
        self._tick_job = self.after(1000, self.tick)

    def tick(self):
        self._tick_job = None
        if not self.session or self.session.locked:
            return
        remaining = self.session.seconds_until_lock()
        if remaining <= 0:
            self.lock("inactivity timeout")
            return
        self.update_status()
        self._schedule_tick()

    def lock(self, reason="manual"):
        if self._tick_job:
            self.after_cancel(self._tick_job)
            self._tick_job = None
        self.clear_clipboard()
        self._close_dialogs()
        if self.session:
            self.session.lock(reason)
            self.session = None
        message = "Vault locked due to inactivity." if "timeout" in reason else ""
        self.show_login(message)

    def on_close(self):
        if self.session:
            self.session.lock("window closed")
        self.clear_clipboard()
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description="Secure Password Manager (GUI)")
    parser.add_argument("--vault", help="path to the vault file (default: vault.json)")
    parser.add_argument("--timeout", type=int, metavar="SECONDS",
                        help=f"inactivity auto-lock time (default: {pm.SESSION_TIMEOUT_SECONDS}); "
                             "a short value is handy for demos")
    args = parser.parse_args()
    App(vault_path=args.vault, auto_lock_seconds=args.timeout).mainloop()


if __name__ == "__main__":
    main()
