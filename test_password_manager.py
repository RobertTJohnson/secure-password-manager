#!/usr/bin/env python3
"""
Automated tests for password_manager.py.
Run with:  python3 test_password_manager.py -v

Most tests lower PBKDF2_ITERATIONS so the suite runs fast; the backward-
compatibility test (vaults made by v1) uses the real iteration count.
"""

import csv
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timedelta
from unittest import mock

import password_manager as pm

MASTER = "correct-horse-battery-9"
REAL_ITERATIONS = pm.PBKDF2_ITERATIONS          # 600,000 by default


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        pm.VAULT_FILE = os.path.join(self.dir, "vault.json")
        pm.PBKDF2_ITERATIONS = 1000            # fast for tests
        pm.clipboard.clear_now()

    def tearDown(self):
        pm.PBKDF2_ITERATIONS = REAL_ITERATIONS
        shutil.rmtree(self.dir, ignore_errors=True)

    def make_vault(self):
        pm.create_vault(MASTER)
        return pm.unlock_vault(MASTER)

    @staticmethod
    def entry(password, days_old=0, username="admin", notes=""):
        updated = (datetime.now() - timedelta(days=days_old)).isoformat(timespec="seconds")
        return {"username": username, "password": password, "notes": notes, "updated": updated}


class TestAtomicWrite(Base):
    def test_writes_content_and_owner_only_permissions(self):
        path = os.path.join(self.dir, "f.txt")
        pm.atomic_write(path, "hello")
        with open(path) as fh:
            self.assertEqual(fh.read(), "hello")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_failed_write_leaves_original_intact_and_no_temp_files(self):
        path = os.path.join(self.dir, "f.txt")
        pm.atomic_write(path, "original")
        with mock.patch("os.replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                pm.atomic_write(path, "new content")
        with open(path) as fh:
            self.assertEqual(fh.read(), "original")
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith(".tmp_")], [])


class TestVault(Base):
    def test_roundtrip_and_ciphertext_on_disk(self):
        fernet, entries = self.make_vault()
        entries["site"] = self.entry("S3cret-Value!xyz")
        pm.persist_entries(fernet, entries)
        with open(pm.VAULT_FILE) as fh:
            raw = fh.read()
        self.assertNotIn("S3cret-Value!xyz", raw)
        self.assertNotIn(MASTER, raw)
        _, again = pm.unlock_vault(MASTER)
        self.assertEqual(again["site"]["password"], "S3cret-Value!xyz")

    def test_wrong_password_then_lockout_then_expiry(self):
        self.make_vault()
        for i in range(4):
            with self.assertRaises(pm.InvalidMasterPassword):
                pm.unlock_vault("wrong")
        with self.assertRaises(pm.VaultLockedError):       # 5th failure starts lockout
            pm.unlock_vault("wrong")
        with self.assertRaises(pm.VaultLockedError):       # even the right password is refused
            pm.unlock_vault(MASTER)
        data = pm.load_vault_raw()                          # simulate lockout expiring
        data["lockout_until"] = (datetime.now() - timedelta(seconds=1)).isoformat()
        pm.save_vault_raw(data)
        pm.unlock_vault(MASTER)                             # works again
        self.assertEqual(pm.load_vault_raw()["failed_attempts"], 0)

    def test_success_resets_failed_counter(self):
        self.make_vault()
        with self.assertRaises(pm.InvalidMasterPassword):
            pm.unlock_vault("wrong")
        pm.unlock_vault(MASTER)
        self.assertEqual(pm.load_vault_raw()["failed_attempts"], 0)

    def test_master_password_validation(self):
        with self.assertRaises(ValueError):
            pm.create_vault("short")
        with self.assertRaises(ValueError):
            pm.create_vault("password123")           # common (stripped form is 'password')
        self.assertFalse(pm.vault_exists())


class TestBackwardCompatibility(unittest.TestCase):
    def test_vault_in_v1_format_opens_in_v2(self):
        """Build a vault exactly as v1 did (same JSON layout, 480k PBKDF2 iterations) and open it."""
        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        d = tempfile.mkdtemp()
        try:
            salt = b"0123456789abcdef"
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
            f = Fernet(base64.urlsafe_b64encode(kdf.derive(b"LegacyMaster123!")))
            old_entries = {"old-site": {"username": "u", "password": "legacy-pw", "notes": "", "updated": "now"}}
            with open(os.path.join(d, "vault.json"), "w") as fh:
                json.dump({
                    "salt": base64.b64encode(salt).decode(),
                    "verifier": f.encrypt(b"vault-unlock-check").decode(),
                    "failed_attempts": 0,
                    "lockout_until": None,
                    "entries": f.encrypt(json.dumps(old_entries).encode()).decode(),
                }, fh)

            pm.VAULT_FILE = os.path.join(d, "vault.json")
            pm.PBKDF2_ITERATIONS = REAL_ITERATIONS
            fernet, loaded = pm.unlock_vault("LegacyMaster123!")
            self.assertEqual(loaded["old-site"]["password"], "legacy-pw")
            loaded["new-site"] = {"username": "x", "password": "new-pw", "notes": "", "updated": "now"}
            pm.persist_entries(fernet, loaded)                 # v2 can also write it back
            _, again = pm.unlock_vault("LegacyMaster123!")
            self.assertEqual(set(again), {"old-site", "new-site"})
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestTamperDetection(Base):
    def _tamper(self, field):
        import base64
        data = pm.load_vault_raw()
        raw = bytearray(base64.urlsafe_b64decode(data[field]))
        raw[40] ^= 0x01                                   # flip one bit of the ciphertext
        data[field] = base64.urlsafe_b64encode(bytes(raw)).decode()
        pm.save_vault_raw(data)

    def test_modified_entries_are_detected_not_decrypted(self):
        fernet, entries = self.make_vault()
        entries["a"] = self.entry("pw-A-123456789!")
        pm.persist_entries(fernet, entries)
        self._tamper("entries")
        with self.assertRaises(pm.VaultCorruptedError):
            pm.unlock_vault(MASTER)
        self.assertEqual(pm.load_vault_raw()["failed_attempts"], 0)   # not a wrong-password event
        self.assertIn("error", [r["outcome"] for r in pm.read_log(10)])

    def test_modified_verifier_is_rejected(self):
        self.make_vault()
        self._tamper("verifier")
        with self.assertRaises(pm.InvalidMasterPassword):
            pm.unlock_vault(MASTER)


class TestKdfSettings(Base):
    def test_iteration_count_is_stored_per_vault(self):
        pm.create_vault(MASTER)
        data = pm.load_vault_raw()
        self.assertEqual(data["kdf_iterations"], 1000)      # the value in force when it was created
        self.assertEqual(data["kdf"], "PBKDF2-HMAC-SHA256")
        pm.PBKDF2_ITERATIONS = 2000                         # raising the default later...
        pm.unlock_vault(MASTER)                             # ...must not break existing vaults

    def test_default_meets_owasp_minimum(self):
        self.assertGreaterEqual(REAL_ITERATIONS, 600_000)

    def test_changing_master_password_upgrades_legacy_vault(self):
        pm.PBKDF2_ITERATIONS = pm.LEGACY_PBKDF2_ITERATIONS
        pm.create_vault(MASTER)
        data = pm.load_vault_raw()
        del data["kdf"], data["kdf_iterations"]             # make it look like a v1 vault
        pm.save_vault_raw(data)
        self.assertEqual(pm.vault_iterations(pm.load_vault_raw()), pm.LEGACY_PBKDF2_ITERATIONS)
        _, entries = pm.unlock_vault(MASTER)

        pm.PBKDF2_ITERATIONS = 5000                         # pretend this is the new, higher default
        pm.change_master_password(MASTER, "upgraded-master-pw-1", entries)
        self.assertEqual(pm.load_vault_raw()["kdf_iterations"], 5000)
        pm.unlock_vault("upgraded-master-pw-1")

    def test_absurd_iteration_counts_are_rejected(self):
        pm.create_vault(MASTER)
        for bad in (0, -5, 10**12, "lots"):
            data = pm.load_vault_raw()
            data["kdf_iterations"] = bad
            pm.save_vault_raw(data)
            with self.assertRaises(pm.VaultCorruptedError):
                pm.unlock_vault(MASTER)


class TestChangeMaster(Base):
    def test_rekeys_vault_and_preserves_entries(self):
        fernet, entries = self.make_vault()
        entries["a"] = self.entry("pw-A-123456789!")
        pm.persist_entries(fernet, entries)
        old_salt = pm.load_vault_raw()["salt"]

        new_fernet = pm.change_master_password(MASTER, "brand-new-master-77", entries)
        self.assertNotEqual(pm.load_vault_raw()["salt"], old_salt)
        with self.assertRaises(pm.InvalidMasterPassword):
            pm.unlock_vault(MASTER)
        _, loaded = pm.unlock_vault("brand-new-master-77")
        self.assertEqual(loaded["a"]["password"], "pw-A-123456789!")
        self.assertIsNotNone(new_fernet)

    def test_rejects_bad_old_weak_new_and_same(self):
        _, entries = self.make_vault()
        with self.assertRaises(pm.InvalidMasterPassword):
            pm.change_master_password("not-the-password", "brand-new-master-77", entries)
        with self.assertRaises(ValueError):
            pm.change_master_password(MASTER, "short", entries)
        with self.assertRaises(ValueError):
            pm.change_master_password(MASTER, MASTER, entries)
        pm.unlock_vault(MASTER)    # vault untouched by the failed attempts


class TestPasswordQuality(unittest.TestCase):
    def test_strength(self):
        self.assertEqual(pm.password_strength_score("password"), "Weak")
        self.assertEqual(pm.password_strength_score("Password123!"), "Weak")     # common base word
        self.assertEqual(pm.password_strength_score("aaaaaaaaaaaaB1!"), "Weak")  # repetitive
        self.assertEqual(pm.password_strength_score("Xk9#mQ2$vL7@pR4!"), "Strong")

    def test_generator(self):
        for _ in range(50):
            pw = pm.generate_password(16)
            self.assertEqual(len(pw), 16)
            self.assertTrue(any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                            and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw))
        self.assertEqual(len(pm.generate_password(3)), 8)     # enforces a sane minimum
        self.assertTrue(pm.generate_password(20, use_symbols=False).isalnum())


class TestAudit(Base):
    def setUp(self):
        super().setUp()
        self.entries = {
            "reuse-1": self.entry("Shared-Pass-Value-42!"),
            "reuse-2": self.entry("Shared-Pass-Value-42!"),
            "common": self.entry("letmein"),
            "weak": self.entry("Ab1!"),
            "stale": self.entry("Zq8#nW5$kT2@vB9!", days_old=200),
            "fine": self.entry("Hy7&cD3*fG6^jL1!", days_old=5),
        }

    def issues(self, findings, site):
        return [f["issue"] for f in findings if f["site"] == site]

    def test_offline_findings(self):
        findings, status = pm.audit_vault(self.entries)
        self.assertEqual(status, "skipped")
        self.assertTrue(any("reused" in i for i in self.issues(findings, "reuse-1")))
        self.assertTrue(any("reused" in i for i in self.issues(findings, "reuse-2")))
        self.assertTrue(any("common" in i.lower() for i in self.issues(findings, "common")))
        self.assertTrue(any("Weak" in i for i in self.issues(findings, "weak")))
        self.assertTrue(any("not changed" in i for i in self.issues(findings, "stale")))
        self.assertEqual(self.issues(findings, "fine"), [])

    def test_sorted_high_to_low_and_summary(self):
        findings, _ = pm.audit_vault(self.entries)
        order = [pm.SEVERITY_ORDER[f["severity"]] for f in findings]
        self.assertEqual(order, sorted(order))
        summary = pm.summarize_findings(findings)
        self.assertGreater(summary["High"], 0)
        self.assertGreater(summary["Medium"], 0)

    def test_online_check_uses_lookup_once_per_unique_password(self):
        calls = []

        def fake_lookup(pw):
            calls.append(pw)
            return 12345 if pw == "letmein" else 0

        findings, status = pm.audit_vault(self.entries, check_online=True, breach_lookup=fake_lookup)
        self.assertEqual(status, "ok")
        self.assertEqual(len(calls), len(set(calls)))
        self.assertTrue(any("12,345" in i for i in self.issues(findings, "common")))

    def test_online_unavailable(self):
        _, status = pm.audit_vault(self.entries, check_online=True, breach_lookup=lambda pw: None)
        self.assertEqual(status, "unavailable")


class TestHIBP(unittest.TestCase):
    def test_only_five_char_prefix_is_sent_and_match_is_local(self):
        import hashlib
        pw = "hunter2-test"
        digest = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        body = f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\r\n{suffix}:777\r\n0000000000000000000000000000000000A:0"
        seen = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return body.encode()

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            return FakeResp()

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(pm.hibp_pwned_count(pw), 777)
        self.assertTrue(seen["url"].endswith("/range/" + prefix))
        self.assertNotIn(suffix, seen["url"])
        self.assertNotIn(pw, seen["url"])

    def test_not_found_and_network_failure(self):
        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"0000000000000000000000000000000000A:0"

        with mock.patch("urllib.request.urlopen", lambda req, timeout=None: FakeResp()):
            self.assertEqual(pm.hibp_pwned_count("whatever-123"), 0)
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            self.assertIsNone(pm.hibp_pwned_count("whatever-123"))


class TestCSV(Base):
    def setUp(self):
        super().setUp()
        self.fernet, self.entries = self.make_vault()
        self.entries["Q-SYS Core, Rm 204"] = self.entry('p,"ass"\nword!1', username="admin", notes="has, comma")
        self.entries["Camera 7"] = self.entry("=cmd|' /C calc'!A0")      # starts with '='
        self.path = os.path.join(self.dir, "out.csv")

    def test_plaintext_roundtrip_preserves_tricky_values(self):
        pm.export_csv(self.entries, self.path)
        fresh = {}
        stats = pm.import_csv(self.path, fresh)
        self.assertEqual(stats["added"], 2)
        self.assertEqual(fresh["Q-SYS Core, Rm 204"]["password"], 'p,"ass"\nword!1')
        self.assertEqual(fresh["Camera 7"]["password"], "=cmd|' /C calc'!A0")
        self.assertEqual(fresh["Q-SYS Core, Rm 204"]["notes"], "has, comma")

    def test_encrypted_export_hides_content_and_roundtrips(self):
        pm.export_csv(self.entries, self.path, fernet=self.fernet)
        with open(self.path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"Camera 7", blob)
        self.assertNotIn(b"admin", blob)
        fresh = {}
        pm.import_csv(self.path, fresh, fernet=self.fernet)
        self.assertEqual(set(fresh), set(self.entries))

    def test_encrypted_file_needs_correct_key(self):
        pm.export_csv(self.entries, self.path, fernet=self.fernet)
        with self.assertRaises(ValueError):
            pm.import_csv(self.path, {}, fernet=None)
        other = pm.Fernet(pm.derive_key("another-master-1234", b"x" * 16))
        with self.assertRaises(ValueError):
            pm.import_csv(self.path, {}, fernet=other)

    def test_conflict_modes(self):
        pm.export_csv(self.entries, self.path)
        existing = {"Camera 7": self.entry("old-password-value")}
        s = pm.import_csv(self.path, dict(existing), on_conflict="skip")
        self.assertEqual((s["skipped"], s["added"]), (1, 1))

        e2 = dict(existing)
        s = pm.import_csv(self.path, e2, on_conflict="overwrite")
        self.assertEqual(s["overwritten"], 1)
        self.assertEqual(e2["Camera 7"]["password"], "=cmd|' /C calc'!A0")

        e3 = dict(existing)
        s = pm.import_csv(self.path, e3, on_conflict="rename")
        self.assertEqual(s["renamed"], 1)
        self.assertIn("Camera 7 (2)", e3)
        self.assertEqual(e3["Camera 7"]["password"], "old-password-value")

    def test_foreign_headers_bom_and_invalid_rows(self):
        p = os.path.join(self.dir, "other.csv")
        with open(p, "w", encoding="utf-8-sig", newline="") as f:
            f.write("Name,Login,Pass,Extra\nRouter,root,hunter2!!,lab\n,nosite,pw,\nNoPass,u,,\n")
        entries = {}
        stats = pm.import_csv(p, entries)
        self.assertEqual(stats["added"], 1)
        self.assertEqual(stats["invalid"], 2)
        self.assertEqual(entries["Router"], {"username": "root", "password": "hunter2!!",
                                             "notes": "lab", "updated": entries["Router"]["updated"]})

    def test_rejects_malformed_files(self):
        p = os.path.join(self.dir, "bad.csv")
        with open(p, "w") as fh:
            fh.write("foo,bar\n1,2\n")
        with self.assertRaises(ValueError):
            pm.import_csv(p, {})
        with open(p, "wb") as fh:
            fh.write(b"\xff\xfe\x00bad")
        with self.assertRaises(ValueError):
            pm.import_csv(p, {})
        with open(p, "w") as fh:
            fh.write("site,password\na,b\n")
        with self.assertRaises(ValueError):
            pm.import_csv(p, {}, on_conflict="bogus")
        with mock.patch.object(pm, "MAX_IMPORT_BYTES", 5):
            with self.assertRaises(ValueError):
                pm.import_csv(p, {})

    def test_export_file_is_owner_only(self):
        pm.export_csv(self.entries, self.path)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)


class TestAuditLog(Base):
    def test_events_logged_without_secrets(self):
        fernet, entries = self.make_vault()
        with self.assertRaises(pm.InvalidMasterPassword):
            pm.unlock_vault("wrong-guess-secret")
        entries["x"] = self.entry("SuperSecretValue-999")
        pm.persist_entries(fernet, entries)
        pm.export_csv(entries, os.path.join(self.dir, "e.csv"))
        with open(pm.audit_log_path()) as fh:
            text = fh.read()
        for secret in (MASTER, "wrong-guess-secret", "SuperSecretValue-999"):
            self.assertNotIn(secret, text)
        events = [r["event"] for r in pm.read_log(50)]
        for expected in ("vault_created", "unlock", "export_csv"):
            self.assertIn(expected, events)
        self.assertIn("failed", [r["outcome"] for r in pm.read_log(50)])

    def test_formula_injection_neutralized_in_log(self):
        pm.log_event("add_entry", "ok", "=HYPERLINK(\"http://evil\")")
        row = pm.read_log(1)[0]
        self.assertTrue(row["detail"].startswith("'="))

    def test_log_failure_never_raises(self):
        with mock.patch("builtins.open", side_effect=OSError("read-only fs")):
            pm.log_event("anything")       # must not raise


class TestSession(Base):
    def test_auto_lock_wipes_memory_even_without_activity(self):
        fernet, entries = self.make_vault()
        entries["a"] = self.entry("x" * 20)
        session = pm.Session(fernet, entries, timeout=0.2)
        time.sleep(0.5)
        self.assertTrue(session.locked)
        self.assertIsNone(session.entries)
        self.assertIsNone(session.fernet)
        self.assertEqual(entries, {})                      # shared dict was cleared in place
        self.assertIn("session_lock", [r["event"] for r in pm.read_log(10)])

    def test_activity_extends_session(self):
        fernet, entries = self.make_vault()
        session = pm.Session(fernet, entries, timeout=0.4)
        for _ in range(3):
            time.sleep(0.2)
            session.touch()
        self.assertFalse(session.locked)
        session.lock("test")
        self.assertTrue(session.locked)


class TestClipboard(Base):
    def setUp(self):
        super().setUp()
        self.store = {"v": ""}
        fake = types.ModuleType("pyperclip")
        fake.copy = lambda t: self.store.__setitem__("v", t)
        fake.paste = lambda: self.store["v"]
        self._patch = mock.patch.dict(sys.modules, {"pyperclip": fake})
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        super().tearDown()

    def test_clears_after_delay(self):
        guard = pm.ClipboardGuard(clear_after=0.2)
        self.assertTrue(guard.copy("topsecret"))
        self.assertEqual(self.store["v"], "topsecret")
        time.sleep(0.5)
        self.assertEqual(self.store["v"], "")

    def test_does_not_clobber_newer_clipboard_content(self):
        guard = pm.ClipboardGuard(clear_after=0.2)
        guard.copy("topsecret")
        self.store["v"] = "something the user copied later"
        time.sleep(0.5)
        self.assertEqual(self.store["v"], "something the user copied later")

    def test_clear_now_and_unavailable_fallback(self):
        guard = pm.ClipboardGuard(clear_after=60)
        guard.copy("topsecret")
        guard.clear_now()
        self.assertEqual(self.store["v"], "")
        with mock.patch.dict(sys.modules, {"pyperclip": None}):
            self.assertFalse(pm.ClipboardGuard().copy("x"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
