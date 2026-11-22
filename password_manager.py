#!/usr/bin/env python3
"""
Secure Password Manager (v2)
-----------------------------
A password manager demonstrating core security concepts:

  Cryptography
    - Key derivation from a master password (PBKDF2-HMAC-SHA256, 600,000 iterations, random salt)
    - Authenticated encryption of the vault (Fernet = AES-128-CBC + HMAC-SHA256)
    - Cryptographically secure password generation (secrets module)

  Attack resistance
    - Rate-limited master password attempts with temporary lockout
    - Session auto-lock on inactivity (decrypted data dropped from memory)
    - Clipboard auto-clear after copying a password
    - Atomic vault writes (a crash mid-save cannot corrupt the vault)
    - Vault, audit log and exports are created with owner-only permissions

  Proactive risk detection
    - Vault audit: reused, weak, common, stale and (optionally) breached passwords
    - Breach check via Have I Been Pwned using k-anonymity (only the first
      5 characters of the SHA-1 hash ever leave the machine)

  Operations
    - CSV import / export (encrypted export recommended; plaintext supported)
    - Change master password (new salt, full re-encryption)
    - CSV audit log of security-relevant events (never contains secrets)

Vault format (vault.json). Vaults from v1 (no "kdf" fields) still open; they are
read with 480,000 iterations and upgraded when the master password is changed:
{
    "kdf": "PBKDF2-HMAC-SHA256",
    "kdf_iterations": 600000,
    "salt": "<base64>",
    "verifier": "<Fernet token of a known plaintext, used to check the master pw>",
    "failed_attempts": 0,
    "lockout_until": null,
    "entries": "<Fernet token of JSON {site: {username, password, notes, updated}}>"
}

Known limitations (worth discussing in the report):
    - The lockout counter lives in the vault file, so it slows down online
      guessing through this program but cannot stop an attacker who copies the
      file and guesses offline; only the PBKDF2 cost and master password
      strength protect against that.
    - Python strings are immutable, so "wiping" memory means dropping
      references and clearing the entry dict; it is best-effort, not a
      guarantee against memory forensics.
"""

import argparse
import base64
import csv
import getpass
import hashlib
import io
import json
import os
import secrets
import string
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VAULT_FILE = "vault.json"
PBKDF2_ITERATIONS = 600_000          # OWASP Password Storage Cheat Sheet: >= 600,000 for PBKDF2-HMAC-SHA256
LEGACY_PBKDF2_ITERATIONS = 480_000   # vaults made before the count was stored in the file used this
MAX_PBKDF2_ITERATIONS = 10_000_000   # sanity cap so an edited vault file cannot hang the program
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 2
SESSION_TIMEOUT_SECONDS = 90         # auto-lock after this much inactivity
CLIPBOARD_CLEAR_SECONDS = 20
STALE_DAYS = 90                      # audit flags passwords older than this
MIN_MASTER_LENGTH = 10
MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_FIELD_LENGTH = 1000
VERIFIER_PLAINTEXT = b"vault-unlock-check"


class VaultLockedError(ValueError):
    """Too many failed attempts; the vault refuses unlocks for a while."""


class InvalidMasterPassword(ValueError):
    """The master password was wrong."""


class VaultCorruptedError(ValueError):
    """The vault passed the password check but its data failed the integrity check."""


# ---------------------------------------------------------------------------
# Safe file helpers
# ---------------------------------------------------------------------------

def atomic_write(path: str, data) -> None:
    """
    Write `data` (str or bytes) to `path` atomically: write a temp file in the
    same directory, flush + fsync it, then os.replace() it over the target.
    Readers see either the old file or the new one, never a half-written one.
    The temp file is created owner-read/write only (0600).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Audit log (CSV)
# ---------------------------------------------------------------------------

AUDIT_FIELDS = ["timestamp", "event", "outcome", "detail"]


def audit_log_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(VAULT_FILE)), "audit_log.csv")


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection in text we write to CSV logs."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def log_event(event: str, outcome: str = "ok", detail: str = "") -> None:
    """Append a row to the audit log. Never log secrets. Never raise."""
    try:
        path = audit_log_path()
        is_new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow(AUDIT_FIELDS)
            writer.writerow([
                datetime.now().isoformat(timespec="seconds"),
                event, outcome, _csv_safe(detail),
            ])
        if is_new:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError:
        pass  # logging must never break the vault


def read_log(limit: int = 20) -> list:
    """Return the most recent `limit` audit log rows as dicts (oldest first)."""
    path = audit_log_path()
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows[-limit:]


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def derive_key(master_password: str, salt: bytes, iterations: int = None) -> bytes:
    """Derive a Fernet-compatible key from the master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations or PBKDF2_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def new_salt() -> bytes:
    return secrets.token_bytes(16)


# ---------------------------------------------------------------------------
# Password quality: common-password list, strength, validation
# ---------------------------------------------------------------------------

_COMMON_SEED = """
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein shadow master 666666 qwertyuiop
123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 121212
000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter
buster soccer harley batman andrew tigger sunshine iloveyou 2000 charlie robert
thomas hockey ranger daniel starwars klaster 112233 george computer michelle
jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie
159753 aaaaaa ginger princess joshua cheese amanda summer love ashley nicole
chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor
matrix welcome admin administrator root toor login passw0rd p@ssw0rd p@ssword
password1 password12 password123 changeme default guest test temp secret
qwerty123 letmein1 welcome1 admin123 football1 monkey1 dragon1 master1
liverpool arsenal chocolate internet service canada hello hello123 whatever
lakers qwert 1q2w3e4r 1q2w3e 000000 iloveu nothing apple orange spring winter
autumn fall camera sound crestron qsys biamp extron
""".split()

COMMON_PASSWORDS = set(_COMMON_SEED)
_extra_loaded = False


def _load_extra_common_passwords() -> None:
    """Merge an optional common_passwords.txt (one per line) next to the script."""
    global _extra_loaded
    if _extra_loaded:
        return
    _extra_loaded = True
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_passwords.txt")
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    COMMON_PASSWORDS.add(word)
    except OSError:
        pass


def is_common_password(pw: str) -> bool:
    """True if the password (or the password minus trailing digits/symbols) is a known common one."""
    _load_extra_common_passwords()
    p = pw.lower()
    if p in COMMON_PASSWORDS:
        return True
    stripped = p.rstrip(string.digits + string.punctuation)
    return bool(stripped) and stripped in COMMON_PASSWORDS


def password_strength_score(pw: str) -> str:
    """Heuristic strength rating: Weak / Moderate / Strong."""
    if is_common_password(pw) or len(pw) < 8:
        return "Weak"                       # short passwords are weak whatever they contain
    if len(set(pw)) < len(pw) / 3:
        return "Weak"                       # heavy repetition, e.g. "aaaaaaaaaaaaB1!"
    score = 0
    if len(pw) >= 12:
        score += 1
    if len(pw) >= 16:
        score += 1
    if any(c.islower() for c in pw):
        score += 1
    if any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(c in string.punctuation for c in pw):
        score += 1
    if score <= 2:
        return "Weak"
    if score <= 4:
        return "Moderate"
    return "Strong"


def validate_master_password(pw: str) -> None:
    """Raise ValueError (with a user-facing message) if pw is unacceptable as a master password."""
    if len(pw) < MIN_MASTER_LENGTH:
        raise ValueError(f"Master password must be at least {MIN_MASTER_LENGTH} characters.")
    if is_common_password(pw):
        raise ValueError("That master password is too common. Pick something less guessable.")


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    symbols = "!@#$%^&*()-_=+[]{}"
    alphabet = string.ascii_letters + string.digits + (symbols if use_symbols else "")
    length = max(length, 8)

    # Guarantee at least one of each character class
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        chars.append(secrets.choice(symbols))
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Vault persistence
# ---------------------------------------------------------------------------

def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE)


def load_vault_raw() -> dict:
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault_raw(data: dict) -> None:
    atomic_write(VAULT_FILE, json.dumps(data, indent=2))


def vault_iterations(data: dict) -> int:
    """PBKDF2 iteration count recorded in the vault (older vaults did not record one)."""
    try:
        iterations = int(data.get("kdf_iterations", LEGACY_PBKDF2_ITERATIONS))
    except (TypeError, ValueError):
        iterations = 0
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise VaultCorruptedError("The vault's key-derivation settings are invalid; "
                                  "the file is damaged or has been tampered with.")
    return iterations


def _encrypt_entries(fernet: Fernet, entries: dict) -> str:
    return fernet.encrypt(json.dumps(entries).encode("utf-8")).decode("utf-8")


def create_vault(master_password: str) -> None:
    validate_master_password(master_password)
    salt = new_salt()
    fernet = Fernet(derive_key(master_password, salt, PBKDF2_ITERATIONS))
    save_vault_raw({
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verifier": fernet.encrypt(VERIFIER_PLAINTEXT).decode("utf-8"),
        "failed_attempts": 0,
        "lockout_until": None,
        "entries": _encrypt_entries(fernet, {}),
    })
    log_event("vault_created")


def unlock_vault(master_password: str, purpose: str = "unlock"):
    """
    Attempt to unlock the vault. Returns (fernet, entries_dict) on success.
    Raises VaultLockedError / InvalidMasterPassword (both ValueError) otherwise.
    `purpose` ("unlock" or "reauth") only labels the audit log.
    """
    data = load_vault_raw()

    # --- Lockout check (before doing any expensive key derivation) ---
    if data.get("lockout_until"):
        lockout_until = datetime.fromisoformat(data["lockout_until"])
        if datetime.now() < lockout_until:
            remaining = int((lockout_until - datetime.now()).total_seconds()) + 1
            log_event(purpose, "blocked", "vault locked out")
            raise VaultLockedError(
                f"Vault is locked due to too many failed attempts. "
                f"Try again in {remaining} seconds."
            )
        data["failed_attempts"] = 0
        data["lockout_until"] = None
        save_vault_raw(data)

    salt = base64.b64decode(data["salt"])
    fernet = Fernet(derive_key(master_password, salt, vault_iterations(data)))

    try:
        if fernet.decrypt(data["verifier"].encode("utf-8")) != VERIFIER_PLAINTEXT:
            raise InvalidToken()
    except InvalidToken:
        data["failed_attempts"] = data.get("failed_attempts", 0) + 1
        if data["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            data["lockout_until"] = (
                datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
            ).isoformat()
            save_vault_raw(data)
            log_event(purpose, "failed", f"attempt {data['failed_attempts']} - lockout started")
            raise VaultLockedError(
                f"Too many failed attempts. Vault locked for {LOCKOUT_MINUTES} minutes."
            )
        save_vault_raw(data)
        remaining = MAX_FAILED_ATTEMPTS - data["failed_attempts"]
        log_event(purpose, "failed", f"attempt {data['failed_attempts']}")
        raise InvalidMasterPassword(
            f"Incorrect master password. {remaining} attempt(s) remaining."
        )

    if data.get("failed_attempts", 0) != 0 or data.get("lockout_until"):
        data["failed_attempts"] = 0
        data["lockout_until"] = None
        save_vault_raw(data)

    try:
        entries = json.loads(fernet.decrypt(data["entries"].encode("utf-8")).decode("utf-8"))
    except (InvalidToken, ValueError):
        # Authenticated encryption caught a modified or damaged vault. This is not a
        # wrong-password event, so it does not count toward the lockout.
        log_event(purpose, "error", "vault data failed integrity check")
        raise VaultCorruptedError(
            "The vault data failed its integrity check. The file is damaged or has been "
            "tampered with. Restore it from a backup or an encrypted export."
        )
    log_event(purpose, "ok")
    return fernet, entries


def persist_entries(fernet: Fernet, entries: dict) -> None:
    data = load_vault_raw()
    data["entries"] = _encrypt_entries(fernet, entries)
    save_vault_raw(data)


def change_master_password(old_password: str, new_password: str, entries: dict) -> Fernet:
    """
    Re-key the vault: verify the old master password, then generate a NEW salt,
    derive a new key, and re-encrypt both the verifier and every entry.
    Returns the new Fernet to use for the rest of the session.
    The new key uses the current default iteration count, so this also upgrades vaults
    created with an older, lower count.
    Note: encrypted CSV exports made before the change can no longer be decrypted.
    """
    unlock_vault(old_password, purpose="reauth")          # re-auth (counts failures)
    validate_master_password(new_password)
    if new_password == old_password:
        raise ValueError("New master password must be different from the current one.")

    salt = new_salt()
    fernet = Fernet(derive_key(new_password, salt, PBKDF2_ITERATIONS))
    save_vault_raw({
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verifier": fernet.encrypt(VERIFIER_PLAINTEXT).decode("utf-8"),
        "failed_attempts": 0,
        "lockout_until": None,
        "entries": _encrypt_entries(fernet, entries),
    })
    log_event("master_password_changed")
    return fernet


# ---------------------------------------------------------------------------
# Vault audit: reuse / weak / common / stale / breached
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def hibp_pwned_count(password: str, timeout: float = 6.0):
    """
    Check a password against Have I Been Pwned using k-anonymity.
    Only the first 5 hex chars of the SHA-1 hash are sent; the match is done
    locally on the returned suffixes. (SHA-1 is required by the HIBP API; it is
    used here as a lookup key, not for protecting anything.)
    Returns the breach count (0 = not found) or None if the service is unreachable.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "CIS4365-PasswordManager-StudentProject", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    for line in body.splitlines():
        found_suffix, _, count = line.partition(":")
        if found_suffix.strip() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def _age_days(updated: str):
    try:
        return (datetime.now() - datetime.fromisoformat(updated)).days
    except (TypeError, ValueError):
        return None


def audit_vault(entries: dict, stale_days: int = STALE_DAYS, check_online: bool = False,
                breach_lookup=hibp_pwned_count):
    """
    Scan every entry for password problems.
    Returns (findings, online_status) where findings is a list of dicts
    {severity, site, issue} sorted High -> Low, and online_status is one of
    "skipped", "ok", "unavailable".
    """
    findings = []

    def add(severity, site, issue):
        findings.append({"severity": severity, "site": site, "issue": issue})

    # Reuse
    by_password = {}
    for site, entry in entries.items():
        by_password.setdefault(entry.get("password", ""), []).append(site)
    for pw, sites in by_password.items():
        if len(sites) > 1 and pw:
            for site in sites:
                others = [s for s in sites if s != site]
                add("High", site, f"Password reused on {len(others)} other "
                                  f"entr{'y' if len(others) == 1 else 'ies'}: {', '.join(others)}")

    # Common / weak / moderate / stale
    for site, entry in entries.items():
        pw = entry.get("password", "")
        if not pw:
            add("High", site, "No password stored")
            continue
        if is_common_password(pw):
            add("High", site, "Appears in the common-password list")
        else:
            strength = password_strength_score(pw)
            if strength == "Weak":
                add("High", site, "Weak password (short or low variety)")
            elif strength == "Moderate":
                add("Low", site, "Moderate strength; a longer, more varied password is better")
        age = _age_days(entry.get("updated"))
        if age is not None and age > stale_days:
            add("Medium", site, f"Password not changed in {age} days")

    # Online breach check (one lookup per unique password)
    online_status = "skipped"
    if check_online:
        online_status = "unavailable"
        cache = {}
        for site, entry in entries.items():
            pw = entry.get("password", "")
            if not pw:
                continue
            if pw not in cache:
                cache[pw] = breach_lookup(pw)
            count = cache[pw]
            if count is None:
                continue
            online_status = "ok"
            if count > 0:
                add("High", site, f"Found in {count:,} known data breaches - change it now")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["site"].lower()))
    return findings, online_status


def summarize_findings(findings: list) -> dict:
    summary = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        summary[f["severity"]] += 1
    return summary


# ---------------------------------------------------------------------------
# CSV import / export
# ---------------------------------------------------------------------------

CSV_FIELDS = ["site", "username", "password", "notes", "updated"]

# Accepted header names (lower-cased) -> our field, so exports from other
# password managers / spreadsheets import cleanly.
CSV_ALIASES = {
    "site": "site", "name": "site", "title": "site", "url": "site", "service": "site",
    "device": "site", "device_name": "site",
    "username": "username", "user": "username", "login": "username",
    "login_username": "username", "email": "username",
    "password": "password", "login_password": "password", "pass": "password",
    "notes": "notes", "note": "notes", "extra": "notes", "comment": "notes",
    "updated": "updated", "modified": "updated", "last_modified": "updated",
}


def entries_to_csv_text(entries: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for site in sorted(entries):
        e = entries[site]
        writer.writerow({
            "site": site,
            "username": e.get("username", ""),
            "password": e.get("password", ""),
            "notes": e.get("notes", ""),
            "updated": e.get("updated", ""),
        })
    return buf.getvalue()


def export_csv(entries: dict, path: str, fernet: Fernet = None) -> None:
    """
    Export all entries. With `fernet`, the CSV is encrypted with the vault key
    (recommended). Without it, the file is PLAINTEXT - anyone who can read the
    file can read every password.
    """
    data = entries_to_csv_text(entries).encode("utf-8")
    if fernet is not None:
        data = fernet.encrypt(data)
    atomic_write(path, data)
    log_event("export_csv", "ok",
              f"{len(entries)} entries, {'encrypted' if fernet else 'PLAINTEXT'}")


def import_csv(path: str, entries: dict, fernet: Fernet = None, on_conflict: str = "skip") -> dict:
    """
    Import entries from a CSV (plain or one made by export_csv with encryption).
    on_conflict: "skip" (keep existing), "overwrite", or "rename" (keep both).
    Mutates `entries` and returns counts: added, skipped, overwritten, renamed, invalid.
    Raises ValueError for unreadable / unsafe / malformed files.
    """
    if on_conflict not in ("skip", "overwrite", "rename"):
        raise ValueError("on_conflict must be 'skip', 'overwrite' or 'rename'.")
    if os.path.getsize(path) > MAX_IMPORT_BYTES:
        raise ValueError("File is too large to import (limit 5 MB).")

    with open(path, "rb") as f:
        raw = f.read()

    if raw.startswith(b"gAAAA"):                       # Fernet token => encrypted export
        if fernet is None:
            raise ValueError("This file is encrypted but no vault key is available.")
        try:
            raw = fernet.decrypt(raw)
        except InvalidToken:
            raise ValueError("Could not decrypt the file (wrong vault, or master password "
                             "changed since the export).")
    try:
        text = raw.decode("utf-8-sig")                 # tolerate Excel's BOM
    except UnicodeDecodeError:
        raise ValueError("File is not valid UTF-8 text.")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row.")
    column_map = {}
    for header in reader.fieldnames:
        target = CSV_ALIASES.get((header or "").strip().lower())
        if target and target not in column_map.values():
            column_map[header] = target
    if "site" not in column_map.values() or "password" not in column_map.values():
        raise ValueError("CSV needs at least a 'site' (or name/title/url) column and a "
                         "'password' column.")

    stats = {"added": 0, "skipped": 0, "overwritten": 0, "renamed": 0, "invalid": 0}
    for row in reader:
        rec = {"site": "", "username": "", "password": "", "notes": "", "updated": ""}
        for header, target in column_map.items():
            rec[target] = (row.get(header) or "").strip()[:MAX_FIELD_LENGTH]
        if not rec["site"] or not rec["password"]:
            stats["invalid"] += 1
            continue
        if _age_days(rec["updated"]) is None:
            rec["updated"] = datetime.now().isoformat(timespec="seconds")

        site = rec["site"]
        if site in entries:
            if on_conflict == "skip":
                stats["skipped"] += 1
                continue
            if on_conflict == "overwrite":
                stats["overwritten"] += 1
            else:
                n = 2
                while f"{site} ({n})" in entries:
                    n += 1
                site = f"{site} ({n})"
                stats["renamed"] += 1
        else:
            stats["added"] += 1
        entries[site] = {k: rec[k] for k in ("username", "password", "notes", "updated")}

    log_event("import_csv", "ok", ", ".join(f"{k}={v}" for k, v in stats.items()))
    return stats


# ---------------------------------------------------------------------------
# Clipboard with auto-clear (uses pyperclip if installed)
# ---------------------------------------------------------------------------

class ClipboardGuard:
    """Copy a secret to the clipboard and wipe it after a delay (only if unchanged)."""

    def __init__(self, clear_after: int = CLIPBOARD_CLEAR_SECONDS):
        self.clear_after = clear_after
        self._timer = None
        self._last = None

    @staticmethod
    def available() -> bool:
        try:
            import pyperclip  # noqa: F401
            return True
        except ImportError:
            return False

    def copy(self, text: str) -> bool:
        try:
            import pyperclip
            pyperclip.copy(text)
        except Exception:
            return False
        self._last = text
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(self.clear_after, self.clear_now)
        self._timer.daemon = True
        self._timer.start()
        return True

    def clear_now(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self._last is not None:
            try:
                import pyperclip
                if pyperclip.paste() == self._last:    # don't clobber something the user copied since
                    pyperclip.copy("")
            except Exception:
                pass
            self._last = None


clipboard = ClipboardGuard()


# ---------------------------------------------------------------------------
# Session handling (auto-lock on inactivity)
# ---------------------------------------------------------------------------

class Session:
    """
    Holds the decrypted vault while unlocked. After `timeout` seconds without
    activity the session locks itself and drops all decrypted data - even while
    the CLI is blocked waiting for input. GUIs pass auto_timer=False and call
    lock() themselves from their own event loop.
    """

    def __init__(self, fernet: Fernet, entries: dict,
                 timeout: float = SESSION_TIMEOUT_SECONDS, auto_timer: bool = True):
        self.fernet = fernet
        self.entries = entries
        self.timeout = timeout
        self.auto_timer = auto_timer
        self.locked = False
        self.last_activity = time.time()
        self._timer = None
        self.touch()

    def touch(self) -> None:
        if self.locked:
            return
        self.last_activity = time.time()
        if not self.auto_timer:
            return
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(self.timeout, self.lock, kwargs={"reason": "inactivity timeout"})
        self._timer.daemon = True
        self._timer.start()

    def seconds_until_lock(self) -> int:
        return max(0, int(self.timeout - (time.time() - self.last_activity)))

    def lock(self, reason: str = "manual") -> None:
        if self.locked:
            return
        self.locked = True
        if self._timer:
            self._timer.cancel()
        if isinstance(self.entries, dict):
            self.entries.clear()
        self.entries = None
        self.fernet = None
        clipboard.clear_now()
        log_event("session_lock", "ok", reason)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def prompt_master_password(prompt: str = "Master password: ") -> str:
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def _clean_path(raw: str) -> str:
    return raw.strip().strip('"').strip("'")


def _reauthenticate() -> bool:
    pw = prompt_master_password("Re-enter your master password to continue: ")
    try:
        unlock_vault(pw, purpose="reauth")
        return True
    except ValueError as e:
        print(f"Error: {e}")
        return False


def cmd_add(session: Session):
    site = input("Site/service name: ").strip()
    if not site:
        print("Site name is required.")
        return
    if site in session.entries:
        if input(f"'{site}' already exists. Overwrite? [y/N]: ").strip().lower() != "y":
            return
    username = input("Username/email: ").strip()

    if input("Generate a strong password? [Y/n]: ").strip().lower() in ("", "y", "yes"):
        length_in = input("Password length (default 16): ").strip()
        password = generate_password(length=int(length_in) if length_in.isdigit() else 16)
        print(f"Generated password: {password}")
    else:
        password = getpass.getpass("Enter password: ")

    notes = input("Notes (optional): ").strip()

    session.entries[site] = {
        "username": username, "password": password, "notes": notes,
        "updated": datetime.now().isoformat(timespec="seconds"),
    }
    persist_entries(session.fernet, session.entries)
    log_event("add_entry", "ok", site)

    print(f"Saved entry for '{site}'. Strength: {password_strength_score(password)}")
    if is_common_password(password):
        print("  WARNING: this password is on the common-password list.")
    reused = [s for s, e in session.entries.items() if s != site and e["password"] == password]
    if reused:
        print(f"  WARNING: this password is already used for: {', '.join(reused)}")


def cmd_view(session: Session):
    site = input("Site/service name to view: ").strip()
    entry = session.entries.get(site)
    if not entry:
        print("No entry found for that site.")
        return
    print(f"\n  Site:     {site}")
    print(f"  Username: {entry['username']}")
    if entry.get("notes"):
        print(f"  Notes:    {entry['notes']}")
    print(f"  Updated:  {entry.get('updated', 'unknown')}")
    print("  Password: ********")
    choice = input("\n  [c] copy password to clipboard, [s] show on screen, [Enter] done: ").strip().lower()
    if choice == "c":
        if clipboard.copy(entry["password"]):
            print(f"  Copied. The clipboard will be cleared in {clipboard.clear_after} seconds.")
            log_event("copy_password", "ok", site)
        else:
            print("  Clipboard unavailable. Install it with: pip install pyperclip (or use [s]).")
    elif choice == "s":
        print(f"  Password: {entry['password']}")
        log_event("view_password", "ok", site)
    print()


def cmd_list(session: Session):
    if not session.entries:
        print("Vault is empty.")
        return
    print("\nStored entries:")
    for site, entry in sorted(session.entries.items()):
        print(f"  - {site}  ({entry['username']})")
    print()


def cmd_delete(session: Session):
    site = input("Site/service name to delete: ").strip()
    if site not in session.entries:
        print("No entry found for that site.")
        return
    if input(f"Delete entry for '{site}'? [y/N]: ").strip().lower() == "y":
        del session.entries[site]
        persist_entries(session.fernet, session.entries)
        log_event("delete_entry", "ok", site)
        print("Deleted.")


def cmd_generate(session: Session):
    length_in = input("Password length (default 16): ").strip()
    pw = generate_password(length=int(length_in) if length_in.isdigit() else 16)
    print(f"Generated password: {pw}\nStrength: {password_strength_score(pw)}")


def cmd_audit(session: Session):
    if not session.entries:
        print("Vault is empty - nothing to audit.")
        return
    online = input("Also check passwords against known breaches online (k-anonymity)? [y/N]: ").strip().lower() == "y"
    if online:
        print("Checking... (only 5-character hash prefixes are sent)")
    findings, status = audit_vault(session.entries, check_online=online)
    log_event("vault_audit", "ok", f"{len(findings)} findings, online={status}")

    print(f"\n=== Vault audit: {len(session.entries)} entries ===")
    if not findings:
        print("No issues found.")
    for f in findings:
        print(f"  [{f['severity'].upper():6}] {f['site']}: {f['issue']}")
    s = summarize_findings(findings)
    print(f"\nSummary: {s['High']} high, {s['Medium']} medium, {s['Low']} low")
    if status == "unavailable":
        print("Note: the breach service could not be reached; online check skipped.")
    print()


def cmd_export(session: Session):
    print("\nExporting creates a file containing your passwords.")
    if not _reauthenticate():
        return
    fmt = input("Format: [e]ncrypted (recommended) or [p]laintext CSV? [E/p]: ").strip().lower()
    encrypted = fmt != "p"
    default = "vault_export.csv.enc" if encrypted else "vault_export.csv"
    path = _clean_path(input(f"Output file (default {default}): ")) or default
    if os.path.exists(path) and input(f"'{path}' exists. Overwrite? [y/N]: ").strip().lower() != "y":
        return
    export_csv(session.entries, path, fernet=session.fernet if encrypted else None)
    if encrypted:
        print(f"Exported {len(session.entries)} entries (encrypted) to {path}.")
        print("It can only be re-imported into a vault using the same master password.")
    else:
        print(f"Exported {len(session.entries)} entries to {path} as PLAINTEXT.")
        print("WARNING: delete this file as soon as you're done with it.")


def cmd_import(session: Session):
    path = _clean_path(input("CSV file to import: "))
    if not os.path.isfile(path):
        print("File not found.")
        return
    mode = input("If a site already exists: [s]kip, [o]verwrite, keep [b]oth? [S/o/b]: ").strip().lower()
    on_conflict = {"o": "overwrite", "b": "rename"}.get(mode, "skip")
    try:
        stats = import_csv(path, session.entries, fernet=session.fernet, on_conflict=on_conflict)
    except ValueError as e:
        print(f"Import failed: {e}")
        return
    persist_entries(session.fernet, session.entries)
    print("Import complete: " + ", ".join(f"{v} {k}" for k, v in stats.items()))


def cmd_change_master(session: Session):
    old = prompt_master_password("Current master password: ")
    new = prompt_master_password("New master password: ")
    if new != prompt_master_password("Confirm new master password: "):
        print("Passwords do not match.")
        return
    try:
        session.fernet = change_master_password(old, new, session.entries)
    except ValueError as e:
        print(f"Error: {e}")
        return
    print("Master password changed and vault re-encrypted with a new salt.")


def cmd_history(session: Session):
    rows = read_log(20)
    if not rows:
        print("No activity recorded yet.")
        return
    print("\nRecent activity (newest last):")
    for r in rows:
        detail = f" - {r['detail']}" if r["detail"] else ""
        print(f"  {r['timestamp']}  {r['event']:<24} {r['outcome']}{detail}")
    print(f"\nFull log: {audit_log_path()}\n")


def print_menu():
    print("""
--- Password Manager ---
  [a] Add entry          [s] Security audit
  [v] View entry         [x] Export to CSV
  [l] List entries       [i] Import from CSV
  [d] Delete entry       [m] Change master password
  [g] Generate password  [h] Activity history
  [q] Lock and quit
-------------------------""")


def run_session(fernet: Fernet, entries: dict, timeout: float = None):
    timeout = timeout or SESSION_TIMEOUT_SECONDS
    session = Session(fernet, entries, timeout=timeout)
    print(f"\nVault unlocked. It will auto-lock after {timeout:g} seconds of inactivity.")
    try:
        if vault_iterations(load_vault_raw()) < PBKDF2_ITERATIONS:
            print("Tip: this vault uses an older, lower key-stretching setting. "
                  "Choose [m] Change master password to upgrade it.")
    except (ValueError, OSError):
        pass

    actions = {
        "a": cmd_add, "v": cmd_view, "l": cmd_list, "d": cmd_delete, "g": cmd_generate,
        "s": cmd_audit, "x": cmd_export, "i": cmd_import, "m": cmd_change_master,
        "h": cmd_history,
    }

    while True:
        if session.locked:
            print("\nSession timed out due to inactivity. Vault locked.")
            break
        print_menu()
        choice = input("Choose an option: ").strip().lower()
        if session.locked:      # the timer fired while we were waiting for input
            print("\nSession timed out due to inactivity. Vault locked.")
            break
        session.touch()

        if choice == "q":
            session.lock("user quit")
            print("Vault locked. Goodbye.")
            break
        if choice in actions:
            try:
                actions[choice](session)
            except (AttributeError, TypeError):
                if session.locked:
                    print("\nSession timed out during that action. Vault locked.")
                    break
                raise
            session.touch()
        else:
            print("Invalid option.")


def main():
    global VAULT_FILE
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    parser.add_argument("--vault", help="path to the vault file (default: vault.json)")
    parser.add_argument("--timeout", type=float, metavar="SECONDS",
                        help=f"inactivity auto-lock time (default: {SESSION_TIMEOUT_SECONDS}); "
                             "a short value is handy for demos")
    args = parser.parse_args()
    if args.vault:
        VAULT_FILE = args.vault

    print("=== Secure Password Manager ===")

    if not vault_exists():
        print("No vault found. Let's create one.")
        while True:
            pw1 = prompt_master_password("Create a master password: ")
            if prompt_master_password("Confirm master password: ") != pw1:
                print("Passwords do not match, try again.\n")
                continue
            try:
                create_vault(pw1)
            except ValueError as e:
                print(f"{e}\n")
                continue
            break
        print("Vault created.\n")

    while True:
        try:
            fernet, entries = unlock_vault(prompt_master_password())
            break
        except (VaultLockedError, VaultCorruptedError) as e:
            print(f"Error: {e}")
            sys.exit(1)
        except InvalidMasterPassword as e:
            print(f"Error: {e}")

    run_session(fernet, entries, timeout=args.timeout)


if __name__ == "__main__":
    main()
