# Demo notes

A walkthrough of the project demo (about 5-6 minutes inside a 12-minute presentation).

## Setup before recording

```bash
pip install -r requirements.txt
python3 password_manager_gui.py --vault demo_vault.json --timeout 15
```

- Use a **fresh demo vault** and a master password you will remember (there is no recovery).
- `--timeout 15` makes the auto-lock fast enough to show on camera.
- Import `sample_data/av_demo_credentials.csv` so the audit has something to find.
- Close other windows and hide notifications. Use a large font in your editor and terminal.

## Steps and talking points

1. **Unlock and look around (0:45).** Show the entry list, click an entry, point out the password is masked, click *Show*.
   *Point:* secrets are hidden by default.
2. **Prove it's encrypted (0:45).** Open `demo_vault.json` in a text editor.
   *Point:* only the salt is readable; the verifier and entries are ciphertext; the master password isn't stored anywhere.
3. **Security audit (1:15).** Run it. Show the reused and common passwords and the stale entries.
   Optionally tick the Have I Been Pwned check (needs internet).
   *Point:* the tool finds risky passwords proactively; the breach check only sends a 5-character hash prefix.
4. **Add an entry with the generator (0:45).** Click *Add*, then *Generate*, and show the strength rating.
5. **Encrypted export (0:45).** Export with the encrypted option, then open the file and show it is unreadable.
   *Point:* exporting requires re-entering the master password; encrypted is the default.
6. **Lockout (0:45).** Click *Lock now*, then enter wrong passwords until the lockout appears.
   *Point:* slows down online guessing.
7. **Auto-lock (0:30).** Leave it idle until the countdown ends and the vault locks itself.
8. **Optional: activity log.** Show the recorded events and that no passwords appear in them.

## If something goes wrong

- *GUI won't start on Linux:* `sudo apt install python3-tk`.
- *Clipboard copy does nothing in the CLI:* `pip install pyperclip` (the GUI doesn't need it).
- *Breach check says the service is unreachable:* no internet or a firewall; the rest of the audit still works.
- *Vault is locked out:* wait 2 minutes, or delete the demo vault and recreate it.
