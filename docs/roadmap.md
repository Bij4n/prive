# Roadmap

prive 1.0 is a fast terminal client for KeePass databases. The plan, in order:

1. **Read** (0.6, done): open KDBX 3.1/4.x with a password and/or key file; `ls`, `search`, `show`,
   `get`, `otp`, `pick`, `audit`, all scriptable (`--json`, stable exit codes).
2. **Unlock once** (done, ships in 0.6): a small agent keeps the opened database in memory for a while, so
   a working session costs one password prompt. Linux and macOS first.
3. **Bring passwords in** (0.7): reading the exports of Proton Pass, Apple Passwords, Google
   Password Manager, LastPass and any CSV is done (`import --check`); creating the new
   database from them comes with `prive init` in 0.7.
4. **Run and encrypt**: `prive run` is done; `encrypt`/`decrypt` files with age comes in
   0.7.
5. **Write** (0.8): add, edit and remove entries in an existing database, only once a
   round-trip test against KeePassXC-made files proves nothing is lost.
6. **1.0**: packages, docs, a week of daily use.

After 1.0: more importers (Bitwarden, 1Password, Dashlane), TOTP QR import, a git credential
helper, an SSH agent for keys stored in the database, the agent on Windows, shell widgets, and
YubiKey challenge-response unlock.

Not planned: a cloud service, browser autofill (KeePassXC's browser extension already does it
well) or a GUI.
