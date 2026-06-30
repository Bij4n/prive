# Roadmap

prive 1.0 is a fast terminal client for KeePass databases. 0.6 (2026-06-30) reads; the plan
from here, in order:

1. **Read** (in 0.6): open KDBX 3.1/4.x with a password and/or key file; `ls`, `search`, `show`,
   `get`, `otp`, `pick`, `audit`, all scriptable (`--json`, stable exit codes).
2. **Unlock once** (in 0.6): a small agent keeps the opened databases in memory
   for a while, so a working session costs one password prompt each. Linux and macOS first.
   The prompt can be skipped altogether with a `password_command` (the system keyring,
   `pass`, `op`).
3. **Everyday use** (in 0.6): several databases by name (`--db work`, `unlock
   --all`), `info`, `doctor`, `diff` for sync conflict copies, `--format` templates on `get`,
   `ls` and `search`, `codes --watch`, colour on a terminal, and a git credential helper.
4. **Bring passwords in, and out** (0.7, next): reading the exports of Proton Pass, Apple
   Passwords, Google Password Manager, LastPass, Bitwarden and any CSV is done (`import
   --check`), and so is `export` for leaving; creating the new database from an import comes
   with `prive init` in 0.7.
5. **Run and encrypt**: `prive run` is done; `encrypt`/`decrypt` files with age comes in
   0.7.
6. **Write** (0.8): add, edit and remove entries in an existing database, only once a
   round-trip test against KeePassXC-made files proves nothing is lost.
7. **1.0**: packages, docs, a week of daily use.

After 1.0: more importers (Bitwarden's and 1Password's JSON, Dashlane's own format), TOTP QR import, merging a
conflict copy (`diff` shows it today; KeePassXC merges it), an SSH agent for keys stored in
the database, the agent on Windows, shell widgets, and YubiKey challenge-response unlock.

Not planned: a cloud service, browser autofill (KeePassXC's browser extension already does it
well) or a GUI.
