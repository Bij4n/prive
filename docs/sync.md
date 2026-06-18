# Syncing and conflict copies

A KeePass database is one file, so any file sync works: Syncthing, Nextcloud, Dropbox,
iCloud Drive, a USB stick. prive reads the file where it is; nothing has to be set up.

## When the file changes under you

KeePassXC, a phone app or the sync tool may write a new version while prive has the
database unlocked. The agent notices (it compares the file's length and checksum on every
request), forgets its copy and asks for the password again, so a command never answers from
an old version. See [agent.md](agent.md).

## Conflict copies

When two devices change the database before they have synced, most sync tools keep both and
name one of them a conflict copy:

| Tool | Conflict copy |
|---|---|
| Syncthing | `Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx` |
| Nextcloud | `Passwords (conflicted copy 2026-06-12 101500).kdbx` |
| Dropbox | `Passwords (Laptop's conflicted copy 2026-06-12).kdbx` |

`prive doctor` looks for them next to the database and says so:

```
warn  sync         a conflict copy next to it: prive diff '/home/me/Sync/Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx' shows what is in it
```

Find out what is in one copy and not the other:

```bash
prive diff ~/Sync/Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx
```

```
Only in Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx:
  Conference Wi-Fi
Changed:
  Bank: password (newer in Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx)
  Personal/Legacy 2FA -> Personal/Legacy 2FA (old): title
```

Entries are paired by their UUID, so a renamed or moved entry shows as changed, not as one
removed and one added. An entry that is in one copy only but sits in the other copy's
recycle bin is marked `(in the recycle bin of ...)`: it was deleted there, not added here.
Only the names of what changed are shown, never the values.
`--json` gives the same for scripts. The other copy is opened with the same password and
key file; give `--other-keyfile` if it uses another key file, and prive asks for its
password when it has a different one.

## Merging

prive doesn't write databases yet, so merge with KeePassXC: **Database > Merge From
Database...** in the app, or on the command line

```bash
keepassxc-cli merge --same-credentials --dry-run Passwords.kdbx Passwords.sync-conflict-...kdbx
keepassxc-cli merge --same-credentials Passwords.kdbx Passwords.sync-conflict-...kdbx
```

then check with `prive diff` that nothing is left, and delete the conflict copy.
