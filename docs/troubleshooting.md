# Troubleshooting

Start with `prive doctor`. It checks the config file, the database file, the key file, the
agent and the clipboard without asking for a password, and says what it found:

```
ok    config file  /home/me/.config/prive/config.toml
ok    database     /home/me/Passwords.kdbx (KDBX 4.1, 48.2 KB)
--    key file     none
ok    sync         no conflict copies next to it
ok    agent        running, /home/me/Passwords.kdbx unlocked (12 min left)
warn  clipboard    no clipboard available: --clip and pick won't work here; print instead
```

`prive doctor --all` does the same for every database in the config file.

`prive config` shows which config file, database and key file prive is using, and where each
setting came from.

**`prive: no password given: stdin is not a terminal`** (exit 5)
prive was run from a script or a pipe and had no way to ask. Give the password with
`--password-stdin` or `PRIVE_PASSWORD_FILE`, or run `prive unlock` first in a terminal.

**`could not open the database: wrong password or key file`** (exit 5)
Check both: a database made with a key file needs `--keyfile` (or `keyfile` in the config)
every time. A database with only a key file needs `--no-password` too.

**`no database 'wrok': no such file, and the config file names home, work`** (exit 3)
`--db` (or `PRIVE_DB`) was neither a file nor one of the `[databases.NAME]` in the config
file. Check the spelling, or write a file in the current directory as `./name`.

**`Work/GitHub: no field 'pin' (it has: title, username, ...)`** (exit 3)
The entry is there, the field isn't. Custom field names are matched exactly first, then
ignoring case; the list shows the names the entry has. In `--format` templates, `{S:name}`
needs the exact name.

**`... is not a KeePass database`**
The path points at something else (an export, a backup in another format, a KeePass 1
`.kdb` file). Open it in KeePassXC to see what it is.

**`The database changed on disk since prive unlock; asking again.`**
KeePassXC or a sync tool saved a new version. The agent forgets old copies on purpose; run
`prive unlock` again.

**`... is mode 755; it must be 700`**
The agent's directory was made by something else, or its permissions were changed. Run
`chmod 700` on it, or delete it and let prive make it again.

**The clipboard is empty after `--clip`** (Linux)
prive needs an X11 session or a Wayland compositor with the data-control protocol (wlroots,
KDE, recent GNOME). Over SSH there is no clipboard; print to the terminal instead.

**Something else**
Run the command again with `RUST_BACKTRACE=1` if it panicked, and open an issue with what it
printed (remove anything secret first).
