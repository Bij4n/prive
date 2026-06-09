# Troubleshooting

**`prive: no password given: stdin is not a terminal`** (exit 5)
prive was run from a script or a pipe and had no way to ask. Give the password with
`--password-stdin` or `PRIVE_PASSWORD_FILE`, or run `prive unlock` first in a terminal.

**`could not open the database: wrong password or key file`** (exit 5)
Check both: a database made with a key file needs `--keyfile` (or `keyfile` in the config)
every time. A database with only a key file needs `--no-password` too.

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
