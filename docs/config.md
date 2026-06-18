# Configuration

prive needs no configuration. The optional config file lives at `$PRIVE_CONFIG`, or
`<config dir>/prive/config.toml`:

| System | Default location |
|---|---|
| Linux | `~/.config/prive/config.toml` |
| macOS | `~/Library/Application Support/prive/config.toml` |
| Windows | `%APPDATA%\prive\config.toml` |

```toml
# Database opened when neither --db nor PRIVE_DB is given. A leading ~/ means your home.
db = "~/Passwords.kdbx"

# Key file for that database, if it uses one. Not used with --db.
keyfile = "/home/me/Passwords.keyx"

# Minutes the agent keeps a database unlocked after its last use (1-1440, default 15).
agent_minutes = 15

# Seconds before a copied secret is cleared from the clipboard (1-600, default 20).
clipboard_seconds = 20
```

## Password command

Instead of typing the master password, let another program hand it over: the system keyring,
`pass`, a password manager's CLI. prive runs it without a shell and reads the first line it
prints; its input and error output stay on your terminal, so it can ask for a PIN or touch.

```toml
db = "~/Passwords.kdbx"
password_command = ["secret-tool", "lookup", "prive", "Passwords"]   # GNOME Keyring, KWallet

[databases.work]
path = "~/Work/Work.kdbx"
password_command = ["pass", "show", "kdbx/work"]
```

Other examples: `["security", "find-generic-password", "-s", "prive", "-w"]` (macOS Keychain),
`["op", "read", "op://Private/KeePass/password"]` (1Password). Store the password there
first, e.g. `secret-tool store --label prive prive Passwords`.

A command is only used with the database it is written next to, never with a file given as
`--db path`. `--password-stdin` and `PRIVE_PASSWORD_FILE` come first. If the command fails
or prints nothing, prive says so and stops. `prive doctor` checks that the program is there
without running it.

## Several databases

Give other databases a name, and open them with `--db NAME` (or `PRIVE_DB=NAME`):

```toml
db = "~/Passwords.kdbx"

[databases.work]
path = "~/Work/Work.kdbx"
keyfile = "~/keys/work.keyx"     # optional; goes with this database only

[databases.family]
path = "~/Sync/Family.kdbx"
```

```bash
prive --db work get GitHub
prive --db family unlock
PRIVE_DB=work prive codes
```

A name is letters, digits, `-` and `_`. Anything with a `/` (or `\` on Windows) is always a
path, so a file called `work` in the current directory is `--db ./work`. When `--db` names
neither a file nor a database in the config, prive says which names there are (exit code 3).
`prive config` lists them and shows what `--db NAME` stands for.

Several databases can be unlocked at once (`prive --db work unlock`); see
[agent.md](agent.md).

Unknown keys are ignored, so a config written for a newer prive still works with an older one.
