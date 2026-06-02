# Commands

Global options: `--db <file>` (or `PRIVE_DB`), `--keyfile <file>` (or `PRIVE_KEYFILE`),
`--password-stdin`, `--no-password` (key file only). Entries are named by title,
`Group/Title` path, or `uuid:<uuid>`.

| Command | What it prints |
|---|---|
| `ls [GROUP] [--json]` | Every entry (or one group and its subgroups): path, then username. Never a password. |
| `search QUERY [--json]` | Entries whose path, username, URL or tags contain QUERY; exact and prefix title matches first. Exit 3 if none. |
| `show ENTRY [--reveal] [--json]` | All of an entry. Password and protected fields hidden unless `--reveal`; in JSON they are `null`. |
| `get ENTRY [-f FIELD] [--clip]` | One field and a newline; the password by default. `-f` takes `username`, `url`, `notes`, `title` or any custom field's name. |
| `otp ENTRY [--min-validity S] [--clip] [--json]` | The current one-time code. In a terminal, stderr says how long it stays valid. With `--min-validity S`, a code expiring in under S seconds is skipped for the next one. |
| `pick [QUERY] [-f FIELD \| --otp] [--print]` | Fuzzy-find an entry, then copy its password (or the field, or the code). `--print` prints it instead. |
| `audit [--hibp] [--max-age DAYS] [--json]` | Weak, reused, expired and old passwords, worst first. Entries excluded from reports in KeePassXC are skipped. |
| `gen [...]` | A new password, passphrase (`--words N`) or PIN (`--pin N`). No database needed. See [generate.md](generate.md). |
| `completions SHELL` | Shell completions for bash, zsh, fish, elvish or PowerShell. |

`--clip` copies instead of printing and clears the clipboard after `clipboard_seconds`
(see [clipboard.md](clipboard.md)).

When a name matches nothing, prive exits with 3 and, if some entry paths look close, lists
them on stderr: `did you mean: Work/GitHub?`.

