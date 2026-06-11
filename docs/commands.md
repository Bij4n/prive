# Commands

Global options: `--db <file>` (or `PRIVE_DB`), `--keyfile <file>` (or `PRIVE_KEYFILE`),
`--password-stdin`, `--no-password` (key file only), `--no-agent` (ignore `prive unlock`),
`--quiet` (no notices on stderr). Entries are named by title,
`Group/Title` path, or `uuid:<uuid>`.

| Command | What it prints |
|---|---|
| `unlock [--minutes N]` | Nothing on stdout. Opens the database once and keeps it in the agent (for N minutes unused, this time); see [agent.md](agent.md). |
| `lock` | Nothing. Forgets the unlocked database. |
| `status [--json]` | `locked`, or which database is unlocked and how long until it locks. |
| `ls [GROUP] [-t TAG]... [-l] [--json]` | Every entry (or one group and its subgroups, or those with all the given tags): path, then username. Never a password. `--long` adds the date each last changed and markers: `2fa` (has a one-time code), `file` (has attachments), `expired`. |
| `search QUERY [--all] [--json]` | Entries whose path, username, URL or tags contain QUERY; exact and prefix title matches first. `--all` also looks in notes and unprotected custom fields, never in passwords. Exit 3 if none. |
| `show ENTRY [--reveal] [--json]` | All of an entry. Password and protected fields hidden unless `--reveal`; in JSON they are `null`. |
| `get ENTRY [-f FIELD] [--clip]` | One field and a newline; the password by default. `-f` takes `username`, `url`, `notes`, `title` or any custom field's name. |
| `otp ENTRY [--min-validity S] [--clip] [--json]` | The current one-time code. In a terminal, stderr says how long it stays valid. With `--min-validity S`, a code expiring in under S seconds is skipped for the next one. |
| `run [-e NAME=ENTRY[:FIELD]]... [--from ENTRY]... -- COMMAND...` | Runs COMMAND with those secrets in its environment and exits with its exit code. See [run.md](run.md). |
| `history ENTRY [--reveal] [--json]` | When each earlier version was saved and whether the password changed after it. Old passwords only with `--reveal`. |
| `file ENTRY [NAME] [-o PATH]` | Without NAME, the entry's attached files and their sizes (tab-separated). With NAME, that file's bytes to stdout (refused on a terminal) or to a new file at PATH, readable only by you. |
| `open ENTRY [--no-copy]` | Opens the entry's URL in the browser (http and https only; a bare `github.com` gets https://) and copies the password. `cmd://` and other schemes are refused. |
| `tags [--json]` | Every tag in use with how many entries carry it. |
| `codes [QUERY] [--json]` | The current code of every entry that has one (or of those matching QUERY), with seconds left. |
| `import FILE --check [--from FMT] [--map F=COL]...` | Reads another app's export and reports what would come across. See [importing.md](importing.md). |
| `pick [QUERY] [-f FIELD \| --otp] [--print]` | Fuzzy-find an entry, then copy its password (or the field, or the code). `--print` prints it instead. |
| `audit [--hibp] [--max-age DAYS] [--json]` | Weak, reused, expired and old passwords, worst first. Entries excluded from reports in KeePassXC are skipped. |
| `gen [...] [-n COUNT]` | A new password, passphrase (`--words N`) or PIN (`--pin N`), or COUNT of them. No database needed. See [generate.md](generate.md). |
| `git-credential get` | Answers git's credential requests; see [git.md](git.md). `store` and `erase` are ignored. |
| `completions SHELL` | Shell completions for bash, zsh, fish, elvish or PowerShell. |

`--clip` copies instead of printing and clears the clipboard after `clipboard_seconds`
(see [clipboard.md](clipboard.md)).

When a name matches nothing, prive exits with 3 and, if some entry paths look close, lists
them on stderr: `did you mean: Work/GitHub?`.

