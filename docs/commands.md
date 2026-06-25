# Commands

Global options: `--db <file>` (or `PRIVE_DB`), `--keyfile <file>` (or `PRIVE_KEYFILE`),
`--password-stdin`, `--no-password` (key file only), `--no-agent` (ignore `prive unlock`),
`--quiet` (no notices on stderr). Entries are named by title,
`Group/Title` path, or `uuid:<uuid>`.

| Command | What it prints |
|---|---|
| `ls [GROUP] [-t TAG]... [--expired \| --expiring DAYS] [--sort path\|title\|changed] [-l] [-p] [--json]` | Every entry (or one group and its subgroups, or those with all the given tags, or those expired or expiring within DAYS): path, then username. Never a password. `--long` adds the date each last changed and markers: `2fa` (has a one-time code), `file` (has attachments), `expired`, `expiring` (within 30 days). `--paths` prints only the paths, for completion and fzf (see [shell.md](shell.md)). `--format TEMPLATE` prints a line per entry from KeePass placeholders, never a secret (see [scripting.md](scripting.md)). `--sort changed` lists the most recently changed first. |
| `search QUERY [--all] [--json \| --format TEMPLATE]` | Entries whose path, username, URL or tags contain QUERY; exact and prefix title matches first. `--all` also looks in notes and unprotected custom fields, never in passwords. `--format` as for `ls`. Exit 3 if none. |
| `show ENTRY [--reveal] [--json]` | All of an entry, with when it changed and when it expires (marked if it has, or will within 30 days). Password and protected fields hidden unless `--reveal`; in JSON they are `null`. |
| `get ENTRY [-f FIELD \| --format TEMPLATE] [--clip]` | One field and a newline; the password by default. `-f` takes `username`, `url`, `notes`, `title` or any custom field's name. `--format '{USERNAME}:{PASSWORD}'` fills in a template instead (see [scripting.md](scripting.md)). |
| `otp ENTRY [--min-validity S] [--clip] [--json]` | The current one-time code. In a terminal, stderr says how long it stays valid. With `--min-validity S`, a code expiring in under S seconds is skipped for the next one; `--next` gives the next code straight away; `--watch` keeps showing the current one with its time left until Ctrl-C. `--qr` / `--uri` show the setup instead (secret included), to move it to a phone or another app. |
| `codes [QUERY] [--json \| --watch]` | The current code of every entry that has one (or of those matching QUERY), with seconds left. `--watch` keeps them on screen, redrawn, until Ctrl-C. |
| `pick [QUERY] [-f FIELD \| --otp] [--print]` | Fuzzy-find an entry, then copy its password (or the field, or the code). `--print` prints it instead. |
| `open ENTRY [--no-copy \| --print]` | Opens the entry's URL in the browser (http and https only; a bare `github.com` gets https://) and copies the password. `cmd://` and other schemes are refused. `--print` prints the address instead (over SSH, or for another browser) and copies nothing. |
| `unlock [--minutes N] [--all]` | Nothing on stdout. Opens the database once and keeps it in the agent (for N minutes unused, this time); `--all` does it for every database in the config file. See [agent.md](agent.md). |
| `lock` | Nothing. Forgets every unlocked database; with `--db` on the command line, only that one. |
| `status [--json]` | `locked`, or each unlocked database (by its config name, if it has one) and how long until they lock. |
| `run [-e NAME=ENTRY[:FIELD]]... [--from ENTRY]... -- COMMAND...` | Runs COMMAND with those secrets in its environment and exits with its exit code. See [run.md](run.md). |
| `git-credential get` | Answers git's credential requests; see [git.md](git.md). `store` and `erase` are ignored. |
| `history ENTRY [--reveal] [--json]` | When each earlier version was saved and whether the password changed after it. Old passwords only with `--reveal`. |
| `file ENTRY [NAME] [-o PATH]` | Without NAME, the entry's attached files and their sizes (tab-separated). With NAME, that file's bytes to stdout (refused on a terminal) or to a new file at PATH, readable only by you. |
| `tags [--json]` | Every tag in use with how many entries carry it. |
| `audit [--hibp] [--max-age DAYS] [--expiring DAYS] [--only KINDS] [--json]` | First the database's own settings, if they are weak (see [security.md](security.md#key-derivation)); then weak, reused, expired and old passwords, worst first; with `--expiring`, also those expiring soon. Entries excluded from reports in KeePassXC are skipped. `--only reused,weak` reports just those kinds (`settings`, `breached`, `weak`, `reused`, `expired`, `expiring`, `old`). |
| `diff OTHER [--other-keyfile FILE] [--json]` | What differs between the database and another copy of it (a sync conflict copy, a backup): entries only in one, and the names of changed fields, never their values. See [sync.md](sync.md). |
| `info [--json]` | How the file is stored: name and description, format, encryption, key derivation settings, the app that last saved it, how many entries and groups it holds and how many entries wait in the recycle bin. No secrets. |
| `gen [...] [-n COUNT]` | A new password, passphrase (`--words N`) or PIN (`--pin N`), or COUNT of them. No database needed. See [generate.md](generate.md). |
| `import FILE --check [--from FMT] [--map F=COL]...` | Reads another app's export and reports what would come across. See [importing.md](importing.md). |
| `doctor [--all] [--json]` | Checks the config file, the database file (found, a KeePass file, which format), the key file, sync conflict copies next to the database, the agent and the clipboard, without asking for a password. One line each: `ok`, `warn`, `FAIL` or `--` (not used). `--all` checks every database the config file names. Exit 1 if anything fails. |
| `config [--json]` | The config file, database and key file a command would use and where each came from, the clipboard and agent timeouts, and the agent's directory. |
| `completions SHELL` | Shell completions for bash, zsh, fish, elvish or PowerShell. |

`--clip` copies instead of printing and clears the clipboard after `clipboard_seconds`
(see [clipboard.md](clipboard.md)).

When a name matches nothing, prive exits with 3 and, if some entry paths look close, lists
them on stderr: `did you mean: Work/GitHub?`.

