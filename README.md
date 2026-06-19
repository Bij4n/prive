# prive

A fast, scriptable terminal client for **KeePass** password databases.

prive opens the same `.kdbx` file as KeePassXC, KeePassDX (Android) and Strongbox (iOS), so
your passwords live in one file you own: those apps cover the phone and the browser, prive
covers the terminal. It prints exactly what you ask for, nothing else, so it fits in scripts,
and it is quick: a 5,000-entry database lists in a tenth of a second
([performance](docs/performance.md)).

> **Status: rewrite in progress (0.6).** Reading works (`ls`, `search`, `show`, `get`, `otp`,
> `codes`, `open`, `file`, `history`, `pick`, `audit`, `gen`), `prive unlock` keeps the
> database open so a session costs one password prompt, and `prive run` hands secrets to
> other commands. Next: creating databases from other apps' exports, file encryption and
> editing; see the [roadmap](docs/roadmap.md).
>
> The old 0.5 line (its own `.pv` vault format and a PGP toolkit) is kept at the tag
> `legacy-0.5.0`. It had serious problems, PGP secret keys stored unencrypted among them;
> please don't use it for real secrets.

## Install

There are no packaged releases yet. With a recent stable Rust (1.88 or later):

```bash
cargo install --git https://github.com/Bij4n/prive --locked
```

Shell completions, man pages and other ways in: [docs/install.md](docs/install.md). Coming from
prive 0.5? See [docs/migrating-from-0.5.md](docs/migrating-from-0.5.md).

## Quick start

```bash
# Tell prive which database to use (or pass --db / set PRIVE_DB each time)
mkdir -p ~/.config/prive
echo 'db = "~/Passwords.kdbx"' > ~/.config/prive/config.toml

prive unlock                     # password once; later commands don't ask (15 min idle)
prive ls                         # every entry: path and username
prive ls Work                    # one group and its subgroups
prive ls --tag cloud             # entries with a tag (prive tags lists them all)
prive search github              # by title, username, URL, group or tag
prive show Work/GitHub           # details; secrets hidden
prive show Work/GitHub --reveal
prive get Work/GitHub            # just the password, for scripts
prive get Work/GitHub --clip     # copy it; cleared after 20 seconds
prive get Work/GitHub -f username
prive get Work/GitHub --format '{USERNAME}:{PASSWORD}'   # several fields in one line
prive otp Work/GitHub            # current one-time code
prive open Work/GitHub           # the site in the browser, password on the clipboard
prive file Work/Deploy id_ed25519 -o ~/.ssh/id_deploy   # an attached file, owner-only
prive pick                       # fuzzy finder; Enter copies the password
prive audit                      # weak key settings; weak, reused, old and expired passwords
prive audit --hibp               # also check Have I Been Pwned (k-anonymity)
prive info                       # format, encryption and key settings of the file
prive diff Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx   # what a conflict copy holds
prive doctor                     # what would get in the way, without a password
prive --db work ls               # another database, by its name in the config file
prive gen --words 6              # a passphrase, no database needed
prive lock                       # forget the unlocked databases now
```

Entries are named by title, by `Group/Title` path when a title is used twice, or by
`uuid:<uuid>`.

## In scripts

- stdout carries only the result; prompts, notices and errors go to stderr.
- Stable exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 ambiguous, 5 wrong password or no
  terminal for the prompt.
- `--password-stdin` or `PRIVE_PASSWORD_FILE` instead of a prompt; prive never waits on a
  prompt nobody can answer.
- `--json` on `ls`, `search`, `show`, `otp`, `audit` and `gen`.

```bash
# Secrets for one command, never on screen, in history or on disk
prive run -e GITHUB_TOKEN=Work/GitHub:token -- gh repo list
prive run --from Work/AWS -- aws s3 ls
```

Everything else is in the [documentation index](docs/README.md), including [scripting](docs/scripting.md), [exit codes](docs/exit-codes.md),
[one-time codes](docs/totp.md), [clipboard](docs/clipboard.md),
[configuration](docs/config.md), [KeePass compatibility](docs/keepass-compatibility.md),
[security](docs/security.md), [design](docs/design.md),
[troubleshooting](docs/troubleshooting.md).

## Contributing

Issues and pull requests are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security
reports: [`SECURITY.md`](SECURITY.md).

## License

MIT. The passphrase word list is the EFF large word list (CC BY 3.0 US); see `assets/`.
