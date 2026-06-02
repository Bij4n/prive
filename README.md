# prive

A fast, scriptable terminal client for **KeePass** password databases.

prive opens the same `.kdbx` file as KeePassXC, KeePassDX (Android) and Strongbox (iOS), so
your passwords live in one file you own: those apps cover the phone and the browser, prive
covers the terminal. It prints exactly what you ask for, nothing else, so it fits in scripts.

> **Status: rewrite in progress (0.6).** Reading works: `ls`, `search`, `show`, `get`, `otp`,
> `pick`, `audit` and `gen`. Unlock-once, imports from other password managers, file
> encryption and editing are next; see the [roadmap](docs/roadmap.md).
>
> The old 0.5 line (its own `.pv` vault format and a PGP toolkit) is kept at the tag
> `legacy-0.5.0`. It had serious problems, PGP secret keys stored unencrypted among them;
> please don't use it for real secrets.

## Install

There are no packaged releases yet. With a recent stable Rust (1.88 or later):

```bash
cargo install --git https://github.com/Bij4n/prive --locked
```

## Quick start

```bash
# Tell prive which database to use (or pass --db / set PRIVE_DB each time)
mkdir -p ~/.config/prive
echo 'db = "/home/me/Passwords.kdbx"' > ~/.config/prive/config.toml

prive ls                         # every entry: path and username
prive ls Work                    # one group and its subgroups
prive ls --tag cloud             # entries with a tag (prive tags lists them all)
prive search github              # by title, username, URL, group or tag
prive show Work/GitHub           # details; secrets hidden
prive show Work/GitHub --reveal
prive get Work/GitHub            # just the password, for scripts
prive get Work/GitHub --clip     # copy it; cleared after 20 seconds
prive get Work/GitHub -f username
prive otp Work/GitHub            # current one-time code
prive open Work/GitHub           # the site in the browser, password on the clipboard
prive pick                       # fuzzy finder; Enter copies the password
prive audit                      # weak, reused, old and expired passwords
prive audit --hibp               # also check Have I Been Pwned (k-anonymity)
prive gen --words 6              # a passphrase, no database needed
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
export GITHUB_TOKEN="$(prive get Work/GitHub -f token)"
```

More in [`docs/`](docs/): [scripting](docs/scripting.md), [exit codes](docs/exit-codes.md),
[one-time codes](docs/totp.md), [clipboard](docs/clipboard.md),
[configuration](docs/config.md), [KeePass compatibility](docs/keepass-compatibility.md),
[security](docs/security.md), [design](docs/design.md).

## Contributing

Issues and pull requests are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security
reports: [`SECURITY.md`](SECURITY.md).

## License

MIT. The passphrase word list is the EFF large word list (CC BY 3.0 US); see `assets/`.
