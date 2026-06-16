# Using prive in scripts

- Results go to **stdout**, one value per line, with nothing else mixed in. Prompts, notices
  ("Copied", entropy) and errors go to **stderr**.
- Failures exit non-zero with a stable code; see [exit codes](exit-codes.md).
- `--json` gives machine-readable output where it makes sense.

## Giving the master password without a prompt

prive asks for the password with a hidden prompt only when stdin is a terminal. When it is
not, prive stops at once (exit code 5) instead of waiting for input nobody can type. To run
non-interactively, use one of:

- `--password-stdin`: the first line of stdin is the password.

  ```bash
  pass show kdbx-master | prive --password-stdin get Work/GitHub
  ```

- `PRIVE_PASSWORD_FILE=<path>`: the first line of that file is the password. Keep the file
  readable by you only.

A database protected by a key file alone takes `--no-password` (with `--keyfile`), and
prive won't ask for a password at all.

There is deliberately no environment variable that holds the password itself: other processes
running as the same user can read a process's environment.

## Choosing the database

`--db <file>` or `PRIVE_DB`, otherwise the database recorded in the config file
(`~/.config/prive/config.toml` on Linux, or `$PRIVE_CONFIG`). A key file is given with
`--keyfile` or `PRIVE_KEYFILE`; a `keyfile` in the config file only goes with the config's
own database.

## Recipes

```bash
# A new password straight into another tool, never on screen
prive gen --length 32 | some-tool --password-stdin

# A passphrase for a disk or a master password
prive gen --words 7 --capitalize

# Machine-readable, with its strength
prive gen --json | jq -r .value
```

```bash
# Every entry with a one-time code, as paths
prive ls --json | jq -r '.[] | select(.has_otp) | .path'

# Log in with a password and the current code
login --user "$(prive get Work/VPN -f username)" \
      --password "$(prive get Work/VPN)" --otp "$(prive otp Work/VPN)"

# Fail a CI step if the database's settings or any password need attention
prive audit --json | jq -e '(.findings | length) + (.database | length) == 0'
```

`get --format` fills in several fields at once, with KeePass's placeholder names. Only
`{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{NOTES}`, `{S:Field name}` and `{TOTP}` are
replaced; any other braces are left as they are, so JSON and shell text pass through. A field
the entry doesn't have is an error (exit 3), never an empty string.

```bash
# user:password for curl, in one call
curl -u "$(prive get Work/API --format '{USERNAME}:{PASSWORD}')" https://api.example.com/

# A JSON object for another program
prive get Work/DB --format '{"user":"{USERNAME}","password":"{PASSWORD}","key":"{S:API key}"}'
```

Values are put in as they are: nothing is escaped for JSON, URLs or the shell. A password
with a `"` in it breaks the JSON above; for anything a password could break, `show --json
--reveal` and `jq` are the safe way.

