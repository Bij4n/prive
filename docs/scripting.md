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
