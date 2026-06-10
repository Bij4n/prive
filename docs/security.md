# Security notes

What prive protects against, and what it doesn't. This will grow as the rewrite does.

## What prive relies on

- **The KeePass file format** (KDBX 4) for encryption at rest. prive reads and, later, writes
  the same files as KeePassXC, so the strength of a database is the strength of its master
  password, key file and key-derivation settings.
- **Your operating system account.** Anything that can run code as you can read prive's
  memory, your clipboard and your terminal. prive does not try to defend against that.

## What prive does

- Never prints a password unless asked: `show` hides passwords and protected fields unless
  `--reveal`; `ls` and `search` never include them, not even in `--json`.
- Never puts the master password on the command line or in an environment variable. It comes
  from a hidden prompt, from stdin (`--password-stdin`) or from a file you name.
- Never waits on a prompt nobody can answer: without a terminal it fails with exit code 5.
- Clears copied secrets from the clipboard after a timeout, unless you have copied something
  else since, and asks the clipboard not to keep them in its history.
- Writes new files atomically (temporary file, flush, rename), readable only by you on Unix.
- Keeps secrets in memory that is wiped when it is freed (`zeroize`), and keeps them out of
  debug output.
- `open` only ever opens http and https addresses, through the system's opener with no
  shell. KeePass's `cmd://` URLs, which run programs, are refused.
- The only network access is the optional Have I Been Pwned check (`audit --hibp`), which
  sends 5 hex characters of each password's SHA-1 hash and nothing else.

## Reading a database

- The file is checked to be a KeePass database before you are asked for its password, so a
  typo in a path never costs you a prompt.
- prive reads the whole file into memory, decrypts it with the `keepass` crate, and copies
  each entry into its own structure. Passwords and protected fields are held in memory that is
  wiped when freed. The decrypted database is dropped as soon as the command is done.
- A wrong password or key file is reported as such (exit code 5); prive never tells you which
  of the two was wrong, because the file format can't know.

## Attachments and history

`prive file` writes an attachment only to a new file (never over an existing one), readable
only by you, or to a pipe; it refuses to dump binary data onto a terminal. `prive history`
shows when earlier versions were saved; the old passwords themselves only with `--reveal`.

## Running commands

`prive run` puts secrets in a child process's environment only, never on its command line
(visible to every user through `ps`) or in a file. The environment is readable by other
processes of the same user, as with any tool that takes credentials that way.

## The agent

`prive unlock` keeps a decrypted database in a background process for a while. It answers
only your own user, over a socket in a private directory, drops the master password after
opening, forgets everything when the file changes or after the idle timeout, and turns off
core dumps and (on Linux) debugger attachment. Details in [agent.md](agent.md).

## Reporting a problem

Please open a GitHub issue marked "security", or, for anything sensitive, ask for a private
contact in the issue without the details.
