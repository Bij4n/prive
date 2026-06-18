# Unlocking once

```bash
prive unlock          # asks for the master password once
prive get Work/GitHub # no prompt
prive otp Bank        # no prompt
prive status          # unlocked: ~/Passwords.kdbx (locks in 14 min 52 s if unused)
prive lock            # forget it now
```

`prive unlock` checks the password, then starts a small background process, the **agent**,
and hands it the database. Later commands ask the agent instead of the file. The agent
forgets the database and exits:

- after `agent_minutes` without being used (15 by default; see [config](config.md));
- when you run `prive lock`;
- when the database file changes on disk (KeePassXC saved it, a sync tool brought a new
  copy). The next command says so and asks for the password again, so you never get
  passwords from a stale copy.

`--no-agent` (or `PRIVE_NO_AGENT=1`) makes a command read the file and ask, even when the
database is unlocked.

The agent can hold several databases. `prive --db work unlock` adds the work database next
to the one already unlocked; each command gets the database it names, and one the agent
doesn't hold is read from the file with a prompt as usual. `prive status` lists them, using
their names from the config file when they have one:

```
unlocked: work, /home/me/Work/Work.kdbx (locks in 14 min 40 s if unused)
unlocked: /home/me/Passwords.kdbx (locks in 14 min 40 s if unused)
```

`prive lock` forgets all of them; `prive --db work lock` forgets only that one. (`PRIVE_DB`
on its own doesn't narrow `lock`, so `prive lock` always locks everything.) A file that
changes on disk is forgotten on its own; the others stay unlocked. The idle timeout counts
from the last request to any of them.

## How it is protected

- The agent listens on a Unix socket in a private directory: `$PRIVE_AGENT_DIR`, else
  `$XDG_RUNTIME_DIR/prive`, else `<temp dir>/prive-<uid>`. The directory must be yours and
  mode 700; if it isn't, prive refuses to use it.
- Every connection is checked: the agent answers only processes running as your user.
- The master password is used once to open the database and then dropped. The agent keeps
  the decrypted entries in memory that is wiped when freed.
- The agent turns off core dumps, and on Linux marks itself non-dumpable so other processes
  of your user can't attach a debugger to it (`ptrace`).
- It holds one database at a time and serves only that one.

What it can't protect against: anything that already runs code as your user can ask the
agent for your passwords, as it could read your keystrokes. Lock before leaving a shared
session, and keep `agent_minutes` short on machines others use.

## Systems

Linux and macOS (and the BSDs). On Windows `prive unlock` says it isn't available yet and
each command asks for the password.
