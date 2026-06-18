# Design

## Shape

prive is one binary that reads a KeePass database and answers one question per command.
It keeps no state of its own besides a small config file; the database is the only source of
truth, and other KeePass apps can change it at any time.

```
cli.rs        argument parsing (clap); the CLI is the public interface
lib.rs        run(): parse, dispatch, map errors to exit codes
commands.rs   one function per command
db.rs         open a KDBX file (password and/or key file) into a list of entries
config.rs     which database and key file to open, clipboard timeout
unlock.rs     where the master password comes from (stdin, file, terminal prompt)
entry.rs      the Entry model every command works on; never Debug-prints secrets
select.rs     name -> entry (path, title, uuid), search, group filter
otp.rs        TOTP from every format KeePass apps use
generate.rs   passwords, EFF passphrases, PINs
audit.rs      weak / reused / old / expired / breached report
hibp.rs       Have I Been Pwned range lookups (the only network access)
browser.rs    open http(s) URLs with the system opener, never a shell
run.rs        `prive run`: secrets into a child's environment, exit code passed on
agent/        the unlock-once agent: private socket dir, protocol, framing, peer check,
              state (unlocked databases by path, each forgotten when its file changes), server, client
import/       reading other apps' exports into common records (CSV by column name)
clip.rs       clipboard copy with a detached clearing helper
output.rs     everything printed: list, show, audit, JSON, pipe-safe stdout
pick.rs       fuzzy picker on stderr
fsutil.rs     atomic, owner-only file creation
```

## Rules the code keeps

- **stdout is data.** Prompts, notices and errors go to stderr, so `$(prive get x)` holds
  exactly the value.
- **Never block without a terminal.** No prompt unless stdin is a terminal.
- **Secrets stay wrapped** in `Zeroizing` and out of `Debug` output.
- **Writes keep what they don't understand.** Nothing writes to an existing database until a
  round-trip test against KeePassXC-made files proves no field is lost.
- **Small dependency tree**, licences checked by cargo-deny, advisories by RustSec.
