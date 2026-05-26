# Design

## Shape

prive is one binary that reads a KeePass database and answers one question per command.
It keeps no state of its own besides a small config file; the database is the only source of
truth, and other KeePass apps can change it at any time.

```
cli.rs        argument parsing (clap); the CLI is the public interface
lib.rs        dispatch: one function per command, errors mapped to exit codes
config.rs     which database and key file to open, clipboard timeout
unlock.rs     where the master password comes from (stdin, file, terminal prompt)
entry.rs      the Entry model every command works on; never Debug-prints secrets
select.rs     name -> entry (path, title, uuid), search, group filter
otp.rs        TOTP from every format KeePass apps use
generate.rs   passwords, EFF passphrases, PINs
audit.rs      weak / reused / old / expired / breached report
hibp.rs       Have I Been Pwned range lookups (the only network access)
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
