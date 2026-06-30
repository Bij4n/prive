# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `import --check` reads Bitwarden's CSV on its own: recognised from its header, secure notes
  tagged `note`, the custom fields packed into its `fields` column split out (kept protected)
- `prive import --check --list`: each entry as it would come across, never a password
- `prive export --plaintext [--format csv|json] [-o FILE]`: everything, references resolved,
  to a new owner-only file or a pipe (never a terminal), to move to another app

### Changed
- `audit --hibp` looks up eight hash prefixes at a time, one request per prefix, and gives
  up on a request after 30 seconds instead of waiting for ever
- `import --check`: apps' own bookkeeping columns (KeePassXC's Icon and dates, Bitwarden's
  type and reprompt, 1Password's flags) are no longer kept as fields; a set Favorite or
  Archived flag becomes a tag

### Fixed
- `import --check` took a CSV in KeePassXC's columns (prive's own export among them) for an
  Apple Passwords export, and left out its groups and one-time codes; 1Password's CSV the
  same, losing its tags. Apple's exports are now known by their exact columns

## [0.6.0] - 2026-06-30

prive starts again as a terminal client for KeePass (`.kdbx`) databases: it opens the same
file as KeePassXC, KeePassDX and Strongbox. This release reads; creating databases, file
encryption and editing come in 0.7 and 0.8 (see `docs/roadmap.md`). The 0.5 vault format,
PGP toolkit and git sync are gone; 0.5 stays at the tag `legacy-0.5.0` and should not be used
for real secrets.

### Reading a database
- KDBX 3.1, 4.0 and 4.1, with a password, a key file or both (`--no-password` for a key file
  alone); every format checked against files KeePassXC wrote, field for field
- `ls` (by group, tag, expiry; `--long`, `--paths`, `--sort`), `search` (`--all` looks in
  notes and unprotected fields, never secrets), `show` (secrets hidden unless `--reveal`),
  `get` (any field, `--clip`), `tags`, `history` (earlier versions), `file` (attachments,
  written owner-only), `open` (the site in the browser, password on the clipboard; http and
  https only, never a shell), `pick` (fuzzy finder)
- Entries named by title, `Group/Title` path or `uuid:`; "did you mean" when nothing
  matches, the candidates when several do
- KeePass field references (`{REF:P@I:...}`) resolved wherever a value is used, as KeePassXC
  does; KeePassXC's extra URLs (`KP2A_URL` fields) count for `search` and `git-credential`
- `--format` templates with KeePass's placeholders (`{USERNAME}`, `{PASSWORD}`, `{S:field}`,
  `{TOTP}`, `{PATH}`, ...) on `get`; on `ls` and `search` they never show a secret
- The recycle bin is left out; expiry is shown (`expired`, `expiring`), columns line up by
  display width

### One-time codes
- Every way KeePass apps store them: otpauth URIs, KeeOtp, KeePass 2's TimeOtp fields,
  KeePassXC's legacy fields; SHA-1/256/512, 4 to 10 digits, Steam Guard
- `otp` (`--min-validity`, `--next`, `--clip`, `--watch`), `codes` for every entry at once
  (`--watch` keeps them on screen), `otp --qr` / `--uri` to move a code to a phone

### Unlocking once
- `prive unlock`: a background agent keeps databases open so a session needs one password
  prompt; several at once, `unlock --all` for every one the config file names
- Private socket directory (mode 700, checked), same-user check on every connection, the
  master password dropped after opening, a database forgotten when its file changes or
  after `agent_minutes` idle; no core dumps, non-dumpable on Linux. Linux, macOS and the BSDs
- `password_command` in the config file: the master password from the system keyring, `pass`,
  `op`, ...; run without a shell
- Databases by name (`[databases.work]`, `--db work`), each with its own key file and
  password command

### Scripts and other programs
- stdout carries only results; `--json` on every command that reports something, with keys
  kept stable (`docs/json.md`); exit codes 0 ok, 1 error, 2 usage, 3 not there, 4 ambiguous,
  5 credentials or no terminal, 130 cancelled
- `--password-stdin` and `PRIVE_PASSWORD_FILE`; never a prompt without a terminal
- `prive run`: secrets in a command's environment, never on its command line or on disk
- `prive git-credential`: git's credential helper for HTTPS remotes
- Colour in `doctor`, `audit` and `diff` on a terminal only (`NO_COLOR`, `CLICOLOR_FORCE`)
- Shell completions and man pages for every command; entry-name completion recipes

### Health and sync
- `audit`: weak, reused, old, expired, expiring and (with `--hibp`) breached passwords, and
  the database's own key settings (AES-KDF, Argon2 below OWASP's minimum); `--only` to pick
  kinds; entries excluded from reports in KeePassXC are skipped
- `info`: format, encryption, key derivation, counts; `--time` for what an open costs here
- `diff`: what a sync conflict copy or backup holds that the database doesn't, paired by
  UUID, field names only; it agrees with what `keepassxc-cli merge` would do
- `doctor`: config, database, key file, password source, conflict copies, agent and
  clipboard, without a password; `--all` for every named database

### Generating passwords
- `gen`: random passwords (every class guaranteed, `--symbols`, `--exclude`,
  `--avoid-ambiguous`), passphrases from the EFF large list or `--word-list FILE`, PINs;
  `--count`, `--clip`, `--json` with honest entropy

### Bringing passwords in
- `import FILE --check`: reads exports from Proton Pass, Apple Passwords, Google Password
  Manager, LastPass and any other CSV (Bitwarden, 1Password, Dashlane by column names,
  `--map` for the rest) and says what would come across; writing the database comes in 0.7

### Safety
- Secrets are held in memory that is wiped when freed and never appear in debug output
- Control characters from a database are spelled out wherever text is shown, so escape
  sequences in a title or note can't reach the terminal
- Copied secrets are cleared from the clipboard after a timeout, only if still there, and
  kept out of clipboard history where the system allows

### Changed since 0.5
- Added the MIT `LICENSE` file; removed the Homebrew, AUR and WinGet manifests, which pointed
  at releases that were never published
- Release builds use rustls, so Linux binaries need no system OpenSSL
- CI on Linux, macOS and Windows, with an MSRV (1.88) job, KeePassXC interop tests, fuzzing,
  cargo-deny and a weekly RustSec check; releases are made by hand, as drafts, with checksums

## [0.5.0] - 2026-05-09

### Added
- `prive pgp fetch <email>` — fetch and import public keys from keys.openpgp.org (HKP) by email or fingerprint
- `prive pgp fetch --fingerprint <fp>` — fetch by fingerprint with optional `--keyserver` override
- `prive pgp publish <key-id>` — publish a public key to keys.openpgp.org
- `prive pw totp-add --qr <image>` — import TOTP from a QR code image (PNG/JPEG/BMP/GIF/TIFF/WebP)
- TOTP SHA-256 and SHA-512 algorithm support; `algorithm=` param parsed from otpauth:// URIs
- `prive pw get --totp` — show TOTP code inline alongside password retrieval
- `prive doctor` — master password strength check with score, crack time, and improvement tips
- `prive audit` — credential expiry detection: Critical for expired, Warning for expiring within 30 days
- CI: shell completions smoke-test job (bash, zsh, fish)
- Release workflow: man page generation job bundles `gen-man` output as tarball artifact
- Packaging manifests: Homebrew formula, AUR PKGBUILD, WinGet manifest
- 14 new integration tests covering notes, tags, password history, expiry auditing, and vault search
- New fuzz target: `fuzz_pgp_armor` — fuzzes PGP armored key parsing and keyring import

### Changed
- Bumped version to 0.5.0

## [0.4.0] - 2026-04-06

### Added
- `prive doctor` command for diagnosing config, vault, and keyring health
- PGP keyserver lookup support (keys.openpgp.org)
- Encrypted single-file vault export/restore bundles
- Comprehensive test suite: 200+ tests across 7 test modules

### Changed
- Bumped version to 0.4.0

## [0.3.0] - 2026-03-31

### Added
- Vault sharing: encrypt entries for another user via PGP
- Tag management: list, rename, delete tags across entries and notes
- Vault statistics command with strength analysis
- 1Password export (JSON + CSV formats)
- Hardware key provider trait (Yubikey/FIDO2 stub)
- Password expiry tracking field

## [0.2.0] - 2026-02-14

### Added
- Git-backed vault synchronization
- File attachments on password entries (1MB limit)
- Clipboard manager with auto-clear
- Comprehensive error types with exit codes
- Fuzz testing targets (6 targets)
- Password strength analyzer with crack time estimation
- Property-based tests (proptest)
- Benchmarks (criterion)

### Changed
- Bumped version to 0.2.0

## [0.1.0] - 2025-12-10

### Added
- Password generation: random, passphrase, PIN, pronounceable, custom charset
- Encrypted vault with Argon2id + AES-256-GCM
- Password CRUD: add, get, list, edit, rm, search
- PGP key management: generate (Cv25519/RSA-4096), import, export
- File encryption/decryption (PGP + symmetric)
- TOTP/2FA code generation
- Security audit with HIBP breach check
- Import/Export: CSV, Bitwarden JSON, KeePass XML
- Interactive TUI with fuzzy search
- Auto-backup with rotation
- TOML config system
- Shell completions (bash/zsh/fish/powershell)
- Session agent (cached vault unlock)
- Secure notes
- Password history tracking
- Multiple vault support
- Vault format migration framework
- PGP trust database
- GitHub Actions CI/CD
