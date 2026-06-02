# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

The 1.0 rewrite has started: prive becomes a terminal client for KeePass (`.kdbx`) databases.
The 0.5 vault format, PGP toolkit and git sync are gone; 0.5 stays at the tag `legacy-0.5.0`.

### Added
- Reading KeePass databases (KDBX 3.1, 4.0, 4.1; password and/or key file), and the commands
  `ls`, `search`, `show` (`--reveal`), `get` (`--field`, `--clip`), `otp`, `pick` and `audit`
  (`--hibp`, `--max-age`), with `--json` where it fits. The recycle bin is left out; entries
  excluded from reports in KeePassXC are skipped by `audit`
- A missing or non-KeePass file is reported before the password is asked for; a wrong
  password or key file exits with 5, nothing found with 3
- "did you mean" suggestions when a name matches nothing
- `otp --min-validity` waits for a fresh code when the current one is about to expire
- `prive open`: the entry's site in the browser (http and https only, no shell) and its
  password on the clipboard
- `prive tags`, `ls --tag`, `ls --long`
- `--quiet` for no notices on stderr; a missing field lists the fields the entry has
- Cancelling `pick` exits with 130, like fzf
- Fuzz targets for otpauth parsing and entry selection, built and run briefly in CI
- `prive gen`: random passwords (every character class guaranteed, optional look-alike
  filtering), passphrases from the EFF large word list, and numeric PINs
- TOTP code generation for every way KeePass apps store secrets (otpauth URIs, KeeOtp,
  KeePass 2 TimeOtp fields, legacy KeePassXC fields), including Steam Guard codes
- Stable exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 ambiguous, 5 credentials
- `gen --clip` copies instead of printing; a detached helper clears the clipboard after the
  configured timeout, and only if it still holds the copied secret. Copies are marked
  "don't keep in history" where supported
- `gen --json`
- Password report engine (weak, reused, old, expired, optional Have I Been Pwned check) and
  the show and list views, ready for the database commands
- `docs/`: exit codes, scripting, TOTP formats, clipboard, configuration, security notes
- CI: minimum supported Rust (1.88) job and a weekly RustSec advisory check
- `prive completions <shell>` (bash, zsh, fish, elvish, PowerShell) and man pages
  (`cargo run --example man`)
- Fuzzy picker module (drawn on stderr) for the upcoming `pick` command
- `--no-password` for databases unlocked by a key file alone; `uuid:` accepts KeePassXC's
  `{...}` form and dashless hex
- Test databases written by KeePassXC (KDBX 3.1, 4.0, 4.1 and key file) and interop tests
  that compare one-time codes with `keepassxc-cli`; CI installs KeePassXC to run them
- `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates, `deny.toml` licence and
  source policy checked in CI

### Fixed
- Windows: `--clip` no longer keeps a caller waiting (a script's `$(...)`) until the
  clipboard is cleared; the helper used to inherit the caller's output pipes
- CI: the Windows test job no longer hangs until the 6-hour limit (two tests reached a console password prompt); every job has a timeout
- Release builds use rustls instead of the system OpenSSL, so the musl target links and Linux binaries no longer need `libssl`
- `pw` and `note` commands report a missing vault before asking for the master password

### Changed
- Added the MIT `LICENSE` file
- README: install from source only, and a notice listing the known problems in 0.5
- Removed the Homebrew, AUR and WinGet manifests; they pointed at releases that were never published

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
