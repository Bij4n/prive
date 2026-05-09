# Changelog

All notable changes to this project will be documented in this file.

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
