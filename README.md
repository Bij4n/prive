# Prive

A cross-platform password & encryption toolkit for the terminal. Single binary, zero runtime dependencies.

## Features

- **Password Management** — Generate, store, and retrieve passwords from an encrypted vault
- **Password Generation** — Random passwords, passphrases, PINs, pronounceable passwords, custom charsets
- **PGP Encryption** — Generate keypairs, encrypt/decrypt files, sign/verify — no GPG required
- **PGP Trust & Keyserver** — Trust levels, revocation certificates, fetch/publish keys on keys.openpgp.org
- **TOTP/2FA** — Generate time-based one-time passwords for your accounts
- **Security Audit** — Check for weak, duplicate, short, old, expiring, and breached passwords
- **Import/Export** — Import from Chrome, Bitwarden, KeePass, LastPass, 1Password, Dashlane, Apple Keychain, Firefox
- **Interactive TUI** — Browse and search your vault with a terminal UI
- **Auto-backup** — Automatic vault backups with configurable rotation
- **Vault Sync** — Git-backed encrypted vault synchronization across devices
- **File Attachments** — Attach files (up to 1MB) to password entries
- **Secure Notes** — Standalone encrypted notes separate from password entries
- **Password History** — Track and view previous passwords for each entry
- **Multiple Vaults** — Create and switch between separate vaults (work, personal)
- **Password Strength** — Detailed strength analysis with crack time estimation
- **Session Agent** — Keep vault unlocked in background to avoid repeated password prompts
- **Clipboard Manager** — Auto-clear clipboard with configurable timeout
- **Health Check** — `prive doctor` diagnoses your setup and master password strength
- **Vault Statistics** — Entry counts, strength distribution, tag breakdown

## Installation

### Homebrew (macOS / Linux)

```bash
brew install Bij4n/prive/prive
```

### AUR (Arch Linux)

```bash
yay -S prive
```

### WinGet (Windows)

```bash
winget install Bij4n.Prive
```

### Pre-built binaries

Download from the [Releases](https://github.com/Bij4n/prive-app/releases) page.

### From source

```bash
cargo install --path .
```

## Quick Start

```bash
# Generate a random password
prive generate
prive generate --length 32 --copy
prive generate --passphrase --words 5
prive generate --pin --length 6
prive generate --pronounceable

# Create your vault
prive vault init

# Add passwords
prive pw add github --generate --username johnd --url github.com
prive pw add aws --generate --length 32 --tags cloud,work

# Retrieve passwords
prive pw get github              # copies to clipboard
prive pw get github --show       # prints to terminal

# List and search
prive pw list
prive pw list --tags work
prive pw search github

# TOTP
prive pw totp-add github --secret JBSWY3DPEHPK3PXP
prive pw totp github

# Security audit
prive audit
prive audit --breach             # also check Have I Been Pwned

# Health check
prive doctor

# PGP
prive pgp generate --email you@example.com
prive pgp list
prive pgp info <KEY_ID>
prive pgp trust <KEY_ID> --level full
prive pgp fetch you@example.com          # fetch from keys.openpgp.org
prive pgp fetch --fingerprint <FP>
prive pgp publish <KEY_ID>               # upload to keys.openpgp.org
prive pgp gen-revoke <KEY_ID>            # generate revocation certificate
prive pgp trust-list
prive encrypt secret.txt --recipient <KEY_ID>
prive decrypt secret.txt.pgp

# Import/Export
prive import passwords.csv --format csv
prive import lastpass.csv --format lastpass
prive import passwords.csv --format 1password
prive import data.csv --format dashlane
prive import passwords.csv --format apple
prive import passwords.csv --format firefox
prive export --format csv --output backup.csv
prive export --format bitwarden --output bitwarden.json
prive export --format lastpass --output lastpass.csv

# Vault management
prive vault list
prive vault create work
prive vault switch work
prive --vault work pw list      # use named vault for one command
prive vault info
prive vault change-password

# Vault sync
prive sync init git@github.com:user/vault.git
prive sync push
prive sync pull
prive sync status

# Attachments
prive pw attach github ~/keys/deploy.pem
prive pw attachments github
prive pw detach github deploy.pem
prive pw get-attachment github deploy.pem

# Secure notes
prive note add "API Keys"
prive note get "API Keys"
prive note list
prive note edit "API Keys"
prive note search api

# Tags
prive tag list
prive tag rename work office
prive tag delete old-tag

# Password history
prive pw history github --show

# Vault sharing (PGP-encrypted)
prive share export github aws --recipient <KEY_ID> --output shared.pgp
prive share import shared.pgp

# Vault statistics
prive stats

# Password strength
# (shown automatically when adding entries)

# Session agent
prive session start              # keeps vault unlocked in background
prive session status
prive session stop
eval $(prive session env)        # export PRIVE_AGENT_SOCK to shell

# Clipboard
prive clip clear                 # immediately clear clipboard
prive clip status

# Interactive mode
prive tui

# Backups
prive backup create
prive backup list
prive backup restore <backup-name>

# Shell completions
prive completions --shell bash >> ~/.bashrc
prive completions --shell zsh >> ~/.zshrc
prive completions --shell fish > ~/.config/fish/completions/prive.fish

# Configuration
prive config init
prive config show
prive config set clipboard.auto_clear true
prive config set clipboard.clear_after_seconds 30
prive config set session.timeout_seconds 600
```

## Vault Security

- Master password derived via **Argon2id** (t=3, m=64MiB, p=4)
- Vault encrypted with **AES-256-GCM**
- Fresh random nonce on every save
- Single encrypted blob — no metadata leakage
- Sensitive memory zeroed on drop via `zeroize`

## PGP

Prive includes a self-contained PGP implementation (via the `pgp` crate) — no system GPG required.

- **Key types**: Ed25519/Cv25519 (default), RSA-4096
- **Encryption**: SEIPDv1 with AES-256
- **Key storage**: ASCII-armored files in `~/.local/share/prive/keyring/`
- **Symmetric**: Passphrase-based file encryption
- **Trust levels**: unknown, untrusted, marginal, full, ultimate — stored in `~/.local/share/prive/trust.json`
- **Revocation certificates**: generated and stored in `~/.local/share/prive/revocations/`
- **Keyserver**: fetch/publish against keys.openpgp.org (VKS API); publish requires email verification

## Configuration

Config file location: `~/.config/prive/config.toml`

```toml
[vault]
# active_vault = "work"   # name of the active vault (omit for default)
# path = "/custom/path/vault.pv"

[clipboard]
auto_clear = true
clear_after_seconds = 45

[generate]
default_length = 20

[backup]
auto_backup = true
max_backups = 10

[session]
timeout_seconds = 300
```

## Supported Platforms

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64 | Supported |
| Linux (musl) | x86_64 | Supported |
| macOS | x86_64, aarch64 | Supported |
| Windows | x86_64 | Supported |

## Data Storage

| Data | Location |
|------|----------|
| Vault | `~/.local/share/prive/vault.pv` |
| PGP Keys | `~/.local/share/prive/keyring/` |
| Trust DB | `~/.local/share/prive/trust.json` |
| Revocations | `~/.local/share/prive/revocations/` |
| Backups | `~/.local/share/prive/backups/` |
| Config | `~/.config/prive/config.toml` |

## Man Pages

```bash
cargo run --bin gen-man          # generates man/ directory
```

## License

MIT
