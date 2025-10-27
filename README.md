# Prive

A cross-platform password & encryption toolkit for the terminal. Single binary, zero runtime dependencies.

## Features

- **Password Management** — Generate, store, and retrieve passwords from an encrypted vault
- **Password Generation** — Random passwords, passphrases, PINs, pronounceable passwords, custom charsets
- **PGP Encryption** — Generate keypairs, encrypt/decrypt files, sign/verify — no GPG required
- **TOTP/2FA** — Generate time-based one-time passwords for your accounts
- **Security Audit** — Check for weak, duplicate, short, and breached passwords
- **Import/Export** — Import from Chrome, Bitwarden, KeePass. Export to CSV or Bitwarden JSON
- **Interactive TUI** — Browse and search your vault with a terminal UI
- **Auto-backup** — Automatic vault backups with configurable rotation

## Installation

### From source

```bash
cargo install --path .
```

### Pre-built binaries

Download from the [Releases](https://github.com/prive/prive-app/releases) page.

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
prive audit --breach    # check Have I Been Pwned
