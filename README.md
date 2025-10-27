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
