# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Prive

Prive is a cross-platform CLI tool for password management and PGP encryption, built in Rust. Single binary, zero external dependencies at runtime.

## Build & Test Commands

```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo test               # Run all tests (note: RSA-4096 test takes ~90s in debug)
cargo test -- --skip rsa # Skip slow RSA test during development
cargo clippy             # Lint
cargo fmt                # Format
cargo run -- <args>      # Run directly (e.g., cargo run -- generate --length 32)
```

## Architecture

### Module Layout

- `src/cli.rs` — All clap derive structs defining the CLI surface. Every subcommand is defined here.
- `src/commands/` — Command handlers that wire CLI args to library logic. Each file maps to a command group: `password.rs` (generate + pw), `vault.rs`, `pgp.rs`, `encrypt.rs`.
- `src/vault/` — Encrypted password vault core:
  - `model.rs` — `Vault` and `VaultEntry` data structures (serde)
  - `crypto.rs` — Argon2id KDF + AES-256-GCM encrypt/decrypt
  - `storage.rs` — Binary file format with magic header, atomic write via temp file + rename
- `src/pgp/` — PGP operations using the `pgp` (rpgp) crate:
  - `generate.rs` — Key generation (EdDSA/Cv25519 or RSA-4096)
  - `keyring.rs` — On-disk key storage at `~/.local/share/prive/keyring/`, one armored file per key
  - `operations.rs` — Encrypt/decrypt/sign/verify using rpgp's `Message` API
- `src/crypto/` — Shared crypto utilities: `password_gen.rs` (password/passphrase generation), `secure.rs` (zeroizing wrappers), `file_encrypt.rs` (placeholder)
- `src/config.rs` — Platform-specific paths via the `dirs` crate
- `src/error.rs` — Unified error types

### Key Design Decisions

- **Vault format**: Single encrypted blob (no per-entry files) to avoid leaking metadata. Binary header with magic bytes + Argon2 params, then AES-256-GCM ciphertext containing JSON.
- **PGP crate**: Uses `pgp` (rpgp) v0.14 — pure Rust, no C deps, MIT licensed. Chose over sequoia-openpgp for cross-compilation simplicity.
- **PGP keys stored separately** from the password vault at `~/.local/share/prive/keyring/`. Private keys use OpenPGP S2K passphrase encryption. This lets file encrypt/decrypt work without unlocking the vault.
- **V4 keys**: Key generation uses `KeyVersion::V4` with `EdDSALegacy` + `ECDH(Curve25519)` for cv25519, not V6/RFC 9580, for maximum compatibility.
- **PublicKeyTrait is not dyn-compatible** in rpgp 0.14 (generic methods). Use concrete types (`SignedPublicSubKey`, primary key references) instead of trait objects.
- **`SignedSecretKey` → `SignedPublicKey`**: Use `Into` conversion (`key.clone().into()`), not `.public_key()` which returns an unsigned `PublicKey`.

### Data Flow

1. User enters master password → Argon2id derives 32-byte key → AES-256-GCM decrypts vault blob → JSON deserialized to `Vault` struct
2. Modifications saved by: serialize to JSON → encrypt with fresh random nonce → atomic write (temp + rename)
3. PGP: `encrypt_to_keys` uses recipient subkeys for encryption, falls back to primary key if no subkeys. `encrypt_to_keys_seipdv1` for v4 compatibility.
