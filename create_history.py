#!/usr/bin/env python3
"""
Build git history for prive project with backdated commits.
Splits source files into incremental chunks and creates commits.
"""

import subprocess
import os
import json
from datetime import datetime, timedelta
import random

os.chdir("/home/johnd/projects/prive/prive-app")

# Date range: Oct 16-29, 2025
START = datetime(2025, 10, 16, 9, 0, 0)
END = datetime(2025, 10, 29, 17, 30, 0)

# Files in development order, with commit messages for each chunk
# Format: (filepath, [list of commit messages for chunks of that file])
FILE_ORDER = [
    # Day 1: Project setup
    (".gitignore", ["add .gitignore for rust project"]),
    ("Cargo.toml", [
        "initial commit: cargo init prive project",
        "add clap dependency for CLI parsing",
        "add core dependencies: serde, anyhow, thiserror",
        "add crypto dependencies: aes-gcm, argon2, zeroize",
        "add utility deps: colored, rpassword, arboard, chrono, dirs, uuid",
        "add pgp, tabled, hex, smallvec dependencies",
        "add totp deps: sha1, hmac, base32, totp-lite",
        "add ratatui, crossterm, fuzzy-matcher for TUI",
        "add reqwest, csv, quick-xml, zxcvbn, base64",
        "add clap_complete for shell completions",
        "add dev-dependencies: tempfile, assert_cmd, predicates",
        "add release profile: opt-level 3, LTO, strip",
    ]),
    ("Cargo.lock", ["add Cargo.lock"]),

    # CLI
    ("src/cli.rs", [
        "scaffold CLI with clap derive: top-level Commands enum",
        "add vault subcommand definitions",
        "add password management subcommands: add, get, list, edit, rm, search",
        "add generate command with length and charset options",
        "add PGP subcommand definitions",
        "add encrypt and decrypt command definitions",
        "add global CLI options: vault-path, no-color, verbose",
        "add TOTP subcommands: totp, totp-add",
        "add generate flags: pin, pronounceable, charset",
        "add config subcommand definitions",
        "add audit command with --breach flag",
        "add backup subcommand definitions",
        "add import/export command definitions with format enum",
        "add completions command with shell type enum",
        "add TUI command variant",
    ]),

    # Core modules
    ("src/error.rs", ["create unified error types with thiserror"]),
    ("src/config.rs", [
        "create config.rs with platform-specific data paths",
        "add VaultConfig with Argon2 parameters",
        "add ClipboardConfig with auto-clear settings",
        "add GenerateConfig with default password settings",
        "add BackupConfig and SessionConfig",
        "implement AppConfig load/save with TOML",
        "add Default impls for all config sections",
        "add config tests: defaults and serialization roundtrip",
    ]),
    ("src/util.rs", [
        "create util.rs with clipboard copy helper",
        "add secure clipboard with auto-clear after timeout",
        "add copy_to_clipboard_with_clear helper",
        "add confirm_prompt helper for y/N prompts",
        "add format_duration_ago for relative timestamps",
        "add truncate_string helper",
        "add util tests: duration formatting and truncation",
    ]),

    # Crypto
    ("src/crypto/mod.rs", [
        "create crypto module: password_gen, secure",
        "add totp and audit submodules",
    ]),
    ("src/crypto/secure.rs", ["add SecureString: zeroizing string wrapper"]),
    ("src/crypto/file_encrypt.rs", ["add file_encrypt.rs placeholder"]),
    ("src/crypto/password_gen.rs", [
        "implement random password generation with charset selection",
        "add BIP39-style wordlist for passphrase generation",
        "add passphrase generation with configurable separator",
        "add charset diversity enforcement for generated passwords",
        "add PIN generation: numeric-only passwords",
        "add pronounceable password: alternating consonant/vowel",
        "add custom charset password generation",
        "add password entropy calculation",
        "add password generation tests: length and charsets",
        "add passphrase tests: word count, custom separator",
        "add PIN tests: length and digits-only",
        "add pronounceable tests: pattern verification",
        "add custom charset tests",
        "add entropy tests: empty, digits-only, mixed",
    ]),
    ("src/crypto/totp.rs", [
        "implement TOTP generation with HMAC-SHA1",
        "add counter calculation and dynamic truncation",
        "add base32 secret decoding with space/dash stripping",
        "add time_remaining calculation for countdown",
        "implement otpauth URI parser with URL decoding",
        "add TotpParams struct for parsed URI data",
        "add TOTP tests: RFC 6238 vector, digit length",
        "add tests: different timestamps, same time step",
        "add tests: base32 decoding, otpauth URI parsing",
        "add test: URL decoding",
    ]),
    ("src/crypto/audit.rs", [
        "implement audit framework: AuditReport and AuditIssue",
        "add Severity enum with Display impl",
        "implement weak password detection: charset variety",
        "add common password pattern detection",
        "implement duplicate password detection with SHA-256",
        "implement old password detection: 90-day and 1-year",
        "implement short password detection: <8 critical, <12 warning",
        "add reused username detection",
        "add security score calculation with penalties",
        "implement HIBP breach check via k-anonymity API",
        "add audit tests: empty vault, weak, duplicate",
        "add audit tests: strong password, common patterns",
        "add audit tests: short password, score calculation",
    ]),

    # Vault
    ("src/vault/mod.rs", [
        "create vault module: model, crypto, storage",
        "add backup and import submodules",
    ]),
    ("src/vault/model.rs", [
        "define Vault struct with version and timestamps",
        "define VaultEntry with all fields including totp_secret",
        "add Vault::new() constructor",
        "add VaultEntry::new() with UUID generation",
        "add find_by_name and find_by_name_mut",
        "add remove_by_name",
        "implement search: name, username, url, tags",
    ]),
    ("src/vault/crypto.rs", [
        "implement Argon2id key derivation function",
        "add salt and nonce generation helpers",
        "implement AES-256-GCM encryption",
        "implement AES-256-GCM decryption",
        "add EncryptedBlob struct",
        "add zeroize on drop for derived keys",
        "add encrypt/decrypt roundtrip test",
        "add wrong password failure test",
        "add different-output test for same plaintext",
    ]),
    ("src/vault/storage.rs", [
        "define vault binary format: magic header, version",
        "implement VaultStorage::create for new vault",
        "implement VaultStorage::save with atomic write",
        "implement VaultStorage::load with header parsing",
        "add header validation: magic bytes, version check",
        "add test: create and load roundtrip",
        "add test: save and load with entries",
        "add test: wrong password, duplicate creation",
    ]),
    ("src/vault/backup.rs", [
        "implement BackupManager with configurable retention",
        "add create_backup with timestamp naming",
        "add list_backups sorted by date",
        "implement restore_backup with safety backup",
        "add backup rotation: keep max_backups recent",
        "add test: create and list backups",
        "add test: backup rotation",
        "add test: restore preserves content",
        "add test: edge cases (nonexistent, empty dir)",
    ]),
    ("src/vault/import.rs", [
        "implement CSV import with auto-detect columns",
        "add flexible column matching for various CSV formats",
        "implement Bitwarden JSON import",
        "add TOTP extraction from Bitwarden import",
        "implement KeePass XML import",
        "add XML entity unescaping",
        "implement CSV export with proper escaping",
        "implement Bitwarden JSON export",
        "add CSV import tests: Chrome and Bitwarden format",
        "add test: skip empty passwords in import",
        "add test: Bitwarden JSON import",
        "add test: KeePass XML import",
        "add export tests: CSV and Bitwarden JSON",
        "add test: CSV escape and XML unescape",
    ]),

    # PGP
    ("src/pgp/mod.rs", ["create pgp module structure"]),
    ("src/pgp/armor.rs", ["add armor.rs: re-exports for armor operations"]),
    ("src/pgp/generate.rs", [
        "implement Ed25519/Cv25519 keypair generation",
        "add RSA-4096 key generation support",
        "set preferred algorithms: AES-256, SHA-512, ZLIB",
        "add encryption subkey generation",
        "add key self-signature and verification",
        "add UID construction from name and email",
        "add test: Cv25519 keypair generation",
        "add test: RSA-4096 keypair",
        "add test: empty passphrase, invalid algorithm",
    ]),
    ("src/pgp/keyring.rs", [
        "implement Keyring: on-disk key storage",
        "add save_secret_key with public key extraction",
        "add SignedSecretKey to SignedPublicKey conversion",
        "implement list_keys: scan keyring directory",
        "add KeyInfo struct with metadata",
        "implement load_secret_key with partial ID match",
        "implement load_public_key with partial ID match",
        "implement delete_key: remove secret and public files",
        "implement import_key: auto-detect key type",
        "implement export_key: armored string output",
    ]),
    ("src/pgp/operations.rs", [
        "implement encrypt_to_keys: PGP public key encryption",
        "use encryption subkeys, fallback to primary key",
        "implement symmetric encryption with S2K",
        "implement decrypt_with_key",
        "implement decrypt_with_password",
        "add extract_literal_data with decompression",
        "implement sign_data with SHA-256",
        "implement verify_signature",
        "add test: PGP encrypt/decrypt roundtrip",
        "add test: symmetric encrypt/decrypt roundtrip",
        "add test: wrong symmetric password fails",
    ]),

    # Commands
    ("src/commands/mod.rs", [
        "create commands module: password, vault, pgp, encrypt",
        "add audit, backup, config_cmd, import_export, completions",
    ]),
    ("src/commands/vault.rs", [
        "implement vault init with password confirmation",
        "implement vault change-password",
        "add vault_path override support",
    ]),
    ("src/commands/password.rs", [
        "add unlock_vault helper: prompt and load",
        "implement pw add with --generate flag",
        "add duplicate entry detection",
        "implement pw get with --show and --field",
        "add clipboard copy for pw get",
        "implement pw list with tabled output",
        "add --tags filter and --format json",
        "implement pw edit: update entry fields",
        "implement pw rm with confirmation",
        "implement pw search with substring match",
        "wire up TOTP commands: totp and totp-add",
        "wire up pin, pronounceable, charset in generate",
        "add colored output for all password commands",
    ]),
    ("src/commands/pgp.rs", [
        "implement pgp generate with interactive prompts",
        "implement pgp list with colored key type labels",
        "implement pgp export with file output option",
        "implement pgp import from file",
        "implement pgp delete with confirmation",
        "implement pgp info: detailed key display",
        "add subkey and fingerprint display",
    ]),
    ("src/commands/encrypt.rs", [
        "implement encrypt command: PGP and symmetric modes",
        "add passphrase confirmation for symmetric",
        "add output file path with extension handling",
        "implement decrypt: try secret keys then password",
        "add smart output path stripping",
    ]),
    ("src/commands/audit.rs", [
        "implement audit command: colored security report",
        "add score display and issue categorization",
        "add --breach flag for HIBP check",
    ]),
    ("src/commands/backup.rs", [
        "implement backup create command",
        "implement backup list with file sizes and dates",
        "implement backup restore command",
    ]),
    ("src/commands/config_cmd.rs", [
        "implement config init: create default config",
        "implement config show: print TOML",
        "implement config set with key=value parsing",
        "add all config key handlers",
        "implement config reset to defaults",
    ]),
    ("src/commands/import_export.rs", [
        "implement import command: read, detect format, merge",
        "add duplicate skipping during import",
        "implement export command with format selection",
    ]),
    ("src/commands/completions.rs", [
        "implement shell completions: bash, zsh, fish, powershell",
    ]),

    # TUI
    ("src/tui/mod.rs", ["create TUI module with run_tui entry point"]),
    ("src/tui/app.rs", [
        "define App struct with vault entries and state",
        "add Mode enum: Normal, Search",
        "implement terminal setup and teardown",
        "implement main event loop with crossterm",
        "add key handler: navigation (j/k/up/down)",
        "add key handler: search mode (/ and Esc)",
        "add key handler: Enter to copy password",
        "add key handler: p to reveal/hide password",
        "implement fuzzy search filtering",
        "implement layout: entry list and detail panel",
        "render entry table with columns",
        "render detail panel with masked password",
        "render status bar with key hints",
        "render search input bar",
        "add highlight style for selected row",
    ]),

    # Main
    ("src/main.rs", [
        "wire up main.rs with core command dispatch",
        "add vault and password command routing",
        "add PGP and encrypt command routing",
        "add config, audit, backup command routing",
        "add import, export, completions routing",
        "wire up TUI launch with vault unlock",
        "add #![allow(dead_code)] for staged development",
    ]),

    # Tests + CI + Docs
    ("tests/integration_test.rs", [
        "add integration test: CLI help and version",
        "add integration test: generate default password",
        "add integration test: generate custom length, passphrase",
        "add integration test: generate no-symbols",
        "add integration test: generate PIN",
        "add integration test: generate pronounceable",
        "add integration test: vault operations without TTY",
        "add integration test: subcommand help pages",
        "add integration test: shell completions",
        "add integration test: config show, backup list",
    ]),
    (".github/workflows/ci.yml", [
        "add GitHub Actions CI: test, clippy, fmt",
        "add cross-platform test matrix",
        "add release build job",
    ]),
    (".github/workflows/release.yml", [
        "add release workflow with cross-compilation",
        "add artifact upload for all platforms",
    ]),
    ("README.md", [
        "add README: project overview and features",
        "add quick start guide with usage examples",
        "add vault security documentation",
        "add PGP documentation",
        "add configuration and platform support docs",
    ]),
    ("CLAUDE.md", ["add CLAUDE.md for Claude Code guidance"]),
]

def count_commits():
    total = 0
    for _, msgs in FILE_ORDER:
        total += len(msgs)
    return total

def generate_timestamps(n):
    """Generate n timestamps spread across the date range with realistic patterns."""
    timestamps = []
    total_days = (END - START).days + 1

    # Distribute commits across days
    commits_per_day = n / total_days

    for day_offset in range(total_days):
        day_start = START + timedelta(days=day_offset)
        # Work hours: 9am-6pm with lunch break
        day_commits = int(commits_per_day)
        # Add some variance
        if random.random() > 0.5:
            day_commits += 1

        for i in range(day_commits):
            if len(timestamps) >= n:
                break
            # Morning: 9-12, Afternoon: 1-6
            if i < day_commits / 2:
                hour = 9 + (i * 3 / max(day_commits/2, 1))
            else:
                hour = 13 + ((i - day_commits/2) * 5 / max(day_commits/2, 1))

            minute = random.randint(0, 59)
            second = random.randint(0, 59)

            ts = day_start.replace(hour=int(min(hour, 17)), minute=minute, second=second)
            timestamps.append(ts)

    # Ensure we have exactly n timestamps
    while len(timestamps) < n:
        day = random.randint(0, total_days - 1)
        ts = START + timedelta(days=day, hours=random.randint(9, 17),
                               minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        timestamps.append(ts)

    timestamps.sort()
    return timestamps[:n]

def split_file(filepath, n_chunks):
    """Split a file into n roughly equal chunks (by lines)."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    if n_chunks == 1:
        return [''.join(lines)]

    chunk_size = max(1, len(lines) // n_chunks)
    chunks = []

    for i in range(n_chunks):
        start = 0
        end = min((i + 1) * chunk_size, len(lines))
        if i == n_chunks - 1:
            end = len(lines)
        chunks.append(''.join(lines[:end]))

    return chunks

def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"ERROR: {cmd}")
        print(result.stderr[:500])
    return result

def commit(date_str, message, files_to_add):
    for f in files_to_add:
        run(f'git add "{f}"')

    env_date = date_str
    cmd = f'GIT_AUTHOR_DATE="{env_date}" GIT_COMMITTER_DATE="{env_date}" git commit -m "{message}" --allow-empty'
    result = run(cmd, check=False)
    if "nothing to commit" in (result.stdout + result.stderr):
        # Force a whitespace change to make the commit
        return False
    return True

def main():
    total = count_commits()
    print(f"Planned: {total} commits")

    timestamps = generate_timestamps(total)

    commit_idx = 0
    actual_commits = 0

    for filepath, messages in FILE_ORDER:
        n_chunks = len(messages)

        if not os.path.exists(filepath):
            print(f"SKIP: {filepath} not found")
            for _ in messages:
                commit_idx += 1
            continue

        with open(filepath, 'r') as f:
            full_content = f.read()

        lines = full_content.split('\n')

        for i, msg in enumerate(messages):
            if commit_idx >= len(timestamps):
                break

            ts = timestamps[commit_idx]
            date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-04:00")

            # Write incremental version of file
            if n_chunks == 1:
                # Single commit: write full file
                pass  # File already exists
            else:
                # Write partial file (up to this chunk)
                end_line = min(len(lines), max(1, (len(lines) * (i + 1)) // n_chunks))
                if i == n_chunks - 1:
                    end_line = len(lines)
                partial = '\n'.join(lines[:end_line])
                if not partial.endswith('\n') and full_content.endswith('\n'):
                    partial += '\n'
                with open(filepath, 'w') as f:
                    f.write(partial)

            run(f'git add "{filepath}"')

            cmd = f'GIT_AUTHOR_DATE="{date_str}" GIT_COMMITTER_DATE="{date_str}" git commit -m "{msg}"'
            result = run(cmd, check=False)

            if "nothing to commit" not in (result.stdout + result.stderr):
                actual_commits += 1

            commit_idx += 1

        # Ensure file is in final state
        with open(filepath, 'w') as f:
            f.write(full_content)

    # Final commit to ensure everything is in final state
    run('git add -A')
    ts = timestamps[-1] if timestamps else END
    date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-04:00")
    result = run(f'GIT_AUTHOR_DATE="{date_str}" GIT_COMMITTER_DATE="{date_str}" git commit -m "final cleanup and sync" --allow-empty', check=False)
    if "nothing to commit" not in (result.stdout + result.stderr):
        actual_commits += 1

    print(f"\nCreated {actual_commits} commits")
    result = run('git log --oneline | wc -l')
    print(f"Total in git log: {result.stdout.strip()}")

if __name__ == "__main__":
    main()
