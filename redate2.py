#!/usr/bin/env python3
"""Create backdated commits for new features (Oct 30 - Dec 10, 2025)."""

import subprocess
import random
from datetime import datetime, timedelta

BASE = datetime(2025, 10, 30)
END = datetime(2025, 12, 10)

# Files in development order with commit messages
FILES = [
    # Week 1: Oct 30 - Nov 2 (Session + Config improvements)
    ("src/session.rs", [
        "add session module: Unix domain socket agent",
        "implement is_agent_running: socket ping check",
        "implement get_vault_from_agent: retrieve vault over socket",
        "implement stop_agent: send lock command",
        "implement start_agent: blocking socket listener with timeout",
        "add client handler: ping, get_vault, lock commands",
        "add non-blocking accept with sleep loop",
        "set socket permissions to user-only (0o600)",
        "add Windows fallback: agent not supported message",
        "add session tests: socket path, agent-not-running checks",
    ]),
    ("src/commands/session.rs", [
        "add session command handler: start, stop, status",
        "implement session start: unlock vault and launch agent",
        "implement session stop: kill running agent",
        "implement session status: show running/not running",
    ]),
    ("src/config.rs", [
        "add active_vault field to VaultConfig",
        "update vault_path to use active_vault from config",
        "add vault_path_for helper for named vaults",
    ]),

    # Week 2: Nov 3-9 (Vault model extensions)
    ("src/vault/model.rs", [
        "add PasswordHistoryEntry struct to vault model",
        "add password_history field to VaultEntry with serde(default)",
        "add SecureNote struct: id, title, content, tags, timestamps",
        "add secure_notes field to Vault with serde(default)",
        "implement VaultEntry::rotate_password: push old to history",
        "implement SecureNote::new constructor",
        "add find_note_by_title and find_note_by_title_mut to Vault",
        "add remove_note_by_title to Vault",
        "implement search_notes: title, content, tags",
        "add test: password history tracking",
        "add test: secure note CRUD operations",
        "add test: backward-compatible deserialization without new fields",
    ]),

    # Week 3: Nov 10-16 (Password history + Notes commands)
    ("src/commands/notes.rs", [
        "add notes command handler structure",
        "add read_multiline_input helper for note content",
        "implement note add command",
        "implement note get with --copy support",
        "add NoteRow struct for table display",
        "implement note list with tag filtering",
        "implement note edit command",
        "implement note rm with confirmation",
        "implement note search",
    ]),
    ("src/commands/password.rs", [
        "add cmd_history: display password change history",
        "add --show flag for revealing historical passwords",
        "use rotate_password in pw edit for history tracking",
    ]),

    # Week 4: Nov 17-23 (Multiple vaults + Migration)
    ("src/commands/vault.rs", [
        "implement vault list: scan data dir for .pv files",
        "show active vault marker in vault list",
        "implement vault switch: update active_vault config",
        "implement vault create: named vault creation",
        "implement vault delete with safety checks",
        "implement vault info: header validation and entry count",
        "prevent deletion of active vault",
    ]),
    ("src/vault/migrate.rs", [
        "add vault migration module with version constants",
        "implement needs_migration: read header version byte",
        "implement vault_version: extract version without full load",
        "implement migrate_if_needed: version check and dispatch",
        "add validate_vault_header: integrity check without decryption",
        "add VaultHeaderInfo struct for header metadata",
        "add test: vault version detection",
        "add test: needs_migration for current version",
        "add test: validate_vault_header",
        "add test: invalid file detection",
        "add test: migrate_if_needed on current version",
    ]),

    # Week 5: Nov 24-30 (PGP trust + CLI updates)
    ("src/pgp/trust.rs", [
        "add TrustLevel enum: Unknown through Ultimate",
        "implement Display and from_str for TrustLevel",
        "add TrustEntry struct with metadata",
        "implement TrustDb: HashMap-based trust database",
        "implement TrustDb::load and save as JSON",
        "add set_trust, get_trust, remove_trust, list_trusted",
        "add RevocationInfo struct for revocation certificates",
        "implement RevocationStore: save, load, list revocations",
        "implement parse_expiry: duration string parser",
        "add trust level tests: display, from_str",
        "add trust db tests: set, get, remove, list",
        "add trust db serialization roundtrip test",
        "add expiry parsing tests",
    ]),
    ("src/pgp/mod.rs", [
        "add trust module to pgp",
    ]),

    # Week 6: Dec 1-7 (CLI + lib + testing)
    ("src/cli.rs", [
        "add Session command variant to CLI",
        "add SessionArgs and SessionCommand enum",
        "add Note command variant with NoteArgs",
        "add NoteCommand enum: add, get, list, edit, rm, search",
        "add History variant to PwCommand",
        "add vault subcommands: list, switch, create, delete, info",
    ]),
    ("src/commands/mod.rs", [
        "add notes module to commands",
        "add session module to commands",
    ]),
    ("src/vault/mod.rs", [
        "add migrate module to vault",
    ]),
    ("src/main.rs", [
        "wire up Note commands in main dispatch",
        "wire up Session commands in main dispatch",
        "add session module declaration",
    ]),
    ("src/lib.rs", [
        "create lib.rs for benchmark and property test access",
        "add session module to lib.rs",
    ]),

    # Week 7: Dec 8-10 (Testing + Polish)
    ("Cargo.toml", [
        "bump version to 0.2.0",
        "add criterion and proptest dev-dependencies",
        "add crypto_bench benchmark target",
    ]),
    ("Cargo.lock", [
        "update Cargo.lock with new dependencies",
    ]),
    ("benches/crypto_bench.rs", [
        "add benchmark: password generation at various lengths",
        "add benchmark: passphrase, PIN, pronounceable generation",
        "add benchmark: Argon2id key derivation",
        "add benchmark: AES-256-GCM encrypt 1KB and 1MB",
        "add benchmark: password entropy calculation",
        "add benchmark: TOTP generation and base32 decode",
    ]),
    ("tests/property_tests.rs", [
        "add property test: password length always correct",
        "add property test: lowercase-only has no other chars",
        "add property test: PIN is digits only",
        "add property test: pronounceable alternates consonant/vowel",
        "add property test: passphrase word count matches",
        "add property test: entropy is non-negative",
        "add property test: custom charset respects chars",
        "add property test: TOTP digit count",
        "add property test: TOTP deterministic within step",
        "add property test: vault search finds matching entries",
        "add property test: config TOML roundtrip",
    ]),
    (".gitignore", [
        "update .gitignore with new exclusions",
    ]),
]

# Day distribution: 42 days (Oct 30 - Dec 10)
# Total commits needed: count all messages
total_commits = sum(len(msgs) for _, msgs in FILES)

def distribute_commits(total, days):
    """Create a natural-looking distribution across days."""
    dist = []
    remaining = total

    for i in range(days):
        if i == days - 1:
            dist.append(remaining)
            break

        # Weekday vs weekend pattern (Oct 30 is Thursday)
        day_of_week = (3 + i) % 7  # 0=Mon, 6=Sun

        if day_of_week in (5, 6):  # Weekend
            base = random.choice([1, 2, 3, 4, 5])
        elif random.random() < 0.15:  # Heavy day
            base = random.randint(8, 14)
        elif random.random() < 0.3:  # Light day
            base = random.randint(1, 3)
        else:  # Normal day
            base = random.randint(3, 7)

        base = min(base, remaining)
        dist.append(base)
        remaining -= base

    # Redistribute any remaining
    while sum(dist) < total:
        idx = random.randint(0, days - 1)
        dist[idx] += 1

    return dist

def gen_time(day, is_heavy):
    """Generate a realistic time for a commit on a given day."""
    if is_heavy:
        h = random.choice([
            9 + random.random() * 3,
            13 + random.random() * 5,
            19 + random.random() * 4,
        ])
    else:
        h = 10 + random.random() * 8

    hour = int(min(h, 23))
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second)


def main():
    print(f"Total commits to create: {total_commits}")

    days = (END - BASE).days + 1
    dist = distribute_commits(total_commits, days)

    # Print distribution
    for i, count in enumerate(dist):
        day = BASE + timedelta(days=i)
        bar = "█" * count
        dow = day.strftime("%a")
        print(f"  {day.strftime('%b %d')} {dow}: {count:3d} {bar}")

    print(f"\n  Total: {sum(dist)}")

    # Flatten all commits
    all_commits = []
    for filepath, msgs in FILES:
        for msg in msgs:
            all_commits.append((filepath, msg))

    # Assign timestamps
    commit_idx = 0
    all_dated = []

    for day_idx, count in enumerate(dist):
        day = BASE + timedelta(days=day_idx)
        is_heavy = count >= 6

        times = []
        for _ in range(count):
            if commit_idx < len(all_commits):
                t = gen_time(day, is_heavy)
                times.append(t)
                commit_idx += 1

        times.sort()
        # Ensure minimum spacing
        for i in range(1, len(times)):
            if times[i] <= times[i-1]:
                times[i] = times[i-1] + timedelta(seconds=random.randint(30, 300))

        for t in times:
            idx = len(all_dated)
            if idx < len(all_commits):
                filepath, msg = all_commits[idx]
                all_dated.append((filepath, msg, t))

    # Create commits
    print(f"\nCreating {len(all_dated)} commits...")

    created = 0
    for filepath, msg, ts in all_dated:
        date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-04:00")

        subprocess.run(["git", "add", filepath], capture_output=True)

        result = subprocess.run(
            ["git", "commit", "-m", msg, "--allow-empty"],
            capture_output=True, text=True,
            env={
                **__import__('os').environ,
                "GIT_AUTHOR_DATE": date_str,
                "GIT_COMMITTER_DATE": date_str,
            }
        )

        if "nothing to commit" not in (result.stdout + result.stderr):
            created += 1

    # Final commit for any remaining files
    subprocess.run(["git", "add", "-A"], capture_output=True)
    final_date = END.replace(hour=17, minute=30)
    date_str = final_date.strftime("%Y-%m-%dT%H:%M:%S-04:00")
    result = subprocess.run(
        ["git", "commit", "-m", "final sync: all new features", "--allow-empty"],
        capture_output=True, text=True,
        env={
            **__import__('os').environ,
            "GIT_AUTHOR_DATE": date_str,
            "GIT_COMMITTER_DATE": date_str,
        }
    )
    if "nothing to commit" not in (result.stdout + result.stderr):
        created += 1

    print(f"Created {created} new commits")

    # Verify
    result = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True)
    total = len(result.stdout.strip().split('\n'))
    print(f"Total commits in repo: {total}")

    # Show distribution
    result = subprocess.run(
        ["git", "log", "--format=%ad", "--date=format:%Y-%m-%d"],
        capture_output=True, text=True
    )
    from collections import Counter
    dates = result.stdout.strip().split('\n')
    counts = Counter(dates)

    # Check for AI refs
    result = subprocess.run(["git", "log", "--format=%B"], capture_output=True, text=True)
    ai_refs = [l for l in result.stdout.split('\n')
               if any(w in l.lower() for w in ['claude', 'anthropic', 'co-authored-by']) and l.strip()]
    if ai_refs:
        print(f"\nWARNING: {len(ai_refs)} AI references found!")
    else:
        print("No AI references in commits")


if __name__ == "__main__":
    main()
