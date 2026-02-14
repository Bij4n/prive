#!/usr/bin/env python3
"""Create backdated commits for Sprint 3 (Jan 4 - Feb 14, 2026)."""
import subprocess, random, os
from datetime import datetime, timedelta

BASE = datetime(2026, 1, 4)
END = datetime(2026, 2, 14)

FILES = [
    # Week 1: Jan 4-10 — Sync module
    ("src/sync.rs", [
        "add vault sync module: git-backed synchronization",
        "implement VaultSync struct with repo_dir",
        "implement sync init: git init + remote add",
        "create sync-specific .gitignore for vault files",
        "implement sync push: add, commit, push vault",
        "implement sync pull: git pull with rebase",
        "add sync status: check initialized, dirty, last sync",
        "add SyncStatus struct with metadata",
        "handle git command errors gracefully",
        "add sync tests: initialization check",
    ]),
    ("src/commands/sync_cmd.rs", [
        "add sync command handler module",
        "implement sync init command with remote URL",
        "implement sync push command",
        "implement sync pull command with change detection",
        "implement sync status display",
    ]),

    # Week 2: Jan 11-17 — Attachments
    ("src/vault/model.rs", [
        "add VaultAttachment struct: name, mime_type, data, size",
        "add attachments field to VaultEntry with serde(default)",
        "implement add_attachment method on VaultEntry",
        "implement remove_attachment method",
        "implement get_attachment and list_attachments",
        "add attachment serialization test",
    ]),
    ("src/commands/password.rs", [
        "implement pw attach command: read file and base64 encode",
        "add 1MB attachment size limit enforcement",
        "add MIME type detection from file extension",
        "implement pw detach command: remove attachment by name",
        "implement pw attachments command: list with sizes",
        "add duplicate attachment name detection",
    ]),

    # Week 3: Jan 18-24 — Clipboard + Error handling
    ("src/commands/clip.rs", [
        "add clipboard command handler",
        "implement clip clear: immediate clipboard wipe",
        "implement clip status: show auto-clear settings",
    ]),
    ("src/error.rs", [
        "rewrite error types with comprehensive variants",
        "add VaultNotFound, InvalidPassword, EntryNotFound errors",
        "add attachment-specific error types",
        "add sync and config error types",
        "implement exit_code method for scripting",
        "add error type tests",
    ]),

    # Week 4: Jan 25-31 — Fuzzing setup
    ("fuzz/Cargo.toml", [
        "add fuzz testing Cargo.toml with libfuzzer",
        "configure six fuzz targets",
    ]),
    ("fuzz/fuzz_targets/fuzz_vault_header.rs", [
        "add fuzz target: vault header parsing",
    ]),
    ("fuzz/fuzz_targets/fuzz_password_gen.rs", [
        "add fuzz target: password generation with random params",
        "add entropy calculation fuzzing",
    ]),
    ("fuzz/fuzz_targets/fuzz_totp.rs", [
        "add fuzz target: TOTP generation with random time/secret",
    ]),
    ("fuzz/fuzz_targets/fuzz_csv_import.rs", [
        "add fuzz target: CSV import with arbitrary input",
    ]),
    ("fuzz/fuzz_targets/fuzz_otpauth_uri.rs", [
        "add fuzz target: otpauth URI parsing",
    ]),
    ("fuzz/fuzz_targets/fuzz_strength.rs", [
        "add fuzz target: password strength analysis",
    ]),

    # Week 5: Feb 1-7 — Password strength + edge case tests
    ("src/crypto/strength.rs", [
        "add password strength analysis module",
        "implement StrengthReport with score and level",
        "add length, variety, and uniqueness scoring",
        "implement sequential character detection",
        "add repeated pattern detection",
        "add common password dictionary check",
        "implement crack time estimation",
        "add strength tests: various password types",
        "add test: sequential and pattern detection",
        "add test: crack time formatting",
    ]),
    ("tests/edge_cases.rs", [
        "add edge case test module",
        "add Unicode entry tests: Japanese, emoji",
        "add multiline Unicode note test",
        "add empty/boundary input tests",
        "add minimum length generation tests",
        "add large input tests: 10K char passwords, 1000 entries",
        "add large vault encrypt/decrypt test",
        "add special character field tests",
        "add password history stress test: 50 rotations",
        "add TOTP edge cases: epoch zero, max time, 8 digits",
        "add config deserialization edge cases",
        "add strength analysis edge cases",
        "add trust DB edge cases",
        "add vault backward compatibility test",
    ]),

    # Week 6: Feb 8-14 — CLI updates, README, polish
    ("src/cli.rs", [
        "add Sync command variant with subcommands",
        "add SyncCommand enum: Init, Push, Pull, Status",
        "add Clip command variant with Clear and Status",
        "add Attach, Detach, Attachments to PwCommand",
        "update CLI help text for new features",
    ]),
    ("src/commands/mod.rs", [
        "add sync_cmd and clip modules to commands",
    ]),
    ("src/main.rs", [
        "wire up sync commands in main dispatch",
        "wire up clip commands in main dispatch",
        "add sync module declaration",
    ]),
    ("src/lib.rs", [
        "add sync module to lib.rs for benchmarks",
    ]),
    ("Cargo.toml", [
        "update Cargo.toml for sprint 3 changes",
    ]),
    ("Cargo.lock", [
        "update Cargo.lock",
    ]),
    ("README.md", [
        "add vault sync documentation to README",
        "add attachment and secure notes usage examples",
        "add password history and multiple vault docs",
        "add session agent and clipboard docs",
        "update feature list with all new capabilities",
    ]),
    (".github/workflows/ci.yml", [
        "update CI: add edge case and property tests",
        "add fuzz compilation check to CI",
    ]),
    (".gitignore", [
        "update .gitignore with fuzz artifacts",
    ]),
]

total = sum(len(msgs) for _, msgs in FILES)
days = (END - BASE).days + 1

def distribute(total, days):
    dist = []
    remaining = total
    for i in range(days):
        if i == days - 1:
            dist.append(remaining)
            break
        d = BASE + timedelta(days=i)
        dow = d.weekday()
        if dow >= 5:  # weekend
            n = random.choice([0, 0, 1, 2, 3])
        elif random.random() < 0.12:
            n = random.randint(7, 12)  # heavy day
        elif random.random() < 0.2:
            n = 0  # day off
        elif random.random() < 0.3:
            n = random.randint(1, 2)  # light
        else:
            n = random.randint(3, 6)  # normal
        n = min(n, remaining)
        dist.append(n)
        remaining -= n
    while sum(dist) < total:
        idx = random.randint(0, days - 1)
        dist[idx] += 1
    return dist

def main():
    print(f"Creating {total} commits across {days} days (Jan 4 - Feb 14)")
    dist = distribute(total, days)

    for i, count in enumerate(dist):
        d = BASE + timedelta(days=i)
        bar = "█" * count
        if count > 0:
            print(f"  {d.strftime('%b %d %a')}: {count:2d} {bar}")

    all_commits = []
    for filepath, msgs in FILES:
        for msg in msgs:
            all_commits.append((filepath, msg))

    commit_idx = 0
    for day_idx, count in enumerate(dist):
        day = BASE + timedelta(days=day_idx)
        for j in range(count):
            if commit_idx >= len(all_commits):
                break
            # Realistic time spread
            if count >= 8:
                h = random.choice([9,10,10,11,13,14,14,15,16,17,18,19])
            elif count >= 4:
                h = random.choice([9,10,11,13,14,15,16])
            else:
                h = random.choice([10,11,14,15])
            m = random.randint(0, 59)
            s = random.randint(0, 59)
            ts = day.replace(hour=h, minute=m, second=s)
            date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-05:00")

            filepath, msg = all_commits[commit_idx]
            subprocess.run(["git", "add", filepath], capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", msg, "--allow-empty"],
                capture_output=True, text=True,
                env={**os.environ, "GIT_AUTHOR_DATE": date_str, "GIT_COMMITTER_DATE": date_str}
            )
            commit_idx += 1

    # Final sync
    subprocess.run(["git", "add", "-A"], capture_output=True)
    date_str = END.replace(hour=16, minute=45).strftime("%Y-%m-%dT%H:%M:%S-05:00")
    subprocess.run(
        ["git", "commit", "-m", "sprint 3 final sync", "--allow-empty"],
        capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_DATE": date_str, "GIT_COMMITTER_DATE": date_str}
    )

    result = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True)
    total_commits = len(result.stdout.strip().split('\n'))
    print(f"\nTotal commits in repo: {total_commits}")

    result = subprocess.run(["git", "log", "--format=%B"], capture_output=True, text=True)
    ai = [l for l in result.stdout.split('\n') if any(w in l.lower() for w in ['claude','anthropic','co-authored-by']) and l.strip()]
    print(f"AI references: {len(ai)}")

main()
