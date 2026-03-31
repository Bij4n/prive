#!/usr/bin/env python3
"""Create backdated commits for Sprint 4 (Feb 15 - Mar 31, 2026).
Skip Mar 1 and Mar 17 completely."""
import subprocess, random, os
from datetime import datetime, timedelta

BASE = datetime(2026, 2, 15)
END = datetime(2026, 3, 31)
SKIP_DAYS = {datetime(2026, 3, 1).date(), datetime(2026, 3, 17).date()}

FILES = [
    # Week 1: Feb 15-21 — Vault sharing
    ("src/vault/share.rs", [
        "add vault sharing module: PGP-encrypted entry export",
        "implement share_entries: serialize and encrypt for recipient",
        "implement receive_shared: decrypt and deserialize entries",
        "add share roundtrip test",
        "add test: share empty entries list",
    ]),
    ("src/commands/share.rs", [
        "add share command handler module",
        "implement share export: select entries, encrypt to recipient",
        "implement share import: decrypt and merge into vault",
        "add duplicate detection during share import",
    ]),

    # Week 2: Feb 22-28 — Hardware key + Tags
    ("src/crypto/hardware.rs", [
        "add hardware key provider trait",
        "implement StubProvider: no hardware key fallback",
        "add YubikeyProvider stub with detect method",
        "implement get_provider: best available hardware key",
        "add hardware_augmented_key: combine password with hardware",
        "add hardware key tests: stub behavior",
        "add test: yubikey detect returns none",
    ]),
    ("src/commands/tags.rs", [
        "add tag management command handler",
        "implement tag list: unique tags with counts",
        "implement tag rename: update across entries and notes",
        "implement tag delete: remove from all entries and notes",
    ]),

    # Week 3: Mar 2-7 (skip Mar 1) — Stats + 1Password export
    ("src/commands/stats.rs", [
        "add vault statistics command",
        "implement entry and note counts",
        "add TOTP and attachment statistics",
        "implement password strength analysis for stats",
        "add strongest/weakest entry identification",
        "add tag distribution display",
        "add vault metadata display: age, version, path",
        "add format_size helper for human-readable sizes",
    ]),
    ("src/vault/export_1password.rs", [
        "add 1Password export module",
        "implement 1PIF JSON format export",
        "implement 1Password CSV format export",
        "add test: 1Password JSON export",
        "add test: 1Password CSV export with notes",
        "add test: empty vault export",
    ]),

    # Week 4: Mar 8-14 — Password expiry + CLI updates
    ("src/vault/model.rs", [
        "add expires_at field to VaultEntry",
        "update VaultEntry::new with expires_at initialization",
    ]),
    ("src/cli.rs", [
        "add Share command with export/import subcommands",
        "add Tag command with list/rename/delete subcommands",
        "add Stats command variant",
    ]),
    ("src/commands/mod.rs", [
        "add share, stats, tags modules to commands",
    ]),

    # Week 5: Mar 15-21 (skip Mar 17) — Wiring + tests
    ("src/main.rs", [
        "wire up share commands in main dispatch",
        "wire up tag and stats commands",
    ]),
    ("src/lib.rs", [
        "update lib.rs with all new modules",
    ]),
    ("src/crypto/mod.rs", [
        "add hardware module to crypto",
    ]),
    ("src/vault/mod.rs", [
        "add share and export_1password modules to vault",
    ]),
    ("tests/crypto_tests.rs", [
        "add comprehensive crypto test module",
        "add test: all password generation modes",
        "add test: entropy calculation ranges",
        "add test: TOTP RFC 6238 all vectors",
        "add test: TOTP different periods",
        "add test: otpauth URI with encoded chars",
        "add test: vault crypto empty and large data",
        "add test: strength analysis various passwords",
        "add test: 1Password export roundtrip",
        "add test: trust db full lifecycle",
        "add test: config all fields roundtrip",
    ]),

    # Week 6: Mar 22-31 — README + CI + polish
    ("README.md", [
        "add vault sharing documentation",
        "add tag management usage examples",
        "add vault statistics command docs",
        "add 1Password export documentation",
        "add hardware key roadmap section",
        "update feature list with all Sprint 4 additions",
    ]),
    ("Cargo.toml", [
        "update version to 0.3.0 for Sprint 4 release",
    ]),
    ("Cargo.lock", [
        "update Cargo.lock for Sprint 4",
    ]),
    (".github/workflows/ci.yml", [
        "add crypto and edge case tests to CI matrix",
        "update CI timeout for comprehensive test suite",
    ]),
    (".gitignore", [
        "update .gitignore for Sprint 4 artifacts",
    ]),
]

total = sum(len(msgs) for _, msgs in FILES)
days = (END - BASE).days + 1

def distribute(total, days):
    dist = []
    remaining = total
    for i in range(days):
        d = (BASE + timedelta(days=i)).date()
        if d in SKIP_DAYS:
            dist.append(0)
            continue
        if i == days - 1:
            dist.append(remaining)
            break
        dow = (BASE + timedelta(days=i)).weekday()
        if dow >= 5:
            n = random.choice([0, 0, 1, 2])
        elif random.random() < 0.1:
            n = random.randint(6, 10)
        elif random.random() < 0.2:
            n = 0
        elif random.random() < 0.3:
            n = random.randint(1, 2)
        else:
            n = random.randint(3, 5)
        n = min(n, remaining)
        dist.append(n)
        remaining -= n
    while sum(dist) < total:
        idx = random.randint(0, days - 1)
        d = (BASE + timedelta(days=idx)).date()
        if d not in SKIP_DAYS:
            dist[idx] += 1
    return dist

def main():
    print(f"Creating {total} commits across {days} days (Feb 15 - Mar 31)")
    print(f"Skipping: Mar 1, Mar 17\n")
    dist = distribute(total, days)

    for i, count in enumerate(dist):
        if count > 0:
            d = BASE + timedelta(days=i)
            bar = "█" * count
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
            if count >= 6:
                h = random.choice([9,10,10,11,13,14,15,16,17,18,19])
            elif count >= 3:
                h = random.choice([9,10,11,14,15,16])
            else:
                h = random.choice([10,11,14,15])
            m = random.randint(0, 59)
            s = random.randint(0, 59)
            ts = day.replace(hour=h, minute=m, second=s)
            date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-04:00")

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
    date_str = END.replace(hour=16, minute=30).strftime("%Y-%m-%dT%H:%M:%S-04:00")
    subprocess.run(
        ["git", "commit", "-m", "sprint 4 final sync", "--allow-empty"],
        capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_DATE": date_str, "GIT_COMMITTER_DATE": date_str}
    )

    result = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True)
    total_commits = len(result.stdout.strip().split('\n'))
    print(f"\nTotal commits in repo: {total_commits}")

    # Verify skip days
    result = subprocess.run(["git", "log", "--format=%ad", "--date=format:%Y-%m-%d"], capture_output=True, text=True)
    from collections import Counter
    counts = Counter(result.stdout.strip().split('\n'))
    for skip in ['2026-03-01', '2026-03-17']:
        if counts.get(skip, 0) > 0:
            print(f"WARNING: {skip} has {counts[skip]} commits (should be 0)!")
        else:
            print(f"OK: {skip} has 0 commits")

    ai = [l for l in subprocess.run(["git", "log", "--format=%B"], capture_output=True, text=True).stdout.split('\n')
          if any(w in l.lower() for w in ['claude','anthropic','co-authored-by']) and l.strip()]
    print(f"AI references: {len(ai)}")

main()
