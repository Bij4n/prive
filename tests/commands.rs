//! Database commands, end to end, against the KeePassXC-made fixtures. The password comes in
//! on stdin, as a script would give it.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// `prive --db kdbx41.kdbx --password-stdin <args>`, isolated from any real config file.
fn prive(args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("prive").unwrap();
    cmd.env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env_remove("PRIVE_DB")
        .env_remove("PRIVE_KEYFILE")
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .arg("--password-stdin")
        .args(args)
        .write_stdin("fixture-pass\n");
    cmd
}

#[test]
fn ls_lists_paths_and_usernames_but_no_secrets() {
    let out = prive(&["ls"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines()
            .any(|l| l.starts_with("Work/GitHub") && l.ends_with("demo"))
    );
    assert!(text.lines().any(|l| l.trim() == "Personal/Legacy 2FA"));
    assert!(!text.contains("gh-Secret-1"));
    assert!(!text.contains("Deleted thing"));
}

#[test]
fn ls_a_group() {
    prive(&["ls", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Work/Cloud/Steam"))
        .stdout(predicate::str::contains("Bank").not());
}

#[test]
fn ls_json_has_no_passwords() {
    let out = prive(&["ls", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let all = v.as_array().unwrap();
    assert_eq!(all.len(), 7);
    let gh = all.iter().find(|e| e["path"] == "Work/GitHub").unwrap();
    assert_eq!(gh["has_otp"], true);
    assert!(gh.get("password").is_none());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("gh-Secret-1"));
}

#[test]
fn search_finds_by_title_tag_and_url() {
    prive(&["search", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Work/GitHub"))
        .stdout(predicate::str::contains("Personal/GitHub"));
    prive(&["search", "cloud"])
        .assert()
        .stdout(predicate::str::contains("Work/GitHub")); // tagged "cloud"
    prive(&["search", "bank.example"])
        .assert()
        .stdout(predicate::str::starts_with("Bank"));
}

#[test]
fn show_hides_secrets_until_revealed() {
    prive(&["show", "Work/GitHub"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Username:  demo"))
        .stdout(predicate::str::contains("6 digits every 30 s, SHA-1"))
        .stdout(predicate::str::contains("API key: ********"))
        .stdout(predicate::str::contains("plan:    team"))
        .stdout(predicate::str::contains("Files:     deploy.txt"))
        .stdout(predicate::str::contains("gh-Secret-1").not())
        .stdout(predicate::str::contains("custom-protected").not());
    prive(&["show", "Work/GitHub", "--reveal"])
        .assert()
        .stdout(predicate::str::contains("Password:  gh-Secret-1"))
        .stdout(predicate::str::contains("API key: custom-protected"));
}

#[test]
fn show_json_and_unknown_or_ambiguous_names() {
    let out = prive(&["show", "Bank", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["username"], "me@example.invalid");
    assert!(v["password"].is_null());

    prive(&["show", "Nope"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());
    prive(&["show", "GitHub"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("Work/GitHub"))
        .stderr(predicate::str::contains("Personal/GitHub"));
}

#[test]
fn get_prints_exactly_one_value() {
    prive(&["get", "Work/GitHub"])
        .assert()
        .success()
        .stdout("gh-Secret-1\n");
    prive(&["get", "Work/GitHub", "--field", "username"])
        .assert()
        .stdout("demo\n");
    prive(&["get", "Work/GitHub", "-f", "API key"])
        .assert()
        .stdout("custom-protected\n");
    prive(&["get", "Work/GitHub", "-f", "nope"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("field 'nope'"));
}

#[test]
fn get_clip_copies_and_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let clip = dir.path().join("clipboard");
    prive(&["get", "Bank", "--clip"])
        .env("PRIVE_CLIPBOARD_FILE", &clip)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Copied"));
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), "b4nk-P@ss-2026!");
}

#[test]
fn otp_prints_a_code_of_the_right_shape() {
    for (entry, len, digits) in [
        ("Work/GitHub", 6, true),
        ("Bank", 8, true),
        ("Work/Cloud/Steam", 5, false),
        ("Personal/Legacy 2FA", 6, true),
    ] {
        let out = prive(&["otp", entry]).output().unwrap();
        assert!(out.status.success(), "{entry}");
        let code = String::from_utf8(out.stdout).unwrap();
        let code = code.trim_end();
        assert_eq!(code.len(), len, "{entry}");
        assert_eq!(code.chars().all(|c| c.is_ascii_digit()), digits, "{entry}");
    }
    prive(&["otp", "Wi-Fi"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no one-time code"));
}

#[test]
fn otp_json() {
    let out = prive(&["otp", "Bank", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["code"].as_str().unwrap().len(), 8);
    assert_eq!(v["period"], 60);
    let left = v["seconds_left"].as_u64().unwrap();
    assert!((1..=60).contains(&left));
}

#[test]
fn audit_finds_the_planted_problems() {
    let out = prive(&["audit"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    // "password1" is weak and used twice; Old VPN expired; Wi-Fi is excluded.
    assert!(text.contains("Personal/GitHub\n  - weak"));
    assert!(text.contains("reused by 1 other entry"));
    assert!(text.contains("Old VPN\n  - expired"));
    assert!(!text.contains("Wi-Fi"));
    assert!(text.contains("1 skipped"));
    assert!(
        !text.contains("password1"),
        "the report must not show passwords"
    );
}
