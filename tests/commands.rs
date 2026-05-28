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
