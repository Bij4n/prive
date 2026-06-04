//! The unlock-once agent, end to end. Each test gets its own private agent directory and a
//! one-minute timeout, and locks the agent when it is done.
#![cfg(unix)]

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

struct Sandbox {
    dir: tempfile::TempDir,
    db: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.kdbx");
        std::fs::copy(fixture("kdbx41.kdbx"), &db).unwrap();
        std::fs::write(dir.path().join("config.toml"), "agent_minutes = 1\n").unwrap();
        Sandbox { dir, db }
    }

    fn agent_dir(&self) -> PathBuf {
        self.dir.path().join("agent")
    }

    /// prive with this sandbox's database, config and agent directory, and no password source.
    fn prive(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("prive").unwrap();
        cmd.env("PRIVE_CONFIG", self.dir.path().join("config.toml"))
            .env("PRIVE_AGENT_DIR", self.agent_dir())
            .env_remove("PRIVE_NO_AGENT")
            .env_remove("PRIVE_PASSWORD_FILE")
            .arg("--db")
            .arg(&self.db)
            .args(args)
            .write_stdin("")
            .timeout(std::time::Duration::from_secs(30));
        cmd
    }

    fn unlock(&self) {
        self.prive(&["--password-stdin", "unlock"])
            .write_stdin("fixture-pass\n")
            .assert()
            .success()
            .stderr(predicate::str::contains("Unlocked db.kdbx"));
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.prive(&["lock"]).output();
    }
}

#[test]
fn unlock_once_then_no_password_until_locked() {
    let s = Sandbox::new();
    // Before unlocking there is no password source: exit 5 at once.
    s.prive(&["get", "Bank"]).assert().code(5);
    s.unlock();
    s.prive(&["get", "Bank"])
        .assert()
        .success()
        .stdout("b4nk-P@ss-2026!\n");
    s.prive(&["otp", "Work/GitHub"]).assert().success();
    s.prive(&["lock"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Locked."));
    s.prive(&["get", "Bank"]).assert().code(5);
}

#[test]
fn status_before_and_after() {
    let s = Sandbox::new();
    s.prive(&["status"]).assert().success().stdout("locked\n");
    s.unlock();
    let out = s.prive(&["status", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["unlocked"], true);
    assert!(v["db"].as_str().unwrap().ends_with("db.kdbx"));
    let left = v["seconds_left"].as_u64().unwrap();
    assert!((1..=60).contains(&left), "{left}");
}

#[test]
fn a_wrong_password_starts_nothing() {
    let s = Sandbox::new();
    s.prive(&["--password-stdin", "unlock"])
        .write_stdin("wrong\n")
        .assert()
        .code(5);
    s.prive(&["status"]).assert().stdout("locked\n");
}

#[test]
fn a_change_on_disk_means_unlocking_again() {
    let s = Sandbox::new();
    s.unlock();
    // KeePassXC (or a sync tool) writes a new version of the file.
    std::fs::copy(fixture("kdbx40.kdbx"), &s.db).unwrap();
    s.prive(&["get", "Bank"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("changed on disk"));
    // The agent has forgotten the old copy, not kept serving it.
    s.prive(&["status"]).assert().stdout("locked\n");
}

#[test]
fn only_the_unlocked_database_is_served() {
    let s = Sandbox::new();
    s.unlock();
    let other = s.dir.path().join("other.kdbx");
    std::fs::copy(fixture("kdbx31.kdbx"), &other).unwrap();
    s.prive(&["get", "Bank"]).assert().success();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", s.dir.path().join("config.toml"))
        .env("PRIVE_AGENT_DIR", s.agent_dir())
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(&other)
        .args(["get", "Bank"])
        .write_stdin("")
        .assert()
        .code(5);
}

#[test]
fn no_agent_reads_the_file_even_when_unlocked() {
    let s = Sandbox::new();
    s.unlock();
    s.prive(&["--no-agent", "get", "Bank"]).assert().code(5);
    s.prive(&["get", "Bank"])
        .env("PRIVE_NO_AGENT", "1")
        .assert()
        .code(5);
    s.prive(&["get", "Bank"]).assert().success();
}
