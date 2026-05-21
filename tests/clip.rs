//! Clipboard behaviour, using the file stand-in instead of the real clipboard.

use std::path::Path;
use std::time::{Duration, Instant};

use assert_cmd::Command;

fn prive(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("prive").unwrap();
    std::fs::write(dir.join("config.toml"), "clipboard_seconds = 1\n").unwrap();
    cmd.env("PRIVE_CONFIG", dir.join("config.toml"))
        .env("PRIVE_CLIPBOARD_FILE", dir.join("clipboard"));
    cmd
}

fn wait_for(path: &Path, want: impl Fn(&str) -> bool) -> String {
    let start = Instant::now();
    loop {
        let now = std::fs::read_to_string(path).unwrap_or_default();
        if want(&now) || start.elapsed() > Duration::from_secs(10) {
            return now;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn copies_then_clears() {
    let dir = tempfile::tempdir().unwrap();
    let out = prive(dir.path())
        .args(["gen", "--clip", "--length", "30"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "the secret must not also be printed");
    let clip = dir.path().join("clipboard");
    let copied = std::fs::read_to_string(&clip).unwrap();
    assert_eq!(copied.chars().count(), 30);
    assert_eq!(wait_for(&clip, str::is_empty), "");
}

#[test]
fn leaves_a_newer_copy_alone() {
    let dir = tempfile::tempdir().unwrap();
    prive(dir.path()).args(["gen", "--clip"]).assert().success();
    let clip = dir.path().join("clipboard");
    std::fs::write(&clip, "something else").unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), "something else");
}
