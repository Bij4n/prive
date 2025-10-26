use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    Command::cargo_bin("prive")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("password & encryption toolkit"));
}

#[test]
fn test_cli_version() {
    Command::cargo_bin("prive")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("prive"));
}

#[test]
fn test_generate_default() {
    Command::cargo_bin("prive")
        .unwrap()
        .arg("generate")
        .assert()
        .success()
        .stdout(predicate::str::is_match("[a-zA-Z0-9!@#$%^&*()\\-_=+\\[\\]{}|;:,.<>?]{20}").unwrap());
}

#[test]
fn test_generate_custom_length() {
    Command::cargo_bin("prive")
        .unwrap()
        .args(["generate", "--length", "32"])
        .assert()
        .success();
}

#[test]
fn test_generate_passphrase() {
    Command::cargo_bin("prive")
        .unwrap()
        .args(["generate", "--passphrase", "--words", "4", "--separator", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("."));
}

#[test]
fn test_generate_no_symbols() {
    let output = Command::cargo_bin("prive")
        .unwrap()
        .args(["generate", "--no-symbols", "--length", "50"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    assert!(
        !stdout.trim().chars().any(|c| symbols.contains(c)),
        "Output should not contain symbols: {stdout}"
    );
}

#[test]
fn test_generate_pin() {
    let output = Command::cargo_bin("prive")
        .unwrap()
        .args(["generate", "--pin", "--length", "6"])
        .output()
        .unwrap();
