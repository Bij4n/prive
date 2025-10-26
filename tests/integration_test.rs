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
