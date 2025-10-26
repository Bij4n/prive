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
