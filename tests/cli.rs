use assert_cmd::Command;
use predicates::prelude::*;

fn prive() -> Command {
    Command::cargo_bin("prive").unwrap()
}

#[test]
fn prints_its_version() {
    prive()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("prive 0.6.0"));
}

#[test]
fn rejects_unknown_arguments_with_usage_exit_code() {
    prive().arg("--no-such-flag").assert().code(2);
}
