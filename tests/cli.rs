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

#[test]
fn gen_prints_one_password() {
    let out = prive().args(["gen", "--length", "32"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.trim_end().chars().count(), 32);
    assert_eq!(text.lines().count(), 1);
}
