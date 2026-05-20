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

#[test]
fn gen_passphrase_and_pin() {
    let out = prive()
        .args(["gen", "--words", "5", "--separator", "."])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .split('.')
            .count(),
        5
    );

    let out = prive().args(["gen", "--pin", "6"]).output().unwrap();
    let pin = String::from_utf8(out.stdout).unwrap();
    assert_eq!(pin.trim().len(), 6);
    assert!(pin.trim().chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn gen_rejects_conflicting_modes_and_bad_lengths() {
    prive()
        .args(["gen", "--words", "5", "--pin", "4"])
        .assert()
        .code(2);
    prive()
        .args(["gen", "--length", "2"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("at least 4"));
}

#[test]
fn errors_go_to_stderr_with_a_prefix_and_nothing_to_stdout() {
    prive()
        .args(["gen", "--pin", "2"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with("prive: "));
}

#[test]
fn no_command_shows_help() {
    prive()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: prive"))
        .stderr(predicate::str::contains("gen"));
}
