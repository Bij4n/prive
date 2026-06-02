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

#[test]
fn gen_json() {
    let out = prive()
        .args(["gen", "--json", "--pin", "8"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["value"].as_str().unwrap().len(), 8);
    assert!(v["entropy_bits"].as_f64().unwrap() > 26.0);
}

#[test]
fn help_documents_the_exit_codes() {
    prive()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("3 not found"))
        .stdout(predicate::str::contains("4 ambiguous entry"));
}

#[test]
fn gen_cannot_both_copy_and_print_json() {
    prive().args(["gen", "--clip", "--json"]).assert().code(2);
}

#[test]
fn completions_for_each_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = prive().args(["completions", shell]).output().unwrap();
        assert!(out.status.success(), "{shell}");
        let text = String::from_utf8(out.stdout).unwrap();
        for command in [
            "gen", "ls", "show", "get", "otp", "open", "pick", "audit", "tags",
        ] {
            assert!(
                text.contains(command),
                "{shell} completions should know the {command} command"
            );
        }
        assert!(
            !text.contains("__clip"),
            "{shell} completions must not offer the helper"
        );
    }
}

#[test]
fn gen_without_look_alikes_or_symbols() {
    let out = prive()
        .args([
            "gen",
            "--length",
            "200",
            "--avoid-ambiguous",
            "--no-symbols",
        ])
        .output()
        .unwrap();
    let pw = String::from_utf8(out.stdout).unwrap();
    let pw = pw.trim_end();
    assert_eq!(pw.chars().count(), 200);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(!pw.chars().any(|c| "0O1lI".contains(c)));
}
