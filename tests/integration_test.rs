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

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim().chars().all(|c| c.is_ascii_digit()));
    assert_eq!(stdout.trim().len(), 6);
}

#[test]
fn test_generate_pronounceable() {
    let output = Command::cargo_bin("prive")
        .unwrap()
        .args(["generate", "--pronounceable", "--length", "10"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim().chars().all(|c| c.is_ascii_lowercase()));
    assert_eq!(stdout.trim().len(), 10);
}

#[test]
fn test_vault_init_no_tty() {
    // vault init requires a TTY for password input, so it should fail gracefully
    Command::cargo_bin("prive")
        .unwrap()
        .args(["vault", "init", "--vault-path", "/tmp/prive_test_nonexistent.pv"])
        .assert()
        .failure();
}

#[test]
fn test_pw_get_no_vault() {
    Command::cargo_bin("prive")
        .unwrap()
        .args(["pw", "get", "nonexistent", "--vault-path", "/tmp/prive_test_no_vault.pv"])
        .assert()
        .failure();
}
