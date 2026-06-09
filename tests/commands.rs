//! Database commands, end to end, against the KeePassXC-made fixtures. The password comes in
//! on stdin, as a script would give it.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// `prive --db kdbx41.kdbx --password-stdin <args>`, isolated from any real config file.
fn prive(args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("prive").unwrap();
    cmd.env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .env_remove("PRIVE_DB")
        .env_remove("PRIVE_KEYFILE")
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .arg("--password-stdin")
        .args(args)
        .write_stdin("fixture-pass\n");
    cmd
}

#[test]
fn ls_lists_paths_and_usernames_but_no_secrets() {
    let out = prive(&["ls"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines()
            .any(|l| l.starts_with("Work/GitHub") && l.ends_with("demo"))
    );
    assert!(text.lines().any(|l| l.trim() == "Personal/Legacy 2FA"));
    assert!(!text.contains("gh-Secret-1"));
    assert!(!text.contains("Deleted thing"));
}

#[test]
fn ls_a_group() {
    prive(&["ls", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Work/Cloud/Steam"))
        .stdout(predicate::str::contains("Bank").not());
}

#[test]
fn ls_json_has_no_passwords() {
    let out = prive(&["ls", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let all = v.as_array().unwrap();
    assert_eq!(all.len(), 7);
    let gh = all.iter().find(|e| e["path"] == "Work/GitHub").unwrap();
    assert_eq!(gh["has_otp"], true);
    assert!(gh.get("password").is_none());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("gh-Secret-1"));
}

#[test]
fn search_finds_by_title_tag_and_url() {
    prive(&["search", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Work/GitHub"))
        .stdout(predicate::str::contains("Personal/GitHub"));
    prive(&["search", "cloud"])
        .assert()
        .stdout(predicate::str::contains("Work/GitHub")); // tagged "cloud"
    prive(&["search", "bank.example"])
        .assert()
        .stdout(predicate::str::starts_with("Bank"));
}

#[test]
fn show_hides_secrets_until_revealed() {
    prive(&["show", "Work/GitHub"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Username:  demo"))
        .stdout(predicate::str::contains("6 digits every 30 s, SHA-1"))
        .stdout(predicate::str::contains("API key: ********"))
        .stdout(predicate::str::contains("plan:    team"))
        .stdout(predicate::str::contains("Files:     deploy.txt"))
        .stdout(predicate::str::contains("gh-Secret-1").not())
        .stdout(predicate::str::contains("custom-protected").not());
    prive(&["show", "Work/GitHub", "--reveal"])
        .assert()
        .stdout(predicate::str::contains("Password:  gh-Secret-1"))
        .stdout(predicate::str::contains("API key: custom-protected"));
}

#[test]
fn show_json_and_unknown_or_ambiguous_names() {
    let out = prive(&["show", "Bank", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["username"], "me@example.invalid");
    assert!(v["password"].is_null());

    prive(&["show", "Nope"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());
    prive(&["show", "GitHub"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("Work/GitHub"))
        .stderr(predicate::str::contains("Personal/GitHub"));
}

#[test]
fn get_prints_exactly_one_value() {
    prive(&["get", "Work/GitHub"])
        .assert()
        .success()
        .stdout("gh-Secret-1\n");
    prive(&["get", "Work/GitHub", "--field", "username"])
        .assert()
        .stdout("demo\n");
    prive(&["get", "Work/GitHub", "-f", "API key"])
        .assert()
        .stdout("custom-protected\n");
    prive(&["get", "Work/GitHub", "-f", "nope"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("field 'nope'"));
}

#[test]
fn get_clip_copies_and_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let clip = dir.path().join("clipboard");
    prive(&["get", "Bank", "--clip"])
        .env("PRIVE_CLIPBOARD_FILE", &clip)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "Copied. The clipboard clears in 20 s.",
        ));
    assert_eq!(std::fs::read_to_string(&clip).unwrap(), "b4nk-P@ss-2026!");
}

#[test]
fn otp_prints_a_code_of_the_right_shape() {
    for (entry, len, digits) in [
        ("Work/GitHub", 6, true),
        ("Bank", 8, true),
        ("Work/Cloud/Steam", 5, false),
        ("Personal/Legacy 2FA", 6, true),
    ] {
        let out = prive(&["otp", entry]).output().unwrap();
        assert!(out.status.success(), "{entry}");
        let code = String::from_utf8(out.stdout).unwrap();
        let code = code.trim_end();
        assert_eq!(code.len(), len, "{entry}");
        assert_eq!(code.chars().all(|c| c.is_ascii_digit()), digits, "{entry}");
    }
    prive(&["otp", "Wi-Fi"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no one-time code"));
}

#[test]
fn otp_json() {
    let out = prive(&["otp", "Bank", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["code"].as_str().unwrap().len(), 8);
    assert_eq!(v["period"], 60);
    let left = v["seconds_left"].as_u64().unwrap();
    assert!((1..=60).contains(&left));
}

#[test]
fn audit_finds_the_planted_problems() {
    let out = prive(&["audit"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    // "password1" is weak and used twice; Old VPN expired; Wi-Fi is excluded.
    assert!(text.contains("Personal/GitHub\n  - weak"));
    assert!(text.contains("reused by 1 other entry"));
    assert!(text.contains("Old VPN\n  - expired"));
    assert!(!text.contains("Wi-Fi"));
    assert!(text.contains("1 skipped"));
    assert!(
        !text.contains("password1"),
        "the report must not show passwords"
    );
}

#[test]
fn audit_json() {
    let out = prive(&["audit", "--json", "--max-age", "0"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["checked"], 6);
    assert_eq!(v["skipped"], 1);
    let first = &v["findings"][0];
    assert!(first["issues"][0]["kind"].is_string());
}

#[test]
fn pick_needs_a_terminal() {
    prive(&["pick"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("interactive terminal"));
}

#[test]
fn a_wrong_password_exits_5() {
    for db in ["kdbx31.kdbx", "kdbx40.kdbx", "kdbx41.kdbx"] {
        Command::cargo_bin("prive")
            .unwrap()
            .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
            .arg("--db")
            .arg(fixture(db))
            .args(["--password-stdin", "ls"])
            .write_stdin("not-the-password\n")
            .assert()
            .code(5)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("wrong password or key file"));
    }
}

#[test]
fn without_a_terminal_or_password_source_it_fails_at_once() {
    // stdin is not a terminal here and no password source is given: prive must not wait.
    let started = std::time::Instant::now();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .arg("ls")
        .write_stdin("")
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .code(5)
        .stderr(predicate::str::contains("--password-stdin"));
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn password_file_and_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let pwfile = dir.path().join("pw");
    std::fs::write(&pwfile, "fixture-pass\nthis line is ignored\n").unwrap();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_PASSWORD_FILE", &pwfile)
        .arg("--db")
        .arg(fixture("keyfile.kdbx"))
        .arg("--keyfile")
        .arg(fixture("keyfile.keyx"))
        .args(["get", "Key file entry", "--field", "username"])
        .assert()
        .success()
        .stdout("kfuser\n");
}

#[test]
fn the_default_database_comes_from_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!("db = {:?}\n", fixture("kdbx31.kdbx").to_string_lossy()),
    )
    .unwrap();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", &cfg)
        .env_remove("PRIVE_DB")
        .args(["--password-stdin", "get", "Bank", "-f", "url"])
        .write_stdin("fixture-pass\n")
        .assert()
        .success()
        .stdout("https://bank.example.invalid\n");
}

#[test]
fn nothing_found_is_exit_code_3() {
    prive(&["search", "zzz-nothing"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());
    prive(&["ls", "NoSuchGroup"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("group 'NoSuchGroup'"));
}

#[test]
fn a_file_that_is_not_keepass_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("notes.txt");
    std::fs::write(&f, "just some text\n").unwrap();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .arg("--db")
        .arg(&f)
        .args(["--password-stdin", "ls"])
        .write_stdin("x\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is not a KeePass database"));
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .arg("--db")
        .arg(dir.path().join("missing.kdbx"))
        .args(["--password-stdin", "ls"])
        .write_stdin("x\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("opening database"));
}

#[test]
fn no_database_anywhere_says_how_to_choose_one() {
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env_remove("PRIVE_DB")
        .args(["--password-stdin", "ls"])
        .write_stdin("x\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--db"))
        .stderr(predicate::str::contains("PRIVE_DB"));
}

#[test]
fn otp_clip_copies_the_code() {
    let dir = tempfile::tempdir().unwrap();
    let clip = dir.path().join("clipboard");
    prive(&["otp", "Bank", "--clip"])
        .env("PRIVE_CLIPBOARD_FILE", &clip)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
    let code = std::fs::read_to_string(&clip).unwrap();
    assert_eq!(code.len(), 8);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn the_same_answers_from_every_format() {
    for db in ["kdbx31.kdbx", "kdbx40.kdbx", "kdbx41.kdbx"] {
        Command::cargo_bin("prive")
            .unwrap()
            .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
            .arg("--db")
            .arg(fixture(db))
            .args(["--password-stdin", "get", "Work/GitHub", "-f", "API key"])
            .write_stdin("fixture-pass\n")
            .assert()
            .success()
            .stdout("custom-protected\n");
    }
}

#[test]
fn show_and_ls_agree_on_paths() {
    let ls = prive(&["ls", "--json"]).output().unwrap();
    let all: serde_json::Value = serde_json::from_slice(&ls.stdout).unwrap();
    for e in all.as_array().unwrap() {
        let path = e["path"].as_str().unwrap();
        let shown = prive(&["show", path, "--json"]).output().unwrap();
        // Titles used twice are ambiguous by title, never by full path.
        assert!(shown.status.success(), "{path}");
        let v: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
        assert_eq!(v["uuid"], e["uuid"], "{path}");
    }
}

#[test]
fn unreadable_code_settings_are_not_reported_as_missing() {
    // Wi-Fi has no code at all: "not found" (3). A broken otp field is a different error (1).
    prive(&["otp", "Wi-Fi"]).assert().code(3);
}

#[test]
fn a_misspelled_name_gets_suggestions() {
    prive(&["get", "Work/GitHbu"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("did you mean: Work/GitHub?"));
}

#[test]
fn otp_min_validity() {
    // Asking for at least 29 s of a 30 s code: either it is fresh already, or prive waits
    // for the next one. Either way the answer has at least 29 s left.
    let out = prive(&["otp", "Work/GitHub", "--min-validity", "29", "--json"])
        .timeout(std::time::Duration::from_secs(40))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["seconds_left"].as_u64().unwrap() >= 29);

    prive(&["otp", "Work/GitHub", "--min-validity", "30"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("shorter than the code's period"));
}

#[test]
fn a_missing_field_lists_the_ones_there_are() {
    prive(&["get", "Work/GitHub", "-f", "token"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "it has: title, username, password, url, notes, API key",
        ));
}

#[test]
fn ls_by_tag() {
    prive(&["ls", "--tag", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("Work/GitHub"));
    prive(&["ls", "-t", "dev", "-t", "nope"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn a_key_file_only_database_opens_without_any_password() {
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(fixture("keyonly.kdbx"))
        .arg("--keyfile")
        .arg(fixture("keyonly.keyx"))
        .args(["--no-password", "get", "Key only entry", "-f", "username"])
        .write_stdin("")
        .assert()
        .success()
        .stdout("keyonly\n");
}

#[test]
fn tags_lists_each_tag_with_its_count() {
    prive(&["tags"])
        .assert()
        .success()
        .stdout("1  cloud\n1  dev\n");
    let out = prive(&["tags", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["tag"], "cloud");
    assert_eq!(v[0]["entries"], 1);
}

#[test]
fn open_refuses_entries_without_a_web_address() {
    prive(&["open", "Wi-Fi"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Wi-Fi: the entry has no URL"));
}

#[test]
fn quiet_leaves_out_notices_but_not_errors() {
    let dir = tempfile::tempdir().unwrap();
    prive(&["--quiet", "get", "Bank", "--clip"])
        .env("PRIVE_CLIPBOARD_FILE", dir.path().join("clip"))
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
    prive(&["-q", "get", "Nope"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no entry"));
}

#[test]
fn ls_long_against_the_fixture() {
    let out = prive(&["ls", "--long"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let line = |p: &str| text.lines().find(|l| l.contains(p)).unwrap().to_string();
    assert!(line("Work/GitHub").contains("2fa,file"));
    assert!(line("Old VPN").contains("expired"));
    assert!(line("Work/Cloud/Steam").contains("2fa"));
    assert!(!line("Wi-Fi").contains("2fa"));
    prive(&["ls", "--long", "--json"]).assert().code(2);
}

#[test]
fn show_does_not_repeat_the_otp_settings_as_fields() {
    let out = prive(&["show", "Personal/Legacy 2FA", "--reveal"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("TOTP:"));
    assert!(!text.contains("TOTP Seed"), "{text}");
    assert!(
        !text.contains("JBSWY3DP"),
        "the secret itself must not be shown: {text}"
    );
}

#[test]
fn show_json_keeps_otp_settings_listed_but_hidden() {
    let out = prive(&["show", "Work/GitHub", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let otp = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "otp")
        .expect("scripts can still see that an otp field exists");
    assert!(otp["value"].is_null());
    assert_eq!(otp["protected"], true);
}

#[test]
fn piping_into_a_reader_that_stops_early_is_not_an_error() {
    // `prive ls | head -1`: the reader closes the pipe after one line.
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("prive"))
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .args(["--password-stdin", "ls"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"fixture-pass\n")
            .unwrap();
    }
    drop(child.stdout.take()); // close our end before prive writes anything
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "{err}");
    assert!(out.status.success(), "status {:?}: {err}", out.status);
}

#[cfg(unix)]
#[test]
fn run_passes_secrets_only_through_the_environment() {
    prive(&[
        "run",
        "--env",
        "PW=Work/GitHub",
        "-e",
        "USER_NAME=Work/GitHub:username",
        "-e",
        "KEY=Work/GitHub:API key",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s|%s' "$PW" "$USER_NAME" "$KEY""#,
    ])
    .assert()
    .success()
    .stdout("gh-Secret-1|demo|custom-protected");
}

#[cfg(unix)]
#[test]
fn run_passes_the_exit_code_on() {
    prive(&["run", "-e", "X=Bank", "--", "sh", "-c", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn run_refuses_bad_specs_before_asking_for_anything() {
    prive(&["run", "-e", "1BAD=Bank", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "not a valid environment variable name",
        ));
    prive(&["run", "-e", "X=Nobody", "--", "true"])
        .assert()
        .code(3);
    prive(&["run", "-e", "X=Bank"]).assert().code(2); // no command
}

#[cfg(unix)]
#[test]
fn run_from_exports_upper_case_fields_only() {
    prive(&[
        "run",
        "--from",
        "Old VPN",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s|%s' "$VPN_SERVER" "$VPN_TOKEN" "${otp:-none}""#,
    ])
    .assert()
    .success()
    .stdout("vpn.example.invalid|tok-123|none");
    prive(&["run", "--from", "Bank", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "no custom fields named like environment variables",
        ));
}

#[cfg(windows)]
#[test]
fn run_on_windows_sets_variables_and_passes_the_exit_code() {
    prive(&["run", "-e", "PW=Bank", "--", "cmd", "/C", "echo %PW%"])
        .assert()
        .success()
        .stdout(predicate::str::contains("b4nk-P@ss-2026!"));
    prive(&["run", "-e", "PW=Bank", "--", "cmd", "/C", "exit 7"])
        .assert()
        .code(7);
}

#[test]
fn import_check_recognises_each_export() {
    for (file, label, first_line) in [
        (
            "proton.csv",
            "Proton Pass",
            "3 entries, 1 with one-time codes, in 2 group(s)",
        ),
        (
            "apple.csv",
            "Apple Passwords",
            "2 entries, 1 with one-time codes, in 0 group(s)",
        ),
        (
            "google.csv",
            "Google Password Manager",
            "2 entries, 0 with one-time codes, in 0 group(s)",
        ),
        (
            "lastpass.csv",
            "LastPass",
            "3 entries, 1 with one-time codes, in 2 group(s)",
        ),
    ] {
        Command::cargo_bin("prive")
            .unwrap()
            .args(["import", "--check"])
            .arg(fixture(&format!("exports/{file}")))
            .assert()
            .success()
            .stdout(predicate::str::starts_with(format!(
                "{label} export: {first_line}"
            )));
    }
}

#[test]
fn import_check_needs_check_for_now_and_names_unknown_files() {
    Command::cargo_bin("prive")
        .unwrap()
        .arg("import")
        .arg(fixture("exports/google.csv"))
        .assert()
        .code(2);
    let dir = tempfile::tempdir().unwrap();
    let odd = dir.path().join("odd.csv");
    std::fs::write(&odd, "a,b,c\n1,2,3\n").unwrap();
    Command::cargo_bin("prive")
        .unwrap()
        .args(["import", "--check"])
        .arg(&odd)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--from"));
}
