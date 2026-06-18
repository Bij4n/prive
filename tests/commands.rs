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
        .stdout(predicate::str::contains("Files:     deploy.txt (17 B)"))
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
        .stderr(predicate::str::contains("Work/GitHub: no field 'nope'"))
        .stderr(predicate::str::contains("no entry matches").not());
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
    // Steam codes come from 26 letters and digits; now and then one is all digits.
    const STEAM: &str = "23456789BCDFGHJKMNPQRTVWXY";
    for (entry, len, alphabet) in [
        ("Work/GitHub", 6, "0123456789"),
        ("Bank", 8, "0123456789"),
        ("Work/Cloud/Steam", 5, STEAM),
        ("Personal/Legacy 2FA", 6, "0123456789"),
    ] {
        let out = prive(&["otp", entry]).output().unwrap();
        assert!(out.status.success(), "{entry}");
        let code = String::from_utf8(out.stdout).unwrap();
        let code = code.trim_end();
        assert_eq!(code.len(), len, "{entry}");
        assert!(
            code.chars().all(|c| alphabet.contains(c)),
            "{entry}: {code}"
        );
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

#[test]
fn import_check_generic_csv() {
    Command::cargo_bin("prive")
        .unwrap()
        .args(["import", "--check"])
        .arg(fixture("exports/bitwarden.csv"))
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "CSV export: 2 entries, 1 with one-time codes, in 1 group(s)",
        ))
        .stdout(predicate::str::contains("username <- login_username"));
    Command::cargo_bin("prive")
        .unwrap()
        .args([
            "import",
            "--check",
            "--map",
            "title=Site",
            "--map",
            "username=Who",
            "--map",
            "password=Secret",
        ])
        .arg(fixture("exports/custom.csv"))
        .assert()
        .success()
        .stdout(predicate::str::contains("2 entries"))
        .stdout(predicate::str::contains("title <- Site"));
    Command::cargo_bin("prive")
        .unwrap()
        .args([
            "import",
            "--check",
            "--from",
            "google",
            "--map",
            "title=Site",
        ])
        .arg(fixture("exports/custom.csv"))
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "--map only applies with --from csv",
        ));
}

#[test]
fn file_lists_and_writes_attachments() {
    prive(&["file", "Work/GitHub"])
        .assert()
        .success()
        .stdout("deploy.txt\t17\n");
    prive(&["file", "Work/GitHub", "deploy.txt"])
        .assert()
        .success()
        .stdout("deploy-key-bytes\n");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("key");
    prive(&[
        "file",
        "Work/GitHub",
        "deploy.txt",
        "--out",
        out.to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::is_empty());
    assert_eq!(std::fs::read(&out).unwrap(), b"deploy-key-bytes\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Never over an existing file.
    prive(&[
        "file",
        "Work/GitHub",
        "deploy.txt",
        "--out",
        out.to_str().unwrap(),
    ])
    .assert()
    .code(1)
    .stderr(predicate::str::contains("already exists"));
    prive(&["file", "Work/GitHub", "nope"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("it has: deploy.txt"));
}

#[test]
fn codes_lists_every_entry_with_a_code() {
    let out = prive(&["codes", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let paths: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "Bank",
            "Personal/Legacy 2FA",
            "Work/Cloud/Steam",
            "Work/GitHub"
        ]
    );
    prive(&["codes", "steam"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("Work/Cloud/Steam  "));
    prive(&["codes", "zzz"]).assert().code(3);
}

#[test]
fn search_all_reaches_notes_but_not_passwords() {
    prive(&["search", "ünïcödé"]).assert().code(3);
    prive(&["search", "--all", "ünïcödé"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("Work/GitHub"));
    prive(&["search", "--all", "gh-Secret-1"]).assert().code(3);
}

#[test]
fn history_shows_when_and_whether_the_password_changed() {
    let out = prive(&["history", "Work/GitHub"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.lines().next().unwrap().ends_with("  now"));
    assert!(text.contains("password changed after this"));
    assert!(!text.contains("old-password"));
    prive(&["history", "Work/GitHub", "--reveal"])
        .assert()
        .stdout(predicate::str::contains(": old-password"));
    prive(&["history", "Bank"])
        .assert()
        .stdout("Bank has no earlier versions\n");
}

#[test]
fn history_json_hides_old_passwords_unless_revealed() {
    let out = prive(&["history", "Work/GitHub", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["password_changed_after"], true);
    assert!(v[0]["password"].is_null());
    let out = prive(&["history", "Work/GitHub", "--json", "--reveal"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["password"], "old-password");
}

#[test]
fn every_command_with_json_prints_valid_json() {
    for args in [
        &["ls", "--json"][..],
        &["search", "github", "--json"],
        &["show", "Bank", "--json"],
        &["otp", "Bank", "--json"],
        &["audit", "--json"],
        &["tags", "--json"],
        &["codes", "--json"],
        &["history", "Work/GitHub", "--json"],
    ] {
        let out = prive(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}"));
    }
}

/// The real thing: `git credential fill` with prive as the helper.
#[test]
fn git_gets_its_password_from_prive() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("git not installed; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pwfile = dir.path().join("pw");
    std::fs::write(&pwfile, "fixture-pass\n").unwrap();
    let prive_bin = assert_cmd::cargo::cargo_bin("prive");
    let helper = format!(
        "!'{}' --db '{}' --no-agent git-credential",
        prive_bin.display(),
        fixture("kdbx41.kdbx").display()
    );
    let mut git = std::process::Command::new("git")
        .args([
            "-c",
            "credential.helper=",
            "-c",
            &format!("credential.helper={helper}"),
        ])
        .args(["credential", "fill"])
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_PASSWORD_FILE", &pwfile)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        git.stdin
            .take()
            .unwrap()
            .write_all(b"protocol=https\nhost=github.com\n\n")
            .unwrap();
    }
    let out = git.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("username=demo"),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("password=gh-Secret-1"), "{text}");
}

#[test]
fn git_credential_store_and_erase_change_nothing() {
    for action in ["store", "erase"] {
        prive(&["git-credential", action])
            .write_stdin("protocol=https\nhost=github.com\nusername=x\npassword=y\n\n")
            .assert()
            .success()
            .stdout(predicate::str::is_empty());
    }
}

#[test]
fn otp_uri_and_qr() {
    let out = prive(&["otp", "Personal/Legacy 2FA", "--uri"])
        .output()
        .unwrap();
    let uri = String::from_utf8(out.stdout).unwrap();
    assert!(
        uri.starts_with("otpauth://totp/Legacy%202FA?secret=JBSWY3DPEHPK3PXP&period=30&digits=6"),
        "{uri}"
    );
    let out = prive(&["otp", "Work/GitHub", "--qr"]).output().unwrap();
    assert!(out.status.success());
    let qr = String::from_utf8(out.stdout).unwrap();
    assert!(qr.lines().count() > 10 && qr.contains('█'));
    prive(&["otp", "Bank", "--qr", "--json"]).assert().code(2);
}

#[test]
fn field_references_are_resolved_wherever_a_value_is_used() {
    prive(&["get", "Old VPN", "-f", "BANK_PASSWORD"])
        .assert()
        .success()
        .stdout("b4nk-P@ss-2026!\n");
    #[cfg(unix)]
    prive(&[
        "run",
        "--from",
        "Old VPN",
        "--",
        "sh",
        "-c",
        r#"printf %s "$BANK_PASSWORD""#,
    ])
    .assert()
    .stdout("b4nk-P@ss-2026!");
    prive(&["run", "-e", "X=Old VPN:BANK_PASSWORD", "--", "true"])
        .assert()
        .success();
}

#[test]
fn show_reveal_resolves_references() {
    prive(&["show", "Old VPN", "--reveal"])
        .assert()
        .stdout(predicate::str::contains("BANK_PASSWORD: b4nk-P@ss-2026!"))
        .stdout(predicate::str::contains("{REF:").not());
}

#[test]
fn config_shows_what_is_in_effect() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, "db = \"/srv/p.kdbx\"\nclipboard_seconds = 9\n").unwrap();
    let out = Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", &cfg)
        .env_remove("PRIVE_DB")
        .args(["config", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["database"], "/srv/p.kdbx");
    assert_eq!(v["database_from"], "config file");
    assert_eq!(v["clipboard_seconds"], 9);
    assert_eq!(v["agent_minutes"], 15);
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", &cfg)
        .args(["--db", "/tmp/other.kdbx", "config"])
        .assert()
        .stdout(predicate::str::contains(
            "database:          /tmp/other.kdbx (--db)",
        ));
}

#[test]
fn otp_next_is_the_following_period() {
    let out = prive(&["otp", "Bank", "--next", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let left = v["seconds_left"].as_u64().unwrap();
    assert!((61..=120).contains(&left), "{left}");
    assert_eq!(v["code"].as_str().unwrap().len(), 8);
}

#[test]
fn audit_expiring_on_the_fixture() {
    // Old VPN expired in 2025: always "expired", never "expires in".
    prive(&["audit", "--expiring", "36500"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Old VPN\n  - expired"))
        .stdout(predicate::str::contains("expires in").not());
}

#[test]
fn ls_json_has_dates_and_attachment_counts() {
    let out = prive(&["ls", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let gh = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "Work/GitHub")
        .unwrap();
    assert_eq!(gh["attachments"], 1);
    assert!(gh["modified"].as_str().unwrap().len() == 19);
    let vpn = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "Old VPN")
        .unwrap();
    assert_eq!(vpn["expires"], "2025-01-01T00:00:00");
}

#[test]
fn ls_paths_prints_only_paths() {
    let out = prive(&["ls", "--paths", "Work"]).output().unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "Work/Cloud/Steam\nWork/GitHub\n"
    );
}

#[test]
fn info_describes_the_file() {
    prive(&["info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Format:       KDBX 4.1"))
        .stdout(predicate::str::contains(
            "Key:          AES-KDF, 1000000 rounds",
        ))
        .stdout(predicate::str::contains(
            "Contents:     7 entries in 3 groups, 1 in the recycle bin",
        ))
        .stdout(predicate::str::contains("Key changed:  2026-05-26"));
}

#[test]
fn info_json() {
    let out = prive(&["info", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["format"], "KDBX 4.1");
    assert_eq!(v["entries"], 7);
    assert_eq!(v["kdf"]["algorithm"], "AES-KDF");
    assert!(v["size"].as_u64().unwrap() > 0);
    assert!(v["path"].as_str().unwrap().ends_with("kdbx41.kdbx"));
}

#[test]
fn audit_reports_the_database_settings_first() {
    let out = prive(&["audit"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("This database\n  - the key is derived with AES-KDF"));
    let out = prive(&["audit", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["database"][0]["kind"], "aes_kdf");
    assert_eq!(v["database"][0]["rounds"], 1_000_000);
}

#[test]
fn get_format_fills_a_template() {
    prive(&[
        "get",
        "Work/GitHub",
        "--format",
        "{USERNAME}:{PASSWORD} {S:plan}",
    ])
    .assert()
    .success()
    .stdout("demo:gh-Secret-1 team\n");
    // Old VPN's BANK_PASSWORD refers to Bank's password.
    prive(&[
        "get",
        "Old VPN",
        "--format",
        r#"{"pw":"{S:BANK_PASSWORD}"}"#,
    ])
    .assert()
    .success()
    .stdout("{\"pw\":\"b4nk-P@ss-2026!\"}\n");
    prive(&["get", "Bank", "--format", "{TOTP}"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{8}\n$").unwrap());
}

#[test]
fn get_format_with_a_missing_field_exits_3() {
    prive(&["get", "Bank", "--format", "{S:nope}"])
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty());
}

/// A config file naming the fixtures, for `--db NAME`.
fn named_config(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(
        &p,
        format!(
            "[databases.main]\npath = {:?}\n[databases.keys]\npath = {:?}\nkeyfile = {:?}\n",
            fixture("kdbx41.kdbx"),
            fixture("keyfile.kdbx"),
            fixture("keyfile.keyx"),
        ),
    )
    .unwrap();
    p
}

fn prive_named(config: &std::path::Path, db: &str, args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("prive").unwrap();
    cmd.env("PRIVE_CONFIG", config)
        .env("PRIVE_NO_AGENT", "1")
        .env_remove("PRIVE_DB")
        .env_remove("PRIVE_KEYFILE")
        .env_remove("PRIVE_PASSWORD_FILE")
        .args(["--db", db, "--password-stdin"])
        .args(args)
        .write_stdin("fixture-pass\n");
    cmd
}

#[test]
fn databases_by_name_with_their_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = named_config(dir.path());
    prive_named(&cfg, "main", &["get", "Bank", "-f", "username"])
        .assert()
        .success()
        .stdout("me@example.invalid\n");
    // The key file comes from [databases.keys], not the command line.
    prive_named(&cfg, "keys", &["ls", "--paths"])
        .assert()
        .success()
        .stdout("Key file entry\n");
    prive_named(&cfg, "mian", &["ls"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("the config file names keys, main"));
}

#[test]
fn config_shows_the_named_databases() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = named_config(dir.path());
    prive_named(&cfg, "keys", &["config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(--db, [databases.keys])"))
        .stdout(predicate::str::contains("keyfile.keyx"))
        .stdout(predicate::str::contains("named databases:   keys"));
    let out = prive_named(&cfg, "main", &["config", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["database"].as_str().unwrap().ends_with("kdbx41.kdbx"));
    assert!(v["databases"]["keys"]["keyfile"].is_string());
    assert_eq!(v["password_from"], "asked for when needed");
}

#[test]
fn diff_against_a_conflict_copy() {
    let conflict = fixture("conflict.kdbx");
    prive(&["diff", conflict.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            "Only in conflict.kdbx:\n  Conference Wi-Fi\n\
             Changed:\n  Bank: password (newer in conflict.kdbx)\n  \
             Personal/Legacy 2FA -> Personal/Legacy 2FA (old): title\n",
        )
        // Names of fields only: no password, old or new, is ever shown.
        .stdout(predicate::str::contains("b4nk").not());
}

#[test]
fn diff_json_and_the_same_file() {
    let conflict = fixture("conflict.kdbx");
    let out = prive(&["diff", conflict.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let d = v["differences"].as_array().unwrap();
    assert_eq!(d.len(), 3);
    assert_eq!(d[0]["kind"], "only_there");
    assert_eq!(d[1]["fields"][0], "password");
    assert_eq!(d[1]["newer"], "there");
    let same = fixture("kdbx41.kdbx");
    prive(&["diff", same.to_str().unwrap()])
        .assert()
        .success()
        .stdout("kdbx41.kdbx and kdbx41.kdbx hold the same entries\n");
}

#[test]
fn diff_with_another_password_and_no_terminal_exits_5() {
    // keyfile.kdbx needs a key file the main database doesn't use.
    let other = fixture("keyfile.kdbx");
    prive(&["diff", other.to_str().unwrap()])
        .assert()
        .code(5)
        .stdout(predicate::str::is_empty());
    let key = fixture("keyfile.keyx");
    prive(&[
        "diff",
        other.to_str().unwrap(),
        "--other-keyfile",
        key.to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains(
        "Only in keyfile.kdbx:\n  Key file entry\n",
    ));
}

fn doctor(db: &std::path::Path, extra: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("prive").unwrap();
    cmd.env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .env("PRIVE_CLIPBOARD_FILE", fixture("no-such-dir/clipboard"))
        .env_remove("PRIVE_DB")
        .env_remove("PRIVE_KEYFILE")
        .arg("--db")
        .arg(db)
        .args(extra)
        .arg("doctor")
        .write_stdin("");
    cmd
}

#[test]
fn doctor_on_a_good_setup_asks_for_nothing() {
    doctor(&fixture("kdbx41.kdbx"), &[])
        .assert()
        .success()
        .stdout(predicate::str::contains("ok    database"))
        .stdout(predicate::str::contains("KDBX 4.1"))
        .stdout(predicate::str::contains("--    key file     none"))
        .stderr(predicate::str::contains("Password").not());
}

#[test]
fn doctor_fails_on_a_missing_database_or_key_file() {
    doctor(&fixture("nope.kdbx"), &[])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL  database"))
        .stderr(predicate::str::contains("1 check failed"));
    let missing_key = fixture("nope.keyx");
    doctor(
        &fixture("keyfile.kdbx"),
        &["--keyfile", missing_key.to_str().unwrap()],
    )
    .assert()
    .code(1)
    .stdout(predicate::str::contains("FAIL  key file"));
}

#[test]
fn doctor_json() {
    let out = doctor(&fixture("kdbx31.kdbx"), &["--quiet"])
        .arg("--json")
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "config file",
            "database",
            "key file",
            "password",
            "sync",
            "agent",
            "clipboard"
        ]
    );
    assert_eq!(v[1]["status"], "ok");
}

#[test]
fn doctor_with_a_broken_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(&cfg, "agent_minutes = 0\n").unwrap();
    Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", &cfg)
        .env("PRIVE_NO_AGENT", "1")
        .env("PRIVE_CLIPBOARD_FILE", dir.path().join("clip"))
        .env_remove("PRIVE_DB")
        .arg("doctor")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL  config file"))
        .stdout(predicate::str::contains("agent_minutes"))
        .stdout(predicate::str::contains(
            "--    database     the config file needs fixing first",
        ));
}

#[test]
fn doctor_points_at_conflict_copies() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Passwords.kdbx");
    std::fs::copy(fixture("kdbx41.kdbx"), &db).unwrap();
    std::fs::copy(
        fixture("conflict.kdbx"),
        dir.path()
            .join("Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx"),
    )
    .unwrap();
    doctor(&db, &[])
        .assert()
        .success()
        .stdout(predicate::str::contains("warn  sync"))
        .stdout(predicate::str::contains("prive diff '"))
        .stdout(predicate::str::contains("Passwords.sync-conflict-20260612"));
}

#[cfg(unix)]
#[test]
fn a_password_command_in_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "db = {:?}\npassword_command = [\"printf\", \"%s\\\\n\", \"fixture-pass\"]\n",
            fixture("kdbx41.kdbx")
        ),
    )
    .unwrap();
    let run = |env_file: Option<&std::path::Path>| {
        let mut c = Command::cargo_bin("prive").unwrap();
        c.env("PRIVE_CONFIG", &cfg)
            .env("PRIVE_NO_AGENT", "1")
            .env_remove("PRIVE_DB")
            .env_remove("PRIVE_PASSWORD_FILE")
            .args(["get", "Bank", "-f", "username"])
            .write_stdin("");
        if let Some(f) = env_file {
            c.env("PRIVE_PASSWORD_FILE", f);
        }
        c
    };
    // No stdin, no terminal: the command gives the password.
    run(None).assert().success().stdout("me@example.invalid\n");
    // PRIVE_PASSWORD_FILE comes first.
    let wrong = dir.path().join("wrong");
    std::fs::write(&wrong, "not-it\n").unwrap();
    run(Some(&wrong)).assert().code(5);
}
