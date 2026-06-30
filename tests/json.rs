//! The keys of every command's `--json` output, as `docs/json.md` lists them. Scripts rely on
//! these: a key may be added, never renamed or dropped without a major version.

use std::path::PathBuf;

use assert_cmd::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn json(args: &[&str]) -> serde_json::Value {
    let out = Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .env("PRIVE_CLIPBOARD_FILE", fixture("no-such-dir/clip"))
        .env_remove("PRIVE_DB")
        .env_remove("PRIVE_PASSWORD_FILE")
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .arg("--password-stdin")
        .args(args)
        .arg("--json")
        .write_stdin("fixture-pass\n")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: {e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn has(v: &serde_json::Value, keys: &[&str], what: &str) {
    for k in keys {
        assert!(v.get(*k).is_some(), "{what}: no '{k}' in {v}");
    }
}

const ENTRY: &[&str] = &[
    "path",
    "title",
    "group",
    "username",
    "url",
    "tags",
    "uuid",
    "has_otp",
    "modified",
    "expires",
    "attachments",
];

#[test]
fn listings() {
    for args in [&["ls"][..], &["search", "github"]] {
        let v = json(args);
        has(&v[0], ENTRY, &format!("{args:?}"));
        assert!(
            v[0].get("password").is_none(),
            "listings never carry a password"
        );
    }
}

#[test]
fn one_entry() {
    let v = json(&["show", "Work/GitHub"]);
    has(&v, ENTRY, "show");
    has(&v, &["password", "notes", "fields"], "show");
    has(
        &v["fields"][0],
        &["name", "value", "protected"],
        "show fields",
    );
}

#[test]
fn codes_and_history_and_tags() {
    has(
        &json(&["otp", "Bank"]),
        &["code", "seconds_left", "period"],
        "otp",
    );
    has(
        &json(&["codes"])[0],
        &["path", "code", "seconds_left", "period"],
        "codes",
    );
    has(
        &json(&["history", "Work/GitHub"])[0],
        &["saved", "username", "password_changed_after", "password"],
        "history",
    );
    has(&json(&["tags"])[0], &["tag", "entries"], "tags");
}

#[test]
fn reports() {
    let a = json(&["audit"]);
    has(&a, &["checked", "skipped", "findings", "database"], "audit");
    has(&a["findings"][0], &["path", "issues"], "audit findings");
    has(&a["findings"][0]["issues"][0], &["kind"], "audit issues");
    has(
        &json(&["info"]),
        &[
            "path",
            "size",
            "entries",
            "groups",
            "recycled",
            "name",
            "description",
            "format",
            "cipher",
            "inner_cipher",
            "compressed",
            "generator",
            "key_changed",
            "kdf",
        ],
        "info",
    );
    let conflict = fixture("conflict.kdbx");
    let d = json(&["diff", conflict.to_str().unwrap()]);
    has(&d, &["here", "there", "differences"], "diff");
    has(
        &d["differences"][0],
        &["kind", "path", "uuid"],
        "diff entries",
    );
    has(
        &json(&["doctor"])[0],
        &["name", "status", "detail"],
        "doctor",
    );
}

#[test]
fn export() {
    let out = Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .arg("--db")
        .arg(fixture("kdbx41.kdbx"))
        .args([
            "--password-stdin",
            "export",
            "--plaintext",
            "--format",
            "json",
        ])
        .write_stdin("fixture-pass\n")
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    has(
        &v[0],
        &[
            "path", "group", "title", "username", "password", "url", "notes", "otp", "tags",
            "fields", "uuid", "modified", "expires",
        ],
        "export",
    );
}

#[test]
fn status_config_and_gen() {
    has(
        &json(&["status"]),
        &["unlocked", "databases", "db", "name", "seconds_left"],
        "status",
    );
    has(
        &json(&["config"]),
        &[
            "config_file",
            "config_file_exists",
            "database",
            "database_from",
            "keyfile",
            "password_from",
            "clipboard_seconds",
            "agent_minutes",
            "agent_dir",
        ],
        "config",
    );
    has(&json(&["gen"]), &["value", "entropy_bits"], "gen");
}
