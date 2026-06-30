//! Cross-checks against KeePassXC's own command-line tool. Skipped (with a note) when
//! `keepassxc-cli` isn't installed; CI installs it on Linux.

use std::path::Path;
use std::process::Command;

use prive::otp::parse_otpauth;

const PASSWORD: &str = "fixture-pass";

fn keepassxc(args: &[&str]) -> Option<String> {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write;
    writeln!(child.stdin.take()?, "{PASSWORD}").ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn available() -> bool {
    let ok = Command::new("keepassxc-cli")
        .arg("--version")
        .output()
        .is_ok();
    if !ok {
        eprintln!("keepassxc-cli not installed; skipping interop checks");
    }
    ok
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// Compare a code KeePassXC computes with ours for the same secret. Codes change at period
/// boundaries, so a mismatch right at a boundary is retried once.
fn same_code_as_keepassxc(entry: &str, uri: &str) {
    let ours = parse_otpauth(uri).expect("fixture uri parses");
    for _ in 0..2 {
        let before = prive::otp::unix_now();
        let theirs = keepassxc(&["show", "-q", "-t", &fixture("kdbx41.kdbx"), entry]).unwrap();
        let after = prive::otp::unix_now();
        if ours.code_at(before) == ours.code_at(after) {
            assert_eq!(theirs, ours.code_at(before), "{entry}");
            return;
        }
    }
    panic!("{entry}: kept crossing a period boundary");
}

#[test]
fn totp_codes_match_keepassxc() {
    if !available() {
        return;
    }
    same_code_as_keepassxc(
        "Work/GitHub",
        "otpauth://totp/GitHub:demo?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1",
    );
    same_code_as_keepassxc(
        "Bank",
        "otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60&digits=8&algorithm=SHA256",
    );
}

#[test]
fn steam_codes_match_keepassxc() {
    if !available() {
        return;
    }
    same_code_as_keepassxc(
        "Work/Cloud/Steam",
        "otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&period=30&digits=5&issuer=Steam&encoder=steam",
    );
}

/// The fixtures are the formats their names promise (checked from the header, so this runs
/// without keepassxc-cli too).
#[test]
fn fixtures_are_the_formats_they_claim() {
    for (name, major, minor) in [
        ("kdbx31.kdbx", 3u16, 1u16),
        ("kdbx40.kdbx", 4, 0),
        ("kdbx41.kdbx", 4, 1),
        ("keyfile.kdbx", 3, 1),
    ] {
        let head = std::fs::read(fixture(name)).unwrap();
        assert_eq!(
            &head[..4],
            &[0x03, 0xd9, 0xa2, 0x9a],
            "{name}: not a KeePass file"
        );
        let minor_found = u16::from_le_bytes([head[8], head[9]]);
        let major_found = u16::from_le_bytes([head[10], head[11]]);
        assert_eq!((major_found, minor_found), (major, minor), "{name}");
    }
}

#[test]
fn keepassxc_reads_the_fixtures_we_test_against() {
    if !available() {
        return;
    }
    let listing = keepassxc(&["ls", "-q", "-R", "-f", &fixture("kdbx41.kdbx")]).unwrap();
    for path in [
        "Bank",
        "Work/GitHub",
        "Work/Cloud/Steam",
        "Personal/GitHub",
        "Personal/Legacy 2FA",
    ] {
        assert!(
            listing.lines().any(|l| l.trim() == path),
            "{path} missing:\n{listing}"
        );
    }
    let kf = keepassxc(&[
        "ls",
        "-q",
        "-k",
        &fixture("keyfile.keyx"),
        &fixture("keyfile.kdbx"),
    ])
    .unwrap();
    assert!(kf.contains("Key file entry"));
}

/// `prive ls --paths` lists the same entries as `keepassxc-cli ls -R -f`, in every format,
/// once KeePassXC's group lines and recycle bin are set aside.
#[test]
fn listings_match_keepassxc() {
    if !available() {
        return;
    }
    for f in ["kdbx31.kdbx", "kdbx40.kdbx", "kdbx41.kdbx"] {
        let ours = assert_cmd::Command::cargo_bin("prive")
            .unwrap()
            .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
            .env("PRIVE_NO_AGENT", "1")
            .args(["--db", &fixture(f), "--password-stdin", "ls", "--paths"])
            .write_stdin(format!("{PASSWORD}\n"))
            .output()
            .unwrap();
        assert!(ours.status.success(), "{f}");
        let mut ours: Vec<String> = String::from_utf8_lossy(&ours.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        let theirs = keepassxc(&["ls", "-q", "-R", "-f", &fixture(f)]).unwrap();
        let mut theirs: Vec<String> = theirs
            .lines()
            .map(str::trim)
            .filter(|l| !l.ends_with('/') && !l.starts_with("Recycle Bin/"))
            .map(str::to_string)
            .collect();
        ours.sort();
        theirs.sort();
        assert_eq!(ours, theirs, "{f}");
    }
}

/// `prive info` and `keepassxc-cli db-info` describe each fixture the same way.
#[test]
fn info_matches_keepassxc() {
    if !available() {
        return;
    }
    for f in ["kdbx31.kdbx", "kdbx40.kdbx", "kdbx41.kdbx"] {
        let ours = assert_cmd::Command::cargo_bin("prive")
            .unwrap()
            .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
            .env("PRIVE_NO_AGENT", "1")
            .args(["--db", &fixture(f), "--password-stdin", "info", "--json"])
            .write_stdin(format!("{PASSWORD}\n"))
            .output()
            .unwrap();
        let ours: serde_json::Value = serde_json::from_slice(&ours.stdout).unwrap();
        let theirs = keepassxc(&["db-info", "-q", &fixture(f)]).unwrap();
        let value = |label: &str| -> String {
            theirs
                .lines()
                .find_map(|l| l.strip_prefix(label))
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        assert_eq!(value("Name:"), ours["name"], "{f}");
        assert_eq!(
            value("Number of entries:"),
            ours["entries"].to_string(),
            "{f}"
        );
        // KeePassXC counts the root group and the recycle bin; prive counts neither.
        assert_eq!(
            value("Number of groups:"),
            (ours["groups"].as_u64().unwrap() + 2).to_string(),
            "{f}"
        );
        assert_eq!(
            value("KDF:"),
            format!("AES ({} rounds)", ours["kdf"]["iterations"]),
            "{f}"
        );
        assert_eq!(value("Cipher:"), "AES 256-bit", "{f}");
        assert_eq!(ours["cipher"], "AES-256", "{f}");
    }
}

/// `prive diff` finds what `keepassxc-cli merge --dry-run` would act on, entry for entry:
/// one to create, one newer in the other copy, one changed on both sides at once.
#[test]
fn diff_agrees_with_a_keepassxc_merge_dry_run() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let here = dir.path().join("here.kdbx");
    std::fs::copy(fixture("kdbx41.kdbx"), &here).unwrap();
    let merge = Command::new("keepassxc-cli")
        .args(["merge", "-s", "--dry-run"])
        .arg(&here)
        .arg(fixture("conflict.kdbx"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        writeln!(merge.stdin.as_ref().unwrap(), "{PASSWORD}").unwrap();
    }
    let out = merge.wait_with_output().unwrap();
    let theirs = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Each line KeePassXC prints names the entry's UUID in brackets.
    let uuid_on = |needle: &str| -> Vec<String> {
        theirs
            .lines()
            .filter(|l| l.contains(needle))
            .filter_map(|l| {
                let (_, rest) = l.rsplit_once('[')?;
                let (uuid, _) = rest.split_once(']')?;
                Some(uuid.to_lowercase())
            })
            .collect()
    };
    let ours = assert_cmd::Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .arg("--db")
        .arg(&here)
        .args(["--password-stdin", "diff"])
        .arg(fixture("conflict.kdbx"))
        .arg("--json")
        .write_stdin(format!("{PASSWORD}\n"))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&ours.stdout).unwrap();
    let ours_where = |pred: &dyn Fn(&serde_json::Value) -> bool| -> Vec<String> {
        v["differences"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| pred(d))
            .map(|d| d["uuid"].as_str().unwrap().replace('-', ""))
            .collect()
    };
    assert_eq!(
        uuid_on("Creating missing"),
        ours_where(&|d| d["kind"] == "only_there"),
        "{theirs}"
    );
    assert_eq!(
        uuid_on("newer source"),
        ours_where(&|d| d["newer"] == "there"),
        "{theirs}"
    );
    assert_eq!(
        uuid_on("conflicting changes"),
        ours_where(&|d| d["kind"] == "changed" && d["newer"] == "unknown"),
        "{theirs}"
    );
}

/// `prive export` and `keepassxc-cli export -f csv` hold the same titles, usernames,
/// passwords, URLs and notes. (KeePassXC also writes the root group's name and the recycle
/// bin; prive leaves both out, so the group column and the deleted entry are set aside.)
#[test]
fn export_matches_keepassxc_csv() {
    if !available() {
        return;
    }
    let theirs = keepassxc(&["export", "-q", "-f", "csv", &fixture("kdbx41.kdbx")]).unwrap();
    let ours = assert_cmd::Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .args([
            "--db",
            &fixture("kdbx41.kdbx"),
            "--password-stdin",
            "export",
            "--plaintext",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .output()
        .unwrap();
    let rows = |text: &[u8]| -> Vec<Vec<String>> {
        let mut r = csv::Reader::from_reader(text);
        let mut out: Vec<Vec<String>> = r
            .records()
            .map(|rec| {
                rec.unwrap()
                    .iter()
                    .skip(1)
                    .take(5)
                    .map(str::to_string)
                    .collect()
            })
            .filter(|cols: &Vec<String>| cols[0] != "Deleted thing")
            .collect();
        out.sort();
        out
    };
    assert_eq!(rows(&ours.stdout), rows(theirs.as_bytes()));
}

/// `prive otp` and `keepassxc-cli show -t` agree on every entry with a code, read from the
/// same file.
#[test]
fn prive_otp_matches_keepassxc_entry_by_entry() {
    if !available() {
        return;
    }
    for entry in [
        "Work/GitHub",
        "Bank",
        "Work/Cloud/Steam",
        "Personal/Legacy 2FA",
    ] {
        let mut matched = false;
        for _ in 0..2 {
            let before = prive::otp::unix_now() / 30;
            let ours = assert_cmd::Command::cargo_bin("prive")
                .unwrap()
                .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
                .args([
                    "--db",
                    &fixture("kdbx41.kdbx"),
                    "--password-stdin",
                    "otp",
                    entry,
                ])
                .write_stdin(format!("{PASSWORD}\n"))
                .output()
                .unwrap();
            let theirs = keepassxc(&["show", "-q", "-t", &fixture("kdbx41.kdbx"), entry]);
            if prive::otp::unix_now() / 30 != before {
                continue; // crossed a boundary while the two ran; try again
            }
            assert_eq!(
                String::from_utf8_lossy(&ours.stdout).trim(),
                theirs.unwrap(),
                "{entry}"
            );
            matched = true;
            break;
        }
        assert!(matched, "{entry}: kept crossing a period boundary");
    }
}

/// KeePassXC resolves the fixture's field reference to the same value prive does.
#[test]
fn field_references_resolve_like_keepassxc() {
    if !available() {
        return;
    }
    let theirs = keepassxc(&[
        "show",
        "-q",
        "-s",
        "-a",
        "BANK_PASSWORD",
        &fixture("kdbx41.kdbx"),
        "Old VPN",
    ])
    .unwrap();
    let ours = assert_cmd::Command::cargo_bin("prive")
        .unwrap()
        .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
        .env("PRIVE_NO_AGENT", "1")
        .args([
            "--db",
            &fixture("kdbx41.kdbx"),
            "--password-stdin",
            "get",
            "Old VPN",
            "-f",
            "BANK_PASSWORD",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&ours.stdout).trim(), theirs);
}

/// A large database KeePassXC wrote: every command stays quick. (Generous limits, to catch
/// anything that grows badly with the number of entries, not to benchmark.)
#[test]
fn five_thousand_entries() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeePassFile><Meta><Generator>t</Generator></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>",
    );
    for g in 0..50 {
        xml.push_str(&format!("<Group><Name>Group {g}</Name>"));
        for i in 0..100 {
            let n = g * 100 + i;
            xml.push_str(&format!(
                "<Entry><String><Key>Title</Key><Value>Site {n}</Value></String>\
                 <String><Key>UserName</Key><Value>user{n}@example.invalid</Value></String>\
                 <String><Key>Password</Key><Value ProtectInMemory=\"True\">pw-{n}-Xq7!</Value></String>\
                 <String><Key>URL</Key><Value>https://site{n}.example.invalid</Value></String>{}</Entry>",
                if n % 10 == 0 {
                    "<String><Key>otp</Key><Value>otpauth://totp/x?secret=JBSWY3DPEHPK3PXP</Value></String>"
                } else {
                    ""
                }
            ));
        }
        xml.push_str("</Group>");
    }
    xml.push_str("</Group></Root></KeePassFile>");
    let src = dir.path().join("big.xml");
    std::fs::write(&src, xml).unwrap();
    let db = dir.path().join("big.kdbx");
    let mut child = Command::new("keepassxc-cli")
        .args(["import", "-q", "-p"])
        .arg(&src)
        .arg(&db)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{PASSWORD}\n{PASSWORD}").unwrap();
    }
    assert!(child.wait().unwrap().success());

    let itself = db.to_str().unwrap().to_string();
    for args in [
        &["ls"][..],
        &["search", "Site 4999"],
        &["search", "--all", "nothing-matches-this"],
        &["get", "Group 49/Site 4999"],
        &["codes"],
        &["audit", "--max-age", "0"],
        &["get", "Site 499"],
        &["info"],
        &["diff", itself.as_str()],
    ] {
        let started = std::time::Instant::now();
        let out = assert_cmd::Command::cargo_bin("prive")
            .unwrap()
            .env("PRIVE_CONFIG", fixture("no-such-config.toml"))
            .env("PRIVE_NO_AGENT", "1")
            .arg("--db")
            .arg(&db)
            .arg("--password-stdin")
            .args(args)
            .write_stdin(format!("{PASSWORD}\n"))
            .output()
            .unwrap();
        let took = started.elapsed();
        assert!(
            out.status.success() || out.status.code() == Some(3),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            took < std::time::Duration::from_secs(20),
            "{args:?} took {took:?}"
        );
        eprintln!("{args:?}: {took:?}");
    }
}
