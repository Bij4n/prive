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
        "otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&encoder=steam",
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
