//! What commands print. Data goes to stdout; everything else (prompts, notices) to stderr.

use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use crate::entry::Entry;

const HIDDEN: &str = "******** (--reveal shows it)";

static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `--quiet`: notices on stderr ("Copied", seconds left, entropy) are left out. Errors and
/// prompts still appear.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, std::sync::atomic::Ordering::Relaxed);
}

/// A notice for the person at the terminal, on stderr, unless `--quiet`.
pub fn notice(text: &str) {
    debug_assert!(
        !(text.contains('{') && text.contains('}')),
        "notice with an unformatted placeholder: {text}"
    );
    if !QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{text}");
    }
}

/// Write text to stdout. A closed pipe (`prive ls | head -1`) is not an error: the reader
/// has what it wanted, so prive stops quietly instead of panicking like `println!` does.
pub fn print(text: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        other => Ok(other?),
    }
}

/// Colours for reports people read: doctor, audit, diff. Written with [`print_styled`].
pub mod style {
    use anstyle::{AnsiColor, Color, Style};

    pub const OK: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
    pub const WARN: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
    pub const BAD: Style = Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)))
        .bold();
    pub const DIM: Style = Style::new().dimmed();
    pub const HEADING: Style = Style::new().bold();
}

/// Write a report that may carry colours to stdout. They are kept on a terminal and dropped
/// for pipes and files, and when `NO_COLOR` is set or `CLICOLOR=0` (`CLICOLOR_FORCE=1` keeps
/// them). Never used for secrets or JSON: dropping colours means rewriting the text, and a
/// value must come out exactly as stored.
pub fn print_styled(text: &str) -> Result<()> {
    let mut out = anstream::AutoStream::auto(std::io::stdout().lock());
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        other => Ok(other?),
    }
}

/// Pretty JSON on stdout, one trailing newline.
pub fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    print(&text)
}

/// How many terminal columns `s` takes: two for CJK characters and most emoji, none for
/// combining marks. Columns line up by this, not by the number of characters.
pub fn width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

/// `s` followed by enough spaces to fill `columns`.
pub fn pad(s: &str, columns: usize) -> String {
    let mut out = s.to_string();
    out.extend(std::iter::repeat_n(' ', columns.saturating_sub(width(s))));
    out
}

/// One line per entry: the path, and the username after two spaces when there is one.
pub fn render_list(entries: &[&Entry]) -> String {
    let columns = entries.iter().map(|e| width(&e.path())).max().unwrap_or(0);
    let mut out = String::new();
    for e in entries {
        if e.username.is_empty() {
            out.push_str(&format!("{}\n", e.path()));
        } else {
            out.push_str(&format!("{}  {}\n", pad(&e.path(), columns), e.username));
        }
    }
    out
}

/// The `audit` report for people: one block per entry with problems, worst first, and a
/// closing summary line.
pub fn render_audit(r: &crate::audit::Report) -> String {
    let mut out = String::new();
    if !r.database.is_empty() {
        out.push_str("This database\n");
        for i in &r.database {
            out.push_str(&format!("  - {}\n", i.describe()));
        }
        out.push_str(
            "  (KeePassXC: Database > Database Security > Encryption Settings; \
             the change takes effect on the next save)\n",
        );
    }
    for f in &r.findings {
        out.push_str(&format!("{}\n", f.path));
        for i in &f.issues {
            out.push_str(&format!("  - {}\n", i.describe()));
        }
    }
    let skipped = if r.skipped > 0 {
        format!(", {} skipped (excluded or no password)", r.skipped)
    } else {
        String::new()
    };
    out.push_str(&format!(
        "{} of {} checked entries need attention{skipped}\n",
        r.findings.len(),
        r.checked
    ));
    out
}

/// `1.2 KB`-style sizes for people.
pub fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// `ls --long`: the date it last changed, markers for a one-time code (`2fa`), attachments
/// (`file`) and expiry (`expired`), then the path and username.
pub fn render_long_list(entries: &[&Entry]) -> String {
    let now = chrono::Utc::now().naive_utc();
    let columns = entries.iter().map(|e| width(&e.path())).max().unwrap_or(0);
    let mut out = String::new();
    for e in entries {
        let date = e
            .modified
            .map(|m| m.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "-".repeat(10));
        let mut marks = Vec::new();
        if crate::otp::Totp::from_entry(e).is_some() {
            marks.push("2fa");
        }
        if !e.attachments.is_empty() {
            marks.push("file");
        }
        if e.expires.is_some_and(|x| x < now) {
            marks.push("expired");
        }
        let line = format!(
            "{date}  {:<13} {}  {}",
            marks.join(","),
            pad(&e.path(), columns),
            e.username
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// `show --json`: every field, with the password and protected values left out (`null`)
/// unless `reveal`.
#[derive(Debug, Serialize)]
pub struct ShowJson {
    #[serde(flatten)]
    pub summary: crate::entry::Summary,
    pub password: Option<String>,
    pub notes: String,
    pub fields: Vec<FieldJson>,
    pub attachments: Vec<String>,
    pub modified: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FieldJson {
    pub name: String,
    pub value: Option<String>,
    pub protected: bool,
}

pub fn show_json(e: &Entry, reveal: bool) -> ShowJson {
    let iso = |t: chrono::NaiveDateTime| t.format("%Y-%m-%dT%H:%M:%S").to_string();
    ShowJson {
        summary: e.summary(),
        password: reveal.then(|| e.password.to_string()),
        notes: e.notes.clone(),
        fields: e
            .custom
            .iter()
            .map(|c| FieldJson {
                name: c.name.clone(),
                value: (!c.protected || reveal).then(|| c.value.to_string()),
                protected: c.protected,
            })
            .collect(),
        attachments: e.attachment_names(),
        modified: e.modified.map(iso),
        expires: e.expires.map(iso),
    }
}

/// The `show` view of one entry. Passwords and protected fields stay hidden unless `reveal`.
/// One line of `otp --watch`: the code, a bar of the time it has left, and the seconds.
/// Padded to the same width every time, so a redraw over it leaves nothing behind.
pub fn watch_line(code: &str, left: u64, period: u64) -> String {
    const WIDTH: u64 = 20;
    let filled = (left * WIDTH).div_ceil(period.max(1)).min(WIDTH) as usize;
    format!(
        "{code}  [{}{}] {left:>3} s ",
        "#".repeat(filled),
        "-".repeat(WIDTH as usize - filled)
    )
}

/// `prive doctor`: one line per check, `ok`, `warn`, `FAIL` or `--` first.
pub fn render_checks(checks: &[crate::doctor::Check]) -> String {
    use crate::doctor::Status;
    let width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in checks {
        let status = match c.status {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
            Status::Skip => "--",
        };
        out.push_str(&format!("{status:<5} {:<width$}  {}\n", c.name, c.detail));
    }
    out
}

/// `prive diff`: entries only in one copy, then changed ones with what changed.
pub fn render_diff(
    here: &std::path::Path,
    there: &std::path::Path,
    diffs: &[crate::diff::Difference],
) -> String {
    use crate::diff::{Kind, Newer};
    let name = |p: &std::path::Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.display().to_string())
    };
    let (a, b) = (name(here), name(there));
    if diffs.is_empty() {
        return format!("{a} and {b} hold the same entries\n");
    }
    let mut out = String::new();
    for (kind, heading) in [
        (Kind::OnlyHere, format!("Only in {a}:")),
        (Kind::OnlyThere, format!("Only in {b}:")),
        (Kind::Changed, "Changed:".to_string()),
    ] {
        let rows: Vec<&crate::diff::Difference> = diffs.iter().filter(|d| d.kind == kind).collect();
        if rows.is_empty() {
            continue;
        }
        out.push_str(&heading);
        out.push('\n');
        for d in rows {
            let mut line = format!("  {}", d.path);
            if let Some(o) = &d.other_path {
                line.push_str(&format!(" -> {o}"));
            }
            if d.recycled_in_other {
                let bin = if kind == Kind::OnlyHere { &b } else { &a };
                line.push_str(&format!(" (in the recycle bin of {bin})"));
            }
            if !d.fields.is_empty() {
                line.push_str(&format!(": {}", d.fields.join(", ")));
            }
            match d.newer {
                Some(Newer::Here) => line.push_str(&format!(" (newer in {a})")),
                Some(Newer::There) => line.push_str(&format!(" (newer in {b})")),
                _ => {}
            }
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// `prive info`: where the database is, how it is protected and what is in it.
pub fn render_info(db: &crate::db::Db, size: u64) -> String {
    let i = &db.info;
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(&format!("{label:<13} {value}\n"));
        }
    };
    line(
        "File:",
        &format!(
            "{} ({})",
            db.path.display(),
            human_size(usize::try_from(size).unwrap_or(usize::MAX))
        ),
    );
    line("Name:", i.name.as_deref().unwrap_or(""));
    line("Format:", &i.format);
    let inner = if i.inner_cipher == "none" {
        "passwords inside are not encrypted again".to_string()
    } else {
        format!("passwords inside also {}", i.inner_cipher)
    };
    line("Encryption:", &format!("{}, {inner}", i.cipher));
    line("Key:", &i.kdf.describe());
    line("Compressed:", if i.compressed { "yes" } else { "no" });
    line("Saved by:", i.generator.as_deref().unwrap_or(""));
    let mut contents = format!(
        "{} {} in {} {}",
        db.entries.len(),
        if db.entries.len() == 1 {
            "entry"
        } else {
            "entries"
        },
        i.groups,
        if i.groups == 1 { "group" } else { "groups" }
    );
    if i.recycled > 0 {
        contents.push_str(&format!(", {} in the recycle bin", i.recycled));
    }
    line("Contents:", &contents);
    if let Some(t) = i.key_changed {
        line("Key changed:", &t.format("%Y-%m-%d").to_string());
    }
    out
}

pub fn render_show(e: &Entry, reveal: bool) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(&format!("{label:<10} {value}\n"));
        }
    };
    line("Path:", &e.path());
    line("Username:", &e.username);
    if !e.password.is_empty() {
        line("Password:", if reveal { &e.password } else { HIDDEN });
    }
    line("URL:", &e.url);
    if let Some(t) = crate::otp::Totp::from_entry(e) {
        line(
            "TOTP:",
            &format!("{} (prive otp shows the code)", t.describe()),
        );
    }
    line("Tags:", &e.tags.join(", "));
    // One-time code settings are summed up on the TOTP line, so they aren't listed again.
    let fields: Vec<&crate::entry::CustomField> = e
        .custom
        .iter()
        .filter(|c| !crate::otp::is_otp_field(&c.name))
        .collect();
    if !fields.is_empty() {
        out.push_str("Fields:\n");
        let columns = fields.iter().map(|c| width(&c.name)).max().unwrap_or(0) + 1;
        for c in fields {
            let value = if c.protected && !reveal {
                HIDDEN
            } else {
                c.value.as_str()
            };
            out.push_str(&format!(
                "  {} {value}\n",
                pad(&format!("{}:", c.name), columns)
            ));
        }
    }
    if !e.attachments.is_empty() {
        let files: Vec<String> = e
            .attachments
            .iter()
            .map(|a| format!("{} ({})", a.name, human_size(a.data.len())))
            .collect();
        out.push_str(&format!("{:<10} {}\n", "Files:", files.join(", ")));
    }
    if let Some(m) = e.modified {
        out.push_str(&format!(
            "{:<10} {}\n",
            "Modified:",
            m.format("%Y-%m-%d %H:%M")
        ));
    }
    if let Some(x) = e.expires {
        out.push_str(&format!(
            "{:<10} {}\n",
            "Expires:",
            x.format("%Y-%m-%d %H:%M")
        ));
    }
    if !e.notes.is_empty() {
        out.push_str("Notes:\n");
        for l in e.notes.lines() {
            out.push_str(&format!("  {l}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_of_a_summary() {
        let e = crate::entry::Entry {
            uuid: "u1".into(),
            title: "Bank".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(e.summary()).unwrap();
        assert_eq!(v["path"], "Bank");
        assert_eq!(v["has_otp"], false);
        assert!(v.get("password").is_none());
    }

    fn github() -> Entry {
        Entry {
            uuid: "u1".into(),
            group: "Work".into(),
            title: "GitHub".into(),
            username: "demo".into(),
            password: zeroize::Zeroizing::new("gh-Secret-1".into()),
            url: "https://github.com".into(),
            tags: vec!["dev".into(), "cloud".into()],
            ..Default::default()
        }
    }

    #[test]
    fn show_hides_the_password_unless_revealed() {
        let hidden = render_show(&github(), false);
        assert!(hidden.contains("Path:      Work/GitHub"));
        assert!(hidden.contains("Username:  demo"));
        assert!(hidden.contains("Tags:      dev, cloud"));
        assert!(!hidden.contains("gh-Secret-1"));
        assert!(render_show(&github(), true).contains("Password:  gh-Secret-1"));
    }

    #[test]
    fn show_leaves_out_empty_fields() {
        let e = Entry {
            title: "Bare".into(),
            ..Default::default()
        };
        assert_eq!(render_show(&e, false), "Path:      Bare\n");
    }

    #[test]
    fn custom_fields_hide_only_protected_values() {
        let mut e = github();
        e.custom = vec![
            crate::entry::CustomField {
                name: "API key".into(),
                value: zeroize::Zeroizing::new("k-123".into()),
                protected: true,
            },
            crate::entry::CustomField {
                name: "plan".into(),
                value: zeroize::Zeroizing::new("basic".into()),
                protected: false,
            },
        ];
        let text = render_show(&e, false);
        assert!(text.contains("Fields:\n  API key: ********"));
        assert!(text.contains("  plan:    basic"));
        assert!(!text.contains("k-123"));
        assert!(render_show(&e, true).contains("API key: k-123"));
    }

    #[test]
    fn notes_are_indented_and_times_shown() {
        let mut e = github();
        e.notes = "line one\nline two".into();
        e.attachments = vec![crate::entry::Attachment {
            name: "deploy.pem".into(),
            data: zeroize::Zeroizing::new(vec![0; 2048]),
        }];
        e.modified = chrono::NaiveDate::from_ymd_opt(2026, 5, 1)
            .unwrap()
            .and_hms_opt(14, 3, 0);
        let text = render_show(&e, false);
        assert!(text.contains("Files:     deploy.pem (2.0 KB)\n"));
        assert!(text.contains("Modified:  2026-05-01 14:03\n"));
        assert!(text.ends_with("Notes:\n  line one\n  line two\n"));
    }

    #[test]
    fn show_json_leaves_secrets_null_unless_revealed() {
        let mut e = github();
        e.custom = vec![crate::entry::CustomField {
            name: "pin".into(),
            value: zeroize::Zeroizing::new("4321".into()),
            protected: true,
        }];
        let hidden = serde_json::to_value(show_json(&e, false)).unwrap();
        assert!(hidden["password"].is_null());
        assert!(hidden["fields"][0]["value"].is_null());
        assert_eq!(hidden["path"], "Work/GitHub");
        let shown = serde_json::to_value(show_json(&e, true)).unwrap();
        assert_eq!(shown["password"], "gh-Secret-1");
        assert_eq!(shown["fields"][0]["value"], "4321");
    }

    #[test]
    fn list_aligns_usernames() {
        let a = github();
        let b = Entry {
            title: "Bank".into(),
            ..Default::default()
        };
        assert_eq!(render_list(&[&a, &b]), "Work/GitHub  demo\nBank\n");
        assert_eq!(render_list(&[]), "");
    }

    #[test]
    fn columns_line_up_by_display_width() {
        assert_eq!(width("GitHub"), 6);
        assert_eq!(width("銀行"), 4, "two columns per CJK character");
        assert_eq!(width("e\u{301}"), 1, "a combining accent takes no column");
        let mk = |t: &str| Entry {
            title: t.into(),
            username: "me".into(),
            ..Entry::default()
        };
        let (a, b) = (mk("銀行"), mk("Bank"));
        // Both usernames start in the same column.
        assert_eq!(render_list(&[&a, &b]), "銀行  me\nBank  me\n");
        assert_eq!(pad("銀", 4), "銀  ");
    }

    #[test]
    fn diff_text() {
        use crate::diff::{Difference, Kind, Newer};
        let d =
            |kind, path: &str, other: Option<&str>, fields: &[&str], newer, recycled| Difference {
                kind,
                path: path.into(),
                other_path: other.map(str::to_string),
                fields: fields.iter().map(|f| f.to_string()).collect(),
                newer,
                uuid: String::new(),
                recycled_in_other: recycled,
            };
        let (a, b) = (
            std::path::Path::new("/x/A.kdbx"),
            std::path::Path::new("B.kdbx"),
        );
        assert_eq!(
            render_diff(a, b, &[]),
            "A.kdbx and B.kdbx hold the same entries\n"
        );
        let text = render_diff(
            a,
            b,
            &[
                d(Kind::OnlyHere, "Old", None, &[], None, true),
                d(Kind::OnlyThere, "New", None, &[], None, false),
                d(
                    Kind::Changed,
                    "Bank",
                    None,
                    &["password"],
                    Some(Newer::Here),
                    false,
                ),
                d(
                    Kind::Changed,
                    "W/GH",
                    Some("P/GH"),
                    &["group"],
                    Some(Newer::Unknown),
                    false,
                ),
            ],
        );
        assert_eq!(
            text,
            "Only in A.kdbx:\n  Old (in the recycle bin of B.kdbx)\n\
             Only in B.kdbx:\n  New\n\
             Changed:\n  Bank: password (newer in A.kdbx)\n  W/GH -> P/GH: group\n"
        );
    }

    #[test]
    fn doctor_lines_line_up() {
        use crate::doctor::{Check, Status};
        let c = |name, status, detail: &str| Check {
            name,
            status,
            detail: detail.into(),
        };
        assert_eq!(
            render_checks(&[
                c("config file", Status::Ok, "/c.toml"),
                c("key file", Status::Skip, "none"),
                c("database", Status::Fail, "missing"),
                c("sync", Status::Warn, "a copy"),
            ]),
            "ok    config file  /c.toml\n\
             --    key file     none\n\
             FAIL  database     missing\n\
             warn  sync         a copy\n"
        );
    }

    #[test]
    fn watch_lines_keep_their_width() {
        assert_eq!(
            watch_line("123456", 30, 30),
            "123456  [####################]  30 s "
        );
        assert_eq!(
            watch_line("123456", 15, 30),
            "123456  [##########----------]  15 s "
        );
        assert_eq!(
            watch_line("123456", 1, 30),
            "123456  [#-------------------]   1 s "
        );
        assert_eq!(
            watch_line("123456", 1, 30).len(),
            watch_line("123456", 30, 30).len()
        );
    }

    #[test]
    fn audit_report_text() {
        let r = crate::audit::Report {
            checked: 3,
            skipped: 1,
            findings: vec![crate::audit::Finding {
                path: "Work/GitHub".into(),
                issues: vec![
                    crate::audit::Issue::Weak { score: 1 },
                    crate::audit::Issue::Reused { with: 1 },
                ],
            }],
            database: Vec::new(),
        };
        assert_eq!(
            render_audit(&r),
            "Work/GitHub\n  - weak (strength 1/4)\n  - reused by 1 other entry\n\
             1 of 3 checked entries need attention, 1 skipped (excluded or no password)\n"
        );
    }

    #[test]
    fn long_list_marks_codes_files_and_expiry() {
        let mut a = github();
        a.modified = chrono::NaiveDate::from_ymd_opt(2026, 5, 1)
            .unwrap()
            .and_hms_opt(9, 0, 0);
        a.attachments = vec![crate::entry::Attachment {
            name: "k.pem".into(),
            data: zeroize::Zeroizing::new(vec![1, 2, 3]),
        }];
        let mut b = Entry {
            title: "Old".into(),
            expires: chrono::NaiveDate::from_ymd_opt(2020, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0),
            ..Default::default()
        };
        b.modified = None;
        assert_eq!(
            render_long_list(&[&a, &b]),
            "2026-05-01  file          Work/GitHub  demo\n\
             ----------  expired       Old\n"
        );
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}
