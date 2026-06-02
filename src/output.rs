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

/// Pretty JSON on stdout, one trailing newline.
pub fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    print(&text)
}

/// One line per entry: the path, and the username after two spaces when there is one.
pub fn render_list(entries: &[&Entry]) -> String {
    let width = entries
        .iter()
        .map(|e| e.path().chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for e in entries {
        if e.username.is_empty() {
            out.push_str(&format!("{}\n", e.path()));
        } else {
            out.push_str(&format!("{:<width$}  {}\n", e.path(), e.username));
        }
    }
    out
}

/// The `audit` report for people: one block per entry with problems, worst first, and a
/// closing summary line.
pub fn render_audit(r: &crate::audit::Report) -> String {
    let mut out = String::new();
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
        attachments: e.attachments.clone(),
        modified: e.modified.map(iso),
        expires: e.expires.map(iso),
    }
}

/// The `show` view of one entry. Passwords and protected fields stay hidden unless `reveal`.
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
    if !e.custom.is_empty() {
        out.push_str("Fields:\n");
        let width = e
            .custom
            .iter()
            .map(|c| c.name.chars().count())
            .max()
            .unwrap_or(0)
            + 1;
        for c in &e.custom {
            let value = if c.protected && !reveal {
                HIDDEN
            } else {
                c.value.as_str()
            };
            out.push_str(&format!("  {:<width$} {value}\n", format!("{}:", c.name)));
        }
    }
    if !e.attachments.is_empty() {
        out.push_str(&format!("{:<10} {}\n", "Files:", e.attachments.join(", ")));
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
        e.attachments = vec!["deploy.pem".into()];
        e.modified = chrono::NaiveDate::from_ymd_opt(2026, 5, 1)
            .unwrap()
            .and_hms_opt(14, 3, 0);
        let text = render_show(&e, false);
        assert!(text.contains("Files:     deploy.pem\n"));
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
        };
        assert_eq!(
            render_audit(&r),
            "Work/GitHub\n  - weak (strength 1/4)\n  - reused by 1 other entry\n\
             1 of 3 checked entries need attention, 1 skipped (excluded or no password)\n"
        );
    }
}
