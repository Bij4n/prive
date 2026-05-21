//! What commands print. Data goes to stdout; everything else (prompts, notices) to stderr.

use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use crate::entry::Entry;

const HIDDEN: &str = "******** (--reveal shows it)";

/// Pretty JSON on stdout, one trailing newline.
pub fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
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
    if crate::otp::Totp::from_entry(e).is_some() {
        line("TOTP:", "yes (prive otp shows the code)");
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
}
