//! One password entry, independent of how it was read from disk.

use chrono::NaiveDateTime;
use serde::Serialize;
use zeroize::Zeroizing;

/// `Debug` never prints the password or protected values, so a stray `{:?}` in an error or
/// log can't leak them.
#[derive(Clone)]
pub struct Entry {
    pub uuid: String,
    /// Group path without the root group, e.g. `Work/Cloud`. Empty for the root.
    pub group: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub password: Zeroizing<String>,
    pub tags: Vec<String>,
    /// Fields other than the five standard ones, sorted by name.
    pub custom: Vec<CustomField>,
    /// When the entry was last changed, if the file records it.
    pub modified: Option<NaiveDateTime>,
    /// Set only when the entry has expiry switched on.
    pub expires: Option<NaiveDateTime>,
    /// False when the user excluded the entry from password reports in KeePassXC.
    pub quality_check: bool,
    /// Names of attached files. Their contents are not read.
    pub attachments: Vec<String>,
}

#[derive(Clone)]
pub struct CustomField {
    pub name: String,
    pub value: Zeroizing<String>,
    /// KeePass "protected" flag: shown hidden by default.
    pub protected: bool,
}

/// What listings print: enough to find and name an entry, never a secret.
#[derive(Debug, Serialize, PartialEq)]
pub struct Summary {
    pub path: String,
    pub title: String,
    pub group: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub uuid: String,
    pub has_otp: bool,
}

/// Sort by path, ignoring case, the order listings use.
pub fn sort_by_path(entries: &mut [Entry]) {
    entries.sort_by_cached_key(|e| e.path().to_lowercase());
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            uuid: String::new(),
            group: String::new(),
            title: String::new(),
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            password: Zeroizing::new(String::new()),
            tags: Vec::new(),
            custom: Vec::new(),
            modified: None,
            expires: None,
            // KeePass's default: an entry takes part in reports unless excluded.
            quality_check: true,
            attachments: Vec::new(),
        }
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("uuid", &self.uuid)
            .field("path", &self.path())
            .field("username", &self.username)
            .field("url", &self.url)
            .field("password", &"<hidden>")
            .field("tags", &self.tags)
            .field("custom", &self.custom)
            .field("attachments", &self.attachments)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value: &dyn std::fmt::Debug = if self.protected {
            &"<hidden>"
        } else {
            &self.value.as_str()
        };
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", value)
            .finish()
    }
}

impl Entry {
    pub fn summary(&self) -> Summary {
        Summary {
            path: self.path(),
            title: self.title.clone(),
            group: self.group.clone(),
            username: self.username.clone(),
            url: self.url.clone(),
            tags: self.tags.clone(),
            uuid: self.uuid.clone(),
            has_otp: crate::otp::Totp::from_entry(self).is_some(),
        }
    }

    /// `Group/Sub/Title`, or just `Title` at the root.
    pub fn path(&self) -> String {
        if self.group.is_empty() {
            self.title.clone()
        } else {
            format!("{}/{}", self.group, self.title)
        }
    }

    /// Names `field` accepts for this entry: the five standard ones, then custom fields.
    pub fn field_names(&self) -> Vec<String> {
        let mut names: Vec<String> = ["title", "username", "password", "url", "notes"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        names.extend(self.custom.iter().map(|c| c.name.clone()));
        names
    }

    /// Any field by name: a standard one (ignoring case; `user`, `login`, `pass` and `note`
    /// are accepted as aliases), else a custom field, exact name first, then ignoring case.
    pub fn field(&self, name: &str) -> Option<&str> {
        match name.to_ascii_lowercase().as_str() {
            "title" => return Some(&self.title),
            "username" | "user" | "login" => return Some(&self.username),
            "password" | "pass" => return Some(&self.password),
            "url" => return Some(&self.url),
            "notes" | "note" => return Some(&self.notes),
            _ => {}
        }
        self.custom
            .iter()
            .find(|c| c.name == name)
            .or_else(|| {
                self.custom
                    .iter()
                    .find(|c| c.name.eq_ignore_ascii_case(name))
            })
            .map(|c| c.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Entry {
        Entry {
            uuid: "u".into(),
            group: "Work/Cloud".into(),
            title: "AWS".into(),
            username: "ops".into(),
            password: Zeroizing::new("s3cret".into()),
            ..Entry::default()
        }
    }

    #[test]
    fn path_joins_group_and_title() {
        assert_eq!(sample().path(), "Work/Cloud/AWS");
        let root = Entry {
            title: "Bank".into(),
            ..Entry::default()
        };
        assert_eq!(root.path(), "Bank");
    }

    #[test]
    fn standard_fields_and_aliases() {
        let e = sample();
        assert_eq!(e.field("Password"), Some("s3cret"));
        assert_eq!(e.field("pass"), Some("s3cret"));
        assert_eq!(e.field("login"), Some("ops"));
        assert_eq!(e.field("nope"), None);
    }

    #[test]
    fn custom_fields_exact_name_wins() {
        let mut e = sample();
        e.custom = vec![
            CustomField {
                name: "api key".into(),
                value: Zeroizing::new("lower".into()),
                protected: true,
            },
            CustomField {
                name: "API Key".into(),
                value: Zeroizing::new("exact".into()),
                protected: true,
            },
        ];
        assert_eq!(e.field("API Key"), Some("exact"));
        assert_eq!(e.field("Api KEY"), Some("lower"));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let mut e = sample();
        e.custom = vec![
            CustomField {
                name: "pin".into(),
                value: Zeroizing::new("4321".into()),
                protected: true,
            },
            CustomField {
                name: "plan".into(),
                value: Zeroizing::new("basic".into()),
                protected: false,
            },
        ];
        let shown = format!("{e:?}");
        assert!(!shown.contains("s3cret"));
        assert!(!shown.contains("4321"));
        assert!(shown.contains("basic"));
        assert!(shown.contains("Work/Cloud/AWS"));
    }

    #[test]
    fn entries_take_part_in_reports_by_default() {
        assert!(Entry::default().quality_check);
    }

    #[test]
    fn summaries_carry_no_secrets() {
        let mut e = sample();
        e.custom = vec![CustomField {
            name: "otp".into(),
            value: Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
            protected: true,
        }];
        let s = e.summary();
        assert_eq!(s.path, "Work/Cloud/AWS");
        assert!(s.has_otp);
        let text = format!("{s:?}");
        assert!(!text.contains("s3cret") && !text.contains("JBSWY3DP"));
    }

    #[test]
    fn sorting_ignores_case() {
        let mk = |g: &str, t: &str| Entry {
            group: g.into(),
            title: t.into(),
            ..Entry::default()
        };
        let mut v = vec![
            mk("work", "b"),
            mk("", "Zed"),
            mk("Work", "A"),
            mk("", "apple"),
        ];
        sort_by_path(&mut v);
        let paths: Vec<String> = v.iter().map(Entry::path).collect();
        assert_eq!(paths, ["apple", "Work/A", "work/b", "Zed"]);
    }

    #[test]
    fn field_names_list_standard_then_custom() {
        let mut e = sample();
        e.custom = vec![CustomField {
            name: "API key".into(),
            value: Zeroizing::new("k".into()),
            protected: true,
        }];
        assert_eq!(
            e.field_names(),
            ["title", "username", "password", "url", "notes", "API key"]
        );
    }
}
