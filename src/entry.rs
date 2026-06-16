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
    /// Attached files, by name, with their contents.
    pub attachments: Vec<Attachment>,
    /// Earlier versions KeePass kept, newest first: when each was saved, and its password.
    pub history: Vec<Version>,
}

/// One saved earlier version of an entry.
#[derive(Clone)]
pub struct Version {
    pub modified: Option<NaiveDateTime>,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Version")
            .field("modified", &self.modified)
            .field("password", &"<hidden>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct CustomField {
    pub name: String,
    pub value: Zeroizing<String>,
    /// KeePass "protected" flag: shown hidden by default.
    pub protected: bool,
}

/// A file attached to an entry (a key, a certificate, a scan). Its bytes are treated as
/// secret: wiped from memory when freed, never printed by `Debug`.
#[derive(Clone)]
pub struct Attachment {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({} bytes)", self.name, self.data.len())
    }
}

/// Custom fields KeePassXC and Keepass2Android keep more addresses of the same login in:
/// `KP2A_URL`, `KP2A_URL_1`, `KP2A_URL_2`, ...
pub fn is_extra_url_field(name: &str) -> bool {
    name == "KP2A_URL"
        || name
            .strip_prefix("KP2A_URL_")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

impl Entry {
    /// The entry's URL, then its extra ones (see [`is_extra_url_field`]), leaving out empty
    /// ones.
    pub fn urls(&self) -> Vec<&str> {
        std::iter::once(self.url.as_str())
            .chain(
                self.custom
                    .iter()
                    .filter(|c| is_extra_url_field(&c.name))
                    .map(|c| c.value.as_str()),
            )
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .collect()
    }

    /// The names of the attached files, in order.
    pub fn attachment_names(&self) -> Vec<String> {
        self.attachments.iter().map(|a| a.name.clone()).collect()
    }
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
    /// `2026-05-01T14:03:00`, when the file records it.
    pub modified: Option<String>,
    pub expires: Option<String>,
    pub attachments: usize,
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
            history: Vec::new(),
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
            modified: self
                .modified
                .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            expires: self
                .expires
                .map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            attachments: self.attachments.len(),
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
    fn debug_output_hides_attachment_bytes_and_old_passwords() {
        let mut e = sample();
        e.attachments = vec![Attachment {
            name: "id_ed25519".into(),
            data: Zeroizing::new(b"PRIVATE-KEY-BYTES".to_vec()),
        }];
        e.history = vec![Version {
            modified: None,
            username: "ops".into(),
            password: Zeroizing::new("old-s3cret".into()),
        }];
        let shown = format!("{e:?} {:?}", e.history);
        assert!(shown.contains("id_ed25519 (17 bytes)"));
        assert!(!shown.contains("PRIVATE-KEY-BYTES"));
        assert!(!shown.contains("old-s3cret"));
    }

    #[test]
    fn extra_urls_follow_the_main_one() {
        let mut e = sample();
        e.url = "https://github.com".into();
        let field = |name: &str, value: &str| CustomField {
            name: name.into(),
            value: Zeroizing::new(value.into()),
            protected: false,
        };
        e.custom = vec![
            field("KP2A_URL", "https://gist.github.com"),
            field("KP2A_URL_1", "https://api.github.com"),
            field("KP2A_URL_2", " "),
            field("KP2A_URL_X", "https://not.an.extra.url"),
            field("plan", "team"),
        ];
        assert_eq!(
            e.urls(),
            [
                "https://github.com",
                "https://gist.github.com",
                "https://api.github.com"
            ]
        );
        assert!(Entry::default().urls().is_empty());
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
