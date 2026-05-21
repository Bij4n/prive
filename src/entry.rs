//! One password entry, independent of how it was read from disk.

use chrono::NaiveDateTime;
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
}

#[derive(Clone)]
pub struct CustomField {
    pub name: String,
    pub value: Zeroizing<String>,
    /// KeePass "protected" flag: shown hidden by default.
    pub protected: bool,
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
    /// `Group/Sub/Title`, or just `Title` at the root.
    pub fn path(&self) -> String {
        if self.group.is_empty() {
            self.title.clone()
        } else {
            format!("{}/{}", self.group, self.title)
        }
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
}
