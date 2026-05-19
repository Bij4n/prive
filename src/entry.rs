//! One password entry, independent of how it was read from disk.

use zeroize::Zeroizing;

#[derive(Debug, Clone, Default)]
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
}

#[derive(Debug, Clone)]
pub struct CustomField {
    pub name: String,
    pub value: Zeroizing<String>,
    /// KeePass "protected" flag: shown hidden by default.
    pub protected: bool,
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
}
