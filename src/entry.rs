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

    /// One of the standard fields by name, ignoring case. `user`, `login`, `pass` and `note`
    /// are accepted as aliases.
    pub fn field(&self, name: &str) -> Option<&str> {
        match name.to_ascii_lowercase().as_str() {
            "title" => Some(&self.title),
            "username" | "user" | "login" => Some(&self.username),
            "password" | "pass" => Some(&self.password),
            "url" => Some(&self.url),
            "notes" | "note" => Some(&self.notes),
            _ => None,
        }
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
}
