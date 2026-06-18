//! `prive diff`: what differs between two copies of one database, such as the conflict copy a
//! sync tool leaves next to the original (`Passwords.sync-conflict-....kdbx`).
//!
//! Entries are paired by UUID, which KeePass keeps when an entry is renamed or moved. Only the
//! names of the fields that differ are reported, never their values.

use serde::Serialize;

use crate::entry::Entry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// In the first database only.
    OnlyHere,
    /// In the other database only.
    OnlyThere,
    /// In both, with differences.
    Changed,
}

/// Which copy saved the entry last, going by its modification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Newer {
    Here,
    There,
    /// Same time, or a copy doesn't record one.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Difference {
    pub kind: Kind,
    /// The path in the first database, or in the other one for `OnlyThere`.
    pub path: String,
    /// The path in the other database, when the entry was moved or renamed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_path: Option<String>,
    /// What differs, by name: `password`, `tags`, `field 'API key'`, ...
    pub fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer: Option<Newer>,
    pub uuid: String,
    /// For an entry in one copy only: the other copy has it in its recycle bin, so it was
    /// deleted there rather than added here.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub recycled_in_other: bool,
}

fn key(uuid: &str) -> String {
    uuid.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The names of what differs between two versions of one entry.
pub fn changed_fields(a: &Entry, b: &Entry) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(name.to_string());
        }
    };
    check("title", a.title == b.title);
    check("group", a.group == b.group);
    check("username", a.username == b.username);
    check("password", *a.password == *b.password);
    check("url", a.url == b.url);
    check("notes", a.notes == b.notes);
    check("tags", a.tags == b.tags);
    check("expiry", a.expires == b.expires);
    check("report exclusion", a.quality_check == b.quality_check);
    let mut names: Vec<&str> = a
        .custom
        .iter()
        .chain(&b.custom)
        .map(|c| c.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        if custom(a, name) != custom(b, name) {
            out.push(format!("field '{name}'"));
        }
    }
    // Compared in place: no copies of the values or file contents are made.
    let same_files = a.attachments.len() == b.attachments.len()
        && a.attachments
            .iter()
            .zip(&b.attachments)
            .all(|(x, y)| x.name == y.name && x.data[..] == y.data[..]);
    if !same_files {
        out.push("attachments".into());
    }
    out
}

fn custom<'a>(e: &'a Entry, name: &str) -> Option<&'a str> {
    e.custom
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value.as_str())
}

/// Every difference between `here` and `there`: entries only in one, then changed ones, each
/// group in path order.
pub fn compare(here: &[Entry], there: &[Entry]) -> Vec<Difference> {
    let mut out = Vec::new();
    for a in here {
        match there.iter().find(|b| key(&b.uuid) == key(&a.uuid)) {
            None => out.push(Difference {
                kind: Kind::OnlyHere,
                path: a.path(),
                other_path: None,
                fields: Vec::new(),
                newer: None,
                uuid: a.uuid.clone(),
                recycled_in_other: false,
            }),
            Some(b) => {
                let fields = changed_fields(a, b);
                if fields.is_empty() {
                    continue;
                }
                let newer = match (a.modified, b.modified) {
                    (Some(x), Some(y)) if x > y => Newer::Here,
                    (Some(x), Some(y)) if x < y => Newer::There,
                    _ => Newer::Unknown,
                };
                out.push(Difference {
                    kind: Kind::Changed,
                    path: a.path(),
                    other_path: (a.path() != b.path()).then(|| b.path()),
                    fields,
                    newer: Some(newer),
                    uuid: a.uuid.clone(),
                    recycled_in_other: false,
                });
            }
        }
    }
    for b in there {
        if !here.iter().any(|a| key(&a.uuid) == key(&b.uuid)) {
            out.push(Difference {
                kind: Kind::OnlyThere,
                path: b.path(),
                other_path: None,
                fields: Vec::new(),
                newer: None,
                uuid: b.uuid.clone(),
                recycled_in_other: false,
            });
        }
    }
    out.sort_by(|x, y| {
        x.kind
            .cmp(&y.kind)
            .then_with(|| x.path.to_lowercase().cmp(&y.path.to_lowercase()))
    });
    out
}

/// Mark the entries found in one copy only that the other copy holds in its recycle bin.
pub fn note_recycled(diffs: &mut [Difference], here_bin: &[String], there_bin: &[String]) {
    let has = |bin: &[String], uuid: &str| bin.iter().any(|u| key(u) == key(uuid));
    for d in diffs {
        d.recycled_in_other = match d.kind {
            Kind::OnlyHere => has(there_bin, &d.uuid),
            Kind::OnlyThere => has(here_bin, &d.uuid),
            Kind::Changed => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::CustomField;
    use zeroize::Zeroizing;

    fn entry(uuid: &str, group: &str, title: &str, pw: &str) -> Entry {
        Entry {
            uuid: uuid.into(),
            group: group.into(),
            title: title.into(),
            password: Zeroizing::new(pw.into()),
            ..Entry::default()
        }
    }

    #[test]
    fn the_same_database_has_no_differences() {
        let a = vec![
            entry("1", "", "Bank", "x"),
            entry("2", "Work", "GitHub", "y"),
        ];
        assert!(compare(&a, &a.clone()).is_empty());
    }

    #[test]
    fn added_removed_and_changed() {
        let here = vec![
            entry("1", "", "Bank", "x"),
            entry("2", "Work", "GitHub", "y"),
            entry("3", "", "Only here", "z"),
        ];
        let mut there = vec![
            entry("1", "", "Bank", "x2"),
            entry("2", "Personal", "GitHub", "y"),
            entry("4", "", "Only there", "w"),
        ];
        there[0].tags = vec!["money".into()];
        let d = compare(&here, &there);
        let kinds: Vec<(Kind, &str)> = d.iter().map(|x| (x.kind, x.path.as_str())).collect();
        assert_eq!(
            kinds,
            [
                (Kind::OnlyHere, "Only here"),
                (Kind::OnlyThere, "Only there"),
                (Kind::Changed, "Bank"),
                (Kind::Changed, "Work/GitHub"),
            ]
        );
        assert_eq!(d[2].fields, ["password", "tags"]);
        assert_eq!(d[3].fields, ["group"]);
        assert_eq!(d[3].other_path.as_deref(), Some("Personal/GitHub"));
    }

    #[test]
    fn custom_fields_and_files_by_name_never_by_value() {
        let mut a = entry("1", "", "AWS", "x");
        let mut b = a.clone();
        a.custom = vec![CustomField {
            name: "SECRET".into(),
            value: Zeroizing::new("old-value".into()),
            protected: true,
        }];
        b.custom = vec![CustomField {
            name: "SECRET".into(),
            value: Zeroizing::new("new-value".into()),
            protected: true,
        }];
        b.attachments = vec![crate::entry::Attachment {
            name: "key.pem".into(),
            data: Zeroizing::new(b"k".to_vec()),
        }];
        let fields = changed_fields(&a, &b);
        assert_eq!(fields, ["field 'SECRET'", "attachments"]);
        let shown = format!("{:?}", compare(&[a], &[b]));
        assert!(!shown.contains("old-value") && !shown.contains("new-value"));
    }

    #[test]
    fn uuids_match_whatever_their_spelling() {
        let a = vec![entry("00000000-0000-0000-0000-0000000000AB", "", "x", "p")];
        let b = vec![entry("000000000000000000000000000000ab", "", "x", "p")];
        assert!(compare(&a, &b).is_empty());
    }

    #[test]
    fn deleted_on_one_side_is_told_apart_from_added() {
        let here = vec![entry("1", "", "Bank", "x"), entry("2", "", "Old", "y")];
        let there = vec![entry("1", "", "Bank", "x"), entry("3", "", "New", "z")];
        let mut d = compare(&here, &there);
        // "Old" sits in the other copy's recycle bin; "New" is simply new there.
        note_recycled(&mut d, &[], &["2".into()]);
        let marks: Vec<(&str, bool)> = d
            .iter()
            .map(|x| (x.path.as_str(), x.recycled_in_other))
            .collect();
        assert_eq!(marks, [("Old", true), ("New", false)]);
    }

    #[test]
    fn which_copy_is_newer() {
        let t = |h: u32| {
            chrono::NaiveDate::from_ymd_opt(2026, 6, 1)
                .unwrap()
                .and_hms_opt(h, 0, 0)
        };
        let mut a = entry("1", "", "Bank", "x");
        let mut b = entry("1", "", "Bank", "y");
        a.modified = t(10);
        b.modified = t(12);
        assert_eq!(
            compare(&[a.clone()], &[b.clone()])[0].newer,
            Some(Newer::There)
        );
        assert_eq!(compare(&[b], &[a])[0].newer, Some(Newer::Here));
    }
}
