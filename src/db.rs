//! Opening a KDBX database into a flat list of entries.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keepass::db::{GroupRef, fields};
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

use crate::entry::{CustomField, Entry};
use crate::unlock::Credentials;

pub struct Db {
    pub path: PathBuf,
    pub entries: Vec<Entry>,
}

impl Db {
    pub fn open(path: &Path, creds: &Credentials) -> Result<Db> {
        let mut file =
            File::open(path).with_context(|| format!("opening database {}", path.display()))?;
        let mut key = DatabaseKey::new();
        if let Some(pw) = &creds.password {
            key = key.with_password(pw);
        }
        if let Some(kf) = &creds.keyfile {
            let mut f =
                File::open(kf).with_context(|| format!("opening key file {}", kf.display()))?;
            key = key
                .with_keyfile(&mut f)
                .with_context(|| format!("reading key file {}", kf.display()))?;
        }
        let db = Database::open(&mut file, key)
            .with_context(|| format!("reading database {}", path.display()))?;
        let recycle = db.recycle_bin().map(|g| g.id());
        let mut entries = Vec::new();
        walk(&db.root(), "", recycle, &mut entries);
        crate::entry::sort_by_path(&mut entries);
        Ok(Db {
            path: path.to_path_buf(),
            entries,
        })
    }
}

/// Collect entries depth-first, leaving out the recycle bin and everything in it.
fn walk(
    group: &GroupRef<'_>,
    path: &str,
    recycle: Option<keepass::db::GroupId>,
    out: &mut Vec<Entry>,
) {
    for e in group.entries() {
        let get = |k: &str| e.get(k).unwrap_or("").to_string();
        let mut custom: Vec<CustomField> = e
            .fields
            .iter()
            .filter(|(k, _)| !fields::KNOWN_FIELDS.contains(&k.as_str()))
            .map(|(k, v)| CustomField {
                name: k.clone(),
                value: Zeroizing::new(v.get().clone()),
                protected: v.is_protected(),
            })
            .collect();
        custom.sort_by(|a, b| a.name.cmp(&b.name));
        let mut attachments: Vec<String> =
            e.attachments_named().map(|(n, _)| n.to_string()).collect();
        attachments.sort();
        out.push(Entry {
            uuid: e.id().uuid().to_string(),
            group: path.to_string(),
            title: get(fields::TITLE),
            username: get(fields::USERNAME),
            url: get(fields::URL),
            notes: get(fields::NOTES),
            password: Zeroizing::new(get(fields::PASSWORD)),
            custom,
            tags: e.tags.clone(),
            quality_check: e.quality_check,
            attachments,
            modified: e.times.last_modification,
            expires: if e.times.expires == Some(true) {
                e.times.expiry
            } else {
                None
            },
        });
    }
    for sub in group.groups() {
        if Some(sub.id()) == recycle {
            continue;
        }
        let p = if path.is_empty() {
            sub.name.clone()
        } else {
            format!("{path}/{}", sub.name)
        };
        walk(&sub, &p, recycle, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    pub(crate) fn creds(pw: &str) -> Credentials {
        Credentials {
            password: Some(Zeroizing::new(pw.into())),
            keyfile: None,
        }
    }

    #[test]
    fn opens_a_keepassxc_database() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let gh = db
            .entries
            .iter()
            .find(|e| e.path() == "Work/GitHub")
            .unwrap();
        assert_eq!(gh.username, "demo");
        assert_eq!(*gh.password, "gh-Secret-1");
        assert_eq!(gh.url, "https://github.com");
        assert!(gh.notes.contains("ünïcödé"));
    }

    #[test]
    fn custom_fields_keep_their_protected_flag() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let gh = db
            .entries
            .iter()
            .find(|e| e.path() == "Work/GitHub")
            .unwrap();
        let names: Vec<(&str, bool)> = gh
            .custom
            .iter()
            .map(|c| (c.name.as_str(), c.protected))
            .collect();
        assert_eq!(names, [("API key", true), ("otp", true), ("plan", false)]);
        assert_eq!(gh.field("plan"), Some("team"));
    }

    #[test]
    fn tags_and_expiry() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let gh = db
            .entries
            .iter()
            .find(|e| e.path() == "Work/GitHub")
            .unwrap();
        // KeePassXC stores tags sorted.
        assert_eq!(gh.tags, ["cloud", "dev"]);
        assert!(gh.modified.is_some());
        assert!(gh.expires.is_none());
        let vpn = db.entries.iter().find(|e| e.title == "Old VPN").unwrap();
        assert_eq!(vpn.expires.unwrap().date().to_string(), "2025-01-01");
    }

    #[test]
    fn report_exclusion_survives_from_keepassxc() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let wifi = db.entries.iter().find(|e| e.title == "Wi-Fi").unwrap();
        assert!(!wifi.quality_check);
        assert!(
            db.entries
                .iter()
                .find(|e| e.title == "Bank")
                .unwrap()
                .quality_check
        );
    }

    #[test]
    fn attachment_names() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let gh = db
            .entries
            .iter()
            .find(|e| e.path() == "Work/GitHub")
            .unwrap();
        assert_eq!(gh.attachments, ["deploy.txt"]);
    }

    #[test]
    fn the_recycle_bin_is_left_out() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        assert!(db.entries.iter().all(|e| e.title != "Deleted thing"));
        assert!(
            db.entries
                .iter()
                .all(|e| !e.group.starts_with("Recycle Bin"))
        );
    }

    #[test]
    fn entries_come_sorted_by_path() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let paths: Vec<String> = db.entries.iter().map(Entry::path).collect();
        let mut sorted = paths.clone();
        sorted.sort_by_key(|p| p.to_lowercase());
        assert_eq!(paths, sorted);
        assert_eq!(paths.first().map(String::as_str), Some("Bank"));
    }
}
