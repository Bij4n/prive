//! Opening a KDBX database into a flat list of entries.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keepass::db::{GroupRef, fields};
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

use crate::entry::Entry;
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
        let mut entries = Vec::new();
        walk(&db.root(), "", &mut entries);
        Ok(Db {
            path: path.to_path_buf(),
            entries,
        })
    }
}

fn walk(group: &GroupRef<'_>, path: &str, out: &mut Vec<Entry>) {
    for e in group.entries() {
        let get = |k: &str| e.get(k).unwrap_or("").to_string();
        out.push(Entry {
            uuid: e.id().uuid().to_string(),
            group: path.to_string(),
            title: get(fields::TITLE),
            username: get(fields::USERNAME),
            url: get(fields::URL),
            notes: get(fields::NOTES),
            password: Zeroizing::new(get(fields::PASSWORD)),
            ..Entry::default()
        });
    }
    for sub in group.groups() {
        let p = if path.is_empty() {
            sub.name.clone()
        } else {
            format!("{path}/{}", sub.name)
        };
        walk(&sub, &p, out);
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
}
