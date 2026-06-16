//! Opening a KDBX database into a flat list of entries.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use keepass::config::{
    CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::{GroupRef, fields};
use keepass::error::{CryptographyError, DatabaseKeyError, DatabaseOpenError};
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::{CustomField, Entry};
use crate::error::Failure;
use crate::unlock::Credentials;

pub struct Db {
    pub path: PathBuf,
    pub entries: Vec<Entry>,
    pub info: Info,
}

/// How a database is stored and protected, and how much is in it. Nothing here is secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Info {
    /// `KDBX 4.1`, `KDBX 3.1`, ...
    pub format: String,
    pub cipher: String,
    /// How protected fields (passwords) are encrypted inside the file.
    pub inner_cipher: String,
    pub kdf: Kdf,
    pub compressed: bool,
    /// The app that last saved the file, as it names itself (`KeePassXC`, `KeePassDX`, ...).
    pub generator: Option<String>,
    pub name: Option<String>,
    /// Groups below the root, leaving out the recycle bin and what is in it.
    pub groups: usize,
    /// Entries waiting in the recycle bin.
    pub recycled: usize,
    pub key_changed: Option<NaiveDateTime>,
}

/// The key derivation settings: what makes each password guess slow.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Kdf {
    /// `Argon2id`, `Argon2d` or `AES-KDF`.
    pub algorithm: String,
    /// Argon2 passes, or AES-KDF rounds.
    pub iterations: u64,
    /// Argon2 only.
    pub memory_kib: Option<u64>,
    pub parallelism: Option<u32>,
}

impl Kdf {
    fn from_config(c: &KdfConfig) -> Kdf {
        match c {
            KdfConfig::Aes { rounds } => Kdf {
                algorithm: "AES-KDF".into(),
                iterations: *rounds,
                ..Kdf::default()
            },
            KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                ..
            } => Kdf {
                algorithm: "Argon2d".into(),
                iterations: *iterations,
                memory_kib: Some(*memory),
                parallelism: Some(*parallelism),
            },
            KdfConfig::Argon2id {
                iterations,
                memory,
                parallelism,
                ..
            } => Kdf {
                algorithm: "Argon2id".into(),
                iterations: *iterations,
                memory_kib: Some(*memory),
                parallelism: Some(*parallelism),
            },
            other => Kdf {
                algorithm: format!("{other:?}"),
                ..Kdf::default()
            },
        }
    }

    /// `Argon2id, 64 MiB, 10 passes, 2 threads` or `AES-KDF, 60000 rounds`.
    pub fn describe(&self) -> String {
        match self.memory_kib {
            Some(kib) => format!(
                "{}, {} MiB, {} passes, {} threads",
                self.algorithm,
                kib / 1024,
                self.iterations,
                self.parallelism.unwrap_or(1)
            ),
            None => format!("{}, {} rounds", self.algorithm, self.iterations),
        }
    }
}

fn describe_format(c: &DatabaseConfig) -> String {
    // keepass prints `KDBX4.1`; KeePassXC's settings say `KDBX 4.1`.
    c.version.to_string().replacen("KDBX", "KDBX ", 1)
}

fn describe_cipher(c: &OuterCipherConfig) -> String {
    match c {
        OuterCipherConfig::AES256 => "AES-256".into(),
        OuterCipherConfig::Twofish => "Twofish".into(),
        OuterCipherConfig::ChaCha20 => "ChaCha20".into(),
        other => format!("{other:?}"),
    }
}

fn describe_inner(c: &InnerCipherConfig) -> String {
    match c {
        InnerCipherConfig::Plain => "none".into(),
        InnerCipherConfig::Salsa20 => "Salsa20".into(),
        InnerCipherConfig::ChaCha20 => "ChaCha20".into(),
        other => format!("{other:?}"),
    }
}

/// Every entry in a group and the groups below it.
fn count_entries(group: &GroupRef<'_>) -> usize {
    group.entries().count() + group.groups().map(|g| count_entries(&g)).sum::<usize>()
}

/// Groups below `group`, not counting `skip` or anything inside it.
fn count_groups(group: &GroupRef<'_>, skip: Option<keepass::db::GroupId>) -> usize {
    group
        .groups()
        .filter(|g| Some(g.id()) != skip)
        .map(|g| 1 + count_groups(&g, skip))
        .sum()
}

/// Read a database file and check it is KeePass, before anyone is asked for a password.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("opening database {}", path.display()))?;
    // KeePass files start with 0x9AA2D903; anything else gets a plain answer instead of a
    // parser error.
    if bytes.len() < 12 || bytes[..4] != [0x03, 0xd9, 0xa2, 0x9a] {
        anyhow::bail!("{} is not a KeePass database", path.display());
    }
    Ok(bytes)
}

impl Db {
    pub fn open(path: &Path, creds: &Credentials) -> Result<Db> {
        Db::from_bytes(path, &read_file(path)?, creds)
    }

    pub fn from_bytes(path: &Path, bytes: &[u8], creds: &Credentials) -> Result<Db> {
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
        let db = match Database::open(&mut &bytes[..], key) {
            Ok(db) => db,
            // KDBX 4 notices a wrong key in its header check. KDBX 3.1 has no such check, so a
            // wrong key shows up as a padding failure when the payload is decrypted.
            Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey))
            | Err(DatabaseOpenError::Cryptography(CryptographyError::InvalidPadding(_))) => {
                return Err(Failure::BadCredentials.into());
            }
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("reading database {}", path.display()))
                );
            }
        };
        let recycle = db.recycle_bin().map(|g| g.id());
        let mut entries = Vec::new();
        walk(&db.root(), "", recycle, &mut entries);
        crate::entry::sort_by_path(&mut entries);
        let info = Info {
            format: describe_format(&db.config),
            cipher: describe_cipher(&db.config.outer_cipher_config),
            inner_cipher: describe_inner(&db.config.inner_cipher_config),
            kdf: Kdf::from_config(&db.config.kdf_config),
            compressed: db.config.compression_config != CompressionConfig::None,
            generator: db.meta.generator.clone().filter(|g| !g.is_empty()),
            name: db.meta.database_name.clone().filter(|n| !n.is_empty()),
            groups: count_groups(&db.root(), recycle),
            recycled: db.recycle_bin().map(|g| count_entries(&g)).unwrap_or(0),
            key_changed: db.meta.master_key_changed,
        };
        Ok(Db {
            path: path.to_path_buf(),
            entries,
            info,
        })
    }
}

/// Earlier versions, newest first, whatever order the file keeps them in.
fn history(e: &keepass::db::EntryRef<'_>) -> Vec<crate::entry::Version> {
    let Some(h) = &e.history else {
        return Vec::new();
    };
    let mut versions: Vec<crate::entry::Version> = h
        .get_entries()
        .iter()
        .map(|old| crate::entry::Version {
            modified: old.times.last_modification,
            username: old.get(fields::USERNAME).unwrap_or("").to_string(),
            password: Zeroizing::new(old.get(fields::PASSWORD).unwrap_or("").to_string()),
        })
        .collect();
    versions.sort_by_key(|v| std::cmp::Reverse(v.modified));
    versions
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
        let mut attachments: Vec<crate::entry::Attachment> = e
            .attachments_named()
            .map(|(n, a)| crate::entry::Attachment {
                name: n.to_string(),
                data: Zeroizing::new(a.data.get().clone()),
            })
            .collect();
        attachments.sort_by(|a, b| a.name.cmp(&b.name));
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
            history: history(&e),
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
        assert_eq!(gh.attachment_names(), ["deploy.txt"]);
        assert_eq!(&gh.attachments[0].data[..], b"deploy-key-bytes\n");
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

    fn is_bad_credentials(e: &anyhow::Error) -> bool {
        matches!(e.downcast_ref::<Failure>(), Some(Failure::BadCredentials))
    }

    #[test]
    fn a_wrong_password_is_bad_credentials() {
        for f in ["kdbx31.kdbx", "kdbx40.kdbx", "kdbx41.kdbx"] {
            let err = Db::open(&fixture(f), &creds("wrong")).err().unwrap();
            assert!(is_bad_credentials(&err), "{f}: {err:#}");
        }
    }

    #[test]
    fn every_fixture_format_opens_the_same() {
        let paths = |f: &str| -> Vec<String> {
            let db = Db::open(&fixture(f), &creds("fixture-pass")).unwrap();
            db.entries.iter().map(Entry::path).collect()
        };
        let v31 = paths("kdbx31.kdbx");
        assert_eq!(v31, paths("kdbx40.kdbx"));
        assert_eq!(v31, paths("kdbx41.kdbx"));
        assert_eq!(
            v31.len(),
            7,
            "seven live entries; the eighth is in the recycle bin"
        );
    }

    #[test]
    fn every_fixture_format_keeps_fields_tags_files_and_history() {
        let shape = |f: &str| -> Vec<String> {
            let db = Db::open(&fixture(f), &creds("fixture-pass")).unwrap();
            db.entries
                .iter()
                .map(|e| {
                    let custom: Vec<String> = e
                        .custom
                        .iter()
                        .map(|c| format!("{}={}:{}", c.name, *c.value, c.protected))
                        .collect();
                    format!(
                        "{} {} {:?} {:?} {:?} {}",
                        e.path(),
                        *e.password,
                        custom,
                        e.tags,
                        e.attachment_names(),
                        e.history.len()
                    )
                })
                .collect()
        };
        let v41 = shape("kdbx41.kdbx");
        assert_eq!(shape("kdbx31.kdbx"), v41);
        assert_eq!(shape("kdbx40.kdbx"), v41);
    }

    #[test]
    fn info_describes_how_each_fixture_is_stored() {
        let v41 = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        assert_eq!(v41.info.format, "KDBX 4.1");
        // keepassxc-cli's import keeps AES-KDF; its app picks Argon2id for new databases.
        assert_eq!(v41.info.kdf.algorithm, "AES-KDF");
        assert_eq!(v41.info.kdf.iterations, 1_000_000);
        assert_eq!(v41.info.cipher, "AES-256");
        assert!(v41.info.compressed);
        // The import keeps the generator named in source.xml.
        assert_eq!(v41.info.generator.as_deref(), Some("prive fixtures"));
        assert_eq!(v41.info.name.as_deref(), Some("Fixture"));
        assert_eq!(v41.info.recycled, 1);
        // Work, Work/Cloud and Personal; the recycle bin is not counted.
        assert_eq!(v41.info.groups, 3);
        let v31 = Db::open(&fixture("kdbx31.kdbx"), &creds("fixture-pass")).unwrap();
        assert_eq!(v31.info.format, "KDBX 3.1");
        assert_eq!(v31.info.kdf.algorithm, "AES-KDF");
        assert!(v31.info.kdf.memory_kib.is_none());
        assert_eq!(v31.info.inner_cipher, "Salsa20");
    }

    #[test]
    fn kdf_descriptions() {
        let argon = Kdf {
            algorithm: "Argon2id".into(),
            iterations: 10,
            memory_kib: Some(65536),
            parallelism: Some(2),
        };
        assert_eq!(argon.describe(), "Argon2id, 64 MiB, 10 passes, 2 threads");
        let aes = Kdf {
            algorithm: "AES-KDF".into(),
            iterations: 60000,
            ..Kdf::default()
        };
        assert_eq!(aes.describe(), "AES-KDF, 60000 rounds");
    }

    #[test]
    fn key_file_databases_need_the_key_file() {
        let with = Credentials {
            password: Some(Zeroizing::new("fixture-pass".into())),
            keyfile: Some(fixture("keyfile.keyx")),
        };
        let db = Db::open(&fixture("keyfile.kdbx"), &with).unwrap();
        assert_eq!(db.entries[0].title, "Key file entry");
        let without = Db::open(&fixture("keyfile.kdbx"), &creds("fixture-pass"))
            .err()
            .unwrap();
        assert!(is_bad_credentials(&without), "{without:#}");
    }

    #[test]
    fn history_is_read() {
        let db = Db::open(&fixture("kdbx41.kdbx"), &creds("fixture-pass")).unwrap();
        let gh = db
            .entries
            .iter()
            .find(|e| e.path() == "Work/GitHub")
            .unwrap();
        assert_eq!(gh.history.len(), 1);
        assert_eq!(*gh.history[0].password, "old-password");
    }
}
