//! Conflict copies that sync tools leave next to a database when two devices changed it
//! before syncing. `prive doctor` points them out; `prive diff` shows what is in them.

use std::path::{Path, PathBuf};

/// Whether `name` is a conflict copy of a database whose file is called `stem` + `.kdbx`:
///
/// - Syncthing: `Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx`
/// - Nextcloud and ownCloud: `Passwords (conflicted copy 2026-06-12 101500).kdbx`
/// - Dropbox: `Passwords (Laptop's conflicted copy 2026-06-12).kdbx`
/// - Resilio Sync and others: `Passwords.Conflict.kdbx`, `Passwords (conflict).kdbx`
pub fn is_conflict_copy(stem: &str, name: &str) -> bool {
    let Some(rest) = name.strip_prefix(stem) else {
        return false;
    };
    let Some(middle) = rest
        .strip_suffix(".kdbx")
        .or_else(|| rest.strip_suffix(".KDBX"))
    else {
        return false;
    };
    let m = middle.to_ascii_lowercase();
    !m.is_empty()
        && (m.starts_with(".sync-conflict-")
            || (m.starts_with(" (") && m.ends_with(')') && m.contains("conflict"))
            || m == ".conflict")
}

/// The conflict copies of `db` in its directory, sorted by name.
pub fn conflict_copies(db: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (db.parent(), db.file_stem().and_then(|s| s.to_str())) else {
        return Vec::new();
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| is_conflict_copy(stem, n))
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sync_tools_use() {
        for name in [
            "Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx",
            "Passwords (conflicted copy 2026-06-12 101500).kdbx",
            "Passwords (Laptop's conflicted copy 2026-06-12).kdbx",
            "Passwords.Conflict.kdbx",
            "Passwords (conflict).kdbx",
        ] {
            assert!(is_conflict_copy("Passwords", name), "{name}");
        }
        for name in [
            "Passwords.kdbx",
            "Passwords.kdbx.old",
            "Passwords-backup.kdbx",
            "Passwords (2).kdbx",
            "Work.sync-conflict-20260612-101500-ABCDEFG.kdbx",
            "Passwords.sync-conflict-20260612-101500-ABCDEFG.keyx",
        ] {
            assert!(!is_conflict_copy("Passwords", name), "{name}");
        }
    }

    #[test]
    fn found_next_to_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("Passwords.kdbx");
        for f in [
            "Passwords.kdbx",
            "Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx",
            "Passwords (conflicted copy 2026-06-12 101500).kdbx",
            "Other.sync-conflict-20260612-101500-ABCDEFG.kdbx",
        ] {
            std::fs::write(dir.path().join(f), b"x").unwrap();
        }
        let found: Vec<String> = conflict_copies(&db)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            found,
            [
                "Passwords (conflicted copy 2026-06-12 101500).kdbx",
                "Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx",
            ]
        );
        assert!(conflict_copies(&dir.path().join("none/x.kdbx")).is_empty());
    }
}
