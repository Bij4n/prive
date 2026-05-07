//! Integration tests for features added in v0.3.0–v0.5.0:
//! secure notes, tags, vault sharing, password history, expiry auditing.

use prive::vault::model::{SecureNote, Vault, VaultEntry};
use prive::vault::storage::VaultStorage;

fn make_vault(tmp: &tempfile::TempDir) -> (std::path::PathBuf, Vault) {
    let path = tmp.path().join("test.pv");
    VaultStorage::create(&path, b"pw").unwrap();
    let vault = VaultStorage::load(&path, b"pw").unwrap();
    (path, vault)
}

fn save_and_reload(path: &std::path::Path, vault: &Vault) -> Vault {
    VaultStorage::save(path, vault, b"pw").unwrap();
    VaultStorage::load(path, b"pw").unwrap()
}

// --- Secure notes ---

#[test]
fn test_secure_note_add_and_get() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    vault.secure_notes.push(SecureNote::new(
        "wifi-pw".into(),
        "my-secret-ssid".into(),
        vec![],
    ));
    let vault = save_and_reload(&path, &vault);

    let note = vault.find_note_by_title("wifi-pw").unwrap();
    assert_eq!(note.content, "my-secret-ssid");
}

#[test]
fn test_secure_note_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    vault.secure_notes.push(SecureNote::new(
        "to-delete".into(),
        "content".into(),
        vec![],
    ));
    vault.remove_note_by_title("to-delete");
    let vault = save_and_reload(&path, &vault);

    assert!(vault.find_note_by_title("to-delete").is_none());
}

#[test]
fn test_secure_note_search() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, mut vault) = make_vault(&tmp);

    vault.secure_notes.push(SecureNote::new(
        "alpha".into(),
        "needle in haystack".into(),
        vec![],
    ));
    vault.secure_notes.push(SecureNote::new(
        "beta".into(),
        "nothing relevant".into(),
        vec![],
    ));

    let results = vault.search_notes("needle");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].title, "alpha");
}

#[test]
fn test_secure_note_with_tags() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    vault.secure_notes.push(SecureNote::new(
        "tagged-note".into(),
        "content".into(),
        vec!["personal".into(), "important".into()],
    ));
    let vault = save_and_reload(&path, &vault);

    let note = vault.find_note_by_title("tagged-note").unwrap();
    assert!(note.tags.contains(&"personal".to_string()));
    assert!(note.tags.contains(&"important".to_string()));
}

// --- Tags ---

#[test]
fn test_tag_rename_across_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    vault.entries.push(VaultEntry::new(
        "entry1".into(),
        None,
        "pass".into(),
        None,
        None,
        vec!["work".into()],
    ));
    vault.entries.push(VaultEntry::new(
        "entry2".into(),
        None,
        "pass2".into(),
        None,
        None,
        vec!["work".into(), "dev".into()],
    ));

    // Rename "work" -> "office"
    for entry in &mut vault.entries {
        for tag in &mut entry.tags {
            if tag.eq_ignore_ascii_case("work") {
                *tag = "office".to_string();
            }
        }
    }

    let vault = save_and_reload(&path, &vault);

    for entry in &vault.entries {
        assert!(!entry.tags.contains(&"work".to_string()));
        assert!(entry.tags.contains(&"office".to_string()));
    }
}

#[test]
fn test_tag_delete_across_entries_and_notes() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    vault.entries.push(VaultEntry::new(
        "e1".into(),
        None,
        "p".into(),
        None,
        None,
        vec!["remove-me".into(), "keep".into()],
    ));
    vault.secure_notes.push(SecureNote::new(
        "n1".into(),
        "content".into(),
        vec!["remove-me".into()],
    ));

    for entry in &mut vault.entries {
        entry.tags.retain(|t| !t.eq_ignore_ascii_case("remove-me"));
    }
    for note in &mut vault.secure_notes {
        note.tags.retain(|t| !t.eq_ignore_ascii_case("remove-me"));
    }

    let vault = save_and_reload(&path, &vault);

    assert!(!vault.entries[0].tags.contains(&"remove-me".to_string()));
    assert!(vault.entries[0].tags.contains(&"keep".to_string()));
    assert!(vault.secure_notes[0].tags.is_empty());
}

// --- Password history ---

#[test]
fn test_password_history_tracks_rotations() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    let mut entry = VaultEntry::new("site".into(), None, "initial".into(), None, None, vec![]);
    entry.rotate_password("second".into());
    entry.rotate_password("third".into());
    vault.entries.push(entry);

    let vault = save_and_reload(&path, &vault);

    let e = vault.find_by_name("site").unwrap();
    assert_eq!(e.password, "third");
    assert_eq!(e.password_history.len(), 2);
    assert_eq!(e.password_history[0].password, "initial");
    assert_eq!(e.password_history[1].password, "second");
}

#[test]
fn test_password_history_persists_across_save_load() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, mut vault) = make_vault(&tmp);

    let mut entry = VaultEntry::new("test".into(), None, "v1".into(), None, None, vec![]);
    for i in 2..=5 {
        entry.rotate_password(format!("v{i}"));
    }
    vault.entries.push(entry);

    let vault = save_and_reload(&path, &vault);
    let e = vault.find_by_name("test").unwrap();
    assert_eq!(e.password, "v5");
    assert_eq!(e.password_history.len(), 4);
}

// --- Expiry auditing ---

#[test]
fn test_audit_expired_entry_flagged_critical() {
    use prive::crypto::audit::{Severity, audit_vault};

    let mut vault = Vault::new();
    let mut entry = VaultEntry::new(
        "expired-cred".into(),
        None,
        "StrongP@ss1234".into(),
        None,
        None,
        vec![],
    );
    entry.expires_at = Some(chrono::Utc::now() - chrono::Duration::days(10));
    vault.entries.push(entry);

    let report = audit_vault(&vault);
    let expired = report
        .expiring_entries
        .iter()
        .find(|i| i.entry_name == "expired-cred");
    assert!(expired.is_some());
    assert_eq!(expired.unwrap().severity, Severity::Critical);
}

#[test]
fn test_audit_expiring_soon_flagged_warning() {
    use prive::crypto::audit::{Severity, audit_vault};

    let mut vault = Vault::new();
    let mut entry = VaultEntry::new(
        "soon-cred".into(),
        None,
        "StrongP@ss1234".into(),
        None,
        None,
        vec![],
    );
    entry.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(7));
    vault.entries.push(entry);

    let report = audit_vault(&vault);
    let expiring = report
        .expiring_entries
        .iter()
        .find(|i| i.entry_name == "soon-cred");
    assert!(expiring.is_some());
    assert_eq!(expiring.unwrap().severity, Severity::Warning);
}

#[test]
fn test_audit_no_expiry_not_flagged() {
    use prive::crypto::audit::audit_vault;

    let mut vault = Vault::new();
    vault.entries.push(VaultEntry::new(
        "no-expiry".into(),
        None,
        "StrongP@ss1234".into(),
        None,
        None,
        vec![],
    ));

    let report = audit_vault(&vault);
    assert!(report.expiring_entries.is_empty());
}

// --- Vault search ---

#[test]
fn test_vault_search_by_url() {
    let mut vault = Vault::new();
    vault.entries.push(VaultEntry::new(
        "My Bank".into(),
        Some("user".into()),
        "pass".into(),
        Some("https://bank.example.com".into()),
        None,
        vec![],
    ));

    let results = vault.search("bank.example");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "My Bank");
}

#[test]
fn test_vault_search_by_tag() {
    let mut vault = Vault::new();
    vault.entries.push(VaultEntry::new(
        "entry".into(),
        None,
        "pass".into(),
        None,
        None,
        vec!["finance".into()],
    ));

    let results = vault.search("finance");
    assert_eq!(results.len(), 1);
}

#[test]
fn test_vault_search_case_insensitive() {
    let mut vault = Vault::new();
    vault.entries.push(VaultEntry::new(
        "GitHub".into(),
        None,
        "pass".into(),
        None,
        None,
        vec![],
    ));

    assert!(!vault.search("github").is_empty());
    assert!(!vault.search("GITHUB").is_empty());
    assert!(!vault.search("GiThUb").is_empty());
}
