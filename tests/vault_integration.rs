/// Integration tests for vault operations.

#[test]
fn test_vault_create_and_load_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"test-password").unwrap();
    let vault = prive::vault::storage::VaultStorage::load(&path, b"test-password").unwrap();
    assert_eq!(vault.version, 1);
    assert!(vault.entries.is_empty());
    assert!(vault.secure_notes.is_empty());
}

#[test]
fn test_vault_entry_crud() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"pass").unwrap();
    let mut vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();

    // Add entry
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "GitHub".into(),
        Some("johnd".into()),
        "secret123".into(),
        Some("https://github.com".into()),
        None,
        vec!["dev".into()],
    ));

    prive::vault::storage::VaultStorage::save(&path, &vault, b"pass").unwrap();

    // Reload and verify
    let vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();
    assert_eq!(vault.entries.len(), 1);
    assert_eq!(vault.entries[0].name, "GitHub");
    assert_eq!(vault.entries[0].password, "secret123");
}

#[test]
fn test_vault_password_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"pass").unwrap();
    let mut vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();

    vault.entries.push(prive::vault::model::VaultEntry::new(
        "Test".into(), None, "old_pass".into(), None, None, vec![],
    ));

    // Rotate password
    vault.entries[0].rotate_password("new_pass".into());
    prive::vault::storage::VaultStorage::save(&path, &vault, b"pass").unwrap();

    // Reload and verify history
    let vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();
    assert_eq!(vault.entries[0].password, "new_pass");
    assert_eq!(vault.entries[0].password_history.len(), 1);
    assert_eq!(vault.entries[0].password_history[0].password, "old_pass");
}

#[test]
fn test_vault_secure_notes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"pass").unwrap();
    let mut vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();

    vault.secure_notes.push(prive::vault::model::SecureNote::new(
        "API Keys".into(),
        "sk-1234567890abcdef".into(),
        vec!["work".into()],
    ));

    prive::vault::storage::VaultStorage::save(&path, &vault, b"pass").unwrap();

    let vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();
    assert_eq!(vault.secure_notes.len(), 1);
    assert_eq!(vault.secure_notes[0].title, "API Keys");
}

#[test]
fn test_vault_search() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"pass").unwrap();
    let mut vault = prive::vault::storage::VaultStorage::load(&path, b"pass").unwrap();

    vault.entries.push(prive::vault::model::VaultEntry::new(
        "GitHub".into(), Some("johnd".into()), "pass1".into(),
        Some("https://github.com".into()), None, vec!["dev".into()],
    ));
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "Gmail".into(), Some("johnd@gmail.com".into()), "pass2".into(),
        Some("https://gmail.com".into()), None, vec!["email".into()],
    ));
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "AWS".into(), Some("admin".into()), "pass3".into(),
        None, None, vec!["cloud".into(), "dev".into()],
    ));

    // Search by name
    let results = vault.search("git");
    assert_eq!(results.len(), 1);

    // Search by tag
    let results = vault.search("dev");
    assert_eq!(results.len(), 2);

    // Search by username
    let results = vault.search("johnd");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_vault_backup_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_path = tmp.path().join("vault.pv");
    let backup_dir = tmp.path().join("backups");

    prive::vault::storage::VaultStorage::create(&vault_path, b"pass").unwrap();

    let manager = prive::vault::backup::BackupManager::with_dir(backup_dir, 5);
    let backup_path = manager.create_backup(&vault_path).unwrap();
    assert!(backup_path.exists());

    let backups = manager.list_backups().unwrap();
    assert_eq!(backups.len(), 1);
}

#[test]
fn test_vault_migration_check() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.pv");

    prive::vault::storage::VaultStorage::create(&path, b"pass").unwrap();

    assert!(!prive::vault::migrate::needs_migration(&path).unwrap());
    assert_eq!(prive::vault::migrate::vault_version(&path).unwrap(), 1);

    let info = prive::vault::migrate::validate_vault_header(&path).unwrap();
    assert_eq!(info.version, 1);
    assert!(info.file_size > 0);
}

#[test]
fn test_import_export_csv_roundtrip() {
    let mut vault = prive::vault::model::Vault::new();
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "Test".into(),
        Some("user".into()),
        "pass123".into(),
        Some("https://test.com".into()),
        Some("a note".into()),
        vec!["tag1".into()],
    ));

    // Export
    let csv = prive::vault::import::export_csv(&vault);
    assert!(csv.contains("Test"));
    assert!(csv.contains("pass123"));

    // Re-import
    let entries = prive::vault::import::import_csv(&csv).unwrap();
    assert!(entries.len() >= 1);
}

#[test]
fn test_totp_generation() {
    let secret = b"12345678901234567890";
    let code = prive::crypto::totp::generate_totp_at(secret, 59, 30, 6).unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_password_strength_analysis() {
    let weak = prive::crypto::strength::analyze_strength("a");
    assert!(matches!(weak.level, prive::crypto::strength::StrengthLevel::VeryWeak | prive::crypto::strength::StrengthLevel::Weak));

    let strong = prive::crypto::strength::analyze_strength("Xk9#mP2$vL7@nQ4!wR8%");
    assert!(strong.score > weak.score);
    assert!(strong.entropy_bits > weak.entropy_bits);
}

#[test]
fn test_audit_vault() {
    let mut vault = prive::vault::model::Vault::new();
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "weak".into(), None, "abc".into(), None, None, vec![],
    ));
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "dup1".into(), None, "same_password!".into(), None, None, vec![],
    ));
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "dup2".into(), None, "same_password!".into(), None, None, vec![],
    ));

    let report = prive::crypto::audit::audit_vault(&vault);
    assert_eq!(report.total_entries, 3);
    assert!(report.score < 100);
    assert!(!report.weak_passwords.is_empty());
    assert!(!report.duplicate_passwords.is_empty());
}

#[test]
fn test_pgp_trust_db() {
    let mut db = prive::pgp::trust::TrustDb::default();
    db.set_trust("ABC", "FP123", prive::pgp::trust::TrustLevel::Full, None);

    assert_eq!(db.get_trust("ABC"), prive::pgp::trust::TrustLevel::Full);
    assert_eq!(db.get_trust("XYZ"), prive::pgp::trust::TrustLevel::Unknown);

    let json = serde_json::to_string(&db).unwrap();
    let loaded: prive::pgp::trust::TrustDb = serde_json::from_str(&json).unwrap();
    assert_eq!(loaded.get_trust("ABC"), prive::pgp::trust::TrustLevel::Full);
}

#[test]
fn test_config_defaults() {
    let config = prive::config::AppConfig::default();
    assert_eq!(config.generate.default_length, 20);
    assert_eq!(config.clipboard.clear_after_seconds, 45);
    assert_eq!(config.backup.max_backups, 10);
    assert_eq!(config.session.timeout_seconds, 300);
    assert!(config.vault.active_vault.is_none());
}

#[test]
fn test_session_not_running() {
    assert!(!prive::session::is_agent_running());
    assert!(prive::session::get_vault_from_agent().is_none());
}
