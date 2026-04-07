/// Edge case tests for prive.

// --- Unicode handling ---

#[test]
fn test_vault_entry_with_unicode_name() {
    let entry = prive::vault::model::VaultEntry::new(
        "日本語テスト".into(),
        Some("ユーザー".into()),
        "パスワード123!".into(),
        Some("https://例え.jp".into()),
        Some("メモ".into()),
        vec!["タグ".into()],
    );
    assert_eq!(entry.name, "日本語テスト");

    // Serialize and deserialize
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: prive::vault::model::VaultEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "日本語テスト");
    assert_eq!(parsed.password, "パスワード123!");
}

#[test]
fn test_vault_entry_with_emoji() {
    let entry = prive::vault::model::VaultEntry::new(
        "🔑 My Key".into(),
        Some("user@email.com".into()),
        "p@ss🔒word".into(),
        None,
        None,
        vec!["🏷️".into()],
    );
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: prive::vault::model::VaultEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "🔑 My Key");
}

#[test]
fn test_secure_note_with_multiline_unicode() {
    let note = prive::vault::model::SecureNote::new(
        "多言語ノート".into(),
        "Line 1: English\nLine 2: 日本語\nLine 3: العربية\nLine 4: 한국어".into(),
        vec![],
    );
    let json = serde_json::to_string(&note).unwrap();
    let parsed: prive::vault::model::SecureNote = serde_json::from_str(&json).unwrap();
    assert!(parsed.content.contains("日本語"));
    assert!(parsed.content.contains("العربية"));
}

// --- Empty / boundary inputs ---

#[test]
fn test_vault_search_empty_query() {
    let mut vault = prive::vault::model::Vault::new();
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "test".into(),
        None,
        "pass".into(),
        None,
        None,
        vec![],
    ));
    // Empty search should match everything (contains "")
    let results = vault.search("");
    assert_eq!(results.len(), 1);
}

#[test]
fn test_vault_search_no_entries() {
    let vault = prive::vault::model::Vault::new();
    let results = vault.search("anything");
    assert!(results.is_empty());
}

#[test]
fn test_password_gen_minimum_length() {
    let pw = prive::crypto::password_gen::generate_password(1, false, false, false);
    assert_eq!(pw.len(), 1);
}

#[test]
fn test_passphrase_single_word() {
    let pp = prive::crypto::password_gen::generate_passphrase(1, "-");
    assert!(!pp.contains('-'));
    assert!(!pp.is_empty());
}

#[test]
fn test_pin_single_digit() {
    let pin = prive::crypto::password_gen::generate_pin(1);
    assert_eq!(pin.len(), 1);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_entropy_single_char() {
    let e = prive::crypto::password_gen::password_entropy("a");
    assert!(e > 0.0);
}

#[test]
fn test_entropy_empty_string() {
    let e = prive::crypto::password_gen::password_entropy("");
    assert_eq!(e, 0.0);
}

// --- Large inputs ---

#[test]
fn test_large_password_generation() {
    let pw = prive::crypto::password_gen::generate_password(10000, true, true, true);
    assert_eq!(pw.len(), 10000);
}

#[test]
fn test_large_passphrase() {
    let pp = prive::crypto::password_gen::generate_passphrase(100, " ");
    assert_eq!(pp.split(' ').count(), 100);
}

#[test]
fn test_vault_many_entries() {
    let mut vault = prive::vault::model::Vault::new();
    for i in 0..1000 {
        vault.entries.push(prive::vault::model::VaultEntry::new(
            format!("entry_{i}"),
            Some(format!("user_{i}")),
            format!("pass_{i}"),
            None,
            None,
            vec![format!("tag_{}", i % 10)],
        ));
    }
    assert_eq!(vault.entries.len(), 1000);

    let results = vault.search("entry_500");
    assert_eq!(results.len(), 1);

    // Serialize roundtrip
    let json = serde_json::to_string(&vault).unwrap();
    let parsed: prive::vault::model::Vault = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.entries.len(), 1000);
}

#[test]
fn test_vault_encrypt_decrypt_large() {
    let mut vault = prive::vault::model::Vault::new();
    for i in 0..100 {
        vault.entries.push(prive::vault::model::VaultEntry::new(
            format!("entry_{i}"),
            Some(format!("user_{i}")),
            "a".repeat(1000),
            Some(format!("https://example{i}.com")),
            Some("x".repeat(5000)),
            vec!["tag".into()],
        ));
    }

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("large.pv");

    prive::vault::storage::VaultStorage::save(&path, &vault, b"password").unwrap();
    let loaded = prive::vault::storage::VaultStorage::load(&path, b"password").unwrap();
    assert_eq!(loaded.entries.len(), 100);
    assert_eq!(loaded.entries[50].password, "a".repeat(1000));
}

// --- Special characters in fields ---

#[test]
fn test_entry_with_special_chars() {
    let entry = prive::vault::model::VaultEntry::new(
        "test\"entry".into(),
        Some("user\\name".into()),
        "p@ss\nword\ttab".into(),
        Some("https://example.com/path?q=a&b=c".into()),
        Some("notes with\n\nnewlines\nand\ttabs".into()),
        vec!["tag,with,commas".into(), "tag\"quotes".into()],
    );

    let json = serde_json::to_string(&entry).unwrap();
    let parsed: prive::vault::model::VaultEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.password, "p@ss\nword\ttab");
    assert_eq!(parsed.tags[0], "tag,with,commas");
}

// --- Password history edge cases ---

#[test]
fn test_password_history_many_rotations() {
    let mut entry = prive::vault::model::VaultEntry::new(
        "test".into(),
        None,
        "pass_0".into(),
        None,
        None,
        vec![],
    );
    for i in 1..=50 {
        entry.rotate_password(format!("pass_{i}"));
    }
    assert_eq!(entry.password, "pass_50");
    assert_eq!(entry.password_history.len(), 50);
    assert_eq!(entry.password_history[0].password, "pass_0");
    assert_eq!(entry.password_history[49].password, "pass_49");
}

// --- TOTP edge cases ---

#[test]
fn test_totp_at_epoch_zero() {
    let secret = b"12345678901234567890";
    let code = prive::crypto::totp::generate_totp_at(secret, 0, 30, 6).unwrap();
    assert_eq!(code.len(), 6);
}

#[test]
fn test_totp_at_max_time() {
    let secret = b"12345678901234567890";
    let code = prive::crypto::totp::generate_totp_at(secret, u64::MAX / 30, 30, 6).unwrap();
    assert_eq!(code.len(), 6);
}

#[test]
fn test_totp_8_digits() {
    let secret = b"12345678901234567890";
    let code = prive::crypto::totp::generate_totp_at(secret, 59, 30, 8).unwrap();
    assert_eq!(code.len(), 8);
    assert_eq!(code, "94287082"); // RFC 6238 vector
}

#[test]
fn test_base32_decode_invalid() {
    let result = prive::crypto::totp::decode_base32_secret("!!!invalid!!!");
    assert!(result.is_err());
}

// --- Config edge cases ---

#[test]
fn test_config_deserialize_empty_toml() {
    let config: prive::config::AppConfig = toml::from_str("").unwrap();
    assert_eq!(config.generate.default_length, 20);
}

#[test]
fn test_config_deserialize_partial_toml() {
    let config: prive::config::AppConfig =
        toml::from_str("[generate]\ndefault_length = 32\n").unwrap();
    assert_eq!(config.generate.default_length, 32);
    assert_eq!(config.clipboard.clear_after_seconds, 45); // default
}

// --- Strength analysis edge cases ---

#[test]
fn test_strength_empty_password() {
    let report = prive::crypto::strength::analyze_strength("");
    assert!(report.score <= 20);
}

#[test]
fn test_strength_very_long_password() {
    let pw = "a".repeat(1000);
    let report = prive::crypto::strength::analyze_strength(&pw);
    // Long but only one char type, so not maximum score
    assert!(report.score > 0);
}

#[test]
fn test_strength_all_same_char() {
    let report = prive::crypto::strength::analyze_strength("aaaaaaaaaaaaaaaa");
    assert!(report.feedback.iter().any(|f| f.contains("repeated")));
}

// --- Trust DB edge cases ---

#[test]
fn test_trust_db_overwrite() {
    let mut db = prive::pgp::trust::TrustDb::default();
    db.set_trust("KEY1", "FP1", prive::pgp::trust::TrustLevel::Marginal, None);
    db.set_trust(
        "KEY1",
        "FP1",
        prive::pgp::trust::TrustLevel::Full,
        Some("upgraded".into()),
    );
    assert_eq!(db.get_trust("KEY1"), prive::pgp::trust::TrustLevel::Full);
    assert_eq!(db.list_trusted().len(), 1);
}

#[test]
fn test_parse_expiry_edge_cases() {
    assert_eq!(
        prive::pgp::trust::parse_expiry("0y"),
        Some(chrono::Duration::days(0))
    );
    assert_eq!(
        prive::pgp::trust::parse_expiry("1d"),
        Some(chrono::Duration::days(1))
    );
    assert!(prive::pgp::trust::parse_expiry("abc").is_none());
    assert!(prive::pgp::trust::parse_expiry("").is_none());
}

// --- Vault model backward compatibility ---

#[test]
fn test_vault_v1_without_notes_or_history() {
    // Simulate a v1 vault JSON without secure_notes or password_history
    let json = r#"{
        "version": 1,
        "created_at": "2025-10-16T09:00:00Z",
        "modified_at": "2025-10-16T09:00:00Z",
        "entries": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "old_entry",
            "username": "user",
            "password": "pass",
            "url": null,
            "notes": null,
            "tags": [],
            "totp_secret": null,
            "created_at": "2025-10-16T09:00:00Z",
            "modified_at": "2025-10-16T09:00:00Z"
        }]
    }"#;

    let vault: prive::vault::model::Vault = serde_json::from_str(json).unwrap();
    assert_eq!(vault.entries.len(), 1);
    assert!(vault.entries[0].password_history.is_empty());
    assert!(vault.secure_notes.is_empty());
}
