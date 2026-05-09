/// Comprehensive crypto module tests.

// --- Password generation comprehensive ---

#[test]
fn test_generate_all_modes() {
    // Random
    let pw = prive::crypto::password_gen::generate_password(20, true, true, true);
    assert_eq!(pw.len(), 20);

    // No symbols
    let pw = prive::crypto::password_gen::generate_password(20, true, true, false);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    // Lowercase only
    let pw = prive::crypto::password_gen::generate_password(20, false, false, false);
    assert!(pw.chars().all(|c| c.is_ascii_lowercase()));

    // Passphrase
    let pp = prive::crypto::password_gen::generate_passphrase(4, "-");
    assert_eq!(pp.split('-').count(), 4);

    // PIN
    let pin = prive::crypto::password_gen::generate_pin(8);
    assert_eq!(pin.len(), 8);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));

    // Pronounceable
    let pw = prive::crypto::password_gen::generate_pronounceable(12);
    assert_eq!(pw.len(), 12);

    // Custom charset
    let pw = prive::crypto::password_gen::generate_custom(10, "abc").unwrap();
    assert!(pw.chars().all(|c| "abc".contains(c)));
}

#[test]
fn test_password_entropy_ranges() {
    // All lowercase, 8 chars: ~37.6 bits
    let e = prive::crypto::password_gen::password_entropy("abcdefgh");
    assert!(e > 30.0 && e < 50.0);

    // Mixed case + digits + symbols, 16 chars: ~105 bits
    let e = prive::crypto::password_gen::password_entropy("Abc123!@#$%^&*()");
    assert!(e > 90.0);

    // Single char type, 4 chars: ~18.8 bits
    let e = prive::crypto::password_gen::password_entropy("1234");
    assert!(e > 10.0 && e < 20.0);
}

// --- TOTP comprehensive ---

#[test]
fn test_totp_rfc6238_all_vectors() {
    let secret = b"12345678901234567890";

    // Time=59, digits=8 -> 94287082
    let code = prive::crypto::totp::generate_totp_at(
        secret,
        59,
        30,
        8,
        prive::crypto::totp::TotpAlgorithm::Sha1,
    )
    .unwrap();
    assert_eq!(code, "94287082");

    // Time=1111111109, digits=8 -> 07081804
    let code = prive::crypto::totp::generate_totp_at(
        secret,
        1111111109,
        30,
        8,
        prive::crypto::totp::TotpAlgorithm::Sha1,
    )
    .unwrap();
    assert_eq!(code, "07081804");

    // Time=1234567890, digits=8 -> 89005924
    let code = prive::crypto::totp::generate_totp_at(
        secret,
        1234567890,
        30,
        8,
        prive::crypto::totp::TotpAlgorithm::Sha1,
    )
    .unwrap();
    assert_eq!(code, "89005924");
}

#[test]
fn test_totp_different_periods() {
    let secret = b"testsecret12345678";

    let code_30 = prive::crypto::totp::generate_totp_at(
        secret,
        1000,
        30,
        6,
        prive::crypto::totp::TotpAlgorithm::Sha1,
    )
    .unwrap();
    let code_60 = prive::crypto::totp::generate_totp_at(
        secret,
        1000,
        60,
        6,
        prive::crypto::totp::TotpAlgorithm::Sha1,
    )
    .unwrap();

    // Different periods may produce different codes
    // (they might coincidentally match, but very unlikely)
    assert_eq!(code_30.len(), 6);
    assert_eq!(code_60.len(), 6);
}

#[test]
fn test_otpauth_uri_with_encoded_chars() {
    let uri = "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Corp";
    let params = prive::crypto::totp::parse_otpauth_uri(uri).unwrap();
    assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(params.issuer, Some("Example Corp".to_string()));
}

// --- Vault crypto ---

#[test]
fn test_vault_crypto_with_empty_data() {
    let blob = prive::vault::crypto::VaultCrypto::encrypt(b"", b"password").unwrap();
    let decrypted = prive::vault::crypto::VaultCrypto::decrypt(&blob, b"password").unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_vault_crypto_with_large_data() {
    let data = vec![42u8; 100_000]; // 100KB
    let blob = prive::vault::crypto::VaultCrypto::encrypt(&data, b"password").unwrap();
    let decrypted = prive::vault::crypto::VaultCrypto::decrypt(&blob, b"password").unwrap();
    assert_eq!(decrypted, data);
}

// --- Strength analysis comprehensive ---

#[test]
fn test_strength_various_passwords() {
    let cases = vec![
        ("", 0..=25),
        ("a", 0..=30),
        ("password", 0..=40),
        ("Password1!", 30..=85),
        ("Xk9#mP2$vL7@", 50..=100),
        ("correct-horse-battery-staple-extra-words", 30..=80),
    ];

    for (pw, expected_range) in cases {
        let report = prive::crypto::strength::analyze_strength(pw);
        assert!(
            expected_range.contains(&report.score),
            "Password '{}' scored {} (expected {:?})",
            pw,
            report.score,
            expected_range
        );
    }
}

#[test]
fn test_strength_crack_time_increases_with_length() {
    let short = prive::crypto::strength::analyze_strength("abc");
    let long = prive::crypto::strength::analyze_strength("abcdefghijklmnop");
    assert!(long.entropy_bits > short.entropy_bits);
}

// --- Audit comprehensive ---

#[test]
fn test_audit_perfect_vault() {
    let mut vault = prive::vault::model::Vault::new();
    // All strong, unique passwords
    for i in 0..5 {
        vault.entries.push(prive::vault::model::VaultEntry::new(
            format!("site_{i}"),
            Some(format!("user_{i}")),
            format!("Xk9#mP{i}$vL7@nQ!"),
            None,
            None,
            vec![],
        ));
    }
    let report = prive::crypto::audit::audit_vault(&vault);
    assert!(
        report.score >= 70,
        "Perfect vault scored only {}",
        report.score
    );
}

#[test]
fn test_audit_all_issues() {
    let mut vault = prive::vault::model::Vault::new();

    // Weak password
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "weak".into(),
        None,
        "abc".into(),
        None,
        None,
        vec![],
    ));

    // Duplicate passwords
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "dup1".into(),
        None,
        "SamePass!123".into(),
        None,
        None,
        vec![],
    ));
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "dup2".into(),
        None,
        "SamePass!123".into(),
        None,
        None,
        vec![],
    ));

    // Common password
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "common".into(),
        None,
        "password123Ab!".into(),
        None,
        None,
        vec![],
    ));

    let report = prive::crypto::audit::audit_vault(&vault);
    assert!(report.score < 50);
    assert!(!report.weak_passwords.is_empty());
    assert!(!report.duplicate_passwords.is_empty());
    assert!(!report.short_passwords.is_empty());
}

// --- Export 1Password ---

#[test]
fn test_1password_export_roundtrip() {
    let mut vault = prive::vault::model::Vault::new();
    vault.entries.push(prive::vault::model::VaultEntry::new(
        "GitHub".into(),
        Some("johnd".into()),
        "secret".into(),
        Some("https://github.com".into()),
        None,
        vec!["dev".into()],
    ));

    let json = prive::vault::export_1password::export_1password(&vault).unwrap();
    assert!(json.contains("GitHub"));
    assert!(json.contains("webforms.WebForm"));

    let csv = prive::vault::export_1password::export_1password_csv(&vault);
    assert!(csv.contains("GitHub"));
    assert!(csv.contains("login"));
}

// --- Trust DB comprehensive ---

#[test]
fn test_trust_db_full_lifecycle() {
    let mut db = prive::pgp::trust::TrustDb::default();

    // Add keys at different trust levels
    db.set_trust(
        "KEY_A",
        "FP_A",
        prive::pgp::trust::TrustLevel::Full,
        Some("verified in person".into()),
    );
    db.set_trust(
        "KEY_B",
        "FP_B",
        prive::pgp::trust::TrustLevel::Marginal,
        None,
    );
    db.set_trust(
        "KEY_C",
        "FP_C",
        prive::pgp::trust::TrustLevel::Ultimate,
        Some("my key".into()),
    );

    assert_eq!(db.list_trusted().len(), 3);

    // Upgrade trust
    db.set_trust(
        "KEY_B",
        "FP_B",
        prive::pgp::trust::TrustLevel::Full,
        Some("now verified".into()),
    );
    assert_eq!(db.get_trust("KEY_B"), prive::pgp::trust::TrustLevel::Full);

    // Remove
    assert!(db.remove_trust("KEY_A"));
    assert_eq!(db.list_trusted().len(), 2);

    // Serialize roundtrip
    let json = serde_json::to_string(&db).unwrap();
    let loaded: prive::pgp::trust::TrustDb = serde_json::from_str(&json).unwrap();
    assert_eq!(
        loaded.get_trust("KEY_C"),
        prive::pgp::trust::TrustLevel::Ultimate
    );
}

// --- Config comprehensive ---

#[test]
fn test_config_all_fields_roundtrip() {
    let mut config = prive::config::AppConfig::default();
    config.generate.default_length = 32;
    config.clipboard.auto_clear = true;
    config.clipboard.clear_after_seconds = 15;
    config.backup.max_backups = 20;
    config.session.timeout_seconds = 600;
    config.vault.active_vault = Some("work".into());

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: prive::config::AppConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(parsed.generate.default_length, 32);
    assert!(parsed.clipboard.auto_clear);
    assert_eq!(parsed.clipboard.clear_after_seconds, 15);
    assert_eq!(parsed.backup.max_backups, 20);
    assert_eq!(parsed.session.timeout_seconds, 600);
    assert_eq!(parsed.vault.active_vault.as_deref(), Some("work"));
}
