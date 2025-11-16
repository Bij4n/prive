use proptest::prelude::*;

proptest! {
    // Password generation always produces the requested length
    #[test]
    fn password_length_always_correct(len in 4usize..200) {
        let pw = prive::crypto::password_gen::generate_password(len, true, true, true);
        prop_assert_eq!(pw.len(), len);
    }

    // Lowercase-only passwords have no uppercase, digits, or symbols
    #[test]
    fn lowercase_only_has_no_other_chars(len in 4usize..100) {
        let pw = prive::crypto::password_gen::generate_password(len, false, false, false);
        prop_assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    // PIN is always digits only
    #[test]
    fn pin_is_digits_only(len in 1usize..20) {
        let pin = prive::crypto::password_gen::generate_pin(len);
        prop_assert_eq!(pin.len(), len);
        prop_assert!(pin.chars().all(|c| c.is_ascii_digit()));
    }

    // Pronounceable passwords alternate consonant/vowel
    #[test]
    fn pronounceable_alternates_correctly(len in 2usize..50) {
        let pw = prive::crypto::password_gen::generate_pronounceable(len);
        let consonants = b"bcdfghjklmnpqrstvwxyz";
        let vowels = b"aeiou";

        prop_assert_eq!(pw.len(), len);
        for (i, c) in pw.bytes().enumerate() {
            if i % 2 == 0 {
                prop_assert!(consonants.contains(&c), "pos {} should be consonant, got {}", i, c as char);
            } else {
                prop_assert!(vowels.contains(&c), "pos {} should be vowel, got {}", i, c as char);
            }
        }
    }

    // Passphrase word count matches
    #[test]
    fn passphrase_word_count_matches(words in 1usize..20) {
        let pp = prive::crypto::password_gen::generate_passphrase(words, "-");
        prop_assert_eq!(pp.split('-').count(), words);
    }

    // Password entropy is always non-negative
    #[test]
    fn entropy_is_non_negative(s in "[a-zA-Z0-9!@#$%]{0,100}") {
        let e = prive::crypto::password_gen::password_entropy(&s);
        prop_assert!(e >= 0.0);
    }

    // Custom charset only produces chars from the charset
    #[test]
    fn custom_charset_respects_chars(len in 1usize..50) {
        let charset = "abcXYZ123";
        let pw = prive::crypto::password_gen::generate_custom(len, charset).unwrap();
        prop_assert_eq!(pw.len(), len);
        prop_assert!(pw.chars().all(|c| charset.contains(c)));
    }

    // TOTP always produces the right number of digits
    #[test]
    fn totp_digit_count(digits in 4u32..10, time in 0u64..2000000000) {
        let secret = b"12345678901234567890";
        let code = prive::crypto::totp::generate_totp_at(secret, time, 30, digits).unwrap();
        prop_assert_eq!(code.len(), digits as usize);
        prop_assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    // Same time step always produces same TOTP
    #[test]
    fn totp_deterministic_within_step(base_time in 0u64..2000000000) {
        let secret = b"test_secret_key_123";
        let step = 30u64;
        let aligned = (base_time / step) * step;
        let code1 = prive::crypto::totp::generate_totp_at(secret, aligned, step, 6).unwrap();
        let code2 = prive::crypto::totp::generate_totp_at(secret, aligned + step - 1, step, 6).unwrap();
        prop_assert_eq!(code1, code2);
    }

    // Vault model: search finds entries that match
    #[test]
    fn vault_search_finds_matching(name in "[a-zA-Z]{3,20}") {
        let mut vault = prive::vault::model::Vault::new();
        vault.entries.push(prive::vault::model::VaultEntry::new(
            name.clone(),
            None,
            "pass".to_string(),
            None,
            None,
            vec![],
        ));
        let results = vault.search(&name);
        prop_assert!(!results.is_empty());
    }

    // Config roundtrip through TOML
    #[test]
    fn config_toml_roundtrip(length in 4usize..200, timeout in 10u64..3600) {
        let mut config = prive::config::AppConfig::default();
        config.generate.default_length = length;
        config.session.timeout_seconds = timeout;

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: prive::config::AppConfig = toml::from_str(&toml_str).unwrap();

        prop_assert_eq!(parsed.generate.default_length, length);
        prop_assert_eq!(parsed.session.timeout_seconds, timeout);
    }
}
