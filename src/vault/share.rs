use pgp::composed::SignedPublicKey;

use crate::pgp::operations;
use crate::vault::model::VaultEntry;

/// Encrypt vault entries for sharing with another user via their PGP public key.
pub fn share_entries(
    entries: &[VaultEntry],
    recipient_key: &SignedPublicKey,
) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Serialization error: {e}"))?;

    operations::encrypt_to_keys(json.as_bytes(), "shared_entries.json", &[recipient_key])
}

/// Decrypt and deserialize shared entries received from another user.
pub fn receive_shared(
    encrypted_data: &[u8],
    secret_key: &pgp::composed::SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<VaultEntry>, String> {
    let (decrypted, _filename) = operations::decrypt_with_key(encrypted_data, secret_key, passphrase)?;

    let entries: Vec<VaultEntry> = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse shared entries: {e}"))?;

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgp::generate::generate_keypair;

    #[test]
    fn test_share_roundtrip() {
        let key = generate_keypair("Test", "test@test.com", "cv25519", "pass").unwrap();
        let pub_key: SignedPublicKey = key.clone().into();

        let entries = vec![
            VaultEntry::new("GitHub".into(), Some("user".into()), "secret".into(), None, None, vec![]),
            VaultEntry::new("AWS".into(), Some("admin".into()), "pass123".into(), None, None, vec!["cloud".into()]),
        ];

        let encrypted = share_entries(&entries, &pub_key).unwrap();
        let decrypted = receive_shared(&encrypted, &key, "pass").unwrap();

        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].name, "GitHub");
        assert_eq!(decrypted[0].password, "secret");
        assert_eq!(decrypted[1].name, "AWS");
    }

    #[test]
    fn test_share_empty_entries() {
        let key = generate_keypair("Test", "test@test.com", "cv25519", "").unwrap();
        let pub_key: SignedPublicKey = key.clone().into();

        let entries: Vec<VaultEntry> = vec![];
        let encrypted = share_entries(&entries, &pub_key).unwrap();
        let decrypted = receive_shared(&encrypted, &key, "").unwrap();
        assert!(decrypted.is_empty());
    }
}
