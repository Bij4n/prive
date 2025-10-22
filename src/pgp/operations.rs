use pgp::composed::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::StringToKey;
use rand::rngs::OsRng;

/// Encrypt data to one or more PGP public keys.
pub fn encrypt_to_keys(
    data: &[u8],
    filename: &str,
    recipients: &[&SignedPublicKey],
) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;
    let message = Message::new_literal_bytes(filename, data);

    // Collect encryption subkeys from all recipients
    let mut enc_keys: Vec<&pgp::SignedPublicSubKey> = Vec::new();
    for r in recipients {
        for sk in &r.public_subkeys {
            enc_keys.push(sk);
        }
    }

    let encrypted = if enc_keys.is_empty() {
        // No subkeys — encrypt to primary keys
        message
            .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, &recipients.iter().map(|r| &r.primary_key).collect::<Vec<_>>())
            .map_err(|e| format!("Encryption error: {e}"))?
    } else {
        message
            .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, &enc_keys)
            .map_err(|e| format!("Encryption error: {e}"))?
    };

    encrypted
        .to_armored_bytes(None.into())
        .map_err(|e| format!("Armor encoding error: {e}"))
}

/// Encrypt data with a passphrase (symmetric PGP encryption).
pub fn encrypt_symmetric(data: &[u8], filename: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;
    let message = Message::new_literal_bytes(filename, data);

    let s2k = StringToKey::new_default(&mut rng);
    let pw = passphrase.to_string();

    let encrypted = message
        .encrypt_with_password_seipdv1(&mut rng, s2k, SymmetricKeyAlgorithm::AES256, || {
            pw.clone()
