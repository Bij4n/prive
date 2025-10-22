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
        })
        .map_err(|e| format!("Encryption error: {e}"))?;

    encrypted
        .to_armored_bytes(None.into())
        .map_err(|e| format!("Armor encoding error: {e}"))
}

/// Decrypt PGP-encrypted data with a secret key.
pub fn decrypt_with_key(
    encrypted_data: &[u8],
    secret_key: &SignedSecretKey,
    key_passphrase: &str,
) -> Result<(Vec<u8>, String), String> {
    let (message, _) = Message::from_armor_single(std::io::Cursor::new(encrypted_data))
        .map_err(|e| format!("Failed to parse PGP message: {e}"))?;

    let pw = key_passphrase.to_string();
    let (decrypted, _key_ids) = message
        .decrypt(|| pw, &[secret_key])
        .map_err(|e| format!("Decryption error: {e}"))?;

    extract_literal_data(&decrypted)
}

/// Decrypt PGP-encrypted data with a passphrase.
pub fn decrypt_with_password(
    encrypted_data: &[u8],
    passphrase: &str,
) -> Result<(Vec<u8>, String), String> {
    let (message, _) = Message::from_armor_single(std::io::Cursor::new(encrypted_data))
        .map_err(|e| format!("Failed to parse PGP message: {e}"))?;

    let pw = passphrase.to_string();
    let decrypted = message
        .decrypt_with_password(|| pw)
        .map_err(|e| format!("Decryption error: {e}"))?;

    extract_literal_data(&decrypted)
}

/// Extract literal data (content + filename) from a decrypted message.
fn extract_literal_data(message: &Message) -> Result<(Vec<u8>, String), String> {
    match message {
        Message::Literal(lit) => {
            let fname = String::new(); // filename access varies by version
            Ok((lit.data().to_vec(), fname))
        }
        Message::Compressed(comp) => {
            let decompressed = comp
                .decompress()
                .map_err(|e| format!("Decompression error: {e}"))?;
            // The decompressor returns a Message
            let msg = Message::from_bytes(decompressed)
                .map_err(|e| format!("Failed to parse decompressed message: {e}"))?;
            extract_literal_data(&msg)
        }
        _ => Err("Unexpected message format after decryption".to_string()),
    }
}

/// Sign data with a secret key.
#[allow(dead_code)]
pub fn sign_data(
    data: &[u8],
    filename: &str,
    secret_key: &SignedSecretKey,
    key_passphrase: &str,
) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;
    let message = Message::new_literal_bytes(filename, data);

    let pw = key_passphrase.to_string();
    let signed = message
        .sign(&mut rng, &secret_key.primary_key, || pw, pgp::crypto::hash::HashAlgorithm::SHA2_256)
        .map_err(|e| format!("Signing error: {e}"))?;

    signed
        .to_armored_bytes(None.into())
        .map_err(|e| format!("Armor encoding error: {e}"))
}

/// Verify a signed PGP message.
#[allow(dead_code)]
pub fn verify_signature(
    signed_data: &[u8],
    public_key: &SignedPublicKey,
) -> Result<Vec<u8>, String> {
    let (message, _) = Message::from_armor_single(std::io::Cursor::new(signed_data))
        .map_err(|e| format!("Failed to parse PGP message: {e}"))?;

    message
        .verify(&public_key.primary_key)
        .map_err(|e| format!("Signature verification failed: {e}"))?;

    extract_literal_data(&message).map(|(data, _)| data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgp::generate::generate_keypair;

    #[test]
    fn test_pgp_encrypt_decrypt_roundtrip() {
        let key = generate_keypair("Test", "test@test.com", "cv25519", "pass123").unwrap();
        let pub_key: SignedPublicKey = key.clone().into();

        let plaintext = b"Hello, PGP world!";
        let encrypted = encrypt_to_keys(plaintext, "test.txt", &[&pub_key]).unwrap();

        let (decrypted, _) = decrypt_with_key(&encrypted, &key, "pass123").unwrap();
        assert_eq!(decrypted, plaintext);
    }
