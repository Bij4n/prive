use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MiB
const ARGON2_PARALLELISM: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub struct VaultCrypto;

impl VaultCrypto {
    /// Derive a 32-byte key from a password using Argon2id.
    pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
        let params = Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(KEY_LEN),
        )
        .map_err(|e| format!("Argon2 params error: {e}"))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
        let mut key = vec![0u8; KEY_LEN];
        argon2
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| format!("Argon2 hash error: {e}"))?;
        Ok(key)
    }

    /// Generate a random salt.
    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// Generate a random nonce.
    pub fn generate_nonce() -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt plaintext with AES-256-GCM using a derived key.
    pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<EncryptedBlob, String> {
        let salt = Self::generate_salt();
        let nonce_bytes = Self::generate_nonce();
        let mut key = Self::derive_key(password, &salt)?;

        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init error: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption error: {e}"))?;

        key.zeroize();

        Ok(EncryptedBlob {
            salt,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt an encrypted blob with AES-256-GCM using a derived key.
    pub fn decrypt(blob: &EncryptedBlob, password: &[u8]) -> Result<Vec<u8>, String> {
        let mut key = Self::derive_key(password, &blob.salt)?;

        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init error: {e}"))?;
        let nonce = Nonce::from_slice(&blob.nonce);
        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|_| "Decryption failed — wrong password or corrupted data".to_string())?;

        key.zeroize();

        Ok(plaintext)
    }
}

pub struct EncryptedBlob {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"test-master-password";
        let plaintext = b"hello vault world";

        let blob = VaultCrypto::encrypt(plaintext, password).unwrap();
        let decrypted = VaultCrypto::decrypt(&blob, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = b"secret data";
        let blob = VaultCrypto::encrypt(plaintext, b"correct-password").unwrap();
        let result = VaultCrypto::decrypt(&blob, b"wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let password = b"same-password";
        let plaintext = b"same-plaintext";

        let blob1 = VaultCrypto::encrypt(plaintext, password).unwrap();
        let blob2 = VaultCrypto::encrypt(plaintext, password).unwrap();

        // Different salt and nonce means different ciphertext
        assert_ne!(blob1.salt, blob2.salt);
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }
}
