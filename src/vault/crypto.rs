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
