use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::vault::crypto::{EncryptedBlob, VaultCrypto};
use crate::vault::model::Vault;

const MAGIC: &[u8; 8] = b"PRIVEVLT";
const FORMAT_VERSION: u8 = 1;

pub struct VaultStorage;

impl VaultStorage {
    /// Create a new vault file at the given path.
    pub fn create(path: &Path, password: &[u8]) -> Result<(), String> {
        if path.exists() {
            return Err(format!("Vault already exists at {}", path.display()));
        }

        let vault = Vault::new();
        Self::save(path, &vault, password)
    }

    /// Save a vault to disk, encrypting it with the given password.
    pub fn save(path: &Path, vault: &Vault, password: &[u8]) -> Result<(), String> {
        let json = serde_json::to_vec(vault).map_err(|e| format!("Serialization error: {e}"))?;
        let blob = VaultCrypto::encrypt(&json, password)?;

        // Build the file contents
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&blob.salt);
        data.extend_from_slice(&blob.nonce);
        data.extend_from_slice(&blob.ciphertext);

        // Atomic write: write to temp file, then rename
        let tmp_path = path.with_extension("pv.tmp");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {e}"))?;
        }

        let mut file =
            fs::File::create(&tmp_path).map_err(|e| format!("Failed to create temp file: {e}"))?;
        file.write_all(&data)
