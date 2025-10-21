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
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temp file: {e}"))?;

        fs::rename(&tmp_path, path).map_err(|e| format!("Failed to rename temp file: {e}"))?;

        Ok(())
    }

    /// Load and decrypt a vault from disk.
    pub fn load(path: &Path, password: &[u8]) -> Result<Vault, String> {
        if !path.exists() {
            return Err("Vault not found. Run `prive vault init` first.".to_string());
        }

        let mut file =
            fs::File::open(path).map_err(|e| format!("Failed to open vault: {e}"))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read vault: {e}"))?;

        // Parse header
        if data.len() < 8 + 1 + 32 + 12 {
            return Err("Vault file is too small or corrupted".to_string());
        }

        if &data[0..8] != MAGIC {
            return Err("Not a valid prive vault file".to_string());
        }

        let version = data[8];
        if version != FORMAT_VERSION {
            return Err(format!("Unsupported vault format version: {version}"));
        }

        let salt_start = 9;
        let nonce_start = salt_start + 32;
        let ciphertext_start = nonce_start + 12;

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[salt_start..nonce_start]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[nonce_start..ciphertext_start]);

        let ciphertext = data[ciphertext_start..].to_vec();

        let blob = EncryptedBlob {
            salt,
            nonce,
            ciphertext,
        };

        let plaintext = VaultCrypto::decrypt(&blob, password)?;
        let vault: Vault =
            serde_json::from_slice(&plaintext).map_err(|e| format!("Deserialization error: {e}"))?;

        Ok(vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_vault_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("prive_test_{}.pv", uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn test_create_and_load_vault() {
        let path = temp_vault_path();
        let password = b"test-password";

        VaultStorage::create(&path, password).unwrap();
        assert!(path.exists());

        let vault = VaultStorage::load(&path, password).unwrap();
        assert_eq!(vault.version, 1);
        assert!(vault.entries.is_empty());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_save_and_load_with_entries() {
        use crate::vault::model::VaultEntry;

        let path = temp_vault_path();
        let password = b"test-password";

        let mut vault = Vault::new();
        vault.entries.push(VaultEntry::new(
            "GitHub".to_string(),
            Some("johnd".to_string()),
            "s3cret!".to_string(),
            Some("https://github.com".to_string()),
            None,
            vec!["dev".to_string()],
        ));

        VaultStorage::save(&path, &vault, password).unwrap();

        let loaded = VaultStorage::load(&path, password).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "GitHub");
        assert_eq!(loaded.entries[0].password, "s3cret!");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_with_wrong_password() {
        let path = temp_vault_path();

        VaultStorage::create(&path, b"correct").unwrap();
        let result = VaultStorage::load(&path, b"wrong");
        assert!(result.is_err());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_create_duplicate_fails() {
        let path = temp_vault_path();

        VaultStorage::create(&path, b"pass").unwrap();
        let result = VaultStorage::create(&path, b"pass");
        assert!(result.is_err());

        fs::remove_file(&path).ok();
    }
}
