//! Encrypted single-file vault export.
//! Bundles the vault + keyring into one portable encrypted file.

use std::fs;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config;
use crate::vault::crypto::VaultCrypto;

#[derive(Serialize, Deserialize)]
struct ExportBundle {
    version: u32,
    created_at: String,
    vault_data: String,          // base64-encoded encrypted vault file
    keyring_files: Vec<KeyFile>, // armored key files
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    name: String,
    content: String,
}

/// Create an encrypted bundle containing the vault and all keyring files.
pub fn create_bundle(vault_path: &Path, password: &[u8]) -> Result<Vec<u8>, String> {
    // Read vault file
    if !vault_path.exists() {
        return Err("Vault file not found".to_string());
    }
    let vault_data = fs::read(vault_path).map_err(|e| format!("Failed to read vault: {e}"))?;
    let vault_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vault_data);

    // Read keyring files
    let keyring_dir = config::keyring_dir();
    let mut keyring_files = Vec::new();
    if keyring_dir.exists()
        && let Ok(entries) = fs::read_dir(&keyring_dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("asc")
                && let Ok(content) = fs::read_to_string(&path)
            {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                keyring_files.push(KeyFile { name, content });
            }
        }
    }

    let bundle = ExportBundle {
        version: 1,
        created_at: Utc::now().to_rfc3339(),
        vault_data: vault_b64,
        keyring_files,
    };

    let json = serde_json::to_string(&bundle).map_err(|e| format!("Serialization error: {e}"))?;

    // Encrypt the bundle with the vault password
    let blob = VaultCrypto::encrypt(json.as_bytes(), password)?;

    // Build output: magic + salt + nonce + ciphertext
    let mut output = Vec::new();
    output.extend_from_slice(b"PRIVEBND"); // bundle magic
    output.push(1); // version
    output.extend_from_slice(&blob.salt);
    output.extend_from_slice(&blob.nonce);
    output.extend_from_slice(&blob.ciphertext);

    Ok(output)
}

/// Restore a vault and keyring from an encrypted bundle.
pub fn restore_bundle(
    bundle_data: &[u8],
    password: &[u8],
    vault_path: &Path,
) -> Result<usize, String> {
    // Parse header
    if bundle_data.len() < 9 + 32 + 12 + 16 {
        return Err("Bundle file is too small or corrupted".to_string());
    }
    if &bundle_data[0..8] != b"PRIVEBND" {
        return Err("Not a valid prive bundle file".to_string());
    }
    let version = bundle_data[8];
    if version != 1 {
        return Err(format!("Unsupported bundle version: {version}"));
    }

    let salt_start = 9;
    let nonce_start = salt_start + 32;
    let ciphertext_start = nonce_start + 12;

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&bundle_data[salt_start..nonce_start]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bundle_data[nonce_start..ciphertext_start]);
    let ciphertext = bundle_data[ciphertext_start..].to_vec();

    let blob = crate::vault::crypto::EncryptedBlob {
        salt,
        nonce,
        ciphertext,
    };

    let plaintext = VaultCrypto::decrypt(&blob, password)?;
    let bundle: ExportBundle =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Failed to parse bundle: {e}"))?;

    // Restore vault
    let vault_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.vault_data,
    )
    .map_err(|e| format!("Failed to decode vault data: {e}"))?;

    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {e}"))?;
    }
    fs::write(vault_path, &vault_bytes).map_err(|e| format!("Failed to write vault: {e}"))?;

    // Restore keyring files
    let keyring_dir = config::keyring_dir();
    fs::create_dir_all(&keyring_dir).map_err(|e| format!("Failed to create keyring dir: {e}"))?;

    let mut key_count = 0;
    for key_file in &bundle.keyring_files {
        let path = keyring_dir.join(&key_file.name);
        fs::write(&path, &key_file.content)
            .map_err(|e| format!("Failed to write key {}: {e}", key_file.name))?;
        key_count += 1;
    }

    Ok(key_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("vault.pv");

        // Create a test vault
        crate::vault::storage::VaultStorage::create(&vault_path, b"password").unwrap();

        // Create bundle
        let bundle = create_bundle(&vault_path, b"bundle-pass").unwrap();
        assert!(!bundle.is_empty());
        assert_eq!(&bundle[0..8], b"PRIVEBND");

        // Restore to new location
        let restore_path = tmp.path().join("restored.pv");
        let key_count = restore_bundle(&bundle, b"bundle-pass", &restore_path).unwrap();

        assert!(restore_path.exists());
        // Key count may be 0 if no keyring exists in test
        assert_eq!(key_count, 0);
    }

    #[test]
    fn test_bundle_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("vault.pv");

        crate::vault::storage::VaultStorage::create(&vault_path, b"password").unwrap();
        let bundle = create_bundle(&vault_path, b"correct").unwrap();

        let restore_path = tmp.path().join("restored.pv");
        let result = restore_bundle(&bundle, b"wrong", &restore_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_invalid_data() {
        let result = restore_bundle(b"garbage", b"pass", Path::new("/tmp/x.pv"));
        assert!(result.is_err());
    }
}
