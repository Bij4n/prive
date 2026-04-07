use std::io::Read;
use std::path::Path;

pub const CURRENT_VERSION: u8 = 1;
const MAGIC: &[u8; 8] = b"PRIVEVLT";

/// Check if a vault file needs migration.
pub fn needs_migration(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Err("Vault file not found".to_string());
    }

    let mut file = std::fs::File::open(path).map_err(|e| format!("Failed to open vault: {e}"))?;

    let mut header = [0u8; 9]; // magic (8) + version (1)
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read vault header: {e}"))?;

    if &header[0..8] != MAGIC {
        return Err("Not a valid prive vault file".to_string());
    }

    let version = header[8];
    Ok(version < CURRENT_VERSION)
}

/// Get the version of a vault file without fully loading it.
pub fn vault_version(path: &Path) -> Result<u8, String> {
    if !path.exists() {
        return Err("Vault file not found".to_string());
    }

    let mut file = std::fs::File::open(path).map_err(|e| format!("Failed to open vault: {e}"))?;

    let mut header = [0u8; 9];
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read vault header: {e}"))?;

    if &header[0..8] != MAGIC {
        return Err("Not a valid prive vault file".to_string());
    }

    Ok(header[8])
}

/// Migrate a vault from an older version to the current version.
/// Currently only version 1 exists, so this is a no-op placeholder
/// for future format changes.
pub fn migrate_if_needed(
    path: &Path,
    _password: &[u8],
) -> Result<Option<crate::vault::model::Vault>, String> {
    let version = vault_version(path)?;

    if version == CURRENT_VERSION {
        return Ok(None); // No migration needed
    }

    if version > CURRENT_VERSION {
        return Err(format!(
            "Vault version {version} is newer than supported version {CURRENT_VERSION}. Please update prive."
        ));
    }

    // Future migration logic goes here
    // For now, all vaults are v1, so nothing to migrate
    Err(format!("Cannot migrate vault version {version}"))
}

/// Validate vault file integrity without decrypting.
pub fn validate_vault_header(path: &Path) -> Result<VaultHeaderInfo, String> {
    if !path.exists() {
        return Err("Vault file not found".to_string());
    }

    let mut file = std::fs::File::open(path).map_err(|e| format!("Failed to open vault: {e}"))?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| format!("Failed to read vault: {e}"))?;

    let min_size = 8 + 1 + 32 + 12 + 16; // magic + version + salt + nonce + min ciphertext
    if data.len() < min_size {
        return Err(format!(
            "Vault file too small ({} bytes, minimum {min_size})",
            data.len()
        ));
    }

    if &data[0..8] != MAGIC {
        return Err("Invalid magic bytes — not a prive vault file".to_string());
    }

    let version = data[8];
    let salt_start = 9;
    let nonce_start = salt_start + 32;
    let ciphertext_start = nonce_start + 12;
    let ciphertext_len = data.len() - ciphertext_start;

    Ok(VaultHeaderInfo {
        version,
        file_size: data.len() as u64,
        ciphertext_size: ciphertext_len as u64,
    })
}

#[derive(Debug)]
pub struct VaultHeaderInfo {
    pub version: u8,
    pub file_size: u64,
    pub ciphertext_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::storage::VaultStorage;

    #[test]
    fn test_vault_version_v1() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.pv");

        VaultStorage::create(&path, b"password").unwrap();
        let version = vault_version(&path).unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn test_needs_migration_current() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.pv");

        VaultStorage::create(&path, b"password").unwrap();
        assert!(!needs_migration(&path).unwrap());
    }

    #[test]
    fn test_needs_migration_nonexistent() {
        let result = needs_migration(Path::new("/tmp/nonexistent_vault.pv"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_vault_header() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.pv");

        VaultStorage::create(&path, b"password").unwrap();
        let info = validate_vault_header(&path).unwrap();
        assert_eq!(info.version, 1);
        assert!(info.file_size > 0);
        assert!(info.ciphertext_size > 0);
    }

    #[test]
    fn test_validate_invalid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.pv");
        std::fs::write(&path, b"not a vault").unwrap();

        let result = validate_vault_header(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_current_version() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.pv");

        VaultStorage::create(&path, b"password").unwrap();
        let result = migrate_if_needed(&path, b"password").unwrap();
        assert!(result.is_none()); // No migration needed
    }
}
