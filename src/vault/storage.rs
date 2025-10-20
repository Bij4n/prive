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
