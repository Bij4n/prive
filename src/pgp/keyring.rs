use std::fs;
use std::path::{Path, PathBuf};

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::types::PublicKeyTrait;

use crate::config;

pub struct Keyring {
    dir: PathBuf,
}

impl Keyring {
    pub fn open() -> Result<Self, String> {
        let dir = config::keyring_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create keyring dir: {e}"))?;
        Ok(Self { dir })
    }

    #[allow(dead_code)]
    pub fn open_at(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("Failed to create keyring dir: {e}"))?;
