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
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn save_secret_key(&self, key: &SignedSecretKey) -> Result<String, String> {
        let key_id = hex::encode(key.key_id().as_ref());
        let armor = key
            .to_armored_string(None.into())
            .map_err(|e| format!("Armor encoding error: {e}"))?;

        let path = self.dir.join(format!("{key_id}.sec.asc"));
        fs::write(&path, &armor).map_err(|e| format!("Failed to write secret key: {e}"))?;

        let pub_key: SignedPublicKey = key.clone().into();
        let pub_armor = pub_key
            .to_armored_string(None.into())
            .map_err(|e| format!("Armor encoding error: {e}"))?;
        let pub_path = self.dir.join(format!("{key_id}.pub.asc"));
        fs::write(&pub_path, &pub_armor)
            .map_err(|e| format!("Failed to write public key: {e}"))?;
