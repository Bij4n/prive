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

        Ok(key_id)
    }

    pub fn list_keys(&self, secret_only: bool) -> Result<Vec<KeyInfo>, String> {
        let mut keys = Vec::new();
        let entries =
            fs::read_dir(&self.dir).map_err(|e| format!("Failed to read keyring: {e}"))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Read dir error: {e}"))?;
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            if name.ends_with(".sec.asc") {
                let content =
                    fs::read_to_string(&path).map_err(|e| format!("Failed to read key: {e}"))?;
                if let Ok((key, _)) = SignedSecretKey::from_string(&content) {
                    let key_id = hex::encode(key.key_id().as_ref());
                    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
                    let uid = key
                        .details
                        .users
                        .first()
                        .map(|u| String::from_utf8_lossy(u.id.id()).to_string())
                        .unwrap_or_default();
                    keys.push(KeyInfo {
                        key_id,
                        fingerprint,
                        uid,
                        has_secret: true,
                        algorithm: format!("{:?}", key.algorithm()),
                    });
                }
            } else if !secret_only && name.ends_with(".pub.asc") {
                let content =
                    fs::read_to_string(&path).map_err(|e| format!("Failed to read key: {e}"))?;
                if let Ok((key, _)) = SignedPublicKey::from_string(&content) {
                    let key_id = hex::encode(key.key_id().as_ref());
                    // Skip if we have a matching secret key
                    let sec_path = self.dir.join(format!("{key_id}.sec.asc"));
                    if sec_path.exists() {
                        continue;
                    }
                    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
