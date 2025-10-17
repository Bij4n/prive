use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("prive")
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("prive")
}

pub fn vault_path() -> PathBuf {
    let cfg = AppConfig::load();
    if let Some(p) = &cfg.vault.path {
        return PathBuf::from(p);
    }
    data_dir().join("vault.pv")
}

pub fn keyring_dir() -> PathBuf {
