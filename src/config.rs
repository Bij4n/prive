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
    data_dir().join("keyring")
}

pub fn config_file_path() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn backup_dir() -> PathBuf {
    data_dir().join("backups")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub clipboard: ClipboardConfig,
    #[serde(default)]
    pub generate: GenerateConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultConfig {
    pub path: Option<String>,
    #[serde(default = "default_argon2_time")]
    pub argon2_time_cost: u32,
    #[serde(default = "default_argon2_memory")]
    pub argon2_memory_cost: u32,
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClipboardConfig {
    #[serde(default = "default_clipboard_timeout")]
    pub clear_after_seconds: u64,
    #[serde(default)]
    pub auto_clear: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenerateConfig {
    #[serde(default = "default_password_length")]
    pub default_length: usize,
    #[serde(default)]
    pub default_no_symbols: bool,
    #[serde(default)]
    pub default_no_numbers: bool,
