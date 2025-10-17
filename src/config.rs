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
    #[serde(default)]
    pub default_no_uppercase: bool,
    #[serde(default = "default_passphrase_words")]
    pub default_words: usize,
    #[serde(default = "default_passphrase_separator")]
    pub default_separator: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackupConfig {
    #[serde(default = "default_true")]
    pub auto_backup: bool,
    #[serde(default = "default_max_backups")]
    pub max_backups: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionConfig {
    #[serde(default = "default_session_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub agent_enabled: bool,
}

fn default_argon2_time() -> u32 { 3 }
fn default_argon2_memory() -> u32 { 65536 }
fn default_argon2_parallelism() -> u32 { 4 }
fn default_clipboard_timeout() -> u64 { 45 }
fn default_password_length() -> usize { 20 }
fn default_passphrase_words() -> usize { 6 }
fn default_passphrase_separator() -> String { "-".to_string() }
fn default_true() -> bool { true }
fn default_max_backups() -> usize { 10 }
fn default_session_timeout() -> u64 { 300 }

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            vault: VaultConfig::default(),
            clipboard: ClipboardConfig::default(),
            generate: GenerateConfig::default(),
            backup: BackupConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            clear_after_seconds: default_clipboard_timeout(),
            auto_clear: false,
        }
    }
}

impl Default for GenerateConfig {
    fn default() -> Self {
        Self {
            default_length: default_password_length(),
            default_no_symbols: false,
            default_no_numbers: false,
            default_no_uppercase: false,
            default_words: default_passphrase_words(),
            default_separator: default_passphrase_separator(),
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            auto_backup: true,
            max_backups: default_max_backups(),
        }
    }
}

impl Default for SessionConfig {
