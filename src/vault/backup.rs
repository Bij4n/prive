use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::config;

pub struct BackupManager {
    backup_dir: PathBuf,
    max_backups: usize,
}

impl BackupManager {
    pub fn new() -> Self {
        let cfg = config::AppConfig::load();
        Self {
            backup_dir: config::backup_dir(),
            max_backups: cfg.backup.max_backups,
        }
    }

    pub fn with_dir(dir: PathBuf, max_backups: usize) -> Self {
        Self {
            backup_dir: dir,
            max_backups,
        }
    }

    /// Create a backup of the vault file.
    pub fn create_backup(&self, vault_path: &Path) -> Result<PathBuf, String> {
        if !vault_path.exists() {
            return Err("Vault file does not exist".to_string());
        }

        fs::create_dir_all(&self.backup_dir)
            .map_err(|e| format!("Failed to create backup dir: {e}"))?;

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_name = format!("vault_{timestamp}.pv.bak");
        let backup_path = self.backup_dir.join(backup_name);

        fs::copy(vault_path, &backup_path)
            .map_err(|e| format!("Failed to create backup: {e}"))?;

        self.rotate_backups()?;

        Ok(backup_path)
    }
