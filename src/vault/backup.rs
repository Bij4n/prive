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

    /// List all available backups, sorted by date (newest first).
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>, String> {
        if !self.backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups: Vec<BackupInfo> = Vec::new();

        let entries =
            fs::read_dir(&self.backup_dir).map_err(|e| format!("Failed to read backup dir: {e}"))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Read dir error: {e}"))?;
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            if name.starts_with("vault_") && name.ends_with(".pv.bak") {
                let metadata = fs::metadata(&path)
                    .map_err(|e| format!("Failed to read metadata: {e}"))?;
                let size = metadata.len();
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs())
                    })
                    .unwrap_or(0);

                backups.push(BackupInfo {
                    path,
                    name,
                    size,
                    timestamp: modified,
                });
            }
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(backups)
    }

    /// Restore a vault from a backup.
    pub fn restore_backup(&self, backup_path: &Path, vault_path: &Path) -> Result<(), String> {
        if !backup_path.exists() {
            return Err(format!("Backup not found: {}", backup_path.display()));
        }
