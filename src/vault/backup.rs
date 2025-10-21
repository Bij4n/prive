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

        // Create a backup of the current vault before restoring
        if vault_path.exists() {
            self.create_backup(vault_path)?;
        }

        fs::copy(backup_path, vault_path)
            .map_err(|e| format!("Failed to restore backup: {e}"))?;

        Ok(())
    }

    /// Remove old backups, keeping only the most recent `max_backups`.
    fn rotate_backups(&self) -> Result<(), String> {
        let backups = self.list_backups()?;

        if backups.len() > self.max_backups {
            for backup in &backups[self.max_backups..] {
                let _ = fs::remove_file(&backup.path);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_and_list_backups() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("vault.pv");
        let backup_dir = tmp.path().join("backups");

        fs::write(&vault_path, b"test vault data").unwrap();

        let manager = BackupManager::with_dir(backup_dir, 5);
        let backup_path = manager.create_backup(&vault_path).unwrap();
        assert!(backup_path.exists());

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_backup_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("vault.pv");
        let backup_dir = tmp.path().join("backups");

        fs::write(&vault_path, b"test vault data").unwrap();

        let manager = BackupManager::with_dir(backup_dir, 3);

        for _ in 0..5 {
            manager.create_backup(&vault_path).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let backups = manager.list_backups().unwrap();
        assert!(backups.len() <= 3);
    }

    #[test]
    fn test_restore_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("vault.pv");
        let backup_dir = tmp.path().join("backups");

        fs::write(&vault_path, b"original data").unwrap();

        let manager = BackupManager::with_dir(backup_dir, 5);
        let backup_path = manager.create_backup(&vault_path).unwrap();

        // Verify backup has original content
        let backup_content = fs::read(&backup_path).unwrap();
        assert_eq!(backup_content, b"original data");

        // Modify the vault
        fs::write(&vault_path, b"modified data").unwrap();

        // Pause to ensure different timestamp for backup-before-restore
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Restore
        manager.restore_backup(&backup_path, &vault_path).unwrap();

        let content = fs::read(&vault_path).unwrap();
