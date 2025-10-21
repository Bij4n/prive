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
