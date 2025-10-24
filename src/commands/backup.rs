use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::BackupCommand;
use crate::config;
use crate::vault::backup::BackupManager;

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

pub fn handle_backup(cmd: &BackupCommand, vault_path_override: Option<&Path>) -> Result<()> {
    match cmd {
        BackupCommand::Create => cmd_create(vault_path_override),
        BackupCommand::List => cmd_list(),
        BackupCommand::Restore { file } => cmd_restore(file, vault_path_override),
    }
}

fn cmd_create(vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    let manager = BackupManager::new();

    let backup_path = manager
        .create_backup(&path)
