use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::VaultCommand;
use crate::config;
use crate::vault::storage::VaultStorage;

pub fn handle_vault(cmd: &VaultCommand, vault_path_override: Option<&Path>) -> Result<()> {
    match cmd {
        VaultCommand::Init => cmd_init(vault_path_override),
        VaultCommand::ChangePassword => cmd_change_password(vault_path_override),
    }
}

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

fn cmd_init(vault_path_override: Option<&Path>) -> Result<()> {
