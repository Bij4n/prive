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
    let path = resolve_vault_path(vault_path_override);

    if path.exists() {
        anyhow::bail!("Vault already exists at {}", path.display());
    }

    println!("Creating new vault at {}", path.display().to_string().dimmed());

    let password = rpassword::prompt_password("Enter master password: ")?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm master password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    VaultStorage::create(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Vault created successfully.", "✓".green());
    Ok(())
}

fn cmd_change_password(vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);

    let old_password = rpassword::prompt_password("Enter current master password: ")?;
    let vault = VaultStorage::load(&path, old_password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let new_password = rpassword::prompt_password("Enter new master password: ")?;
    if new_password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm new master password: ")?;
    if new_password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    VaultStorage::save(&path, &vault, new_password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Master password changed successfully.", "✓".green());
    Ok(())
}
