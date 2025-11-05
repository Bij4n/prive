use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::VaultCommand;
use crate::config;
use crate::vault::migrate;
use crate::vault::storage::VaultStorage;

pub fn handle_vault(cmd: &VaultCommand, vault_path_override: Option<&Path>) -> Result<()> {
    match cmd {
        VaultCommand::Init => cmd_init(vault_path_override),
        VaultCommand::ChangePassword => cmd_change_password(vault_path_override),
        VaultCommand::List => cmd_list(),
        VaultCommand::Switch { name } => cmd_switch(name),
        VaultCommand::Create { name } => cmd_create(name),
        VaultCommand::Delete { name, force } => cmd_delete(name, *force),
        VaultCommand::Info => cmd_info(vault_path_override),
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

fn cmd_list() -> Result<()> {
    let data_dir = config::data_dir();
    if !data_dir.exists() {
        println!("No vaults found.");
        return Ok(());
    }

    let cfg = config::AppConfig::load();
    let active = cfg.vault.active_vault.as_deref();

    let entries = fs::read_dir(&data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to read data directory: {e}"))?;

    let mut found = false;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("pv") {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let is_active = active.is_some_and(|a| a == name)
                || (active.is_none() && name == "vault");

            let marker = if is_active { " (active)".green().to_string() } else { String::new() };
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            println!("  {} ({} bytes){}", name, size, marker);
            found = true;
        }
    }

    if !found {
        println!("No vaults found.");
    }

    Ok(())
}

fn cmd_switch(name: &str) -> Result<()> {
    let path = config::data_dir().join(format!("{name}.pv"));
    if !path.exists() {
        anyhow::bail!("Vault '{}' does not exist", name);
    }

    let mut cfg = config::AppConfig::load();
    cfg.vault.active_vault = Some(name.to_string());
    cfg.save().map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Switched to vault '{name}'.", "✓".green());
    Ok(())
}

fn cmd_create(name: &str) -> Result<()> {
    let path = config::data_dir().join(format!("{name}.pv"));
    if path.exists() {
        anyhow::bail!("Vault '{}' already exists", name);
    }

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

    println!("{} Vault '{name}' created.", "✓".green());
    Ok(())
}

fn cmd_delete(name: &str, force: bool) -> Result<()> {
    let path = config::data_dir().join(format!("{name}.pv"));
    if !path.exists() {
        anyhow::bail!("Vault '{}' does not exist", name);
    }

    let cfg = config::AppConfig::load();
    if cfg.vault.active_vault.as_deref() == Some(name) {
        anyhow::bail!("Cannot delete the active vault. Switch to another vault first.");
    }

    if !force {
        print!("Delete vault '{name}'? This cannot be undone. [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    fs::remove_file(&path)?;
    println!("{} Vault '{name}' deleted.", "✓".green());
    Ok(())
}

fn cmd_info(vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    if !path.exists() {
        anyhow::bail!("Vault not found at {}", path.display());
    }

    let header = migrate::validate_vault_header(&path)
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{}: {}", "Path".bold(), path.display());
    println!("{}: {}", "Format version".bold(), header.version);
    println!("{}: {} bytes", "File size".bold(), header.file_size);
    println!("{}: {} bytes", "Ciphertext size".bold(), header.ciphertext_size);

    // Try to load and show entry count
    let password = rpassword::prompt_password("Master password (to show details): ")?;
    if let Ok(vault) = VaultStorage::load(&path, password.as_bytes()) {
        println!("{}: {}", "Entries".bold(), vault.entries.len());
        println!("{}: {}", "Notes".bold(), vault.secure_notes.len());
        println!("{}: {}", "Created".bold(), vault.created_at.format("%Y-%m-%d %H:%M"));
        println!("{}: {}", "Modified".bold(), vault.modified_at.format("%Y-%m-%d %H:%M"));
    }

    Ok(())
}
