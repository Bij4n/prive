use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::ShareCommand;
use crate::config;
use crate::pgp::keyring::Keyring;
use crate::vault::share;
use crate::vault::storage::VaultStorage;

pub fn handle_share(cmd: &ShareCommand, vault_path: Option<&Path>) -> Result<()> {
    match cmd {
        ShareCommand::Export {
            names,
            recipient,
            output,
        } => cmd_export(vault_path, names, recipient, output),
        ShareCommand::Import { file } => cmd_import(vault_path, file),
    }
}

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

fn cmd_export(
    vault_path: Option<&Path>,
    names: &[String],
    recipient_key_id: &str,
    output: &Path,
) -> Result<()> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    // Find the entries to share
    let mut entries_to_share = Vec::new();
    for name in names {
        let entry = vault
            .find_by_name(name)
            .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;
        entries_to_share.push(entry.clone());
    }

    if entries_to_share.is_empty() {
        anyhow::bail!("No entries to share");
    }

    // Load recipient's public key
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let pub_key = keyring
        .load_public_key(recipient_key_id)
        .map_err(|e| anyhow::anyhow!(e))?;

    let encrypted = share::share_entries(&entries_to_share, &pub_key)
        .map_err(|e| anyhow::anyhow!(e))?;

    fs::write(output, &encrypted)?;

    println!(
        "{} Shared {} entries -> {}",
        "✓".green(),
        entries_to_share.len(),
        output.display()
    );

    Ok(())
}

fn cmd_import(vault_path: Option<&Path>, file: &Path) -> Result<()> {
    let path = resolve_vault_path(vault_path);
    let master_password = rpassword::prompt_password("Master password: ")?;
    let mut vault = VaultStorage::load(&path, master_password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let encrypted_data = fs::read(file)?;

    // Try each secret key in the keyring
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let keys = keyring.list_keys(true).map_err(|e| anyhow::anyhow!(e))?;

    let mut entries = None;

    for key_info in &keys {
        if let Ok(secret_key) = keyring.load_secret_key(&key_info.key_id) {
            let passphrase = rpassword::prompt_password(
                format!("Passphrase for key {} (empty if none): ", &key_info.key_id),
            )?;

            match share::receive_shared(&encrypted_data, &secret_key, &passphrase) {
                Ok(e) => {
                    entries = Some(e);
                    break;
                }
                Err(_) => continue,
            }
        }
    }

    let entries = entries.ok_or_else(|| anyhow::anyhow!("Could not decrypt shared entries with any key"))?;

    let count = entries.len();
    for entry in entries {
        if vault.find_by_name(&entry.name).is_none() {
            vault.entries.push(entry);
        } else {
            println!("  {} Skipping duplicate: {}", "!".yellow(), entry.name);
        }
    }
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Imported {} shared entries.", "✓".green(), count);
    Ok(())
}
