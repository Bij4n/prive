use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::{ExportArgs, ExportFormat, ImportArgs, ImportFormat};
use crate::config;
use crate::vault::import;
use crate::vault::storage::VaultStorage;

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

pub fn handle_import(args: &ImportArgs, vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    let password = rpassword::prompt_password("Master password: ")?;
    let mut vault =
        VaultStorage::load(&path, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    let content = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {e}", args.file.display()))?;

    let entries = match args.format {
        ImportFormat::Csv => import::import_csv(&content).map_err(|e| anyhow::anyhow!(e))?,
        ImportFormat::Bitwarden => {
            import::import_bitwarden_json(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::Keepass => {
            import::import_keepass_xml(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::Lastpass => {
            import::import_lastpass_csv(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::OnePassword => {
            import::import_onepassword_csv(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::Dashlane => {
            import::import_dashlane_csv(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::Apple => {
            import::import_apple_csv(&content).map_err(|e| anyhow::anyhow!(e))?
        }
        ImportFormat::Firefox => {
            import::import_firefox_csv(&content).map_err(|e| anyhow::anyhow!(e))?
        }
    };

    let count = entries.len();

    if count == 0 {
        println!("No entries found in the import file.");
        return Ok(());
    }

    vault.entries.extend(entries);
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Imported {} entries from {}.",
        "✓".green(),
        count,
        args.file.display()
    );
    Ok(())
}

pub fn handle_export(args: &ExportArgs, vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    let output = match args.format {
        ExportFormat::Csv => import::export_csv(&vault),
        ExportFormat::BitwardenJson => {
            import::export_bitwarden_json(&vault).map_err(|e| anyhow::anyhow!(e))?
        }
        ExportFormat::Lastpass => import::export_lastpass_csv(&vault),
    };

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &output)
            .map_err(|e| anyhow::anyhow!("Failed to write to '{}': {e}", output_path.display()))?;
        println!(
            "{} Exported {} entries to {}.",
            "✓".green(),
            vault.entries.len(),
            output_path.display()
        );
    } else {
        print!("{output}");
    }

    Ok(())
}
