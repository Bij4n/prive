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
    let mut vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let content = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {e}", args.file.display()))?;

    let entries = match args.format {
        ImportFormat::Csv => import::import_csv(&content).map_err(|e| anyhow::anyhow!(e))?,
        ImportFormat::Bitwarden => {
