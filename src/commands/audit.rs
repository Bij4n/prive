use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::AuditArgs;
use crate::config;
use crate::crypto::audit::{self, Severity};
use crate::vault::storage::VaultStorage;

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

pub fn handle_audit(args: &AuditArgs, vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let report = audit::audit_vault(&vault);

    // Print score
    let score_color = if report.score >= 80 {
        report.score.to_string().green()
    } else if report.score >= 50 {
        report.score.to_string().yellow()
    } else {
        report.score.to_string().red()
    };

    println!("\n{} Vault Security Audit", "===".bold());
    println!("Total entries: {}", report.total_entries);
    println!("Security score: {}/100\n", score_color);
