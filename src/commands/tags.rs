use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::TagCommand;
use crate::config;
use crate::vault::storage::VaultStorage;

pub fn handle_tag(cmd: &TagCommand, vault_path: Option<&Path>) -> Result<()> {
    match cmd {
        TagCommand::List => cmd_list(vault_path),
        TagCommand::Rename { old, new } => cmd_rename(vault_path, old, new),
        TagCommand::Delete { tag } => cmd_delete(vault_path, tag),
    }
}

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

fn cmd_list(vault_path: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut tag_counts: HashMap<String, usize> = HashMap::new();

    for entry in &vault.entries {
        for tag in &entry.tags {
            *tag_counts.entry(tag.clone()).or_default() += 1;
        }
    }
    for note in &vault.secure_notes {
        for tag in &note.tags {
            *tag_counts.entry(tag.clone()).or_default() += 1;
        }
    }

    if tag_counts.is_empty() {
        println!("No tags found.");
        return Ok(());
    }

    let mut tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
    tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    for (tag, count) in &tags {
        println!("  {} ({count})", tag.bold());
    }
    println!("\n{} unique tags", tags.len());

    Ok(())
}

fn cmd_rename(vault_path: Option<&Path>, old: &str, new: &str) -> Result<()> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let mut vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut count = 0;

    for entry in &mut vault.entries {
        for tag in &mut entry.tags {
            if tag.eq_ignore_ascii_case(old) {
                *tag = new.to_string();
                count += 1;
            }
        }
    }
    for note in &mut vault.secure_notes {
        for tag in &mut note.tags {
            if tag.eq_ignore_ascii_case(old) {
                *tag = new.to_string();
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("Tag '{}' not found.", old);
        return Ok(());
    }

    vault.modified_at = chrono::Utc::now();
    VaultStorage::save(&path, &vault, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Renamed tag '{}' -> '{}' ({} occurrences).",
        "✓".green(),
        old,
        new,
        count
    );
    Ok(())
}

fn cmd_delete(vault_path: Option<&Path>, tag: &str) -> Result<()> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let mut vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut count = 0;

    for entry in &mut vault.entries {
        let before = entry.tags.len();
        entry.tags.retain(|t| !t.eq_ignore_ascii_case(tag));
        count += before - entry.tags.len();
    }
    for note in &mut vault.secure_notes {
        let before = note.tags.len();
        note.tags.retain(|t| !t.eq_ignore_ascii_case(tag));
        count += before - note.tags.len();
    }

    if count == 0 {
        println!("Tag '{}' not found.", tag);
        return Ok(());
    }

    vault.modified_at = chrono::Utc::now();
    VaultStorage::save(&path, &vault, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Removed tag '{}' ({} occurrences).",
        "✓".green(),
        tag,
        count
    );
    Ok(())
}
