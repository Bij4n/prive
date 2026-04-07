use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::config;
use crate::crypto::strength;
use crate::vault::storage::VaultStorage;

pub fn handle_stats(vault_path: Option<&Path>) -> Result<()> {
    let path = vault_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path);

    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    println!("{}", "Vault Statistics".bold().underline());
    println!();

    // Basic counts
    println!("  {}: {}", "Password entries".bold(), vault.entries.len());
    println!("  {}: {}", "Secure notes".bold(), vault.secure_notes.len());

    // TOTP count
    let totp_count = vault
        .entries
        .iter()
        .filter(|e| e.totp_secret.is_some())
        .count();
    println!("  {}: {}", "Entries with TOTP".bold(), totp_count);

    // Attachment stats
    let attachment_count: usize = vault.entries.iter().map(|e| e.attachments.len()).sum();
    let attachment_size: u64 = vault
        .entries
        .iter()
        .flat_map(|e| e.attachments.iter())
        .map(|a| a.size)
        .sum();
    if attachment_count > 0 {
        println!(
            "  {}: {} ({} bytes total)",
            "Attachments".bold(),
            attachment_count,
            format_size(attachment_size)
        );
    }

    // Password stats
    if !vault.entries.is_empty() {
        println!();
        println!("{}", "Password Analysis".bold().underline());
        println!();

        let mut total_length = 0;
        let mut min_length = usize::MAX;
        let mut max_length = 0;
        let mut strongest_name = String::new();
        let mut strongest_score = 0u32;
        let mut weakest_name = String::new();
        let mut weakest_score = 100u32;

        for entry in &vault.entries {
            let len = entry.password.len();
            total_length += len;
            min_length = min_length.min(len);
            max_length = max_length.max(len);

            let report = strength::analyze_strength(&entry.password);
            if report.score >= strongest_score {
                strongest_score = report.score;
                strongest_name = entry.name.clone();
            }
            if report.score <= weakest_score {
                weakest_score = report.score;
                weakest_name = entry.name.clone();
            }
        }

        let avg_length = total_length / vault.entries.len();
        println!(
            "  {}: {} chars",
            "Average password length".bold(),
            avg_length
        );
        println!("  {}: {} chars", "Shortest password".bold(), min_length);
        println!("  {}: {} chars", "Longest password".bold(), max_length);
        println!(
            "  {}: {} (score: {})",
            "Strongest".bold(),
            strongest_name.green(),
            strongest_score
        );
        println!(
            "  {}: {} (score: {})",
            "Weakest".bold(),
            weakest_name.red(),
            weakest_score
        );

        // Password history stats
        let history_count: usize = vault.entries.iter().map(|e| e.password_history.len()).sum();
        if history_count > 0 {
            println!(
                "  {}: {} total rotations",
                "Password history".bold(),
                history_count
            );
        }
    }

    // Tag stats
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    for entry in &vault.entries {
        for tag in &entry.tags {
            *tag_counts.entry(tag.clone()).or_default() += 1;
        }
    }

    if !tag_counts.is_empty() {
        println!();
        println!("{}", "Tags".bold().underline());
        println!();
        println!("  {}: {}", "Unique tags".bold(), tag_counts.len());

        let mut tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        tags.sort_by(|a, b| b.1.cmp(&a.1));
        let top = tags.iter().take(5);
        for (tag, count) in top {
            println!("  {}: {count} entries", tag.dimmed());
        }
    }

    // Vault metadata
    println!();
    println!("{}", "Vault Info".bold().underline());
    println!();
    println!(
        "  {}: {}",
        "Created".bold(),
        vault.created_at.format("%Y-%m-%d %H:%M")
    );
    println!(
        "  {}: {}",
        "Last modified".bold(),
        vault.modified_at.format("%Y-%m-%d %H:%M")
    );
    println!("  {}: {}", "Format version".bold(), vault.version);
    println!("  {}: {}", "Path".bold(), path.display());

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
