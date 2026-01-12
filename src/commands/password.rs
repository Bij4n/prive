use std::path::{Path, PathBuf};

use anyhow::Result;
use base64::Engine;
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::cli::{GenerateArgs, PwCommand};
use crate::config;
use crate::crypto::password_gen;
use crate::crypto::totp;
use crate::util;
use crate::vault::model::{VaultAttachment, VaultEntry};
use crate::vault::storage::VaultStorage;

pub fn handle_generate(args: &GenerateArgs) -> Result<()> {
    let result = if args.pin {
        password_gen::generate_pin(args.length)
    } else if args.pronounceable {
        password_gen::generate_pronounceable(args.length)
    } else if let Some(charset) = &args.charset {
        password_gen::generate_custom(args.length, charset)
            .map_err(|e| anyhow::anyhow!(e))?
    } else if args.passphrase {
        password_gen::generate_passphrase(args.words, &args.separator)
    } else {
        password_gen::generate_password(
            args.length,
            !args.no_uppercase,
            !args.no_numbers,
            !args.no_symbols,
        )
    };

    if args.copy {
        util::copy_to_clipboard(&result)?;
        println!("{} Password copied to clipboard.", "✓".green());
    } else {
        println!("{result}");
    }

    Ok(())
}

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

fn unlock_vault(vault_path: Option<&Path>) -> Result<(std::path::PathBuf, crate::vault::model::Vault, String)> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok((path, vault, password))
}

pub fn handle_pw(cmd: &PwCommand, vault_path_override: Option<&Path>) -> Result<()> {
    match cmd {
        PwCommand::Add {
            name,
            username,
            password,
            generate,
            length,
            url,
            notes,
            tags,
        } => cmd_add(
            vault_path_override,
            name,
            username.as_deref(),
            password.as_deref(),
            *generate,
            *length,
            url.as_deref(),
            notes.as_deref(),
            tags,
        ),
        PwCommand::Get { name, show, copy, field } => {
            cmd_get(vault_path_override, name, *show, *copy, field.as_deref())
        }
        PwCommand::List { tags, format } => cmd_list(vault_path_override, tags, format),
        PwCommand::Edit {
            name,
            username,
            password,
            url,
            notes,
            tags,
        } => cmd_edit(
            vault_path_override,
            name,
            username.as_deref(),
            password.as_deref(),
            url.as_deref(),
            notes.as_deref(),
            tags.as_deref(),
        ),
        PwCommand::Rm { name, force } => cmd_rm(vault_path_override, name, *force),
        PwCommand::Search { query } => cmd_search(vault_path_override, query),
        PwCommand::Totp { name } => cmd_totp(vault_path_override, name),
        PwCommand::TotpAdd { name, secret, uri } => {
            cmd_totp_add(vault_path_override, name, secret.as_deref(), uri.as_deref())
        }
        PwCommand::History { name, show } => cmd_history(vault_path_override, name, *show),
        PwCommand::Attach { name, file } => cmd_attach(vault_path_override, name, file),
        PwCommand::Detach { name, attachment } => {
            cmd_detach(vault_path_override, name, attachment)
        }
        PwCommand::Attachments { name } => cmd_attachments(vault_path_override, name),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_add(
    vault_path: Option<&Path>,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    generate: bool,
    length: usize,
    url: Option<&str>,
    notes: Option<&str>,
    tags: &[String],
) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    if vault.find_by_name(name).is_some() {
        anyhow::bail!("Entry '{}' already exists", name);
    }

    let pw = if generate {
        let generated = password_gen::generate_password(length, true, true, true);
        println!("Generated password: {}", generated.dimmed());
        generated
    } else if let Some(p) = password {
        p.to_string()
    } else {
        let p = rpassword::prompt_password("Enter password for this entry: ")?;
        if p.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        p
    };

    let entry = VaultEntry::new(
        name.to_string(),
        username.map(String::from),
        pw,
        url.map(String::from),
        notes.map(String::from),
        tags.to_vec(),
    );
    vault.entries.push(entry);
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Entry '{}' added.", "✓".green(), name);
    Ok(())
}

fn cmd_get(
    vault_path: Option<&Path>,
    name: &str,
    show: bool,
    copy: bool,
    field: Option<&str>,
) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    let value = match field {
        Some("username") => entry.username.as_deref().unwrap_or("(none)").to_string(),
        Some("url") => entry.url.as_deref().unwrap_or("(none)").to_string(),
        Some("notes") => entry.notes.as_deref().unwrap_or("(none)").to_string(),
        Some("password") | None => entry.password.clone(),
        Some(f) => anyhow::bail!("Unknown field: '{f}'. Use: username, password, url, notes"),
    };

    if show {
        if field.is_none() {
            // Show full entry details
            println!("{}: {}", "Name".bold(), entry.name);
            if let Some(u) = &entry.username {
                println!("{}: {u}", "Username".bold());
            }
            println!("{}: {}", "Password".bold(), entry.password);
            if let Some(u) = &entry.url {
                println!("{}: {u}", "URL".bold());
            }
            if let Some(n) = &entry.notes {
                println!("{}: {n}", "Notes".bold());
            }
            if !entry.tags.is_empty() {
                println!("{}: {}", "Tags".bold(), entry.tags.join(", "));
            }
        } else {
            println!("{value}");
        }
    } else if copy || (!show && field.is_none()) {
        util::copy_to_clipboard(&value)?;
        println!("{} Password copied to clipboard.", "✓".green());
    } else {
        println!("{value}");
    }

    Ok(())
}

#[derive(Tabled)]
struct EntryRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Username")]
    username: String,
    #[tabled(rename = "URL")]
    url: String,
    #[tabled(rename = "Tags")]
    tags: String,
}

fn cmd_list(vault_path: Option<&Path>, filter_tags: &[String], format: &str) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let entries: Vec<&VaultEntry> = if filter_tags.is_empty() {
        vault.entries.iter().collect()
    } else {
        vault
            .entries
            .iter()
            .filter(|e| {
                filter_tags
                    .iter()
                    .any(|t| e.tags.iter().any(|et| et.eq_ignore_ascii_case(t)))
            })
            .collect()
    };

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(
                &entries
                    .iter()
                    .map(|e| serde_json::json!({
                        "name": e.name,
                        "username": e.username,
                        "url": e.url,
                        "tags": e.tags,
                    }))
                    .collect::<Vec<_>>(),
            )?;
            println!("{json}");
        }
        _ => {
            let rows: Vec<EntryRow> = entries
                .iter()
                .map(|e| EntryRow {
                    name: e.name.clone(),
                    username: e.username.clone().unwrap_or_default(),
                    url: e.url.clone().unwrap_or_default(),
                    tags: e.tags.join(", "),
                })
                .collect();
            let table = Table::new(rows);
            println!("{table}");
        }
    }

    println!(
        "\n{} total entries{}",
        entries.len(),
        if !filter_tags.is_empty() {
            " (filtered)"
        } else {
            ""
        }
    );

    Ok(())
}

fn cmd_edit(
    vault_path: Option<&Path>,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    tags: Option<&[String]>,
) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name_mut(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    if let Some(u) = username {
        entry.username = Some(u.to_string());
    }
    if let Some(p) = password {
        entry.rotate_password(p.to_string());
    }
    if let Some(u) = url {
        entry.url = Some(u.to_string());
    }
    if let Some(n) = notes {
        entry.notes = Some(n.to_string());
    }
    if let Some(t) = tags {
        entry.tags = t.to_vec();
    }
    entry.modified_at = chrono::Utc::now();
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Entry '{}' updated.", "✓".green(), name);
    Ok(())
}

fn cmd_rm(vault_path: Option<&Path>, name: &str, force: bool) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    if vault.find_by_name(name).is_none() {
        anyhow::bail!("Entry '{}' not found", name);
    }

    if !force {
        print!("Delete entry '{name}'? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    vault.remove_by_name(name);
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Entry '{}' deleted.", "✓".green(), name);
    Ok(())
}

fn cmd_search(vault_path: Option<&Path>, query: &str) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let results = vault.search(query);

    if results.is_empty() {
        println!("No entries matching '{query}'.");
        return Ok(());
    }

    let rows: Vec<EntryRow> = results
        .iter()
        .map(|e| EntryRow {
            name: e.name.clone(),
            username: e.username.clone().unwrap_or_default(),
            url: e.url.clone().unwrap_or_default(),
            tags: e.tags.join(", "),
        })
        .collect();

    let table = Table::new(rows);
    println!("{table}");
    println!("\n{} results for '{query}'", results.len());

    Ok(())
}

fn cmd_totp(vault_path: Option<&Path>, name: &str) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    let secret_str = entry
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' has no TOTP secret configured", name))?;

    let secret_bytes = totp::decode_base32_secret(secret_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode TOTP secret: {e}"))?;

    let code = totp::generate_totp(&secret_bytes, 30, 6)
        .map_err(|e| anyhow::anyhow!("Failed to generate TOTP: {e}"))?;

    let remaining = totp::time_remaining(30);

    println!("{}: {}", "TOTP Code".bold(), code.green().bold());
    println!(
        "Expires in {} seconds",
        remaining.to_string().yellow()
    );

    Ok(())
}

fn cmd_totp_add(
    vault_path: Option<&Path>,
    name: &str,
    secret: Option<&str>,
    uri: Option<&str>,
) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name_mut(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    let totp_secret = if let Some(uri_str) = uri {
        let params = totp::parse_otpauth_uri(uri_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse otpauth URI: {e}"))?;
        params.secret
    } else if let Some(s) = secret {
        // Validate that the secret is valid base32
        totp::decode_base32_secret(s)
            .map_err(|e| anyhow::anyhow!("Invalid base32 secret: {e}"))?;
        s.to_string()
    } else {
        anyhow::bail!("Provide either --secret or --uri");
    };

    entry.totp_secret = Some(totp_secret);
    entry.modified_at = chrono::Utc::now();
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} TOTP secret added to '{}'.", "✓".green(), name);
    Ok(())
}

fn cmd_history(vault_path: Option<&Path>, name: &str, show: bool) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    if entry.password_history.is_empty() {
        println!("No password history for '{name}'.");
        return Ok(());
    }

    println!("{}: {} ({} previous passwords)\n", "History for".bold(), name, entry.password_history.len());

    for (i, hist) in entry.password_history.iter().enumerate().rev() {
        let pw_display = if show {
            hist.password.clone()
        } else {
            "*".repeat(hist.password.len().min(20))
        };
        let date = hist.changed_at.format("%Y-%m-%d %H:%M");
        println!("  {}. {} (changed {})", i + 1, pw_display, date);
    }

    let current_display = if show {
        entry.password.clone()
    } else {
        "*".repeat(entry.password.len().min(20))
    };
    println!("\n  {}: {}", "Current".green().bold(), current_display);

    if !show {
        println!("\n  {}", "Use --show to reveal passwords".dimmed());
    }

    Ok(())
}

/// Maximum attachment size: 1 MB
const MAX_ATTACHMENT_SIZE: u64 = 1_048_576;

fn cmd_attach(vault_path: Option<&Path>, name: &str, file: &PathBuf) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name_mut(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    let metadata = std::fs::metadata(file)
        .map_err(|e| anyhow::anyhow!("Cannot read file '{}': {}", file.display(), e))?;

    if metadata.len() > MAX_ATTACHMENT_SIZE {
        anyhow::bail!(
            "File is too large ({} bytes). Maximum attachment size is 1 MB.",
            metadata.len()
        );
    }

    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "attachment".to_string());

    // Check for duplicate attachment names
    if entry.get_attachment(&file_name).is_some() {
        anyhow::bail!(
            "Attachment '{}' already exists on entry '{}'. Remove it first.",
            file_name,
            name
        );
    }

    let raw_data = std::fs::read(file)
        .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

    let mime_type = detect_mime_type(&file_name);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&raw_data);

    let attachment = VaultAttachment {
        name: file_name.clone(),
        mime_type,
        data: encoded,
        size: metadata.len(),
        added_at: chrono::Utc::now(),
    };

    entry.add_attachment(attachment);
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Attached '{}' to entry '{}'.",
        "✓".green(),
        file_name,
        name
    );
    Ok(())
}

fn cmd_detach(vault_path: Option<&Path>, name: &str, attachment_name: &str) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name_mut(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    if !entry.remove_attachment(attachment_name) {
        anyhow::bail!(
            "Attachment '{}' not found on entry '{}'",
            attachment_name,
            name
        );
    }

    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Removed attachment '{}' from entry '{}'.",
        "✓".green(),
        attachment_name,
        name
    );
    Ok(())
}

fn cmd_attachments(vault_path: Option<&Path>, name: &str) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let entry = vault
        .find_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("Entry '{}' not found", name))?;

    let attachments = entry.list_attachments();

    if attachments.is_empty() {
        println!("No attachments for '{name}'.");
        return Ok(());
    }

    println!("{}: {}\n", "Attachments for".bold(), name);
    for (i, att) in attachments.iter().enumerate() {
        let size_display = if att.size >= 1024 {
            format!("{:.1} KB", att.size as f64 / 1024.0)
        } else {
            format!("{} B", att.size)
        };
        println!(
            "  {}. {} ({}, {}), added {}",
            i + 1,
            att.name.bold(),
            att.mime_type.dimmed(),
            size_display,
            att.added_at.format("%Y-%m-%d %H:%M")
        );
    }
    println!("\n{} attachment(s) total", attachments.len());

    Ok(())
}

/// Simple MIME type detection based on file extension.
fn detect_mime_type(filename: &str) -> String {
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "csv" => "text/csv",
        "doc" | "docx" => "application/msword",
        "pem" | "crt" | "key" => "application/x-pem-file",
        _ => "application/octet-stream",
    }
    .to_string()
}
