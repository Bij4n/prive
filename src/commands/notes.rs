use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::cli::NoteCommand;
use crate::config;
use crate::vault::model::SecureNote;
use crate::vault::storage::VaultStorage;

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

fn unlock_vault(
    vault_path: Option<&Path>,
) -> Result<(std::path::PathBuf, crate::vault::model::Vault, String)> {
    let path = resolve_vault_path(vault_path);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;
    Ok((path, vault, password))
}

pub fn handle_note(cmd: &NoteCommand, vault_path: Option<&Path>) -> Result<()> {
    match cmd {
        NoteCommand::Add { title, tags } => cmd_add(vault_path, title, tags),
        NoteCommand::Get { title, copy } => cmd_get(vault_path, title, *copy),
        NoteCommand::List { tags } => cmd_list(vault_path, tags),
        NoteCommand::Edit { title } => cmd_edit(vault_path, title),
        NoteCommand::Rm { title, force } => cmd_rm(vault_path, title, *force),
        NoteCommand::Search { query } => cmd_search(vault_path, query),
    }
}

fn read_multiline_input() -> Result<String> {
    println!(
        "{}",
        "(Enter note content. End with an empty line or Ctrl+D)".dimmed()
    );
    let stdin = io::stdin();
    let mut lines = Vec::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }

    Ok(lines.join("\n"))
}

fn cmd_add(vault_path: Option<&Path>, title: &str, tags: &[String]) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    if vault.find_note_by_title(title).is_some() {
        anyhow::bail!("Note '{}' already exists", title);
    }

    let content = read_multiline_input()?;
    if content.is_empty() {
        anyhow::bail!("Note content cannot be empty");
    }

    vault
        .secure_notes
        .push(SecureNote::new(title.to_string(), content, tags.to_vec()));
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Note '{}' added.", "✓".green(), title);
    Ok(())
}

fn cmd_get(vault_path: Option<&Path>, title: &str, copy: bool) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let note = vault
        .find_note_by_title(title)
        .ok_or_else(|| anyhow::anyhow!("Note '{}' not found", title))?;

    if copy {
        crate::util::copy_to_clipboard(&note.content)?;
        println!("{} Note content copied to clipboard.", "✓".green());
    } else {
        println!("{}: {}", "Title".bold(), note.title);
        if !note.tags.is_empty() {
            println!("{}: {}", "Tags".bold(), note.tags.join(", "));
        }
        println!(
            "{}: {}",
            "Created".bold(),
            note.created_at.format("%Y-%m-%d %H:%M")
        );
        println!(
            "{}: {}",
            "Modified".bold(),
            note.modified_at.format("%Y-%m-%d %H:%M")
        );
        println!();
        println!("{}", note.content);
    }

    Ok(())
}

#[derive(Tabled)]
struct NoteRow {
    #[tabled(rename = "Title")]
    title: String,
    #[tabled(rename = "Tags")]
    tags: String,
    #[tabled(rename = "Created")]
    created: String,
    #[tabled(rename = "Preview")]
    preview: String,
}

fn cmd_list(vault_path: Option<&Path>, filter_tags: &[String]) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let notes: Vec<&SecureNote> = if filter_tags.is_empty() {
        vault.secure_notes.iter().collect()
    } else {
        vault
            .secure_notes
            .iter()
            .filter(|n| {
                filter_tags
                    .iter()
                    .any(|t| n.tags.iter().any(|nt| nt.eq_ignore_ascii_case(t)))
            })
            .collect()
    };

    if notes.is_empty() {
        println!("No notes found.");
        return Ok(());
    }

    let rows: Vec<NoteRow> = notes
        .iter()
        .map(|n| {
            let preview = if n.content.len() > 40 {
                format!("{}...", &n.content[..37])
            } else {
                n.content.clone()
            };
            NoteRow {
                title: n.title.clone(),
                tags: n.tags.join(", "),
                created: n.created_at.format("%Y-%m-%d").to_string(),
                preview: preview.replace('\n', " "),
            }
        })
        .collect();

    let table = Table::new(rows);
    println!("{table}");
    println!("\n{} note(s)", notes.len());

    Ok(())
}

fn cmd_edit(vault_path: Option<&Path>, title: &str) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    let note = vault
        .find_note_by_title_mut(title)
        .ok_or_else(|| anyhow::anyhow!("Note '{}' not found", title))?;

    println!("Current content:");
    println!("{}", note.content.dimmed());
    println!();

    let content = read_multiline_input()?;
    if !content.is_empty() {
        note.content = content;
        note.modified_at = chrono::Utc::now();
    }
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Note '{}' updated.", "✓".green(), title);
    Ok(())
}

fn cmd_rm(vault_path: Option<&Path>, title: &str, force: bool) -> Result<()> {
    let (path, mut vault, master_pw) = unlock_vault(vault_path)?;

    if vault.find_note_by_title(title).is_none() {
        anyhow::bail!("Note '{}' not found", title);
    }

    if !force {
        print!("Delete note '{title}'? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    vault.remove_note_by_title(title);
    vault.modified_at = chrono::Utc::now();

    VaultStorage::save(&path, &vault, master_pw.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Note '{}' deleted.", "✓".green(), title);
    Ok(())
}

fn cmd_search(vault_path: Option<&Path>, query: &str) -> Result<()> {
    let (_path, vault, _master_pw) = unlock_vault(vault_path)?;

    let results = vault.search_notes(query);

    if results.is_empty() {
        println!("No notes matching '{query}'.");
        return Ok(());
    }

    let rows: Vec<NoteRow> = results
        .iter()
        .map(|n| {
            let preview = if n.content.len() > 40 {
                format!("{}...", &n.content[..37])
            } else {
                n.content.clone()
            };
            NoteRow {
                title: n.title.clone(),
                tags: n.tags.join(", "),
                created: n.created_at.format("%Y-%m-%d").to_string(),
                preview: preview.replace('\n', " "),
            }
        })
        .collect();

    let table = Table::new(rows);
    println!("{table}");
    println!("\n{} result(s) for '{query}'", results.len());

    Ok(())
}
