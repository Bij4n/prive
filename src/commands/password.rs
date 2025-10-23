use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::cli::{GenerateArgs, PwCommand};
use crate::config;
use crate::crypto::password_gen;
use crate::crypto::totp;
use crate::util;
use crate::vault::model::VaultEntry;
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
