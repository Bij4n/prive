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
