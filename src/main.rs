#![allow(dead_code)]

mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod pgp;
mod session;
mod tui;
mod util;
mod vault;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};
use commands::{
    audit, backup, completions, config_cmd, encrypt, import_export, notes, password,
    pgp as pgp_cmd, session as session_cmd, vault as vault_cmd,
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let vault_path = cli.vault_path.as_deref();

    match &cli.command {
        Commands::Vault(args) => vault_cmd::handle_vault(&args.command, vault_path),
        Commands::Pw(args) => password::handle_pw(&args.command, vault_path),
        Commands::Generate(args) => password::handle_generate(args),
        Commands::Pgp(args) => pgp_cmd::handle_pgp(&args.command),
        Commands::Encrypt(args) => encrypt::handle_encrypt(args),
        Commands::Decrypt(args) => encrypt::handle_decrypt(args),
        Commands::Config(args) => config_cmd::handle_config(&args.command),
        Commands::Audit(args) => audit::handle_audit(args, vault_path),
        Commands::Backup(args) => backup::handle_backup(&args.command, vault_path),
        Commands::Import(args) => import_export::handle_import(args, vault_path),
        Commands::Export(args) => import_export::handle_export(args, vault_path),
        Commands::Completions(args) => completions::handle_completions(args),
        Commands::Note(args) => notes::handle_note(&args.command, vault_path),
        Commands::Session(args) => session_cmd::handle_session(&args.command, vault_path),
        Commands::Tui => {
            let path = vault_path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(config::vault_path);
            let password = rpassword::prompt_password("Master password: ")?;
            let vault_data = vault::storage::VaultStorage::load(&path, password.as_bytes())
                .map_err(|e| anyhow::anyhow!(e))?;
            tui::run_tui(&vault_data)
        }
    }
}
