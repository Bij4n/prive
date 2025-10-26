#![allow(dead_code)]

mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod pgp;
mod tui;
mod util;
mod vault;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};
use commands::{
    audit, backup, completions, config_cmd, encrypt, import_export, password, pgp as pgp_cmd,
    vault as vault_cmd,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
