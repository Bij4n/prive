use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "prive", version, about = "Cross-platform password & encryption toolkit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Override default vault file location
    #[arg(long, global = true)]
    pub vault_path: Option<PathBuf>,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Increase verbosity
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage the encrypted vault
    Vault(VaultArgs),
    /// Manage stored passwords
    Pw(PwArgs),
