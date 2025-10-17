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
    /// Generate a password (standalone, no vault needed)
    Generate(GenerateArgs),
    /// Manage PGP keys
    Pgp(PgpArgs),
    /// Encrypt a file
    Encrypt(EncryptArgs),
    /// Decrypt a file
    Decrypt(DecryptArgs),
    /// Manage configuration
    Config(ConfigArgs),
    /// Audit vault security
    Audit(AuditArgs),
    /// Manage backups
    Backup(BackupArgs),
    /// Import entries from file
    Import(ImportArgs),
    /// Export vault entries
    Export(ExportArgs),
    /// Generate shell completions
    Completions(CompletionsArgs),
    /// Launch interactive TUI mode
    Tui,
}

// --- Vault ---

#[derive(Parser)]
pub struct VaultArgs {
    #[command(subcommand)]
