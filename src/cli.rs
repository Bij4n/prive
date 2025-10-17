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
    pub command: VaultCommand,
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Create a new vault with a master password
    Init,
    /// Change the vault master password
    ChangePassword,
}

// --- Password Management ---

#[derive(Parser)]
pub struct PwArgs {
    #[command(subcommand)]
    pub command: PwCommand,
}

#[derive(Subcommand)]
pub enum PwCommand {
    /// Add a new password entry
    Add {
        /// Entry name (e.g. "GitHub")
        name: String,
        /// Username or email
        #[arg(short, long)]
        username: Option<String>,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Auto-generate the password
        #[arg(short, long)]
        generate: bool,
        /// Generated password length
        #[arg(short, long, default_value = "20")]
        length: usize,
        /// Associated URL
        #[arg(long)]
        url: Option<String>,
        /// Notes
        #[arg(long)]
        notes: Option<String>,
        /// Comma-separated tags
        #[arg(short, long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Retrieve a password
    Get {
        /// Entry name
        name: String,
        /// Print password to stdout instead of clipboard
        #[arg(long)]
        show: bool,
        /// Copy to clipboard (default behavior)
        #[arg(long)]
        copy: bool,
        /// Retrieve a specific field
        #[arg(long)]
        field: Option<String>,
    },
    /// List all entries
    List {
        /// Filter by tags
        #[arg(short, long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Edit an existing entry
    Edit {
        /// Entry name
        name: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(short, long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
    },
    /// Delete an entry
    Rm {
