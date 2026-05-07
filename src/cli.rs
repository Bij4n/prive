use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "prive",
    version,
    about = "Cross-platform password & encryption toolkit"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Override default vault file location (full path)
    #[arg(long, global = true)]
    pub vault_path: Option<PathBuf>,

    /// Select a named vault (e.g. "work", "personal")
    #[arg(long, global = true, conflicts_with = "vault_path")]
    pub vault: Option<String>,

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
    /// Manage secure notes
    Note(NoteArgs),
    /// Manage agent session
    Session(SessionArgs),
    /// Manage clipboard
    Clip(ClipArgs),
    /// Sync vault via git remote
    Sync(SyncArgs),
    /// Share entries with another user
    Share(ShareArgs),
    /// Manage tags
    Tag(TagArgs),
    /// Show vault statistics
    Stats,
    /// Diagnose config, vault, and keyring health
    Doctor,
}

// --- Share ---

#[derive(Parser)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub command: ShareCommand,
}

#[derive(Subcommand)]
pub enum ShareCommand {
    /// Export entries encrypted for a recipient
    Export {
        /// Entry names to share
        #[arg(required = true)]
        names: Vec<String>,
        /// Recipient's PGP key ID
        #[arg(long)]
        recipient: String,
        /// Output file path
        #[arg(short, long)]
        output: std::path::PathBuf,
    },
    /// Import shared entries from a file
    Import {
        /// Path to the shared file
        file: std::path::PathBuf,
    },
}

// --- Tags ---

#[derive(Parser)]
pub struct TagArgs {
    #[command(subcommand)]
    pub command: TagCommand,
}

#[derive(Subcommand)]
pub enum TagCommand {
    /// List all tags with entry counts
    List,
    /// Rename a tag across all entries and notes
    Rename {
        /// Current tag name
        old: String,
        /// New tag name
        new: String,
    },
    /// Remove a tag from all entries and notes
    Delete {
        /// Tag to remove
        tag: String,
    },
}

// --- Session ---

#[derive(Parser)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Subcommand)]
pub enum SessionCommand {
    /// Start the vault agent (keeps vault unlocked in background)
    Start,
    /// Stop the running agent
    Stop,
    /// Check agent status
    Status,
    /// Print shell environment variables for agent integration (use with eval)
    Env,
}

// --- Clipboard ---

#[derive(Parser)]
pub struct ClipArgs {
    #[command(subcommand)]
    pub command: ClipCommand,
}

#[derive(Subcommand)]
pub enum ClipCommand {
    /// Clear the clipboard immediately
    Clear,
    /// Show clipboard auto-clear status and timeout
    Status,
}

// --- Sync ---

#[derive(Parser)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub command: SyncCommand,
}

#[derive(Subcommand)]
pub enum SyncCommand {
    /// Initialize git-backed vault sync with a remote URL
    Init {
        /// Git remote URL
        url: String,
    },
    /// Push vault changes to remote
    Push,
    /// Pull vault changes from remote
    Pull,
    /// Show sync status
    Status,
}

// --- Notes ---

#[derive(Parser)]
pub struct NoteArgs {
    #[command(subcommand)]
    pub command: NoteCommand,
}

#[derive(Subcommand)]
pub enum NoteCommand {
    /// Add a new secure note
    Add {
        /// Note title
        title: String,
        /// Comma-separated tags
        #[arg(short, long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// View a secure note
    Get {
        /// Note title
        title: String,
        /// Copy content to clipboard
        #[arg(long)]
        copy: bool,
    },
    /// List all notes
    List {
        /// Filter by tags
        #[arg(short, long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Edit a note
    Edit {
        /// Note title
        title: String,
    },
    /// Delete a note
    Rm {
        /// Note title
        title: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Search notes
    Search {
        /// Search query
        query: String,
    },
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
    /// List all vaults
    List,
    /// Switch active vault
    Switch {
        /// Vault name
        name: String,
    },
    /// Create a named vault
    Create {
        /// Vault name
        name: String,
    },
    /// Delete a named vault
    Delete {
        /// Vault name
        name: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Show vault info (version, entry count, file size)
    Info,
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
        /// Entry name
        name: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Search entries by name, URL, or tags
    Search {
        /// Search query
        query: String,
    },
    /// Show TOTP code for an entry
    Totp {
        /// Entry name
        name: String,
    },
    /// Add TOTP secret to an entry
    TotpAdd {
        /// Entry name
        name: String,
        /// Base32-encoded TOTP secret
        #[arg(long)]
        secret: Option<String>,
        /// otpauth:// URI
        #[arg(long)]
        uri: Option<String>,
    },
    /// Show password history for an entry
    History {
        /// Entry name
        name: String,
        /// Show actual passwords (default: masked)
        #[arg(long)]
        show: bool,
    },
    /// Attach a file to an entry
    Attach {
        /// Entry name
        name: String,
        /// Path to the file to attach
        file: PathBuf,
    },
    /// Remove an attachment from an entry
    Detach {
        /// Entry name
        name: String,
        /// Attachment name to remove
        attachment: String,
    },
    /// List attachments for an entry
    Attachments {
        /// Entry name
        name: String,
    },
    /// Export (download) an attachment to a file
    GetAttachment {
        /// Entry name
        name: String,
        /// Attachment name
        attachment: String,
        /// Output file path (defaults to attachment name in current dir)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

// --- Password Generation ---

#[derive(Parser)]
pub struct GenerateArgs {
    /// Password length
    #[arg(short, long, default_value = "20")]
    pub length: usize,

    /// Exclude symbols
    #[arg(long)]
    pub no_symbols: bool,

    /// Exclude numbers
    #[arg(long)]
    pub no_numbers: bool,

    /// Exclude uppercase letters
    #[arg(long)]
    pub no_uppercase: bool,

    /// Generate a diceware-style passphrase instead
    #[arg(long)]
    pub passphrase: bool,

    /// Number of words for passphrase
    #[arg(short, long, default_value = "6")]
    pub words: usize,

    /// Separator for passphrase words
    #[arg(short, long, default_value = "-")]
    pub separator: String,

    /// Copy result to clipboard
    #[arg(short, long)]
    pub copy: bool,

    /// Generate a numeric PIN
    #[arg(long)]
    pub pin: bool,

    /// Generate a pronounceable password
    #[arg(long)]
    pub pronounceable: bool,

    /// Custom character set
    #[arg(long)]
    pub charset: Option<String>,
}

// --- PGP ---

#[derive(Parser)]
pub struct PgpArgs {
    #[command(subcommand)]
    pub command: PgpCommand,
}

#[derive(Subcommand)]
pub enum PgpCommand {
    /// Generate a new PGP keypair
    Generate {
        /// Name for the key UID
        #[arg(long)]
        name: Option<String>,
        /// Email for the key UID
        #[arg(long)]
        email: Option<String>,
        /// Algorithm: cv25519 or rsa4096
        #[arg(long, default_value = "cv25519")]
        algorithm: String,
        /// Expiration (e.g. "2y", "never")
        #[arg(long, default_value = "2y")]
        expire: String,
    },
    /// List keys in keyring
    List {
        /// Show only secret keys
        #[arg(long)]
        secret: bool,
    },
    /// Export a key (ASCII armored)
    Export {
        /// Key ID or fingerprint
        key_id: String,
        /// Export the secret key
        #[arg(long)]
        secret: bool,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Import a key from file
    Import {
        /// Path to the key file
        file: PathBuf,
    },
    /// Delete a key from the keyring
    Delete {
        /// Key ID or fingerprint
        key_id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Show key details
    Info {
        /// Key ID or fingerprint
        key_id: String,
    },
    /// Set trust level for a key
    Trust {
        /// Key ID or fingerprint
        key_id: String,
        /// Trust level: unknown, untrusted, marginal, full, ultimate
        #[arg(long, default_value = "full")]
        level: String,
        /// Optional reason
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove trust for a key
    Untrust {
        /// Key ID or fingerprint
        key_id: String,
    },
    /// List trusted keys
    TrustList,
    /// Generate a revocation certificate for a key
    GenRevoke {
        /// Key ID or fingerprint
        key_id: String,
        /// Reason for revocation
        #[arg(long, default_value = "Key no longer used")]
        reason: String,
        /// Output file (defaults to <key_id>.rev.asc)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List stored revocation certificates
    Revocations,
}

// --- File Encryption ---

#[derive(Parser)]
pub struct EncryptArgs {
    /// File to encrypt
    pub file: PathBuf,

    /// Encrypt to PGP recipient (repeatable)
    #[arg(short, long)]
    pub recipient: Vec<String>,

    /// Encrypt with passphrase instead of PGP
    #[arg(long)]
    pub symmetric: bool,

    /// Sign with a secret key
    #[arg(long)]
    pub sign: Option<String>,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// ASCII armor output
    #[arg(short, long)]
    pub armor: bool,
}

#[derive(Parser)]
pub struct DecryptArgs {
    /// File to decrypt
    pub file: PathBuf,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verify signature if present
    #[arg(long)]
    pub verify: bool,
}

// --- Config ---

#[derive(Parser)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Create default configuration
    Init,
    /// Show current configuration
    Show,
    /// Set a configuration value (key=value)
    Set {
        /// Key=value pair (e.g. "generate.default_length=24")
        pair: String,
    },
    /// Reset configuration to defaults
    Reset,
}

// --- Audit ---

#[derive(Parser)]
pub struct AuditArgs {
    /// Check passwords against Have I Been Pwned
    #[arg(long)]
    pub breach: bool,
}

// --- Backup ---

#[derive(Parser)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Create a new backup
    Create,
    /// List available backups
    List,
    /// Restore vault from a backup
    Restore {
        /// Path to backup file
        file: PathBuf,
    },
}

// --- Import ---

#[derive(Parser)]
pub struct ImportArgs {
    /// Import file format
    #[arg(long, value_enum, default_value = "csv")]
    pub format: ImportFormat,

    /// Path to the import file
    pub file: PathBuf,
}

#[derive(Clone, ValueEnum)]
pub enum ImportFormat {
    Csv,
    Bitwarden,
    Keepass,
    /// LastPass CSV export (File > Export > LastPass CSV File)
    Lastpass,
    /// 1Password CSV export
    #[value(name = "1password")]
    OnePassword,
    /// Dashlane CSV export
    Dashlane,
    /// Apple iCloud Passwords / Safari CSV export
    Apple,
    /// Firefox CSV export (about:logins > Export)
    Firefox,
}

// --- Export ---

#[derive(Parser)]
pub struct ExportArgs {
    /// Export file format
    #[arg(long, value_enum, default_value = "csv")]
    pub format: ExportFormat,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
pub enum ExportFormat {
    Csv,
    BitwardenJson,
    /// LastPass-compatible CSV export
    Lastpass,
}

// --- Completions ---

#[derive(Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(long, value_enum)]
    pub shell: ShellType,
}

#[derive(Clone, ValueEnum)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    Powershell,
}
