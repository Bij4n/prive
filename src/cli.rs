//! Command-line interface. Data goes to stdout; prompts, notices and errors go to stderr.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "prive",
    version,
    arg_required_else_help = true,
    about = "Fast, scriptable terminal client for KeePass (KDBX) password databases",
    long_about = "Fast, scriptable terminal client for KeePass (KDBX) password databases.\n\n\
        prive opens the same .kdbx file as KeePassXC, KeePassDX and Strongbox. \
        Results go to stdout and everything else to stderr, so commands compose in scripts.\n\n\
        Exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 ambiguous entry, \
        5 wrong password or no terminal for the prompt, 130 cancelled.",
    after_help = "Entries are named by title, by Group/Title path, or by uuid:<uuid>."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct Global {
    /// Database file [default: the one in the config file]
    #[arg(long, global = true, env = "PRIVE_DB", value_name = "FILE")]
    pub db: Option<PathBuf>,

    /// Key file, if the database uses one
    #[arg(long, global = true, env = "PRIVE_KEYFILE", value_name = "FILE")]
    pub keyfile: Option<PathBuf>,

    /// Read the master password from the first line of stdin
    #[arg(long, global = true, conflicts_with = "no_password")]
    pub password_stdin: bool,

    /// Don't use the unlocked database from `prive unlock`; read the file and ask
    #[arg(
        long,
        global = true,
        env = "PRIVE_NO_AGENT",
        value_parser = clap::builder::FalseyValueParser::new()
    )]
    pub no_agent: bool,

    /// Leave out notices on stderr ("Copied", seconds left, entropy); errors still show
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// The database has no password, only a key file
    #[arg(long, global = true, requires = "keyfile")]
    pub no_password: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Unlock the database once; later commands use it without asking (Linux and macOS)
    Unlock,

    /// Forget the unlocked database now
    Lock,

    /// Say whether a database is unlocked, and for how long
    Status {
        #[arg(long)]
        json: bool,
    },

    /// Print one field of an entry (the password by default), nothing else
    Get {
        entry: String,
        /// password, username, url, notes, title, or a custom field's name
        #[arg(short, long, default_value = "password")]
        field: String,
        /// Copy to the clipboard instead of printing; cleared after a timeout
        #[arg(short, long)]
        clip: bool,
    },

    /// Print the current one-time (TOTP) code of an entry
    Otp {
        entry: String,
        /// If the current code expires sooner than this, wait for the next one (useful in
        /// scripts that type the code somewhere slow)
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        min_validity: u64,
        /// Copy to the clipboard instead of printing
        #[arg(short, long, conflicts_with = "json")]
        clip: bool,
        /// Print {"code": ..., "seconds_left": ..., "period": ...}
        #[arg(long)]
        json: bool,
    },

    /// Run a command with secrets in its environment (never printed, never on disk)
    Run {
        /// NAME=ENTRY (the password) or NAME=ENTRY:FIELD; repeat for several
        #[arg(
            short,
            long = "env",
            value_name = "NAME=ENTRY[:FIELD]",
            required_unless_present = "from"
        )]
        env: Vec<String>,
        /// Also export every custom field of this entry whose name is a valid variable name
        /// (e.g. AWS_ACCESS_KEY_ID); repeat for several entries
        #[arg(long, value_name = "ENTRY")]
        from: Vec<String>,
        /// The command and its arguments, after `--`
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },

    /// Open an entry's URL in the browser and copy its password
    Open {
        entry: String,
        /// Only open the URL; don't copy anything
        #[arg(long)]
        no_copy: bool,
    },

    /// Show an entry; passwords and protected fields stay hidden unless --reveal
    Show {
        /// Title, Group/Title path, or uuid:UUID
        entry: String,
        #[arg(long)]
        reveal: bool,
        #[arg(long)]
        json: bool,
    },

    /// List the tags in use, with how many entries carry each
    Tags {
        #[arg(long)]
        json: bool,
    },

    /// Find entries by title, username, URL, group or tag
    Search {
        query: String,
        #[arg(long)]
        json: bool,
    },

    /// List entries: paths and usernames, never passwords
    Ls {
        /// Only entries in this group and its subgroups
        group: Option<String>,
        /// Only entries with this tag (repeat for several: all must match)
        #[arg(short, long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Also show when each changed, and whether it has a code, files or has expired
        #[arg(short, long, conflicts_with = "json")]
        long: bool,
        #[arg(long)]
        json: bool,
    },

    /// Choose an entry interactively and copy its password
    Pick(PickArgs),

    /// Read another password manager's export and say what would come across
    Import {
        /// The export file (CSV)
        file: std::path::PathBuf,
        /// Which app made it [default: recognised from its header]
        #[arg(long, value_enum)]
        from: Option<crate::import::Format>,
        /// For --from csv: which column holds a field, e.g. --map username=Login (repeat)
        #[arg(long, value_name = "FIELD=COLUMN")]
        map: Vec<String>,
        /// Only read and report. (Writing a KeePass database from it comes next.)
        #[arg(long, required = true)]
        check: bool,
    },

    /// Report weak, reused, old and expired passwords
    Audit {
        /// Also check each password against Have I Been Pwned (sends 5 hex characters of its
        /// SHA-1 hash per password; nothing else leaves the machine)
        #[arg(long)]
        hibp: bool,
        /// Flag passwords not changed for more than this many days (0: don't check)
        #[arg(long, default_value_t = 365, value_name = "DAYS")]
        max_age: i64,
        #[arg(long)]
        json: bool,
    },

    /// Generate a password, passphrase or PIN (no database needed)
    Gen(GenArgs),

    /// Print shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Args)]
pub struct PickArgs {
    /// Start with this search text
    pub query: Option<String>,

    /// Take this field instead of the password
    #[arg(short, long, conflicts_with = "otp")]
    pub field: Option<String>,

    /// Take the current one-time code instead of the password
    #[arg(long)]
    pub otp: bool,

    /// Print the value instead of copying it
    #[arg(long)]
    pub print: bool,
}

#[derive(Debug, Args)]
pub struct GenArgs {
    /// Number of characters
    #[arg(short, long, default_value_t = 24)]
    pub length: usize,

    /// Leave out symbols
    #[arg(long)]
    pub no_symbols: bool,

    /// Leave out digits
    #[arg(long)]
    pub no_digits: bool,

    /// Leave out upper-case letters
    #[arg(long)]
    pub no_upper: bool,

    /// Leave out look-alike characters (0 O 1 l I |)
    #[arg(long)]
    pub avoid_ambiguous: bool,

    /// Generate a passphrase of this many words instead (EFF large word list)
    #[arg(short, long, value_name = "N", conflicts_with = "pin")]
    pub words: Option<usize>,

    /// Separator between passphrase words
    #[arg(long, default_value = "-", requires = "words")]
    pub separator: String,

    /// Capitalise each passphrase word
    #[arg(long, requires = "words")]
    pub capitalize: bool,

    /// Generate a numeric PIN of this many digits instead
    #[arg(long, value_name = "N")]
    pub pin: Option<usize>,

    /// Copy to the clipboard instead of printing; cleared after a timeout
    #[arg(short, long, conflicts_with = "json")]
    pub clip: bool,

    /// Print {"value": ..., "entropy_bits": ...}
    #[arg(long)]
    pub json: bool,
}
