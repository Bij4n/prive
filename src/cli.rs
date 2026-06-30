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
    /// Database file, or the name of one in the config file [default: the config's db]
    #[arg(
        help_heading = "Global options",
        long,
        global = true,
        env = "PRIVE_DB",
        value_name = "FILE"
    )]
    pub db: Option<PathBuf>,

    /// Key file, if the database uses one
    #[arg(
        help_heading = "Global options",
        long,
        global = true,
        env = "PRIVE_KEYFILE",
        value_name = "FILE"
    )]
    pub keyfile: Option<PathBuf>,

    /// Read the master password from the first line of stdin
    #[arg(
        help_heading = "Global options",
        long,
        global = true,
        conflicts_with = "no_password"
    )]
    pub password_stdin: bool,

    /// Don't use a database unlocked with `prive unlock`; read the file and ask
    #[arg(
        help_heading = "Global options",
        long,
        global = true,
        env = "PRIVE_NO_AGENT",
        value_parser = clap::builder::FalseyValueParser::new()
    )]
    pub no_agent: bool,

    /// Leave out notices on stderr ("Copied", seconds left, entropy); errors still show
    #[arg(help_heading = "Global options", short, long, global = true)]
    pub quiet: bool,

    /// The database has no password, only a key file
    #[arg(
        help_heading = "Global options",
        long,
        global = true,
        requires = "keyfile"
    )]
    pub no_password: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List entries: paths and usernames, never passwords
    Ls {
        /// Only entries in this group and its subgroups
        group: Option<String>,
        /// Only entries with this tag (repeat for several: all must match)
        #[arg(short, long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Also show when each changed, and whether it has a code, files, or has expired or soon will
        #[arg(short, long, conflicts_with = "json")]
        long: bool,
        /// Only the paths, one per line (for shell completion and fzf)
        #[arg(short = 'p', long, conflicts_with_all = ["json", "long"])]
        paths: bool,
        /// One line per entry from a template, never with secrets: '{PATH}\t{USERNAME}\t{URL}'
        #[arg(long, value_name = "TEMPLATE", conflicts_with_all = ["json", "long", "paths"])]
        format: Option<String>,
        /// Only entries that have expired
        #[arg(long, conflicts_with = "expiring")]
        expired: bool,
        /// Only entries that have expired or will within DAYS
        #[arg(long, value_name = "DAYS")]
        expiring: Option<i64>,
        /// The order to list them in
        #[arg(long, value_enum, default_value_t = crate::select::Order::Path)]
        sort: crate::select::Order,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Find entries by title, username, URL, group or tag
    Search {
        query: String,
        /// Also look in notes and unprotected custom fields (never in passwords)
        #[arg(short = 'a', long)]
        all: bool,
        /// Only matches with this tag (repeat for several: all must match)
        #[arg(short, long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// One line per match from a template, never with secrets (as `ls --format`)
        #[arg(long, value_name = "TEMPLATE", conflicts_with = "json")]
        format: Option<String>,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Show an entry; passwords and protected fields stay hidden unless --reveal
    Show {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        #[arg(long)]
        reveal: bool,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Print one field of an entry (the password by default), nothing else
    Get {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        /// password, username, url, notes, title, or a custom field's name
        #[arg(short, long, default_value = "password")]
        field: String,
        /// Fill in a template instead of printing one field, with KeePass's placeholders:
        /// '{USERNAME}:{PASSWORD}', '{S:API key}', '{TOTP}'
        #[arg(long, value_name = "TEMPLATE", conflicts_with = "field")]
        format: Option<String>,
        /// Copy to the clipboard instead of printing; cleared after a timeout
        #[arg(short, long)]
        clip: bool,
    },

    /// Print the current one-time (TOTP) code of an entry
    Otp {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        /// If the current code expires sooner than this, wait for the next one (useful in
        /// scripts that type the code somewhere slow)
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        min_validity: u64,
        /// The code after the current one, without waiting (for sites that ask for two)
        #[arg(long, conflicts_with = "min_validity")]
        next: bool,
        /// Copy to the clipboard instead of printing
        #[arg(short, long, conflicts_with = "json")]
        clip: bool,
        /// Print {"code": ..., "seconds_left": ..., "period": ...}
        #[arg(long)]
        json: bool,
        /// Instead of a code, show the setup as a QR code to scan into a phone's authenticator
        /// (this shows the secret)
        #[arg(long, conflicts_with_all = ["clip", "json", "uri"])]
        qr: bool,
        /// Instead of a code, print the setup as an otpauth:// URI (this shows the secret)
        #[arg(long, conflicts_with_all = ["clip", "json"])]
        uri: bool,
        /// Keep showing the current code and its time left, like an authenticator app, until
        /// Ctrl-C (terminal only)
        #[arg(long, conflicts_with_all = ["clip", "json", "qr", "uri", "next", "min_validity"])]
        watch: bool,
    },

    /// Every current one-time code, like an authenticator app's list
    Codes {
        /// Only entries matching this search
        query: Option<String>,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
        /// Keep the list on screen, codes and times redrawn, until Ctrl-C (terminal only)
        #[arg(long, conflicts_with = "json")]
        watch: bool,
    },

    /// Choose an entry interactively and copy its password
    Pick(PickArgs),

    /// Open an entry's URL in the browser and copy its password
    Open {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        /// Only open the URL; don't copy anything
        #[arg(long)]
        no_copy: bool,
        /// Print the address instead of opening it (over SSH, or to open it elsewhere); copies
        /// nothing
        #[arg(long, conflicts_with = "no_copy")]
        print: bool,
    },

    /// Unlock the database once; later commands use it without asking (Linux and macOS)
    Unlock {
        /// Lock after this many minutes unused, this time (default: agent_minutes, 15)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=1440))]
        minutes: Option<u64>,
        /// Unlock the config file's database and every named one, each with its own key file
        /// and password command, or a prompt
        #[arg(long)]
        all: bool,
    },

    /// Forget the unlocked databases now (with --db, only that one)
    Lock,

    /// Say which databases are unlocked, and for how long
    Status {
        /// Print JSON instead of text, for scripts
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

    /// Git credential helper: git config --global credential.helper '!prive git-credential'
    #[command(name = "git-credential")]
    GitCredential {
        /// What git asks: get (answered), store and erase (ignored: prive never writes)
        #[arg(value_parser = ["get", "store", "erase"])]
        action: String,
    },

    /// An entry's earlier versions: when each was saved, and whether the password changed
    History {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        /// Show the old passwords themselves
        #[arg(long)]
        reveal: bool,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// List an entry's attached files, or write one out
    File {
        /// The entry: its title, its Group/Title path, or uuid:UUID
        entry: String,
        /// The file to write out; without it, the files are listed
        name: Option<String>,
        /// Write it here (readable only by you) instead of to stdout
        #[arg(short, long, value_name = "PATH", requires = "name")]
        out: Option<std::path::PathBuf>,
    },

    /// List the tags in use, with how many entries carry each
    Tags {
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Report weak key settings, and weak, reused, old and expired passwords
    Audit {
        /// Also check each password against Have I Been Pwned (sends 5 hex characters of its
        /// SHA-1 hash per password; nothing else leaves the machine)
        #[arg(long)]
        hibp: bool,
        /// Flag passwords not changed for more than this many days (0: don't check)
        #[arg(long, default_value_t = 365, value_name = "DAYS")]
        max_age: i64,
        /// Also flag entries that expire within this many days
        #[arg(long, default_value_t = 0, value_name = "DAYS")]
        expiring: i64,
        /// Report only these kinds of problem: --only reused,weak
        #[arg(long, value_delimiter = ',', value_name = "KINDS")]
        only: Vec<crate::audit::Kind>,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Compare the database with another copy of it (a sync conflict copy, a backup)
    Diff {
        /// The other copy
        other: PathBuf,
        /// Key file for the other copy, when it isn't the same as the database's
        #[arg(long, value_name = "FILE")]
        other_keyfile: Option<PathBuf>,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Show how the database is stored: format, encryption, key settings, counts
    Info {
        /// Also time opening the file on this machine (asks for the password even when
        /// unlocked): what the key derivation settings cost here
        #[arg(long)]
        time: bool,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Generate a password, passphrase or PIN (no database needed)
    Gen(GenArgs),

    /// Write every entry with its passwords in plain text (CSV or JSON), to move elsewhere
    Export {
        /// Only this group and its subgroups
        group: Option<String>,
        /// Only entries with this tag (repeat for several: all must match)
        #[arg(short, long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// The layout to write
        #[arg(long, value_enum, default_value_t = crate::export::Format::Csv)]
        format: crate::export::Format,
        /// Write to this new file (readable only by you; never replaced). Without it, stdout,
        /// but never a terminal
        #[arg(short, long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Also write every attached file under this directory, as Group/Title/name (new
        /// files only, readable only by you)
        #[arg(long, value_name = "DIR")]
        files: Option<PathBuf>,
        /// Say you know the result holds every password unencrypted (required)
        #[arg(long, required = true)]
        plaintext: bool,
    },

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
        /// Also list each entry that would come across: path, username, site, whether it has
        /// a code, its other fields by name. Never a password
        #[arg(long)]
        list: bool,
        /// Print JSON instead of text, for scripts (the list included, never a password)
        #[arg(long)]
        json: bool,
    },

    /// Check the config, database, key file, agent and clipboard, without a password
    Doctor {
        /// Check every database the config file names, not only the one a command would open
        #[arg(long)]
        all: bool,
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

    /// Show the settings in effect and where each came from
    Config {
        /// Print JSON instead of text, for scripts
        #[arg(long)]
        json: bool,
    },

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

    /// Use only these symbols, for sites that allow some: --symbols '!@#$'
    #[arg(long, value_name = "CHARS", conflicts_with_all = ["no_symbols", "words", "pin"])]
    pub symbols: Option<String>,

    /// Never use these characters: --exclude '<>&"'
    #[arg(long, value_name = "CHARS", conflicts_with_all = ["words", "pin"])]
    pub exclude: Option<String>,

    /// Generate a passphrase of this many words instead (EFF large word list)
    #[arg(short, long, value_name = "N", conflicts_with = "pin")]
    pub words: Option<usize>,

    /// Separator between passphrase words
    #[arg(long, default_value = "-", requires = "words")]
    pub separator: String,

    /// Take passphrase words from this file instead of the EFF list: one word a line, or
    /// numbered lines like the EFF lists'; at least 1024 different words
    #[arg(long, value_name = "FILE", requires = "words")]
    pub word_list: Option<std::path::PathBuf>,

    /// Capitalise each passphrase word
    #[arg(long, requires = "words")]
    pub capitalize: bool,

    /// Generate a numeric PIN of this many digits instead
    #[arg(long, value_name = "N")]
    pub pin: Option<usize>,

    /// Copy to the clipboard instead of printing; cleared after a timeout
    #[arg(short, long, conflicts_with_all = ["json", "count"])]
    pub clip: bool,

    /// Print this many, one per line
    #[arg(short = 'n', long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=1000))]
    pub count: u16,

    /// Print {"value": ..., "entropy_bits": ...}
    #[arg(long)]
    pub json: bool,
}
