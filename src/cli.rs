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
        5 wrong password or no terminal for the prompt."
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
    #[arg(long, global = true)]
    pub password_stdin: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a password, passphrase or PIN (no database needed)
    Gen(GenArgs),

    /// Print shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
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
