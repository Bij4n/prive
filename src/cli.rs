//! Command-line interface. Data goes to stdout; prompts, notices and errors go to stderr.

use std::path::PathBuf;

use clap::{Args, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "prive",
    version,
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
