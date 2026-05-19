//! Command-line interface. Data goes to stdout; prompts, notices and errors go to stderr.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "prive",
    version,
    about = "Fast, scriptable terminal client for KeePass (KDBX) password databases"
)]
pub struct Cli {}
