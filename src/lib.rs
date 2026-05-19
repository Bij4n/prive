//! prive: a fast, scriptable terminal client for KeePass (KDBX) password databases.

pub mod cli;

use std::process::ExitCode;

use clap::Parser;

pub fn run() -> ExitCode {
    let _cli = cli::Cli::parse();
    ExitCode::SUCCESS
}
