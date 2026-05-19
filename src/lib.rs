//! prive: a fast, scriptable terminal client for KeePass (KDBX) password databases.

pub mod cli;
pub mod config;
pub mod entry;
pub mod error;
pub mod select;
pub mod unlock;

use std::process::ExitCode;

use clap::Parser;

pub fn run() -> ExitCode {
    let _cli = cli::Cli::parse();
    ExitCode::SUCCESS
}
