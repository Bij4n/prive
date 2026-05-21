//! prive: a fast, scriptable terminal client for KeePass (KDBX) password databases.

pub mod audit;
pub mod cli;
pub mod clip;
pub mod config;
pub mod entry;
pub mod error;
pub mod generate;
pub mod hibp;
pub mod otp;
pub mod select;
pub mod unlock;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => error::report(&e),
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Gen(args) => {
            let g = if let Some(n) = args.words {
                generate::passphrase(n, &args.separator, args.capitalize)?
            } else if let Some(n) = args.pin {
                generate::pin(n)?
            } else {
                generate::password(&generate::CharsetSpec {
                    length: args.length,
                    upper: !args.no_upper,
                    digits: !args.no_digits,
                    symbols: !args.no_symbols,
                    avoid_ambiguous: args.avoid_ambiguous,
                })?
            };
            println!("{}", g.value);
            if std::io::stderr().is_terminal() {
                eprintln!("({:.0} bits of entropy)", g.entropy_bits);
            }
            Ok(())
        }
        Command::ClipHelper { seconds } => clip::helper(seconds),
    }
}
