//! prive: a fast, scriptable terminal client for KeePass (KDBX) password databases.
//!
//! The binary is a thin layer over this library: [`cli`] defines the interface, [`run`]
//! dispatches each command and maps errors to [exit codes](error::Failure). Everything a
//! command prints goes through [`output`]. See `docs/design.md` for the module map and the
//! rules the code keeps.

pub mod audit;
pub mod cli;
pub mod clip;
pub mod config;
pub mod entry;
pub mod error;
pub mod fsutil;
pub mod generate;
pub mod hibp;
pub mod otp;
pub mod output;
pub mod pick;
pub mod select;
pub mod unlock;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

pub fn run() -> ExitCode {
    // The clipboard helper is internal: handled before clap so it never shows up in help,
    // completions or man pages.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(clip::HELPER_ARG) {
        let seconds = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
        return match clip::helper(seconds) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => error::report(&e),
        };
    }
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
            if args.clip {
                copy_and_tell(&g.value)?;
            } else if args.json {
                output::print_json(&g)?;
                return Ok(());
            } else {
                output::print(&format!("{}\n", g.value))?;
            }
            if std::io::stderr().is_terminal() {
                eprintln!("({:.0} bits of entropy)", g.entropy_bits);
            }
            Ok(())
        }
        Command::Completions { shell } => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            let mut out = Vec::new();
            clap_complete::generate(shell, &mut cmd, "prive", &mut out);
            output::print(&String::from_utf8_lossy(&out))
        }
    }
}

/// Copy a secret, then say on stderr when it will be cleared.
fn copy_and_tell(secret: &str) -> Result<()> {
    let seconds = config::Config::load()?.clipboard_seconds();
    clip::copy(secret, seconds)?;
    eprintln!("Copied. The clipboard clears in {seconds} s.");
    Ok(())
}
