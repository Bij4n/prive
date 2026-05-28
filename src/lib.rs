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
pub mod db;
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
        Command::Get { entry, field, clip } => {
            let db = open(&cli.global)?;
            let e = select::select(&db.entries, &entry)?;
            let value = e.field(&field).ok_or_else(|| {
                error::Failure::NotFound(format!("{}: field '{field}'", e.path()))
            })?;
            if clip {
                copy_and_tell(value)
            } else {
                output::print(&format!("{value}\n"))
            }
        }
        Command::Otp { entry, clip, json } => {
            let db = open(&cli.global)?;
            let e = select::select(&db.entries, &entry)?;
            let totp = otp::Totp::from_entry(e).ok_or_else(|| {
                error::Failure::NotFound(format!("{}: no one-time code", e.path()))
            })?;
            let (code, left) = totp.now();
            if json {
                return output::print_json(&serde_json::json!({
                    "code": code,
                    "seconds_left": left,
                    "period": totp.period,
                }));
            }
            if clip {
                copy_and_tell(&code)?;
            } else {
                output::print(&format!("{code}\n"))?;
            }
            if std::io::stderr().is_terminal() {
                eprintln!("(valid for {left} more seconds)");
            }
            Ok(())
        }
        Command::Show {
            entry,
            reveal,
            json,
        } => {
            let db = open(&cli.global)?;
            let e = select::select(&db.entries, &entry)?;
            if json {
                output::print_json(&output::show_json(e, reveal))
            } else {
                output::print(&output::render_show(e, reveal))
            }
        }
        Command::Search { query, json } => {
            let db = open(&cli.global)?;
            let hits = select::search(&db.entries, &query);
            if json {
                let summaries: Vec<_> = hits.iter().map(|e| e.summary()).collect();
                output::print_json(&summaries)
            } else {
                output::print(&output::render_list(&hits))
            }
        }
        Command::Ls { group, json } => {
            let db = open(&cli.global)?;
            let shown = select::in_group(&db.entries, group.as_deref().unwrap_or(""));
            if json {
                let summaries: Vec<_> = shown.iter().map(|e| e.summary()).collect();
                output::print_json(&summaries)
            } else {
                output::print(&output::render_list(&shown))
            }
        }
        Command::Pick(args) => {
            let db = open(&cli.global)?;
            let Some(e) = pick::pick(&db.entries, args.query.as_deref())? else {
                return Ok(()); // cancelled
            };
            let value = if args.otp {
                otp::Totp::from_entry(e)
                    .ok_or_else(|| {
                        error::Failure::NotFound(format!("{}: no one-time code", e.path()))
                    })?
                    .now()
                    .0
            } else {
                let name = args.field.as_deref().unwrap_or("password");
                e.field(name)
                    .ok_or_else(|| {
                        error::Failure::NotFound(format!("{}: field '{name}'", e.path()))
                    })?
                    .to_string()
            };
            if args.print {
                output::print(&format!("{value}\n"))
            } else {
                eprintln!("{}", e.path());
                copy_and_tell(&value)
            }
        }
        Command::Audit {
            hibp,
            max_age,
            json,
        } => {
            let db = open(&cli.global)?;
            let report = audit::audit(
                &db.entries,
                &audit::Options {
                    max_age_days: max_age,
                    breach_check: hibp,
                },
            )?;
            if json {
                output::print_json(&report)
            } else {
                output::print(&output::render_audit(&report))
            }
        }
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

/// Open the database the command line or config file points at.
fn open(global: &cli::Global) -> Result<db::Db> {
    let cfg = config::Config::load()?;
    let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
    let creds = unlock::KeySource::for_target(global, &target)?;
    db::Db::open(&target.db, &creds)
}

/// Copy a secret, then say on stderr when it will be cleared.
fn copy_and_tell(secret: &str) -> Result<()> {
    let seconds = config::Config::load()?.clipboard_seconds();
    clip::copy(secret, seconds)?;
    eprintln!("Copied. The clipboard clears in {seconds} s.");
    Ok(())
}
