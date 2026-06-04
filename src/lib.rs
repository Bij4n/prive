//! prive: a fast, scriptable terminal client for KeePass (KDBX) password databases.
//!
//! The binary is a thin layer over this library: [`cli`] defines the interface, [`run()`]
//! dispatches each command and maps errors to [exit codes](error::Failure). Everything a
//! command prints goes through [`output`]. See `docs/design.md` for the module map and the
//! rules the code keeps.

pub mod agent;
pub mod audit;
pub mod browser;
pub mod cli;
pub mod clip;
pub mod commands;
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
pub mod run;
pub mod select;
pub mod unlock;

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
    #[cfg(unix)]
    if args.get(1).map(String::as_str) == Some(agent::client::AGENT_ARG) {
        let seconds = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(900);
        let started = agent::server::serve(std::time::Duration::from_secs(seconds), || {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = writeln!(out, "ok");
            let _ = out.flush();
        });
        if let Err(e) = started {
            println!("err: {e:#}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => error::report(&e),
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let g = &cli.global;
    output::set_quiet(g.quiet);
    match &cli.command {
        Command::Unlock => commands::unlock(g),
        Command::Lock => commands::lock(),
        Command::Status { json } => commands::status(*json),
        Command::Ls {
            group,
            tags,
            long,
            json,
        } => commands::ls(g, group.as_deref(), tags, *long, *json),
        Command::Search { query, json } => commands::search(g, query, *json),
        Command::Tags { json } => commands::tags(g, *json),
        Command::Show {
            entry,
            reveal,
            json,
        } => commands::show(g, entry, *reveal, *json),
        Command::Get { entry, field, clip } => commands::get(g, entry, field, *clip),
        Command::Otp {
            entry,
            min_validity,
            clip,
            json,
        } => commands::otp(g, entry, *min_validity, *clip, *json),
        Command::Pick(args) => commands::pick(g, args),
        Command::Run { env, command } => commands::run(g, env, command),
        Command::Open { entry, no_copy } => commands::open_url(g, entry, *no_copy),
        Command::Audit {
            hibp,
            max_age,
            json,
        } => commands::audit(g, *hibp, *max_age, *json),
        Command::Gen(args) => commands::generate(args),
        Command::Completions { shell } => commands::completions(*shell),
    }
}
