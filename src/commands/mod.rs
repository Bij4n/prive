//! One function per command. Each opens what it needs, does one thing, and prints through
//! `output` so stdout carries only the result.
//!
//! They are grouped by what they work on: entries (ls, show, get, ...),
//! codes, the agent (unlock, lock, status), reports (audit, info, diff, doctor) and tools (run,
//! gen, import, config, git-credential, completions). This module keeps what they share:
//! opening the database from the agent or the file, finding a field or a code, copying.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::cli::{GenArgs, Global, PickArgs};
use crate::error::Failure;
use crate::{
    audit, browser, clip, config, db, entry::Entry, generate, otp, output, pick, select, unlock,
};

mod entries;
pub use entries::*;

mod tools;
pub use tools::*;

mod reports;
pub use reports::*;

mod codes;
pub use codes::*;

mod agent;
pub use agent::*;

/// Open the database the command line or config file points at: from the agent if it holds
/// it, otherwise by reading the file and asking for the password.
fn open(global: &Global) -> Result<db::Db> {
    let cfg = config::Config::load()?;
    let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
    #[cfg(unix)]
    if !global.no_agent
        && let Some(db) = from_agent(&target.db)
    {
        return Ok(db);
    }
    // A missing or non-KeePass file is reported before the password is asked for.
    let bytes = db::read_file(&target.db)?;
    let creds = unlock::KeySource::for_target(global, &target)?;
    db::Db::from_bytes(&target.db, &bytes, &creds)
}

/// The agent's copy of `path`, if it holds one. Anything going wrong with the agent just means
/// asking for the password as usual.
#[cfg(unix)]
fn from_agent(path: &std::path::Path) -> Option<db::Db> {
    use crate::agent::client::{Answer, entries};
    match entries(path) {
        Ok(Answer::Entries(db)) => Some(*db),
        Ok(Answer::Locked(reason)) if reason.contains("changed on disk") => {
            output::notice("The database changed on disk since `prive unlock`; asking again.");
            None
        }
        _ => None,
    }
}

/// `work (Work.kdbx)` for a database the config file names, else just its file name.
fn display_name(cfg: &config::Config, path: &std::path::Path) -> String {
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match cfg.name_of(path) {
        Some(n) => format!("{n} ({file})"),
        None => file,
    }
}

/// Copy a secret, then say on stderr when it will be cleared.
fn copy_and_tell(secret: &str) -> Result<()> {
    let seconds = config::Config::load()?.clipboard_seconds();
    clip::copy(secret, seconds)?;
    output::notice(&format!("Copied. The clipboard clears in {seconds} s."));
    Ok(())
}

fn field_of<'a>(e: &'a Entry, name: &str) -> Result<&'a str> {
    e.field(name).ok_or_else(|| {
        Failure::Missing(format!(
            "{}: no field '{name}' (it has: {})",
            e.path(),
            e.field_names().join(", ")
        ))
        .into()
    })
}

fn totp_of(e: &Entry) -> Result<otp::Totp> {
    if let Some(t) = otp::Totp::from_entry(e) {
        return Ok(t);
    }
    if otp::has_otp_settings(e) {
        anyhow::bail!(
            "{}: has one-time code settings prive can't read (see docs/totp.md)",
            e.path()
        );
    }
    Err(Failure::Missing(format!("{}: no one-time code", e.path())).into())
}
