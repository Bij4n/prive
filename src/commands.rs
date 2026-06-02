//! One function per command. Each opens what it needs, does one thing, and prints through
//! `output` so stdout carries only the result.

use std::io::IsTerminal;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::cli::{GenArgs, Global, PickArgs};
use crate::error::Failure;
use crate::{audit, clip, config, db, entry::Entry, generate, otp, output, pick, select, unlock};

/// Open the database the command line or config file points at.
fn open(global: &Global) -> Result<db::Db> {
    let cfg = config::Config::load()?;
    let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
    // A missing or non-KeePass file is reported before the password is asked for.
    let bytes = db::read_file(&target.db)?;
    let creds = unlock::KeySource::for_target(global, &target)?;
    db::Db::from_bytes(&target.db, &bytes, &creds)
}

/// Copy a secret, then say on stderr when it will be cleared.
fn copy_and_tell(secret: &str) -> Result<()> {
    let seconds = config::Config::load()?.clipboard_seconds();
    clip::copy(secret, seconds)?;
    eprintln!("Copied. The clipboard clears in {seconds} s.");
    Ok(())
}

fn field_of<'a>(e: &'a Entry, name: &str) -> Result<&'a str> {
    e.field(name).ok_or_else(|| {
        Failure::NotFound(format!(
            "{}: field '{name}' (it has: {})",
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
    Err(Failure::NotFound(format!("{}: no one-time code", e.path())).into())
}

fn list(entries: &[&Entry], json: bool) -> Result<()> {
    if json {
        let summaries: Vec<_> = entries.iter().map(|e| e.summary()).collect();
        output::print_json(&summaries)
    } else {
        output::print(&output::render_list(entries))
    }
}

pub fn ls(global: &Global, group: Option<&str>, tags: &[String], json: bool) -> Result<()> {
    let db = open(global)?;
    let mut shown = select::in_group(&db.entries, group.unwrap_or(""));
    for t in tags {
        shown = select::with_tag(&shown, t);
    }
    if let Some(g) = group
        && shown.is_empty()
    {
        return Err(Failure::NotFound(format!("group '{g}'")).into());
    }
    list(&shown, json)
}

pub fn tags(global: &Global, json: bool) -> Result<()> {
    let db = open(global)?;
    let counts = select::tag_counts(&db.entries);
    if json {
        let list: Vec<_> = counts
            .iter()
            .map(|(t, n)| serde_json::json!({ "tag": t, "entries": n }))
            .collect();
        return output::print_json(&list);
    }
    let width = counts
        .iter()
        .map(|(_, n)| n.to_string().len())
        .max()
        .unwrap_or(1);
    let text: String = counts
        .iter()
        .map(|(t, n)| format!("{n:>width$}  {t}\n"))
        .collect();
    output::print(&text)
}

pub fn search(global: &Global, query: &str, json: bool) -> Result<()> {
    let db = open(global)?;
    let hits = select::search(&db.entries, query);
    // Like grep: nothing found is a failure scripts can test for (exit code 3).
    if hits.is_empty() {
        return Err(Failure::NotFound(query.to_string()).into());
    }
    list(&hits, json)
}

pub fn show(global: &Global, entry: &str, reveal: bool, json: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    if json {
        output::print_json(&output::show_json(e, reveal))
    } else {
        output::print(&output::render_show(e, reveal))
    }
}

pub fn get(global: &Global, entry: &str, field: &str, clip: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let value = field_of(e, field)?;
    if clip {
        copy_and_tell(value)
    } else {
        output::print(&format!("{value}\n"))
    }
}

pub fn otp(global: &Global, entry: &str, min_validity: u64, clip: bool, json: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    let (mut code, mut left) = totp.now();
    anyhow::ensure!(
        min_validity < totp.period,
        "--min-validity must be shorter than the code's period ({} s)",
        totp.period
    );
    if left < min_validity {
        if std::io::stderr().is_terminal() {
            eprintln!("(waiting {left} s for a fresh code)");
        }
        std::thread::sleep(std::time::Duration::from_secs(left));
        (code, left) = totp.now();
    }
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

pub fn pick(global: &Global, args: &PickArgs) -> Result<()> {
    let db = open(global)?;
    let Some(e) = pick::pick(&db.entries, args.query.as_deref())? else {
        return Err(Failure::Cancelled.into());
    };
    let value = Zeroizing::new(if args.otp {
        totp_of(e)?.now().0
    } else {
        field_of(e, args.field.as_deref().unwrap_or("password"))?.to_string()
    });
    if args.print {
        output::print(&format!("{}\n", value.as_str()))
    } else {
        eprintln!("{}", e.path());
        copy_and_tell(&value)
    }
}

pub fn audit(global: &Global, hibp: bool, max_age: i64, json: bool) -> Result<()> {
    let db = open(global)?;
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

pub fn generate(args: &GenArgs) -> Result<()> {
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
    if args.json {
        return output::print_json(&g);
    }
    if args.clip {
        copy_and_tell(&g.value)?;
    } else {
        output::print(&format!("{}\n", g.value))?;
    }
    if std::io::stderr().is_terminal() {
        eprintln!("({:.0} bits of entropy)", g.entropy_bits);
    }
    Ok(())
}

pub fn completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = <crate::cli::Cli as clap::CommandFactory>::command();
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut cmd, "prive", &mut out);
    output::print(&String::from_utf8_lossy(&out))
}
