//! One function per command. Each opens what it needs, does one thing, and prints through
//! `output` so stdout carries only the result.

use std::io::IsTerminal;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::cli::{GenArgs, Global, PickArgs};
use crate::error::Failure;
use crate::{
    audit, browser, clip, config, db, entry::Entry, generate, otp, output, pick, select, unlock,
};

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
        Ok(Answer::Entries(entries)) => Some(db::Db {
            path: path.to_path_buf(),
            entries,
        }),
        Ok(Answer::Locked(reason)) if reason.contains("changed on disk") => {
            output::notice("The database changed on disk since `prive unlock`; asking again.");
            None
        }
        _ => None,
    }
}

/// Open the database once, then hand it to the agent so later commands need no password.
pub fn unlock(global: &Global) -> Result<()> {
    #[cfg(unix)]
    {
        let cfg = config::Config::load()?;
        let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
        let bytes = db::read_file(&target.db)?;
        let creds = unlock::KeySource::for_target(global, &target)?;
        // Check the password here, so a wrong one is exit code 5 like everywhere else.
        db::Db::from_bytes(&target.db, &bytes, &creds)?;
        let idle = cfg.agent_idle();
        crate::agent::client::start(idle)?;
        crate::agent::client::unlock(
            &target.db,
            creds.keyfile.clone(),
            creds.password.as_ref().map(|p| p.as_str()),
        )?;
        let name = target
            .db
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        output::notice(&format!(
            "Unlocked {name}. It locks after {} minutes unused, or with `prive lock`.",
            idle.as_secs() / 60
        ));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = global;
        anyhow::bail!("unlocking once isn't available on this system yet; each command asks")
    }
}

pub fn lock() -> Result<()> {
    #[cfg(unix)]
    {
        if crate::agent::client::lock()? {
            output::notice("Locked.");
        } else {
            output::notice("Nothing was unlocked.");
        }
    }
    Ok(())
}

pub fn status(json: bool) -> Result<()> {
    #[cfg(unix)]
    let state = crate::agent::client::status()?;
    #[cfg(not(unix))]
    let state: Option<(Option<std::path::PathBuf>, u64)> = None;
    let (db, left) = match state {
        Some((Some(db), left)) => (Some(db), left),
        _ => (None, 0),
    };
    if json {
        return output::print_json(&serde_json::json!({
            "unlocked": db.is_some(),
            "db": db,
            "seconds_left": left,
        }));
    }
    match db {
        Some(db) => output::print(&format!(
            "unlocked: {} (locks in {} min {} s if unused)\n",
            db.display(),
            left / 60,
            left % 60
        )),
        None => output::print("locked\n"),
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

pub fn ls(
    global: &Global,
    group: Option<&str>,
    tags: &[String],
    long: bool,
    json: bool,
) -> Result<()> {
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
    if long {
        return output::print(&output::render_long_list(&shown));
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
            output::notice(&format!("(waiting {left} s for a fresh code)"));
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
        output::notice(&format!("(valid for {left} more seconds)"));
    }
    Ok(())
}

pub fn run(global: &Global, specs: &[String], from: &[String], command: &[String]) -> Result<()> {
    let specs: Vec<crate::run::EnvSpec> = specs
        .iter()
        .map(|s| crate::run::parse_spec(s))
        .collect::<Result<_>>()?;
    let db = open(global)?;
    let mut vars = Vec::new();
    for name in from {
        let e = select::select(&db.entries, name)?;
        let fields = crate::run::fields_as_env(e);
        if fields.is_empty() {
            anyhow::bail!(
                "{}: no custom fields named like environment variables",
                e.path()
            );
        }
        vars.extend(fields);
    }
    // --env comes last, so it overrides a field of the same name.
    for s in &specs {
        vars.push((s.name.clone(), crate::run::resolve(&db.entries, s)?));
    }
    drop(db); // the child gets only what it asked for
    let (program, args) = command.split_first().expect("clap requires a command");
    let code = crate::run::exec(program, args, &vars)?;
    std::process::exit(code);
}

/// The everyday login: open the site, password on the clipboard ready to paste.
pub fn open_url(global: &Global, entry: &str, no_copy: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let url = browser::web_url(&e.url).map_err(|err| anyhow::anyhow!("{}: {err}", e.path()))?;
    browser::open(&url)?;
    output::notice(&format!("Opened {url}"));
    if !no_copy && !e.password.is_empty() {
        copy_and_tell(&e.password)?;
    }
    Ok(())
}

/// Read an export and print what would come across. Needs no database.
pub fn import_check(file: &std::path::Path, from: Option<crate::import::Format>) -> Result<()> {
    use anyhow::Context;
    let text = Zeroizing::new(
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
    );
    let format = match from {
        Some(f) => f,
        None => crate::import::Format::detect(&text).with_context(|| {
            format!(
                "can't tell which app made {}; name it with --from (proton, apple, google, lastpass)",
                file.display()
            )
        })?,
    };
    let (records, report) = format.parse(&text)?;
    output::print(&format!("{:?} export: {}", format, report.render(&records)))
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
        output::notice(&e.path());
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
        output::notice(&format!("({:.0} bits of entropy)", g.entropy_bits));
    }
    Ok(())
}

pub fn completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = <crate::cli::Cli as clap::CommandFactory>::command();
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut cmd, "prive", &mut out);
    output::print(&String::from_utf8_lossy(&out))
}
