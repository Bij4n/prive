//! One function per command. Each opens what it needs, does one thing, and prints through
//! `output` so stdout carries only the result.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::cli::{GenArgs, Global, PickArgs};
use crate::error::Failure;
use crate::{
    audit, browser, clip, config, db, entry::Entry, generate, otp, output, pick, select, unlock,
};

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

fn list(entries: &[&Entry], json: bool) -> Result<()> {
    if json {
        let summaries: Vec<_> = entries.iter().map(|e| e.summary()).collect();
        output::print_json(&summaries)
    } else {
        output::print_human(&output::render_list(entries))
    }
}

/// How `ls` prints what it found.
pub enum Listing<'a> {
    Plain,
    Long,
    Paths,
    Json,
    /// `--format`: a template per entry, never with secrets.
    Format(&'a str),
}

pub fn ls(
    global: &Global,
    group: Option<&str>,
    tags: &[String],
    expiring: Option<i64>,
    order: select::Order,
    shape: Listing<'_>,
) -> Result<()> {
    if let Listing::Format(t) = shape {
        // Refused before the password is asked for.
        crate::template::check_listing(t)?;
    }
    let db = open(global)?;
    let mut shown = select::in_group(&db.entries, group.unwrap_or(""));
    // Checked before the tags narrow it: a group with no entry carrying the tag still exists.
    if let Some(g) = group
        && shown.is_empty()
    {
        return Err(Failure::Missing(format!("no group '{g}'")).into());
    }
    for t in tags {
        shown = select::with_tag(&shown, t);
    }
    if let Some(days) = expiring {
        shown = select::expiring(&shown, chrono::Utc::now().naive_utc(), days);
    }
    select::sort(&mut shown, order);
    match shape {
        Listing::Long => output::print_human(&output::render_long_list(&shown)),
        Listing::Paths => {
            let text: String = shown.iter().map(|e| format!("{}\n", e.path())).collect();
            output::print_human(&text)
        }
        Listing::Format(t) => formatted(t, &shown, &db.entries),
        Listing::Json => list(&shown, true),
        Listing::Plain => list(&shown, false),
    }
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
    output::print_human(&text)
}

pub fn search(
    global: &Global,
    query: &str,
    all: bool,
    format: Option<&str>,
    json: bool,
) -> Result<()> {
    if let Some(t) = format {
        crate::template::check_listing(t)?;
    }
    let db = open(global)?;
    let hits = if all {
        select::search_everywhere(&db.entries, query)
    } else {
        select::search(&db.entries, query)
    };
    // Like grep: nothing found is a failure scripts can test for (exit code 3).
    if hits.is_empty() {
        return Err(Failure::NotFound(query.to_string()).into());
    }
    match format {
        Some(t) => formatted(t, &hits, &db.entries),
        None => list(&hits, json),
    }
}

/// `--format`: one line per entry from a template, in listing mode (no secrets).
fn formatted(template: &str, entries: &[&Entry], all: &[Entry]) -> Result<()> {
    let mut text = String::new();
    for e in entries {
        text.push_str(&crate::template::render_listing(template, e, all)?);
        text.push('\n');
    }
    output::print_human(&text)
}

pub fn show(global: &Global, entry: &str, reveal: bool, json: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    // What --reveal shows is what would be used: references resolved.
    let resolved;
    let e = if reveal {
        let mut copy = e.clone();
        copy.password = crate::refs::resolve(&db.entries, &e.password);
        for c in &mut copy.custom {
            c.value = crate::refs::resolve(&db.entries, &c.value);
        }
        resolved = copy;
        &resolved
    } else {
        e
    };
    if json {
        output::print_json(&output::show_json(e, reveal))
    } else {
        output::print_human(&output::render_show(e, reveal))
    }
}

pub fn get(
    global: &Global,
    entry: &str,
    field: &str,
    format: Option<&str>,
    clip: bool,
) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let value = match format {
        Some(template) => crate::template::render(template, e, &db.entries)?,
        None => crate::refs::resolve(&db.entries, field_of(e, field)?),
    };
    if clip {
        copy_and_tell(&value)
    } else {
        output::print(&format!("{}\n", value.as_str()))
    }
}

/// Redraw the current code and a bar of the time it has left, once a quarter second, until
/// interrupted.
pub fn otp_watch(global: &Global, entry: &str) -> Result<()> {
    use std::io::Write;
    // Checked first, so a pipe never gets a password prompt for nothing.
    anyhow::ensure!(
        std::io::stdout().is_terminal(),
        "--watch needs a terminal; scripts use `prive otp` (with --min-validity if needed)"
    );
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    output::notice(&format!("{} (Ctrl-C to stop)", e.path()));
    let mut out = std::io::stdout();
    loop {
        let (code, left) = totp.now();
        write!(out, "\r{}", output::watch_line(&code, left, totp.period))?;
        out.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

pub fn otp(
    global: &Global,
    entry: &str,
    min_validity: u64,
    next: bool,
    clip: bool,
    json: bool,
) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    let (mut code, mut left) = totp.now();
    anyhow::ensure!(
        min_validity < totp.period,
        "--min-validity must be shorter than the code's period ({} s)",
        totp.period
    );
    if next {
        let t = otp::unix_now() + left;
        code = totp.code_at(t);
        left += totp.period;
    } else if left < min_validity {
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
        let fields = crate::run::fields_as_env(e, &db.entries);
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

/// The entry's one-time code setup, as a QR code to scan or as an otpauth URI.
pub fn otp_setup(global: &Global, entry: &str, qr: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    let issuer = if e.title.is_empty() {
        e.path()
    } else {
        e.title.clone()
    };
    let uri = Zeroizing::new(totp.to_uri(&issuer, &e.username));
    if qr {
        output::print(&crate::qr::render(&uri)?)?;
        output::notice(
            "Scan it with the authenticator app. Anyone who sees it can make your codes.",
        );
        Ok(())
    } else {
        output::print(&format!("{}\n", uri.as_str()))
    }
}

/// The current code of every entry that has one (or of those matching `query`).
pub fn codes(global: &Global, query: Option<&str>, json: bool, watch: bool) -> Result<()> {
    if watch {
        anyhow::ensure!(
            std::io::stdout().is_terminal(),
            "--watch needs a terminal; scripts use `prive codes --json`"
        );
    }
    let db = open(global)?;
    let pool: Vec<&Entry> = match query {
        Some(q) => select::search(&db.entries, q),
        None => db.entries.iter().collect(),
    };
    let codes: Vec<(String, otp::Totp)> = pool
        .iter()
        .filter_map(|e| otp::Totp::from_entry(e).map(|t| (e.path(), t)))
        .collect();
    if codes.is_empty() {
        return Err(Failure::Missing("no entries with one-time codes".into()).into());
    }
    if watch {
        return watch_codes(&codes);
    }
    let rows: Vec<(String, String, u64)> = codes
        .iter()
        .map(|(path, t)| {
            let (code, left) = t.now();
            (path.clone(), code, left)
        })
        .collect();
    if json {
        // The same fields as `otp --json`, with the entry's path.
        let list: Vec<_> = rows
            .iter()
            .zip(&codes)
            .map(|((p, c, l), (_, t))| {
                serde_json::json!({ "path": p, "code": c, "seconds_left": l, "period": t.period })
            })
            .collect();
        return output::print_json(&list);
    }
    let columns = rows
        .iter()
        .map(|(p, _, _)| output::width(p))
        .max()
        .unwrap_or(0);
    let text: String = rows
        .iter()
        .map(|(p, c, l)| format!("{}  {c:<10} {l:>2}s\n", output::pad(p, columns)))
        .collect();
    output::print_human(&text)
}

/// Draw every code with its time left, then redraw the same lines in place (the cursor goes
/// back up over them) four times a second until interrupted.
fn watch_codes(codes: &[(String, otp::Totp)]) -> Result<()> {
    use std::io::Write;
    let width = codes
        .iter()
        .map(|(p, _)| output::width(p))
        .max()
        .unwrap_or(0);
    output::notice("Ctrl-C to stop");
    let mut out = std::io::stdout();
    let mut first = true;
    loop {
        if !first {
            write!(out, "\x1b[{}A", codes.len())?;
        }
        first = false;
        for (path, t) in codes {
            let (code, left) = t.now();
            writeln!(
                out,
                "\r{}  {}",
                output::pad(&output::visible(path), width),
                output::watch_line(&format!("{code:<10}"), left, t.period)
            )?;
        }
        out.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// When an entry was changed before, and what changed about its password.
pub fn history(global: &Global, entry: &str, reveal: bool, json: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let when = |m: Option<chrono::NaiveDateTime>| {
        m.map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "unknown date".into())
    };
    // Each version's password compared with the one saved after it.
    let mut newer = e.password.as_str();
    let mut rows = Vec::new();
    for v in &e.history {
        let changed = v.password.as_str() != newer;
        rows.push((when(v.modified), v, changed));
        newer = v.password.as_str();
    }
    if json {
        let list: Vec<_> = rows
            .iter()
            .map(|(t, v, changed)| {
                serde_json::json!({
                    "saved": t,
                    "username": v.username,
                    "password_changed_after": changed,
                    "password": reveal.then(|| v.password.as_str()),
                })
            })
            .collect();
        return output::print_json(&list);
    }
    if rows.is_empty() {
        return output::print_human(&format!("{} has no earlier versions\n", e.path()));
    }
    let mut text = format!("{}  now\n", when(e.modified));
    for (t, v, changed) in rows {
        let mark = if changed {
            "password changed after this"
        } else {
            "same password"
        };
        if reveal {
            text.push_str(&format!("{t}  {mark}: {}\n", v.password.as_str()));
        } else {
            text.push_str(&format!("{t}  {mark}\n"));
        }
    }
    output::print_human(&text)
}

/// List an entry's attachments, or write one to a new file or to stdout.
pub fn file(
    global: &Global,
    entry: &str,
    name: Option<&str>,
    out: Option<&std::path::Path>,
) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let Some(name) = name else {
        let text: String = e
            .attachments
            .iter()
            .map(|a| format!("{}\t{}\n", a.name, a.data.len()))
            .collect();
        return output::print_human(&text);
    };
    let a = e
        .attachments
        .iter()
        .find(|a| a.name == name)
        .or_else(|| {
            e.attachments
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| {
            Failure::Missing(format!(
                "{}: no file '{name}' (it has: {})",
                e.path(),
                e.attachment_names().join(", ")
            ))
        })?;
    match out {
        Some(path) => {
            crate::fsutil::write_new_file(path, &a.data)?;
            output::notice(&format!(
                "Wrote {} ({}).",
                path.display(),
                output::human_size(a.data.len())
            ));
            Ok(())
        }
        None => {
            if std::io::stdout().is_terminal() {
                anyhow::bail!("not writing a file to the terminal; use --out PATH or a pipe");
            }
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&a.data).and_then(|()| stdout.flush()) {
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                other => Ok(other?),
            }
        }
    }
}

/// The everyday login: open the site, password on the clipboard ready to paste.
pub fn open_url(global: &Global, entry: &str, no_copy: bool, print: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let url = browser::web_url(&e.url).map_err(|err| anyhow::anyhow!("{}: {err}", e.path()))?;
    if print {
        // The same address `open` would use: checked to be http(s), a bare host given https.
        return output::print(&format!("{url}\n"));
    }
    browser::open(&url)?;
    output::notice(&format!("Opened {url}"));
    if !no_copy && !e.password.is_empty() {
        copy_and_tell(&crate::refs::resolve(&db.entries, &e.password))?;
    }
    Ok(())
}

/// Read an export and print what would come across. Needs no database.
pub fn import_check(
    file: &std::path::Path,
    from: Option<crate::import::Format>,
    map: &[String],
) -> Result<()> {
    use anyhow::Context;
    let text = Zeroizing::new(
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
    );
    let map = crate::import::generic::parse_map(map)?;
    // --map only makes sense for the generic CSV reader, so it implies --from csv.
    let format = match (from, map.is_empty()) {
        (Some(f), _) => f,
        (None, false) => crate::import::Format::Csv,
        (None, true) => crate::import::Format::detect(&text).with_context(|| {
            format!(
                "can't tell which app made {}; name it with --from (proton, apple, google, lastpass, csv)",
                file.display()
            )
        })?,
    };
    let (records, report) = format.parse(&text, &map)?;
    output::print_human(&format!(
        "{} export: {}",
        format.label(),
        report.render(&records)
    ))
}

pub fn pick(global: &Global, args: &PickArgs) -> Result<()> {
    let db = open(global)?;
    let Some(e) = pick::pick(&db.entries, args.query.as_deref())? else {
        return Err(Failure::Cancelled.into());
    };
    let value = Zeroizing::new(if args.otp {
        totp_of(e)?.now().0
    } else {
        crate::refs::resolve(
            &db.entries,
            field_of(e, args.field.as_deref().unwrap_or("password"))?,
        )
        .to_string()
    });
    if args.print {
        output::print(&format!("{}\n", value.as_str()))
    } else {
        output::notice(&e.path());
        copy_and_tell(&value)
    }
}

pub fn audit(
    global: &Global,
    hibp: bool,
    max_age: i64,
    expiring: i64,
    only: &[audit::Kind],
    json: bool,
) -> Result<()> {
    let db = open(global)?;
    let mut report = audit::audit(
        &db.entries,
        &audit::Options {
            max_age_days: max_age,
            breach_check: hibp,
            expiring_days: expiring,
        },
    )?;
    report.database = audit::check_database(&db.info);
    report.only(only);
    if json {
        output::print_json(&report)
    } else {
        output::print_styled(&output::render_audit(&report))
    }
}

pub fn generate(args: &GenArgs) -> Result<()> {
    if args.count > 1 {
        let mut text = String::new();
        for _ in 0..args.count {
            text.push_str(&one_generated(args)?.value);
            text.push('\n');
        }
        return output::print(&text);
    }
    let g = one_generated(args)?;
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

fn one_generated(args: &GenArgs) -> Result<generate::Generated> {
    Ok(if let Some(n) = args.words {
        match &args.word_list {
            Some(file) => {
                let text = std::fs::read_to_string(file)
                    .with_context(|| format!("reading the word list {}", file.display()))?;
                let list = generate::word_list(&text)
                    .with_context(|| format!("word list {}", file.display()))?;
                generate::passphrase_from(&list, n, &args.separator, args.capitalize)?
            }
            None => generate::passphrase(n, &args.separator, args.capitalize)?,
        }
    } else if let Some(n) = args.pin {
        generate::pin(n)?
    } else {
        generate::password(&generate::CharsetSpec {
            length: args.length,
            upper: !args.no_upper,
            digits: !args.no_digits,
            symbols: !args.no_symbols,
            avoid_ambiguous: args.avoid_ambiguous,
            symbol_set: args.symbols.clone(),
            exclude: args.exclude.clone().unwrap_or_default(),
        })?
    })
}

/// Compare the database with `other`. The other copy is tried with the same password (and
/// key file, unless `--other-keyfile`) first, as a conflict copy normally has them; only if
/// that fails, and there is a terminal to ask on, is its own password asked for.
pub fn diff(
    global: &Global,
    other: &std::path::Path,
    other_keyfile: Option<&std::path::Path>,
    json: bool,
) -> Result<()> {
    let cfg = config::Config::load()?;
    let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
    #[cfg(unix)]
    let unlocked = if global.no_agent {
        None
    } else {
        from_agent(&target.db)
    };
    #[cfg(not(unix))]
    let unlocked: Option<db::Db> = None;
    let there_bytes = db::read_file(other)?;
    let (here, creds) = match unlocked {
        Some(d) => (d, None),
        None => {
            let bytes = db::read_file(&target.db)?;
            let c = unlock::KeySource::for_target(global, &target)?;
            (db::Db::from_bytes(&target.db, &bytes, &c)?, Some(c))
        }
    };
    let keyfile = other_keyfile
        .map(std::path::Path::to_path_buf)
        .or_else(|| target.keyfile.clone());
    let ask = |password_stdin: bool| -> Result<db::Db> {
        let c = unlock::KeySource {
            password_stdin,
            no_password: global.no_password,
            keyfile: keyfile.clone(),
            password_command: None,
        }
        .credentials(other)?;
        db::Db::from_bytes(other, &there_bytes, &c)
    };
    let there = match creds {
        // The agent had the database, so no password was read yet.
        None => ask(global.password_stdin)?,
        Some(c) => {
            let same = unlock::Credentials {
                password: c.password.clone(),
                keyfile: keyfile.clone(),
            };
            match db::Db::from_bytes(other, &there_bytes, &same) {
                Ok(d) => d,
                Err(e)
                    if matches!(e.downcast_ref::<Failure>(), Some(Failure::BadCredentials))
                        && !global.password_stdin
                        && std::io::stdin().is_terminal() =>
                {
                    output::notice("The other copy has a different password or key file.");
                    ask(false)?
                }
                Err(e) => return Err(e),
            }
        }
    };
    let mut differences = crate::diff::compare(&here.entries, &there.entries);
    crate::diff::note_recycled(&mut differences, &here.recycled, &there.recycled);
    if json {
        return output::print_json(&serde_json::json!({
            "here": here.path,
            "there": there.path,
            "differences": differences,
        }));
    }
    output::print_styled(&output::render_diff(&here.path, &there.path, &differences))
}

pub fn info(global: &Global, time: bool, json: bool) -> Result<()> {
    let (db, took) = if time {
        // Timed from the file, never the agent: the point is what an unlock costs here.
        let cfg = config::Config::load()?;
        let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
        let bytes = db::read_file(&target.db)?;
        let creds = unlock::KeySource::for_target(global, &target)?;
        let started = std::time::Instant::now();
        let db = db::Db::from_bytes(&target.db, &bytes, &creds)?;
        (db, Some(started.elapsed()))
    } else {
        (open(global)?, None)
    };
    let size = std::fs::metadata(&db.path).map(|m| m.len()).unwrap_or(0);
    if json {
        let mut v = serde_json::to_value(&db.info)?;
        v["path"] = serde_json::json!(db.path);
        v["size"] = serde_json::json!(size);
        v["entries"] = serde_json::json!(db.entries.len());
        if let Some(t) = took {
            v["open_seconds"] = serde_json::json!(t.as_secs_f64());
        }
        return output::print_json(&v);
    }
    let mut text = output::render_info(&db, size);
    if let Some(t) = took {
        text.push_str(&format!(
            "{:<13} {:.2} s on this machine, nearly all of it the key derivation\n",
            "Opening:",
            t.as_secs_f64()
        ));
    }
    output::print_human(&text)
}

/// Run every check and print what each found. Exit 1 when any check fails.
pub fn doctor(global: &Global, all: bool, json: bool) -> Result<()> {
    let sections = if all {
        crate::doctor::run_all()
    } else {
        vec![(
            String::new(),
            crate::doctor::run(global.db.as_deref(), global.keyfile.as_deref()),
        )]
    };
    if json && all {
        let v: Vec<serde_json::Value> = sections
            .iter()
            .map(|(name, checks)| {
                serde_json::json!({
                    "database": (!name.is_empty()).then_some(name),
                    "checks": checks,
                })
            })
            .collect();
        output::print_json(&v)?;
    } else if json {
        output::print_json(&sections[0].1)?;
    } else {
        let h = output::style::HEADING;
        let width = sections
            .iter()
            .flat_map(|(_, c)| c)
            .map(|c| c.name.len())
            .max()
            .unwrap_or(0);
        let mut text = String::new();
        for (name, checks) in &sections {
            if !name.is_empty() {
                text.push_str(&format!("{h}{}{h:#}\n", output::visible(name)));
            }
            text.push_str(&output::render_checks_at(checks, width));
        }
        output::print_styled(&text)?;
    }
    let failed = sections
        .iter()
        .flat_map(|(_, c)| c)
        .filter(|c| c.status == crate::doctor::Status::Fail)
        .count();
    if failed > 0 {
        anyhow::bail!(
            "{failed} {} failed",
            if failed == 1 { "check" } else { "checks" }
        );
    }
    Ok(())
}

/// The settings in effect: where the config file is, which database and key file a command
/// would open (and why), the clipboard and agent timeouts, and where the agent's socket is.
pub fn show_config(global: &Global, json: bool) -> Result<()> {
    let path = config::Config::path();
    let cfg = config::Config::load()?;
    let target = cfg
        .target(global.db.as_deref(), global.keyfile.as_deref())
        .ok();
    let source = match (&global.db, &cfg.db) {
        (Some(d), _) if std::env::var_os("PRIVE_DB").is_some_and(|v| v == d.as_os_str()) => {
            "PRIVE_DB"
        }
        (Some(_), _) => "--db",
        (None, Some(_)) => "config file",
        (None, None) => "not set",
    };
    // `--db work` is reported as the file it stands for, and where the name came from.
    let db_from = match global.db.as_deref().filter(|d| cfg.named(d).is_some()) {
        Some(name) => format!("{source}, [databases.{}]", name.display()),
        None => source.to_string(),
    };
    let db = target
        .as_ref()
        .map(|t| t.db.clone())
        .or_else(|| global.db.clone());
    // The order unlock.rs tries them in, leaving out --password-stdin (it is per command).
    let password_from = if let Some(f) = std::env::var_os("PRIVE_PASSWORD_FILE") {
        format!("PRIVE_PASSWORD_FILE {}", std::path::Path::new(&f).display())
    } else if let Some(cmd) = target.as_ref().and_then(|t| t.password_command.as_ref()) {
        format!("password_command {}", cmd.join(" "))
    } else {
        "asked for when needed".to_string()
    };
    let keyfile = target.and_then(|t| t.keyfile);
    #[cfg(unix)]
    let agent_dir = Some(crate::agent::dir::agent_dir());
    #[cfg(not(unix))]
    let agent_dir: Option<std::path::PathBuf> = None;
    if json {
        return output::print_json(&serde_json::json!({
            "config_file": path,
            "config_file_exists": path.as_ref().is_some_and(|p| p.exists()),
            "database": db,
            "database_from": db_from,
            "keyfile": keyfile,
            "password_from": password_from,
            "clipboard_seconds": cfg.clipboard_seconds(),
            "agent_minutes": cfg.agent_idle().as_secs() / 60,
            "agent_dir": agent_dir,
            "databases": cfg.databases,
        }));
    }
    let show = |p: &Option<std::path::PathBuf>| {
        p.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into())
    };
    let exists = if path.as_ref().is_some_and(|p| p.exists()) {
        ""
    } else {
        " (doesn't exist)"
    };
    let mut text = format!(
        "config file:       {}{exists}\n\
         database:          {} ({db_from})\n\
         key file:          {}\n\
         password:          {password_from}\n\
         clipboard clears:  after {} s\n\
         agent locks:       after {} min unused\n\
         agent directory:   {}\n",
        show(&path),
        show(&db),
        show(&keyfile),
        cfg.clipboard_seconds(),
        cfg.agent_idle().as_secs() / 60,
        show(&agent_dir),
    );
    let columns = cfg
        .databases
        .keys()
        .map(|n| output::width(n))
        .max()
        .unwrap_or(0);
    for (i, (name, d)) in cfg.databases.iter().enumerate() {
        let label = if i == 0 { "named databases:" } else { "" };
        text.push_str(&format!(
            "{label:<18} {}  {}\n",
            output::pad(name, columns),
            d.path.display()
        ));
    }
    output::print_human(&text)
}

/// Answer git's credential request from stdin. Never an error that stops git: anything that
/// goes wrong (locked, nothing fits, several fit) is said on stderr, and git carries on with
/// its next helper or its own prompt.
pub fn git_credential(global: &Global, action: &str) -> Result<()> {
    use std::io::Read;
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut input)?;
    if action != "get" {
        return Ok(()); // store / erase: prive doesn't write the database
    }
    let req = crate::gitcred::parse_request(&input);
    if req.host.is_empty() {
        return Ok(());
    }
    let db = match open(global) {
        Ok(db) => db,
        Err(e) => {
            if matches!(e.downcast_ref::<Failure>(), Some(Failure::NoTerminal)) {
                eprintln!("prive: run `prive unlock` so git can use your passwords");
            } else {
                eprintln!("prive: {e:#}");
            }
            return Ok(());
        }
    };
    let found = crate::gitcred::matches(&db.entries, &req);
    match found.as_slice() {
        [one] => output::print(&crate::gitcred::answer(one, &db.entries)),
        [] => Ok(()),
        many => {
            eprintln!(
                "prive: {} entries fit {}; set the username in the remote URL to choose: {}",
                many.len(),
                req.host,
                many.iter().map(|e| e.path()).collect::<Vec<_>>().join(", ")
            );
            Ok(())
        }
    }
}

pub fn completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = <crate::cli::Cli as clap::CommandFactory>::command();
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut cmd, "prive", &mut out);
    output::print(&String::from_utf8_lossy(&out))
}
