//! Commands about entries: list, find, show, get a field, history, files, open, pick.

use super::*;

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
    tags: &[String],
    format: Option<&str>,
    json: bool,
) -> Result<()> {
    if let Some(t) = format {
        crate::template::check_listing(t)?;
    }
    let db = open(global)?;
    let mut hits = if all {
        select::search_everywhere(&db.entries, query)
    } else {
        select::search(&db.entries, query)
    };
    for t in tags {
        hits = select::with_tag(&hits, t);
    }
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
    let mut text = format!("{}  current version\n", when(e.modified));
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
