//! Reports on a database as a whole: audit, info, diff against a copy, doctor.

use super::*;

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
            "{:<13} {:.2} s on this machine (the key derivation, then reading the entries)\n",
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
