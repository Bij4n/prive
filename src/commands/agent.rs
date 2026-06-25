//! Unlocking once: hand databases to the agent, forget them, say which are held.

use super::*;

/// Open one database, check its password, and hand it to the agent. `password`, when given,
/// is used instead of asking (`unlock --all --password-stdin` reads stdin only once).
#[cfg(unix)]
fn unlock_target(
    global: &Global,
    cfg: &config::Config,
    target: &config::Target,
    idle: std::time::Duration,
    password: Option<&Zeroizing<String>>,
) -> Result<()> {
    let bytes = db::read_file(&target.db)?;
    let creds = match password {
        Some(p) => unlock::Credentials {
            password: Some(p.clone()),
            keyfile: target.keyfile.clone(),
        },
        None => unlock::KeySource::for_target(global, target)?,
    };
    // Check the password here, so a wrong one is exit code 5 like everywhere else.
    db::Db::from_bytes(&target.db, &bytes, &creds)?;
    crate::agent::client::start(idle)?;
    crate::agent::client::unlock(
        &target.db,
        creds.keyfile.clone(),
        creds.password.as_ref().map(|p| p.as_str()),
    )?;
    output::notice(&format!(
        "Unlocked {}. It locks after {} minutes unused, or with `prive lock`.",
        display_name(cfg, &target.db),
        idle.as_secs() / 60
    ));
    Ok(())
}

/// Open the database once (or, with `all`, every one the config file names), then hand it to
/// the agent so later commands need no password.
pub fn unlock(global: &Global, minutes: Option<u64>, all: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let cfg = config::Config::load()?;
        let idle = minutes
            .map(|m| std::time::Duration::from_secs(m * 60))
            .unwrap_or_else(|| cfg.agent_idle());
        if !all {
            let target = cfg.target(global.db.as_deref(), global.keyfile.as_deref())?;
            return unlock_target(global, &cfg, &target, idle, None);
        }
        let named_on_command_line = global
            .db
            .as_ref()
            .is_some_and(|d| std::env::var_os("PRIVE_DB").is_none_or(|v| v != d.as_os_str()));
        anyhow::ensure!(
            !named_on_command_line,
            "--all unlocks every database in the config file; leave out --db"
        );
        let mut targets = Vec::new();
        if cfg.db.is_some() {
            targets.push(cfg.target(None, None)?);
        }
        for name in cfg.databases.keys() {
            targets.push(cfg.target(Some(std::path::Path::new(name)), None)?);
        }
        let canonical =
            |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        // The default database is often also given a name; unlock it once.
        let mut seen = std::collections::HashSet::new();
        targets.retain(|t| seen.insert(canonical(&t.db)));
        anyhow::ensure!(
            !targets.is_empty(),
            "nothing to unlock: the config file names no database"
        );
        let held: Vec<std::path::PathBuf> = crate::agent::client::status()?
            .map(|(open, _)| open)
            .unwrap_or_default();
        let shared = if global.password_stdin {
            unlock::KeySource {
                password_stdin: true,
                ..unlock::KeySource::default()
            }
            .credentials(std::path::Path::new("all"))?
            .password
        } else {
            None
        };
        let mut failed = Vec::new();
        for t in &targets {
            let name = display_name(&cfg, &t.db);
            if held.contains(&canonical(&t.db)) {
                output::notice(&format!("{name} is already unlocked."));
                continue;
            }
            if let Err(e) = unlock_target(global, &cfg, t, idle, shared.as_ref()) {
                eprintln!("prive: {name}: {}", output::visible(&format!("{e:#}")));
                failed.push(name);
            }
        }
        anyhow::ensure!(failed.is_empty(), "not unlocked: {}", failed.join(", "));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (global, minutes, all);
        anyhow::bail!("unlocking once isn't available on this system yet; each command asks")
    }
}

/// Forget every unlocked database, or with `--db` on the command line only that one.
/// `PRIVE_DB` alone doesn't narrow it: `prive lock` is the way to lock everything now.
pub fn lock(global: &Global) -> Result<()> {
    #[cfg(unix)]
    {
        let only = global
            .db
            .as_ref()
            .filter(|d| std::env::var_os("PRIVE_DB").is_none_or(|v| v != d.as_os_str()));
        match only {
            Some(d) => {
                let cfg = config::Config::load()?;
                let target = cfg.target(Some(d), None)?;
                let name = cfg
                    .name_of(&target.db)
                    .map(str::to_string)
                    .unwrap_or_else(|| target.db.display().to_string());
                if crate::agent::client::lock(Some(&target.db))? {
                    output::notice(&format!("Locked {name}."));
                } else {
                    output::notice(&format!("{name} was not unlocked."));
                }
            }
            None => {
                if crate::agent::client::lock(None)? {
                    output::notice("Locked.");
                } else {
                    output::notice("Nothing was unlocked.");
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = global;
    Ok(())
}

pub fn status(json: bool) -> Result<()> {
    let cfg = config::Config::load().unwrap_or_default();
    #[cfg(unix)]
    let state = crate::agent::client::status()?;
    #[cfg(not(unix))]
    let state: Option<(Vec<std::path::PathBuf>, u64)> = None;
    let (open, left) = state.unwrap_or_default();
    if json {
        let databases: Vec<serde_json::Value> = open
            .iter()
            .map(|d| serde_json::json!({ "path": d, "name": cfg.name_of(d) }))
            .collect();
        return output::print_json(&serde_json::json!({
            "unlocked": !open.is_empty(),
            "db": open.first(),
            "name": open.first().and_then(|d| cfg.name_of(d)),
            "databases": databases,
            "seconds_left": left,
        }));
    }
    if open.is_empty() {
        return output::print_human("locked\n");
    }
    let mut text = String::new();
    for db in &open {
        text.push_str(&format!(
            "unlocked: {}{} (locks in {} min {} s if unused)\n",
            cfg.name_of(db)
                .map(|n| format!("{n}, "))
                .unwrap_or_default(),
            db.display(),
            left / 60,
            left % 60
        ));
    }
    output::print_human(&text)
}
