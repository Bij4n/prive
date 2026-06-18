//! `prive doctor`: check everything a command depends on, without asking for a password.
//! Each check says what it found; any `Fail` makes the command exit 1.

use std::path::Path;

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// Works, but something may get in the way.
    Warn,
    /// Commands that need this will fail.
    Fail,
    /// Not used here (no key file, no agent on this system).
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

/// The config file: there or not, and readable.
pub fn config_file() -> (Check, Option<Config>) {
    let Some(path) = Config::path() else {
        return (
            check(
                "config file",
                Status::Warn,
                "no config directory on this system",
            ),
            Some(Config::default()),
        );
    };
    if !path.exists() {
        return (
            check(
                "config file",
                Status::Ok,
                format!("{} (none; defaults apply)", path.display()),
            ),
            Some(Config::default()),
        );
    }
    match Config::load_from(&path) {
        Ok(cfg) => (
            check("config file", Status::Ok, path.display().to_string()),
            Some(cfg),
        ),
        Err(e) => (check("config file", Status::Fail, format!("{e:#}")), None),
    }
}

/// The database file: found, a KeePass file, and which format, read from its header alone.
pub fn database(path: &Path) -> Check {
    let bytes = match crate::db::read_file(path) {
        Ok(b) => b,
        Err(e) => return check("database", Status::Fail, format!("{e:#}")),
    };
    let version = keepass::Database::get_version(&mut &bytes[..])
        .map(|v| v.to_string().replacen("KDBX", "KDBX ", 1))
        .unwrap_or_else(|_| "unknown format".into());
    let size = crate::output::human_size(bytes.len());
    let detail = format!("{} ({version}, {size})", path.display());
    // KeePass 1 (`KDB`) and the KeePass 2 pre-release format (`KDBX 2`) can't be read.
    if version == "KDB" || version.starts_with("KDBX 2") {
        return check(
            "database",
            Status::Fail,
            format!("{detail}: too old; open it in KeePassXC and save it again"),
        );
    }
    check("database", Status::Ok, detail)
}

pub fn keyfile(path: Option<&Path>) -> Check {
    match path {
        None => check("key file", Status::Skip, "none"),
        Some(p) => match std::fs::metadata(p) {
            Ok(m) if m.is_file() => check("key file", Status::Ok, p.display().to_string()),
            Ok(_) => check(
                "key file",
                Status::Fail,
                format!("{} is not a file", p.display()),
            ),
            Err(e) => check("key file", Status::Fail, format!("{}: {e}", p.display())),
        },
    }
}

/// The agent's directory and whether an agent is running, and for which database.
#[cfg(unix)]
pub fn agent() -> Check {
    let dir = crate::agent::dir::agent_dir();
    if dir.exists()
        && let Err(e) = crate::agent::dir::check_private(&dir)
    {
        return check("agent", Status::Fail, format!("{e:#}"));
    }
    match crate::agent::client::status() {
        Ok(Some((Some(db), left))) => check(
            "agent",
            Status::Ok,
            format!(
                "running, {} unlocked ({} min left)",
                db.display(),
                left.div_ceil(60)
            ),
        ),
        Ok(Some((None, _))) => check("agent", Status::Ok, "running, nothing unlocked"),
        Ok(None) => check("agent", Status::Ok, "not running (prive unlock starts it)"),
        Err(e) => check("agent", Status::Warn, format!("{e:#}")),
    }
}

#[cfg(not(unix))]
pub fn agent() -> Check {
    check("agent", Status::Skip, "not available on this system yet")
}

pub fn clipboard() -> Check {
    match crate::clip::available() {
        Ok(how) => check("clipboard", Status::Ok, how),
        Err(e) => check(
            "clipboard",
            Status::Warn,
            format!("{e:#}: --clip and pick won't work here; print instead"),
        ),
    }
}

/// Every check, in the order a command meets them.
pub fn run(db: Option<&Path>, keyfile_arg: Option<&Path>) -> Vec<Check> {
    let (cfg_check, cfg) = config_file();
    let mut checks = vec![cfg_check];
    match cfg.map(|c| c.target(db, keyfile_arg)) {
        Some(Ok(target)) => {
            checks.push(database(&target.db));
            checks.push(keyfile(target.keyfile.as_deref()));
        }
        Some(Err(e)) => checks.push(check("database", Status::Fail, format!("{e:#}"))),
        None => checks.push(check(
            "database",
            Status::Skip,
            "the config file needs fixing first",
        )),
    }
    checks.push(agent());
    checks.push(clipboard());
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn a_database_is_checked_from_its_header() {
        let c = database(&fixture("kdbx41.kdbx"));
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("KDBX 4.1"), "{}", c.detail);
        assert!(
            database(&fixture("kdbx31.kdbx"))
                .detail
                .contains("KDBX 3.1")
        );
        let missing = database(&fixture("nope.kdbx"));
        assert_eq!(missing.status, Status::Fail);
        let not_keepass = database(&fixture("source.xml"));
        assert_eq!(not_keepass.status, Status::Fail);
        assert!(not_keepass.detail.contains("not a KeePass database"));
    }

    #[test]
    fn key_files() {
        assert_eq!(keyfile(None).status, Status::Skip);
        assert_eq!(keyfile(Some(&fixture("keyfile.keyx"))).status, Status::Ok);
        assert_eq!(keyfile(Some(&fixture("nope.keyx"))).status, Status::Fail);
        assert_eq!(keyfile(Some(&fixture(""))).status, Status::Fail);
    }
}
