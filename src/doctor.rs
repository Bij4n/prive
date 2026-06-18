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

/// Conflict copies a sync tool left next to the database.
pub fn conflicts(db: &Path) -> Check {
    let found = crate::sync::conflict_copies(db);
    match found.as_slice() {
        [] => check("sync", Status::Ok, "no conflict copies next to it"),
        [one] => check(
            "sync",
            Status::Warn,
            format!(
                "a conflict copy next to it: prive diff '{}' shows what is in it",
                one.display()
            ),
        ),
        [first, ..] => check(
            "sync",
            Status::Warn,
            format!(
                "{} conflict copies next to it; start with prive diff '{}'",
                found.len(),
                first.display()
            ),
        ),
    }
}

/// Whether `program` can be run: a path that exists, or a name found on `PATH`.
fn findable(program: &str) -> bool {
    let p = Path::new(program);
    if p.components().count() > 1 {
        return p.is_file();
    }
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            exts.iter()
                .any(|e| dir.join(format!("{program}{e}")).is_file())
        })
    })
}

/// Where the password will come from, checked without reading it.
pub fn password(command: Option<&[String]>) -> Check {
    if let Some(file) = std::env::var_os("PRIVE_PASSWORD_FILE") {
        let p = Path::new(&file);
        return if p.is_file() {
            check(
                "password",
                Status::Ok,
                format!("from PRIVE_PASSWORD_FILE {}", p.display()),
            )
        } else {
            check(
                "password",
                Status::Fail,
                format!("PRIVE_PASSWORD_FILE {} is not a file", p.display()),
            )
        };
    }
    match command.and_then(<[String]>::first) {
        Some(program) if findable(program) => check(
            "password",
            Status::Ok,
            format!("from password_command {program}"),
        ),
        Some(program) => check(
            "password",
            Status::Fail,
            format!("password_command {program} is not installed or not on PATH"),
        ),
        None => check("password", Status::Ok, "asked for when needed"),
    }
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
        Ok(Some((open, _))) if open.is_empty() => {
            check("agent", Status::Ok, "running, nothing unlocked")
        }
        Ok(Some((open, left))) => check(
            "agent",
            Status::Ok,
            format!(
                "running, {} unlocked ({} min left)",
                open.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                left.div_ceil(60)
            ),
        ),
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
            let db_check = database(&target.db);
            let found = db_check.status != Status::Fail;
            checks.push(db_check);
            checks.push(keyfile(target.keyfile.as_deref()));
            checks.push(password(target.password_command.as_deref()));
            if found {
                checks.push(conflicts(&target.db));
            }
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
    fn conflict_copies_are_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("Passwords.kdbx");
        std::fs::write(&db, b"x").unwrap();
        assert_eq!(conflicts(&db).status, Status::Ok);
        std::fs::write(
            dir.path()
                .join("Passwords.sync-conflict-20260612-101500-ABCDEFG.kdbx"),
            b"x",
        )
        .unwrap();
        let c = conflicts(&db);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("prive diff"), "{}", c.detail);
    }

    #[cfg(unix)]
    #[test]
    fn password_commands_are_looked_for_not_run() {
        if std::env::var_os("PRIVE_PASSWORD_FILE").is_some() {
            return;
        }
        let cmd = |p: &str| vec![p.to_string(), "lookup".into()];
        assert_eq!(password(Some(&cmd("sh"))).status, Status::Ok);
        assert_eq!(password(Some(&cmd("/bin/sh"))).status, Status::Ok);
        assert_eq!(
            password(Some(&cmd("prive-no-such-program"))).status,
            Status::Fail
        );
        assert_eq!(password(None).status, Status::Ok);
    }

    #[test]
    fn key_files() {
        assert_eq!(keyfile(None).status, Status::Skip);
        assert_eq!(keyfile(Some(&fixture("keyfile.keyx"))).status, Status::Ok);
        assert_eq!(keyfile(Some(&fixture("nope.keyx"))).status, Status::Fail);
        assert_eq!(keyfile(Some(&fixture(""))).status, Status::Fail);
    }
}
