//! Small TOML config: which database to open by default, other databases by name, and
//! clipboard and agent behaviour.
//!
//! Location: `$PRIVE_CONFIG` if set, otherwise `<config dir>/prive/config.toml`
//! (`~/.config/prive/config.toml` on Linux).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CLIPBOARD_SECONDS: u64 = 20;
/// How long the agent keeps a database unlocked without being used, by default.
pub const DEFAULT_AGENT_MINUTES: u64 = 15;

/// Shortest and longest clipboard timeouts accepted from the config file.
pub const CLIPBOARD_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 1..=600;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Database opened when neither `--db` nor `PRIVE_DB` is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,
    /// Key file used with the default database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<PathBuf>,
    /// Seconds before a copied secret is cleared from the clipboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clipboard_seconds: Option<u64>,
    /// Minutes the agent keeps a database unlocked after its last use (1 to 1440).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_minutes: Option<u64>,
    /// Other databases, by name: `--db work` opens `[databases.work]`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub databases: BTreeMap<String, Named>,
}

/// A database with a name of its own in the config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Named {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<PathBuf>,
}

/// A name for `[databases.NAME]`: something `--db` can't mistake for a path.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

impl Config {
    pub fn path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("PRIVE_CONFIG") {
            return Some(PathBuf::from(p));
        }
        dirs::config_dir().map(|d| d.join("prive").join("config.toml"))
    }

    pub fn load() -> Result<Config> {
        match Self::path() {
            Some(p) if p.exists() => Self::load_from(&p),
            _ => Ok(Config::default()),
        }
    }

    pub fn load_from(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        if let Some(m) = cfg.agent_minutes {
            anyhow::ensure!(
                (1..=1440).contains(&m),
                "agent_minutes in {} must be between 1 and 1440",
                path.display()
            );
        }
        for name in cfg.databases.keys() {
            anyhow::ensure!(
                valid_name(name),
                "[databases.{name}] in {}: a name is letters, digits, - and _ only",
                path.display()
            );
        }
        if let Some(n) = cfg.clipboard_seconds {
            anyhow::ensure!(
                CLIPBOARD_SECONDS_RANGE.contains(&n),
                "clipboard_seconds in {} must be between {} and {}",
                path.display(),
                CLIPBOARD_SECONDS_RANGE.start(),
                CLIPBOARD_SECONDS_RANGE.end()
            );
        }
        Ok(cfg)
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::path().context("no config directory on this system")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    pub fn clipboard_seconds(&self) -> u64 {
        self.clipboard_seconds.unwrap_or(DEFAULT_CLIPBOARD_SECONDS)
    }

    pub fn agent_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60 * self.agent_minutes.unwrap_or(DEFAULT_AGENT_MINUTES))
    }
}

/// The database a command opens, and its key file.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub db: PathBuf,
    pub keyfile: Option<PathBuf>,
}

impl Config {
    /// `--db` (or `PRIVE_DB`) wins over the config file, and may be one of its
    /// `[databases.NAME]`. A key file from the config file only goes with the database it is
    /// written next to, never with one named on the command line.
    pub fn target(&self, db: Option<&Path>, keyfile: Option<&Path>) -> Result<Target> {
        if let Some(named) = db.and_then(|d| self.named(d)) {
            return Ok(Target {
                db: expand_home(&named.path),
                keyfile: keyfile
                    .map(Path::to_path_buf)
                    .or_else(|| named.keyfile.as_deref().map(expand_home)),
            });
        }
        // A mistyped name would otherwise come back as "no such file", which hides the names.
        if let Some(d) = db
            && !self.databases.is_empty()
            && d.to_str().is_some_and(valid_name)
            && !d.exists()
        {
            let names: Vec<&str> = self.databases.keys().map(String::as_str).collect();
            return Err(crate::error::Failure::Missing(format!(
                "no database '{}': no such file, and the config file names {}",
                d.display(),
                names.join(", ")
            ))
            .into());
        }
        match db {
            Some(d) => Ok(Target {
                db: d.to_path_buf(),
                keyfile: keyfile.map(Path::to_path_buf),
            }),
            None => {
                let db = self.db.as_deref().map(expand_home).context(
                    "no database given: use --db, set PRIVE_DB, or run `prive init <file>`",
                )?;
                Ok(Target {
                    db,
                    keyfile: keyfile
                        .map(Path::to_path_buf)
                        .or_else(|| self.keyfile.as_deref().map(expand_home)),
                })
            }
        }
    }
}

impl Config {
    /// The `[databases.NAME]` entry `arg` names, if it is a name rather than a path.
    pub fn named(&self, arg: &Path) -> Option<&Named> {
        let name = arg.to_str()?;
        if !valid_name(name) {
            return None;
        }
        self.databases.get(name)
    }

    /// The name the config file gives the database at `path`, if any (paths compared after
    /// resolving `~/`, symlinks and relative parts).
    pub fn name_of(&self, path: &Path) -> Option<&str> {
        let want = std::fs::canonicalize(path).ok()?;
        self.databases
            .iter()
            .find(|(_, d)| std::fs::canonicalize(expand_home(&d.path)).ok().as_ref() == Some(&want))
            .map(|(name, _)| name.as_str())
    }
}

/// A leading `~/` in a config file path means the home directory, as people write it.
/// (Paths from the command line are already expanded by the shell.)
fn expand_home(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), dirs::home_dir()) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_unknown_keys() {
        let cfg: Config =
            toml::from_str("db = \"/tmp/x.kdbx\"\nclipboard_seconds = 5\n[vault]\nold = 1\n")
                .unwrap();
        assert_eq!(cfg.db.as_deref(), Some(Path::new("/tmp/x.kdbx")));
        assert_eq!(cfg.clipboard_seconds(), 5);
        let again: Config = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(again, cfg);
    }

    #[test]
    fn defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.clipboard_seconds(), DEFAULT_CLIPBOARD_SECONDS);
        assert!(cfg.db.is_none());
    }

    #[test]
    fn clipboard_timeout_must_be_sensible() {
        let dir = std::env::temp_dir().join(format!("prive-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        std::fs::write(&p, "clipboard_seconds = 0\n").unwrap();
        assert!(Config::load_from(&p).is_err());
        std::fs::write(&p, "clipboard_seconds = 30\n").unwrap();
        assert_eq!(Config::load_from(&p).unwrap().clipboard_seconds(), 30);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn command_line_database_wins_and_keeps_its_own_key_file() {
        let cfg = Config {
            db: Some("/home/me/main.kdbx".into()),
            keyfile: Some("/home/me/main.key".into()),
            ..Config::default()
        };
        let from_cfg = cfg.target(None, None).unwrap();
        assert_eq!(from_cfg.db, Path::new("/home/me/main.kdbx"));
        assert_eq!(
            from_cfg.keyfile.as_deref(),
            Some(Path::new("/home/me/main.key"))
        );

        let other = cfg
            .target(Some(Path::new("/tmp/other.kdbx")), None)
            .unwrap();
        assert_eq!(
            other.keyfile, None,
            "the config key file belongs to the config database"
        );

        let err = Config::default()
            .target(None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("prive init"));
    }

    #[test]
    fn a_key_file_on_the_command_line_wins() {
        let cfg = Config {
            db: Some("/home/me/main.kdbx".into()),
            keyfile: Some("/home/me/main.key".into()),
            ..Config::default()
        };
        let t = cfg
            .target(None, Some(Path::new("/media/usb/other.key")))
            .unwrap();
        assert_eq!(t.db, Path::new("/home/me/main.kdbx"));
        assert_eq!(
            t.keyfile.as_deref(),
            Some(Path::new("/media/usb/other.key"))
        );
    }

    #[test]
    fn a_tilde_in_the_config_means_home() {
        let cfg = Config {
            db: Some("~/Passwords.kdbx".into()),
            keyfile: Some("~/keys/db.keyx".into()),
            ..Config::default()
        };
        let t = cfg.target(None, None).unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(t.db, home.join("Passwords.kdbx"));
        assert_eq!(t.keyfile.unwrap(), home.join("keys/db.keyx"));
        let abs = Config {
            db: Some("/srv/p.kdbx".into()),
            ..Config::default()
        };
        assert_eq!(abs.target(None, None).unwrap().db, Path::new("/srv/p.kdbx"));
    }

    #[test]
    fn databases_by_name() {
        let cfg: Config = toml::from_str(
            "db = \"/home/me/main.kdbx\"\n\
             [databases.work]\npath = \"/home/me/work.kdbx\"\nkeyfile = \"/home/me/work.keyx\"\n\
             [databases.home-2]\npath = \"~/home.kdbx\"\n",
        )
        .unwrap();
        let work = cfg.target(Some(Path::new("work")), None).unwrap();
        assert_eq!(work.db, Path::new("/home/me/work.kdbx"));
        assert_eq!(
            work.keyfile.as_deref(),
            Some(Path::new("/home/me/work.keyx"))
        );
        let home = cfg.target(Some(Path::new("home-2")), None).unwrap();
        assert_eq!(home.db, dirs::home_dir().unwrap().join("home.kdbx"));
        assert_eq!(home.keyfile, None);
        // A key file on the command line still wins.
        let k = cfg
            .target(Some(Path::new("work")), Some(Path::new("/media/k.keyx")))
            .unwrap();
        assert_eq!(k.keyfile.as_deref(), Some(Path::new("/media/k.keyx")));
        // Anything else is a path, even next to a name.
        let path = cfg.target(Some(Path::new("./work")), None).unwrap();
        assert_eq!(path.db, Path::new("./work"));
        assert_eq!(path.keyfile, None);
        let other = cfg.target(Some(Path::new("other.kdbx")), None).unwrap();
        assert_eq!(other.db, Path::new("other.kdbx"));
    }

    #[test]
    fn a_path_finds_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("work.kdbx");
        std::fs::write(&db, b"x").unwrap();
        let mut cfg = Config::default();
        cfg.databases.insert(
            "work".into(),
            Named {
                path: db.clone(),
                keyfile: None,
            },
        );
        assert_eq!(cfg.name_of(&db), Some("work"));
        // The same file by another route is still the same database.
        assert_eq!(
            cfg.name_of(&dir.path().join(".").join("work.kdbx")),
            Some("work")
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("link.kdbx");
            std::os::unix::fs::symlink(&db, &link).unwrap();
            assert_eq!(cfg.name_of(&link), Some("work"));
        }
        assert_eq!(cfg.name_of(&dir.path().join("other.kdbx")), None);
    }

    #[test]
    fn a_mistyped_name_lists_the_names() {
        let cfg: Config = toml::from_str(
            "[databases.work]\npath = \"/w.kdbx\"\n[databases.home]\npath = \"/h.kdbx\"\n",
        )
        .unwrap();
        let err = cfg.target(Some(Path::new("wrok")), None).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::Missing(_))
        ));
        assert!(err.to_string().contains("home, work"), "{err}");
        // Without named databases, a missing file is reported when it is opened, as before.
        assert!(
            Config::default()
                .target(Some(Path::new("wrok")), None)
                .is_ok()
        );
    }

    #[test]
    fn database_names_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "[databases.\"my.db\"]\npath = \"/x.kdbx\"\n").unwrap();
        assert!(Config::load_from(&p).is_err());
        std::fs::write(&p, "[databases.work]\n").unwrap();
        assert!(Config::load_from(&p).is_err(), "a path is needed");
        std::fs::write(&p, "[databases.work]\npath = \"/x.kdbx\"\n").unwrap();
        assert_eq!(Config::load_from(&p).unwrap().databases.len(), 1);
    }

    #[test]
    fn agent_minutes() {
        assert_eq!(Config::default().agent_idle().as_secs(), 15 * 60);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(&p, "agent_minutes = 0\n").unwrap();
        assert!(Config::load_from(&p).is_err());
        std::fs::write(&p, "agent_minutes = 60\n").unwrap();
        assert_eq!(Config::load_from(&p).unwrap().agent_idle().as_secs(), 3600);
    }
}
