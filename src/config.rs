//! Small TOML config: which database to open by default, and clipboard behaviour.
//!
//! Location: `$PRIVE_CONFIG` if set, otherwise `<config dir>/prive/config.toml`
//! (`~/.config/prive/config.toml` on Linux).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CLIPBOARD_SECONDS: u64 = 20;
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
}

/// The database a command opens, and its key file.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub db: PathBuf,
    pub keyfile: Option<PathBuf>,
}

impl Config {
    /// `--db` (or `PRIVE_DB`) wins over the config file. A key file from the config file only
    /// goes with the config file's database, never with one named on the command line.
    pub fn target(&self, db: Option<&Path>, keyfile: Option<&Path>) -> Result<Target> {
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
}
