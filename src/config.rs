//! Small TOML config: which database to open by default, and clipboard behaviour.
//!
//! Location: `<config dir>/prive/config.toml` (`~/.config/prive/config.toml` on Linux).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CLIPBOARD_SECONDS: u64 = 20;

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
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
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
}
