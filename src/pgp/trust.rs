use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config;

/// Trust level for a PGP key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Unknown,
    Untrusted,
    Marginal,
    Full,
    Ultimate,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::Unknown => write!(f, "unknown"),
            TrustLevel::Untrusted => write!(f, "untrusted"),
            TrustLevel::Marginal => write!(f, "marginal"),
            TrustLevel::Full => write!(f, "full"),
            TrustLevel::Ultimate => write!(f, "ultimate"),
        }
    }
}

impl TrustLevel {
    pub fn parse_level(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "untrusted" | "never" => TrustLevel::Untrusted,
            "marginal" => TrustLevel::Marginal,
            "full" => TrustLevel::Full,
            "ultimate" => TrustLevel::Ultimate,
            _ => TrustLevel::Unknown,
        }
    }
}

/// Trust database entry for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub key_id: String,
    pub fingerprint: String,
    pub trust_level: TrustLevel,
    pub set_at: DateTime<Utc>,
    pub reason: Option<String>,
}

/// Trust database stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustDb {
    pub entries: HashMap<String, TrustEntry>,
}

impl TrustDb {
    fn db_path() -> PathBuf {
        config::data_dir().join("trustdb.json")
    }

    pub fn load() -> Self {
        let path = Self::db_path();
        if path.exists()
            && let Ok(content) = fs::read_to_string(&path)
            && let Ok(db) = serde_json::from_str(&content)
        {
            return db;
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::db_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create dir: {e}"))?;
        }
        let content =
            serde_json::to_string_pretty(self).map_err(|e| format!("Serialization error: {e}"))?;
        fs::write(&path, content).map_err(|e| format!("Failed to write trust db: {e}"))?;
        Ok(())
    }

    pub fn set_trust(
        &mut self,
        key_id: &str,
        fingerprint: &str,
        level: TrustLevel,
        reason: Option<String>,
    ) {
        self.entries.insert(
            key_id.to_string(),
            TrustEntry {
                key_id: key_id.to_string(),
                fingerprint: fingerprint.to_string(),
                trust_level: level,
                set_at: Utc::now(),
                reason,
            },
        );
    }

    pub fn get_trust(&self, key_id: &str) -> TrustLevel {
        self.entries
            .get(key_id)
            .map(|e| e.trust_level)
            .unwrap_or(TrustLevel::Unknown)
    }

    pub fn remove_trust(&mut self, key_id: &str) -> bool {
        self.entries.remove(key_id).is_some()
    }

    pub fn list_trusted(&self) -> Vec<&TrustEntry> {
        let mut entries: Vec<&TrustEntry> = self.entries.values().collect();
        entries.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        entries
    }
}

/// Key revocation certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationInfo {
    pub key_id: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub certificate: String, // ASCII armored revocation cert
}

/// Manage revocation certificates.
pub struct RevocationStore;

impl RevocationStore {
    fn revocation_dir() -> PathBuf {
        config::keyring_dir().join("revocations")
    }

    pub fn save_revocation(
        key_id: &str,
        certificate: &str,
        reason: &str,
    ) -> Result<PathBuf, String> {
        let dir = Self::revocation_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create revocation dir: {e}"))?;

        let info = RevocationInfo {
            key_id: key_id.to_string(),
            reason: reason.to_string(),
            created_at: Utc::now(),
            certificate: certificate.to_string(),
        };

        let path = dir.join(format!("{key_id}.rev.json"));
        let content =
            serde_json::to_string_pretty(&info).map_err(|e| format!("Serialization error: {e}"))?;
        fs::write(&path, content).map_err(|e| format!("Failed to write revocation: {e}"))?;

        Ok(path)
    }

    pub fn load_revocation(key_id: &str) -> Result<Option<RevocationInfo>, String> {
        let path = Self::revocation_dir().join(format!("{key_id}.rev.json"));
        if !path.exists() {
            return Ok(None);
        }
        let content =
            fs::read_to_string(&path).map_err(|e| format!("Failed to read revocation: {e}"))?;
        let info: RevocationInfo =
            serde_json::from_str(&content).map_err(|e| format!("Parse error: {e}"))?;
        Ok(Some(info))
    }

    pub fn list_revocations() -> Result<Vec<RevocationInfo>, String> {
        let dir = Self::revocation_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut revocations = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|e| format!("Failed to read dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Read dir error: {e}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(content) = fs::read_to_string(&path)
                && let Ok(info) = serde_json::from_str(&content)
            {
                revocations.push(info);
            }
        }
        Ok(revocations)
    }
}

/// Check if a key has expired based on its creation date and a duration string.
pub fn parse_expiry(expire_str: &str) -> Option<chrono::Duration> {
    let s = expire_str.trim().to_lowercase();
    if s == "never" || s == "0" || s.is_empty() {
        return None;
    }
    if let Some(years) = s.strip_suffix('y')
        && let Ok(n) = years.parse::<i64>()
    {
        return Some(chrono::Duration::days(n * 365));
    }
    if let Some(months) = s.strip_suffix('m')
        && let Ok(n) = months.parse::<i64>()
    {
        return Some(chrono::Duration::days(n * 30));
    }
    if let Some(days) = s.strip_suffix('d')
        && let Ok(n) = days.parse::<i64>()
    {
        return Some(chrono::Duration::days(n));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_display() {
        assert_eq!(format!("{}", TrustLevel::Full), "full");
        assert_eq!(format!("{}", TrustLevel::Unknown), "unknown");
        assert_eq!(format!("{}", TrustLevel::Ultimate), "ultimate");
    }

    #[test]
    fn test_trust_level_from_str() {
        assert_eq!(TrustLevel::parse_level("full"), TrustLevel::Full);
        assert_eq!(TrustLevel::parse_level("MARGINAL"), TrustLevel::Marginal);
        assert_eq!(TrustLevel::parse_level("garbage"), TrustLevel::Unknown);
    }

    #[test]
    fn test_trust_db_set_get() {
        let mut db = TrustDb::default();
        db.set_trust("ABC123", "FINGERPRINT", TrustLevel::Full, None);
        assert_eq!(db.get_trust("ABC123"), TrustLevel::Full);
        assert_eq!(db.get_trust("NONEXISTENT"), TrustLevel::Unknown);
    }

    #[test]
    fn test_trust_db_remove() {
        let mut db = TrustDb::default();
        db.set_trust("ABC123", "FP", TrustLevel::Marginal, None);
        assert!(db.remove_trust("ABC123"));
        assert!(!db.remove_trust("ABC123"));
        assert_eq!(db.get_trust("ABC123"), TrustLevel::Unknown);
    }

    #[test]
    fn test_trust_db_list() {
        let mut db = TrustDb::default();
        db.set_trust("B", "FP2", TrustLevel::Full, None);
        db.set_trust("A", "FP1", TrustLevel::Marginal, None);
        let list = db.list_trusted();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].key_id, "A"); // sorted
    }

    #[test]
    fn test_trust_db_serialization() {
        let mut db = TrustDb::default();
        db.set_trust("KEY1", "FP1", TrustLevel::Ultimate, Some("my key".into()));
        let json = serde_json::to_string(&db).unwrap();
        let loaded: TrustDb = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.get_trust("KEY1"), TrustLevel::Ultimate);
    }

    #[test]
    fn test_parse_expiry() {
        assert_eq!(parse_expiry("2y"), Some(chrono::Duration::days(730)));
        assert_eq!(parse_expiry("6m"), Some(chrono::Duration::days(180)));
        assert_eq!(parse_expiry("90d"), Some(chrono::Duration::days(90)));
        assert!(parse_expiry("never").is_none());
        assert!(parse_expiry("0").is_none());
        assert!(parse_expiry("").is_none());
    }
}
