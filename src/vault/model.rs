use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub entries: Vec<VaultEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultEntry {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub totp_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl Vault {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            version: 1,
            created_at: now,
            modified_at: now,
            entries: Vec::new(),
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<&VaultEntry> {
        self.entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn find_by_name_mut(&mut self, name: &str) -> Option<&mut VaultEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn remove_by_name(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !e.name.eq_ignore_ascii_case(name));
        self.entries.len() < before
    }
