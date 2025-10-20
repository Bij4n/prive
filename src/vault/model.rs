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
