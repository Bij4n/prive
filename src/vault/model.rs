use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::crypto::totp::TotpAlgorithm;

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub entries: Vec<VaultEntry>,
    #[serde(default)]
    pub secure_notes: Vec<SecureNote>,
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
    #[serde(default)]
    pub totp_algorithm: Option<TotpAlgorithm>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<VaultAttachment>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultAttachment {
    pub name: String,
    pub mime_type: String,
    pub data: String, // base64-encoded
    pub size: u64,
    pub added_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecureNote {
    pub id: Uuid,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            version: 1,
            created_at: now,
            modified_at: now,
            entries: Vec::new(),
            secure_notes: Vec::new(),
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
        self.entries.retain(|e| !e.name.eq_ignore_ascii_case(name));
        self.entries.len() < before
    }

    pub fn search(&self, query: &str) -> Vec<&VaultEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.name.to_lowercase().contains(&q)
                    || e.username
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&q))
                    || e.url
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&q))
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    // --- Secure Notes ---

    pub fn find_note_by_title(&self, title: &str) -> Option<&SecureNote> {
        self.secure_notes
            .iter()
            .find(|n| n.title.eq_ignore_ascii_case(title))
    }

    pub fn find_note_by_title_mut(&mut self, title: &str) -> Option<&mut SecureNote> {
        self.secure_notes
            .iter_mut()
            .find(|n| n.title.eq_ignore_ascii_case(title))
    }

    pub fn remove_note_by_title(&mut self, title: &str) -> bool {
        let before = self.secure_notes.len();
        self.secure_notes
            .retain(|n| !n.title.eq_ignore_ascii_case(title));
        self.secure_notes.len() < before
    }

    pub fn search_notes(&self, query: &str) -> Vec<&SecureNote> {
        let q = query.to_lowercase();
        self.secure_notes
            .iter()
            .filter(|n| {
                n.title.to_lowercase().contains(&q)
                    || n.content.to_lowercase().contains(&q)
                    || n.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }
}

impl VaultEntry {
    pub fn new(
        name: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
        tags: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            username,
            password,
            url,
            notes,
            tags,
            totp_secret: None,
            totp_algorithm: None,
            password_history: Vec::new(),
            attachments: Vec::new(),
            expires_at: None,
            created_at: now,
            modified_at: now,
        }
    }

    /// Add a file attachment to this entry.
    pub fn add_attachment(&mut self, attachment: VaultAttachment) {
        self.attachments.push(attachment);
        self.modified_at = Utc::now();
    }

    /// Remove an attachment by name. Returns `true` if one was removed.
    pub fn remove_attachment(&mut self, name: &str) -> bool {
        let before = self.attachments.len();
        self.attachments
            .retain(|a| !a.name.eq_ignore_ascii_case(name));
        let removed = self.attachments.len() < before;
        if removed {
            self.modified_at = Utc::now();
        }
        removed
    }

    /// Get an attachment by name.
    pub fn get_attachment(&self, name: &str) -> Option<&VaultAttachment> {
        self.attachments
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
    }

    /// List all attachments.
    pub fn list_attachments(&self) -> &[VaultAttachment] {
        &self.attachments
    }

    /// Push current password to history before changing it.
    pub fn rotate_password(&mut self, new_password: String) {
        self.password_history.push(PasswordHistoryEntry {
            password: self.password.clone(),
            changed_at: Utc::now(),
        });
        self.password = new_password;
        self.modified_at = Utc::now();
    }
}

impl SecureNote {
    pub fn new(title: String, content: String, tags: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title,
            content,
            tags,
            created_at: now,
            modified_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_new() {
        let vault = Vault::new();
        assert_eq!(vault.version, 1);
        assert!(vault.entries.is_empty());
        assert!(vault.secure_notes.is_empty());
    }

    #[test]
    fn test_password_history() {
        let mut entry = VaultEntry::new("test".into(), None, "old_pass".into(), None, None, vec![]);
        entry.rotate_password("new_pass".into());
        assert_eq!(entry.password, "new_pass");
        assert_eq!(entry.password_history.len(), 1);
        assert_eq!(entry.password_history[0].password, "old_pass");

        entry.rotate_password("newer_pass".into());
        assert_eq!(entry.password, "newer_pass");
        assert_eq!(entry.password_history.len(), 2);
    }

    #[test]
    fn test_secure_note_crud() {
        let mut vault = Vault::new();
        vault.secure_notes.push(SecureNote::new(
            "API Keys".into(),
            "sk-1234567890".into(),
            vec!["work".into()],
        ));

        assert!(vault.find_note_by_title("API Keys").is_some());
        assert!(vault.find_note_by_title("api keys").is_some()); // case insensitive
        assert!(vault.find_note_by_title("nonexistent").is_none());

        let results = vault.search_notes("1234");
        assert_eq!(results.len(), 1);

        assert!(vault.remove_note_by_title("API Keys"));
        assert!(vault.secure_notes.is_empty());
    }

    #[test]
    fn test_vault_serde_with_new_fields() {
        // Test that old vaults without new fields still deserialize
        let json = r#"{
            "version": 1,
            "created_at": "2025-10-16T09:00:00Z",
            "modified_at": "2025-10-16T09:00:00Z",
            "entries": [{
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "test",
                "username": null,
                "password": "pass",
                "url": null,
                "notes": null,
                "tags": [],
                "totp_secret": null,
                "created_at": "2025-10-16T09:00:00Z",
                "modified_at": "2025-10-16T09:00:00Z"
            }]
        }"#;
        let vault: Vault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert!(vault.entries[0].password_history.is_empty());
        assert!(vault.entries[0].attachments.is_empty());
        assert!(vault.secure_notes.is_empty());
    }

    fn make_attachment(name: &str) -> VaultAttachment {
        VaultAttachment {
            name: name.to_string(),
            mime_type: "application/octet-stream".to_string(),
            data: "dGVzdA==".to_string(), // base64 for "test"
            size: 4,
            added_at: Utc::now(),
        }
    }

    #[test]
    fn test_add_attachment() {
        let mut entry = VaultEntry::new("test".into(), None, "pass".into(), None, None, vec![]);
        assert!(entry.list_attachments().is_empty());

        entry.add_attachment(make_attachment("readme.txt"));
        assert_eq!(entry.list_attachments().len(), 1);
        assert_eq!(entry.list_attachments()[0].name, "readme.txt");
    }

    #[test]
    fn test_get_attachment() {
        let mut entry = VaultEntry::new("test".into(), None, "pass".into(), None, None, vec![]);
        entry.add_attachment(make_attachment("logo.png"));

        assert!(entry.get_attachment("logo.png").is_some());
        assert!(entry.get_attachment("LOGO.PNG").is_some()); // case insensitive
        assert!(entry.get_attachment("missing.txt").is_none());
    }

    #[test]
    fn test_remove_attachment() {
        let mut entry = VaultEntry::new("test".into(), None, "pass".into(), None, None, vec![]);
        entry.add_attachment(make_attachment("a.txt"));
        entry.add_attachment(make_attachment("b.txt"));

        assert!(entry.remove_attachment("a.txt"));
        assert_eq!(entry.list_attachments().len(), 1);
        assert_eq!(entry.list_attachments()[0].name, "b.txt");

        assert!(!entry.remove_attachment("nonexistent"));
    }

    #[test]
    fn test_attachment_serde_roundtrip() {
        let mut entry = VaultEntry::new("serde_test".into(), None, "pw".into(), None, None, vec![]);
        entry.add_attachment(make_attachment("doc.pdf"));

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: VaultEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.attachments.len(), 1);
        assert_eq!(deserialized.attachments[0].name, "doc.pdf");
        assert_eq!(deserialized.attachments[0].size, 4);
    }
}
