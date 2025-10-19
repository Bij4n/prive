use sha2::{Digest, Sha256};

use crate::vault::model::{Vault, VaultEntry};

#[derive(Debug)]
pub struct AuditReport {
    pub total_entries: usize,
    pub weak_passwords: Vec<AuditIssue>,
    pub duplicate_passwords: Vec<AuditIssue>,
    pub old_passwords: Vec<AuditIssue>,
    pub short_passwords: Vec<AuditIssue>,
    pub reused_usernames: Vec<AuditIssue>,
    pub score: u32,
}

#[derive(Debug)]
pub struct AuditIssue {
    pub entry_name: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}
