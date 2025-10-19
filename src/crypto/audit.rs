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

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

pub fn audit_vault(vault: &Vault) -> AuditReport {
    let mut report = AuditReport {
        total_entries: vault.entries.len(),
        weak_passwords: Vec::new(),
        duplicate_passwords: Vec::new(),
        old_passwords: Vec::new(),
        short_passwords: Vec::new(),
        reused_usernames: Vec::new(),
        score: 100,
    };

    if vault.entries.is_empty() {
        return report;
    }

    check_weak_passwords(&vault.entries, &mut report);
    check_duplicate_passwords(&vault.entries, &mut report);
