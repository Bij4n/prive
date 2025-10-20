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
    check_old_passwords(&vault.entries, &mut report);
    check_short_passwords(&vault.entries, &mut report);
    check_reused_usernames(&vault.entries, &mut report);

    // Calculate score
    let _total_issues = report.weak_passwords.len()
        + report.duplicate_passwords.len()
        + report.old_passwords.len()
        + report.short_passwords.len();

    let penalty_per_critical = 15u32;
    let penalty_per_warning = 5u32;

    let mut penalty = 0u32;
    for issue in report
        .weak_passwords
        .iter()
        .chain(report.duplicate_passwords.iter())
        .chain(report.old_passwords.iter())
        .chain(report.short_passwords.iter())
    {
        match issue.severity {
            Severity::Critical => penalty += penalty_per_critical,
            Severity::Warning => penalty += penalty_per_warning,
            Severity::Info => penalty += 1,
        }
    }

    report.score = 100u32.saturating_sub(penalty);

    report
}

fn check_weak_passwords(entries: &[VaultEntry], report: &mut AuditReport) {
    for entry in entries {
        let pw = &entry.password;

        let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = pw.chars().any(|c| c.is_ascii_digit());
        let has_symbol = pw.chars().any(|c| !c.is_ascii_alphanumeric());
        let variety = [has_lower, has_upper, has_digit, has_symbol]
            .iter()
            .filter(|&&v| v)
            .count();

        if variety <= 1 {
            report.weak_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Critical,
                description: "Password uses only one character type".to_string(),
            });
        } else if variety == 2 {
            report.weak_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Warning,
                description: "Password uses only two character types".to_string(),
            });
        }

        // Check for common patterns
        let lower = pw.to_lowercase();
        let common = [
            "password", "123456", "qwerty", "admin", "letmein", "welcome",
            "monkey", "dragon", "master", "abc123", "login", "princess",
        ];
        for pattern in &common {
            if lower.contains(pattern) {
                report.weak_passwords.push(AuditIssue {
                    entry_name: entry.name.clone(),
                    severity: Severity::Critical,
                    description: format!("Password contains common pattern: '{pattern}'"),
                });
                break;
            }
        }
    }
}

fn check_duplicate_passwords(entries: &[VaultEntry], report: &mut AuditReport) {
    let mut seen: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for entry in entries {
        let hash = hex::encode(Sha256::digest(entry.password.as_bytes()));
        seen.entry(hash)
            .or_default()
            .push(entry.name.clone());
    }

    for (_hash, names) in &seen {
        if names.len() > 1 {
            for name in names {
                report.duplicate_passwords.push(AuditIssue {
                    entry_name: name.clone(),
                    severity: Severity::Critical,
                    description: format!(
                        "Password reused across {} entries: {}",
                        names.len(),
                        names.join(", ")
                    ),
                });
            }
        }
    }
}

fn check_old_passwords(entries: &[VaultEntry], report: &mut AuditReport) {
    let now = chrono::Utc::now();
    let ninety_days = chrono::Duration::days(90);
    let one_year = chrono::Duration::days(365);

    for entry in entries {
