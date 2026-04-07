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
            "password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon",
            "master", "abc123", "login", "princess",
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
        seen.entry(hash).or_default().push(entry.name.clone());
    }

    for names in seen.values() {
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
        let age = now - entry.modified_at;
        if age > one_year {
            report.old_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Warning,
                description: format!("Password not changed in {} days", age.num_days()),
            });
        } else if age > ninety_days {
            report.old_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Info,
                description: format!("Password is {} days old", age.num_days()),
            });
        }
    }
}

fn check_short_passwords(entries: &[VaultEntry], report: &mut AuditReport) {
    for entry in entries {
        let len = entry.password.len();
        if len < 8 {
            report.short_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Critical,
                description: format!("Password is only {len} characters long"),
            });
        } else if len < 12 {
            report.short_passwords.push(AuditIssue {
                entry_name: entry.name.clone(),
                severity: Severity::Warning,
                description: format!("Password is only {len} characters long (recommended: 12+)"),
            });
        }
    }
}

fn check_reused_usernames(entries: &[VaultEntry], report: &mut AuditReport) {
    let mut seen: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for entry in entries {
        if let Some(username) = &entry.username {
            let lower = username.to_lowercase();
            seen.entry(lower).or_default().push(entry.name.clone());
        }
    }

    for (username, names) in &seen {
        if names.len() > 1 {
            report.reused_usernames.push(AuditIssue {
                entry_name: username.clone(),
                severity: Severity::Info,
                description: format!(
                    "Username used across {} entries: {}",
                    names.len(),
                    names.join(", ")
                ),
            });
        }
    }
}

/// Check if a password has been exposed in data breaches using the
/// Have I Been Pwned API (k-anonymity model — only first 5 chars of SHA-1 hash sent).
pub fn check_breach(password: &str) -> Result<Option<u64>, String> {
    let hash = {
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize()).to_uppercase()
    };

    let prefix = &hash[..5];
    let suffix = &hash[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = reqwest::blocking::Client::new()
        .get(&url)
        .header("User-Agent", "prive-password-manager")
        .send()
        .map_err(|e| format!("HTTP request failed: {e}"))?
        .text()
        .map_err(|e| format!("Failed to read response: {e}"))?;

    for line in response.lines() {
        if let Some((hash_suffix, count_str)) = line.split_once(':')
            && hash_suffix.trim() == suffix
        {
            let count: u64 = count_str.trim().parse().unwrap_or(0);
            return Ok(Some(count));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::VaultEntry;

    fn make_entry(name: &str, password: &str) -> VaultEntry {
        VaultEntry::new(
            name.to_string(),
            Some("user".to_string()),
            password.to_string(),
            None,
            None,
            vec![],
        )
    }

    #[test]
    fn test_audit_empty_vault() {
        let vault = Vault::new();
        let report = audit_vault(&vault);
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.score, 100);
    }

    #[test]
    fn test_audit_weak_password() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("test", "abc"));
        let report = audit_vault(&vault);
        assert!(!report.weak_passwords.is_empty());
        assert!(!report.short_passwords.is_empty());
    }

    #[test]
    fn test_audit_duplicate_passwords() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("site1", "MyP@ssw0rd!234"));
        vault.entries.push(make_entry("site2", "MyP@ssw0rd!234"));
        let report = audit_vault(&vault);
        assert!(!report.duplicate_passwords.is_empty());
    }

    #[test]
    fn test_audit_strong_password() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("secure", "Xk9#mP2$vL7@nQ4!"));
        let report = audit_vault(&vault);
        assert!(report.weak_passwords.is_empty());
        assert!(report.short_passwords.is_empty());
    }

    #[test]
    fn test_audit_common_pattern() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("bad", "password123!A"));
        let report = audit_vault(&vault);
        let has_common = report
            .weak_passwords
            .iter()
            .any(|i| i.description.contains("common pattern"));
        assert!(has_common);
    }

    #[test]
    fn test_audit_short_password() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("short", "Ab1!"));
        let report = audit_vault(&vault);
        let has_short = report
            .short_passwords
            .iter()
            .any(|i| i.severity == Severity::Critical);
        assert!(has_short);
    }

    #[test]
    fn test_audit_score_decreases_with_issues() {
        let mut vault = Vault::new();
        vault.entries.push(make_entry("bad1", "abc"));
        vault.entries.push(make_entry("bad2", "abc"));
        let report = audit_vault(&vault);
        assert!(report.score < 100);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
        assert_eq!(format!("{}", Severity::Warning), "WARNING");
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }
}
