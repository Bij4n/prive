//! Password health report.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::entry::Entry;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Issue {
    /// zxcvbn strength 0-2 out of 4.
    Weak { score: u8 },
    /// The same password is used by this many other entries.
    Reused { with: usize },
}

#[derive(Debug)]
pub struct Finding {
    pub path: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct Report {
    pub checked: usize,
    pub findings: Vec<Finding>,
}

pub fn audit(entries: &[Entry]) -> Report {
    // Compare hashes, not the passwords themselves, so no extra plaintext copies pile up.
    let mut by_password: HashMap<[u8; 32], usize> = HashMap::new();
    for e in entries {
        *by_password.entry(fingerprint(&e.password)).or_default() += 1;
    }

    let mut findings = Vec::new();
    for e in entries {
        let mut issues = Vec::new();
        let score = zxcvbn::zxcvbn(&e.password, &[]).score() as u8;
        if score < 3 {
            issues.push(Issue::Weak { score });
        }
        let same = by_password[&fingerprint(&e.password)];
        if same > 1 {
            issues.push(Issue::Reused { with: same - 1 });
        }
        if !issues.is_empty() {
            findings.push(Finding {
                path: e.path(),
                issues,
            });
        }
    }
    Report {
        checked: entries.len(),
        findings,
    }
}

fn fingerprint(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    pub(super) fn entry(title: &str, pw: &str) -> Entry {
        Entry {
            uuid: title.into(),
            title: title.into(),
            username: "me".into(),
            password: Zeroizing::new(pw.into()),
            ..Entry::default()
        }
    }

    #[test]
    fn flags_weak_passwords_only() {
        let r = audit(&[entry("a", "password1"), entry("b", "kH3@pN8%sJ5*eB1(cG7)")]);
        assert_eq!(r.checked, 2);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].path, "a");
        assert!(matches!(r.findings[0].issues[0], Issue::Weak { .. }));
    }

    #[test]
    fn flags_reuse_on_every_entry_involved() {
        let strong = "vX7#qL9!mZ2$wR4^tY6&";
        let r = audit(&[entry("a", strong), entry("b", strong), entry("c", strong)]);
        assert_eq!(r.findings.len(), 3);
        for f in &r.findings {
            assert_eq!(f.issues, vec![Issue::Reused { with: 2 }]);
        }
    }
}
