//! Password health report.

use crate::entry::Entry;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Issue {
    /// zxcvbn strength 0-2 out of 4.
    Weak { score: u8 },
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
    let mut findings = Vec::new();
    for e in entries {
        let mut issues = Vec::new();
        let score = zxcvbn::zxcvbn(&e.password, &[]).score() as u8;
        if score < 3 {
            issues.push(Issue::Weak { score });
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
}
