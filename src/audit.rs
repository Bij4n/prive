//! Password health report.
//!
//! Entries the user excluded from reports in KeePassXC ("Exclude from database reports") are
//! skipped, as are entries with no password.

use std::collections::HashMap;

use chrono::{NaiveDateTime, Utc};
use sha2::{Digest, Sha256};

use crate::entry::Entry;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Issue {
    /// zxcvbn strength 0-2 out of 4.
    Weak { score: u8 },
    /// The same password is used by this many other entries.
    Reused { with: usize },
    /// Past its expiry date.
    Expired,
    /// Not changed for this many days.
    Old { days: i64 },
}

impl Issue {
    pub fn describe(&self) -> String {
        match self {
            Issue::Weak { score } => format!("weak (strength {score}/4)"),
            Issue::Reused { with: 1 } => "reused by 1 other entry".to_string(),
            Issue::Reused { with } => format!("reused by {with} other entries"),
            Issue::Expired => "expired".to_string(),
            Issue::Old { days } => format!("not changed for {days} days"),
        }
    }
}

#[derive(Debug)]
pub struct Finding {
    pub path: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug)]
pub struct Report {
    pub checked: usize,
    pub skipped: usize,
    pub findings: Vec<Finding>,
}

pub struct Options {
    /// Flag passwords not changed for more than this many days.
    pub max_age_days: i64,
}

impl Default for Options {
    fn default() -> Self {
        Options { max_age_days: 365 }
    }
}

pub fn audit(entries: &[Entry], opts: &Options) -> Report {
    let now = Utc::now().naive_utc();
    let checked: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.quality_check && !e.password.is_empty())
        .collect();
    // Compare hashes, not the passwords themselves, so no extra plaintext copies pile up.
    let mut by_password: HashMap<[u8; 32], usize> = HashMap::new();
    for e in &checked {
        *by_password.entry(fingerprint(&e.password)).or_default() += 1;
    }

    let mut findings = Vec::new();
    for e in &checked {
        let mut issues = Vec::new();
        // A password built from the site name or username is weaker than it looks.
        let hints = [e.title.as_str(), e.username.as_str(), e.url.as_str()];
        let score = zxcvbn::zxcvbn(&e.password, &hints).score() as u8;
        if score < 3 {
            issues.push(Issue::Weak { score });
        }
        let same = by_password[&fingerprint(&e.password)];
        if same > 1 {
            issues.push(Issue::Reused { with: same - 1 });
        }
        if let Some(exp) = e.expires
            && exp < now
        {
            issues.push(Issue::Expired);
        }
        if let Some(days) = age_days(e.modified, now)
            && days > opts.max_age_days
        {
            issues.push(Issue::Old { days });
        }
        if !issues.is_empty() {
            findings.push(Finding {
                path: e.path(),
                issues,
            });
        }
    }
    Report {
        checked: checked.len(),
        skipped: entries.len() - checked.len(),
        findings,
    }
}

fn age_days(modified: Option<NaiveDateTime>, now: NaiveDateTime) -> Option<i64> {
    modified.map(|m| (now - m).num_days())
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
        let r = audit(
            &[entry("a", "password1"), entry("b", "kH3@pN8%sJ5*eB1(cG7)")],
            &Options::default(),
        );
        assert_eq!(r.checked, 2);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].path, "a");
        assert!(matches!(r.findings[0].issues[0], Issue::Weak { .. }));
    }

    #[test]
    fn flags_reuse_on_every_entry_involved() {
        let strong = "vX7#qL9!mZ2$wR4^tY6&";
        let r = audit(
            &[entry("a", strong), entry("b", strong), entry("c", strong)],
            &Options::default(),
        );
        assert_eq!(r.findings.len(), 3);
        for f in &r.findings {
            assert_eq!(f.issues, vec![Issue::Reused { with: 2 }]);
        }
    }

    #[test]
    fn flags_old_passwords() {
        let mut old = entry("old", "vX7#qL9!mZ2$wR4^tY6&");
        old.modified = Some(Utc::now().naive_utc() - chrono::Duration::days(400));
        let mut fresh = entry("fresh", "kH3@pN8%sJ5*eB1(cG7)");
        fresh.modified = Some(Utc::now().naive_utc() - chrono::Duration::days(3));
        let r = audit(&[old, fresh], &Options::default());
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].issues, vec![Issue::Old { days: 400 }]);
        let strict = audit(&r_entries(), &Options { max_age_days: 1 });
        assert_eq!(strict.findings.len(), 1);
    }

    fn r_entries() -> Vec<Entry> {
        let mut e = entry("x", "kH3@pN8%sJ5*eB1(cG7)");
        e.modified = Some(Utc::now().naive_utc() - chrono::Duration::days(3));
        vec![e]
    }

    #[test]
    fn flags_expired_entries() {
        let mut gone = entry("gone", "kH3@pN8%sJ5*eB1(cG7)");
        gone.expires = Some(Utc::now().naive_utc() - chrono::Duration::days(1));
        let mut later = entry("later", "vX7#qL9!mZ2$wR4^tY6&");
        later.expires = Some(Utc::now().naive_utc() + chrono::Duration::days(30));
        let r = audit(&[gone, later], &Options::default());
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].issues, vec![Issue::Expired]);
    }

    #[test]
    fn excluded_and_empty_entries_are_skipped() {
        let mut excluded = entry("x", "123");
        excluded.quality_check = false;
        let r = audit(&[excluded, entry("y", "")], &Options::default());
        assert_eq!((r.checked, r.skipped), (0, 2));
        assert!(r.findings.is_empty());
    }

    #[test]
    fn passwords_made_from_the_entry_itself_are_weak() {
        let mut e = entry("Spotify", "SpotifyMe2026");
        e.username = "me2026".into();
        let r = audit(&[e], &Options::default());
        assert!(matches!(r.findings[0].issues[0], Issue::Weak { .. }));
    }

    #[test]
    fn issues_read_as_plain_english() {
        assert_eq!(Issue::Weak { score: 1 }.describe(), "weak (strength 1/4)");
        assert_eq!(
            Issue::Reused { with: 1 }.describe(),
            "reused by 1 other entry"
        );
        assert_eq!(
            Issue::Reused { with: 3 }.describe(),
            "reused by 3 other entries"
        );
        assert_eq!(
            Issue::Old { days: 400 }.describe(),
            "not changed for 400 days"
        );
    }
}
