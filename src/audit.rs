//! Password health report.
//!
//! Entries the user excluded from reports in KeePassXC ("Exclude from database reports") are
//! skipped, as are entries with no password and entries whose password refers to another
//! entry's.

use std::collections::HashMap;

use chrono::{NaiveDateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::entry::Entry;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Issue {
    /// Found this many times in known breaches.
    Breached { count: u64 },
    /// zxcvbn strength 0-2 out of 4.
    Weak { score: u8 },
    /// The same password is used by this many other entries.
    Reused { with: usize },
    /// Past its expiry date.
    Expired,
    /// Not changed for this many days.
    Old { days: i64 },
}

impl Report {
    /// No entry needs attention.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl Issue {
    pub fn describe(&self) -> String {
        match self {
            Issue::Breached { count } => format!("found in {count} breaches (Have I Been Pwned)"),
            Issue::Weak { score } => format!("weak (strength {score}/4)"),
            Issue::Reused { with: 1 } => "reused by 1 other entry".to_string(),
            Issue::Reused { with } => format!("reused by {with} other entries"),
            Issue::Expired => "expired".to_string(),
            Issue::Old { days } => format!("not changed for {days} days"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub checked: usize,
    pub skipped: usize,
    pub findings: Vec<Finding>,
}

pub struct Options {
    /// Flag passwords not changed for more than this many days; 0 turns the check off.
    pub max_age_days: i64,
    /// Look each password up in Have I Been Pwned (see `hibp`). Off by default: it is the
    /// only part of prive that talks to the network.
    pub breach_check: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_age_days: 365,
            breach_check: false,
        }
    }
}

pub fn audit(entries: &[Entry], opts: &Options) -> anyhow::Result<Report> {
    let now = Utc::now().naive_utc();
    // An entry whose password is a reference to another entry's ({REF:P@...}) is checked
    // through that other entry, as KeePassXC does; counting it again would flag every shared
    // password as reused.
    let checked: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.quality_check && !e.password.is_empty() && !e.password.contains("{REF:"))
        .collect();
    // Compare hashes, not the passwords themselves, so no extra plaintext copies pile up.
    let mut by_password: HashMap<[u8; 32], usize> = HashMap::new();
    for e in &checked {
        *by_password.entry(fingerprint(&e.password)).or_default() += 1;
    }

    let mut breach_cache = HashMap::new();
    let mut findings = Vec::new();
    for (n, e) in checked.iter().enumerate() {
        let mut issues = Vec::new();
        if opts.breach_check {
            // A big database takes a while against the network; say how far along it is.
            if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
                eprint!("\rChecking Have I Been Pwned: {}/{}", n + 1, checked.len());
            }
            let count = crate::hibp::breach_count(&e.password, &mut breach_cache)?;
            if count > 0 {
                issues.push(Issue::Breached { count });
            }
        }
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
        if opts.max_age_days > 0
            && let Some(days) = age_days(e.modified, now)
            && days > opts.max_age_days
        {
            issues.push(Issue::Old { days });
        }
        if !issues.is_empty() {
            issues.sort();
            findings.push(Finding {
                path: e.path(),
                issues,
            });
        }
    }
    if opts.breach_check && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        eprintln!();
    }
    // Worst first: breached, then weak, reused, expired, old; ties by path.
    findings.sort_by(|a, b| {
        a.issues[0]
            .cmp(&b.issues[0])
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(Report {
        checked: checked.len(),
        skipped: entries.len() - checked.len(),
        findings,
    })
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
        )
        .unwrap();
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
        )
        .unwrap();
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
        let r = audit(&[old, fresh], &Options::default()).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].issues, vec![Issue::Old { days: 400 }]);
        let strict = audit(
            &r_entries(),
            &Options {
                max_age_days: 1,
                ..Options::default()
            },
        )
        .unwrap();
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
        let r = audit(&[gone, later], &Options::default()).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].issues, vec![Issue::Expired]);
    }

    #[test]
    fn excluded_and_empty_entries_are_skipped() {
        let mut excluded = entry("x", "123");
        excluded.quality_check = false;
        let r = audit(&[excluded, entry("y", "")], &Options::default()).unwrap();
        assert_eq!((r.checked, r.skipped), (0, 2));
        assert!(r.findings.is_empty());
    }

    #[test]
    fn passwords_made_from_the_entry_itself_are_weak() {
        let mut e = entry("Spotify", "SpotifyMe2026");
        e.username = "me2026".into();
        let r = audit(&[e], &Options::default()).unwrap();
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

    #[test]
    fn worst_findings_come_first() {
        let strong = "vX7#qL9!mZ2$wR4^tY6&";
        let mut old = entry("aaa-old", "kH3@pN8%sJ5*eB1(cG7)");
        old.modified = Some(Utc::now().naive_utc() - chrono::Duration::days(800));
        let r = audit(
            &[
                old,
                entry("zzz-weak", "password1"),
                entry("m1", strong),
                entry("m2", strong),
            ],
            &Options::default(),
        )
        .unwrap();
        let order: Vec<&str> = r.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(order, ["zzz-weak", "m1", "m2", "aaa-old"]);
    }

    #[test]
    fn a_strong_unique_set_is_clean() {
        let r = audit(
            &[
                entry("a", "vX7#qL9!mZ2$wR4^tY6&"),
                entry("b", "kH3@pN8%sJ5*eB1(cG7)"),
            ],
            &Options::default(),
        )
        .unwrap();
        assert!(r.is_clean());
    }

    #[test]
    fn age_check_can_be_turned_off() {
        let mut old = entry("old", "vX7#qL9!mZ2$wR4^tY6&");
        old.modified = Some(Utc::now().naive_utc() - chrono::Duration::days(5000));
        let off = Options {
            max_age_days: 0,
            ..Options::default()
        };
        assert!(audit(&[old], &off).unwrap().is_clean());
    }

    #[test]
    fn a_referenced_password_is_not_counted_twice() {
        let target = entry("Bank", "vX7#qL9!mZ2$wR4^tY6&");
        let mut shared = entry("Shared", "{REF:P@T:Bank}");
        shared.uuid = "s".into();
        let r = audit(&[target, shared], &Options::default()).unwrap();
        assert_eq!((r.checked, r.skipped), (1, 1));
        assert!(r.is_clean());
    }
}
