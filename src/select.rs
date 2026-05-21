//! Turning what the user typed into exactly one entry.
//!
//! Accepted forms, tried in order:
//! - `uuid:<uuid>`
//! - a full path, `Group/Sub/Title` (a leading `/` is ignored)
//! - a title, if exactly one entry has it
//!
//! Comparisons ignore case. Several matches fail with the candidates listed; none fails with
//! "not found". There is no fuzzy guessing here: `pick` is the fuzzy way in.

use crate::entry::Entry;
use crate::error::Failure;

pub fn select<'a>(entries: &'a [Entry], query: &str) -> Result<&'a Entry, Failure> {
    if let Some(uuid) = query.strip_prefix("uuid:") {
        return entries
            .iter()
            .find(|e| e.uuid.eq_ignore_ascii_case(uuid.trim()))
            .ok_or_else(|| Failure::NotFound(query.to_string()));
    }
    let wanted = query.trim_start_matches('/').to_lowercase();

    let by_path: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.path().to_lowercase() == wanted)
        .collect();
    match by_path.len() {
        1 => return Ok(by_path[0]),
        n if n > 1 => return Err(ambiguous(query, &by_path)),
        _ => {}
    }

    let by_title: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.title.to_lowercase() == wanted)
        .collect();
    match by_title.len() {
        1 => Ok(by_title[0]),
        0 => Err(Failure::NotFound(query.to_string())),
        _ => Err(ambiguous(query, &by_title)),
    }
}

fn ambiguous(query: &str, matches: &[&Entry]) -> Failure {
    Failure::Ambiguous {
        query: query.to_string(),
        candidates: matches
            .iter()
            .map(|e| format!("{}  (uuid:{})", e.path(), e.uuid))
            .collect(),
    }
}

/// Entries in `group` or any group below it, ignoring case. A leading or trailing `/` is ignored.
pub fn in_group<'a>(entries: &'a [Entry], group: &str) -> Vec<&'a Entry> {
    let g = group.trim_matches('/').to_lowercase();
    if g.is_empty() {
        return entries.iter().collect();
    }
    entries
        .iter()
        .filter(|e| {
            let eg = e.group.to_lowercase();
            eg == g || eg.starts_with(&format!("{g}/"))
        })
        .collect()
}

/// Case-insensitive substring search over the path (group and title), username, URL and tags.
/// Titles that match exactly come first, then titles that start with the query, then the rest;
/// within each, the original order is kept.
pub fn search<'a>(entries: &'a [Entry], query: &str) -> Vec<&'a Entry> {
    let q = query.to_lowercase();
    let mut hits: Vec<&Entry> = entries
        .iter()
        .filter(|e| {
            e.path().to_lowercase().contains(&q)
                || e.username.to_lowercase().contains(&q)
                || e.url.to_lowercase().contains(&q)
                || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .collect();
    hits.sort_by_key(|e| {
        let t = e.title.to_lowercase();
        if t == q {
            0
        } else if t.starts_with(&q) {
            1
        } else {
            2
        }
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(group: &str, title: &str, uuid: &str) -> Entry {
        Entry {
            uuid: uuid.into(),
            group: group.into(),
            title: title.into(),
            ..Entry::default()
        }
    }

    fn sample() -> Vec<Entry> {
        vec![
            entry("Work", "GitHub", "a"),
            entry("Personal", "GitHub", "b"),
            entry("", "Bank", "c"),
        ]
    }

    #[test]
    fn title_path_and_uuid() {
        let e = sample();
        assert_eq!(select(&e, "bank").unwrap().uuid, "c");
        assert_eq!(select(&e, "/work/github").unwrap().uuid, "a");
        assert_eq!(select(&e, "uuid:C").unwrap().title, "Bank");
    }

    #[test]
    fn duplicate_titles_are_ambiguous_until_a_path_is_given() {
        let e = sample();
        match select(&e, "GitHub") {
            Err(Failure::Ambiguous { candidates, .. }) => {
                assert_eq!(candidates.len(), 2);
                assert!(candidates.iter().any(|c| c.starts_with("Work/GitHub")));
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        assert_eq!(select(&e, "Personal/GitHub").unwrap().uuid, "b");
    }

    #[test]
    fn search_covers_groups_urls_and_tags() {
        let mut e = sample();
        e[2].url = "https://bank.example".into();
        e[0].tags = vec!["Cloud".into()];
        assert_eq!(search(&e, "github").len(), 2);
        assert_eq!(search(&e, "WORK").len(), 1);
        assert_eq!(search(&e, "example").len(), 1);
        assert_eq!(search(&e, "cloud").len(), 1);
        assert!(search(&e, "zzz").is_empty());
    }

    #[test]
    fn not_found() {
        let e = sample();
        assert!(matches!(select(&e, "nope"), Err(Failure::NotFound(_))));
        assert!(matches!(select(&e, "uuid:zz"), Err(Failure::NotFound(_))));
    }

    #[test]
    fn exact_and_prefix_title_matches_come_first() {
        let e = vec![
            entry("Old", "my-github-backup", "1"),
            entry("Work", "github-enterprise", "2"),
            entry("", "GitHub", "3"),
        ];
        let order: Vec<&str> = search(&e, "github")
            .iter()
            .map(|e| e.uuid.as_str())
            .collect();
        assert_eq!(order, ["3", "2", "1"]);
    }

    #[test]
    fn groups_include_their_subgroups_only() {
        let e = vec![
            entry("Work", "a", "1"),
            entry("Work/Cloud", "b", "2"),
            entry("Workshop", "c", "3"),
            entry("", "d", "4"),
        ];
        let ids = |v: Vec<&Entry>| v.iter().map(|e| e.uuid.clone()).collect::<Vec<_>>();
        assert_eq!(ids(in_group(&e, "work")), ["1", "2"]);
        assert_eq!(ids(in_group(&e, "/Work/Cloud/")), ["2"]);
        assert_eq!(in_group(&e, "").len(), 4);
    }
}
