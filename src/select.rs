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
    if query.trim().is_empty() {
        return Err(Failure::NotFound(query.to_string()));
    }
    if let Some(uuid) = query.strip_prefix("uuid:") {
        let wanted = normalize_uuid(uuid);
        if wanted.is_empty() {
            return Err(Failure::NotFound(query.to_string()));
        }
        return entries
            .iter()
            .find(|e| normalize_uuid(&e.uuid) == wanted)
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
        0 => Err(Failure::NoSuchEntry {
            query: query.to_string(),
            close: suggestions(entries, query),
        }),
        _ => Err(ambiguous(query, &by_title)),
    }
}

/// Edit distance between two strings by characters, counting a swap of two neighbours as one
/// edit (optimal string alignment), since that is the most common typing slip.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[n][m]
}

/// Up to three entry paths that look like a misspelling of `query`, closest first.
pub fn suggestions(entries: &[Entry], query: &str) -> Vec<String> {
    let q = query.trim_start_matches('/').to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let limit = (q.chars().count() / 3).max(1);
    let mut scored: Vec<(usize, String)> = entries
        .iter()
        .filter_map(|e| {
            let by_path = distance(&q, &e.path().to_lowercase());
            let by_title = distance(&q, &e.title.to_lowercase());
            let d = by_path.min(by_title);
            (d <= limit).then(|| (d, e.path()))
        })
        .collect();
    scored.sort();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(3).map(|(_, p)| p).collect()
}

/// UUIDs compare as bare lower-case hex: KeePassXC shows `{ab3be06b-edf0-...}`, other tools
/// print them without braces or dashes.
fn normalize_uuid(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
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

/// Entries carrying `tag`, ignoring case.
pub fn with_tag<'a>(entries: &[&'a Entry], tag: &str) -> Vec<&'a Entry> {
    entries
        .iter()
        .copied()
        .filter(|e| e.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
        .collect()
}

/// Every tag in use and how many entries carry it, most used first, then by name. Tags that
/// differ only in case are counted together under their most common spelling.
pub fn tag_counts(entries: &[Entry]) -> Vec<(String, usize)> {
    use std::collections::HashMap;
    let mut by_key: HashMap<String, (usize, HashMap<&str, usize>)> = HashMap::new();
    for e in entries {
        for t in &e.tags {
            let slot = by_key.entry(t.to_lowercase()).or_default();
            slot.0 += 1;
            *slot.1.entry(t.as_str()).or_default() += 1;
        }
    }
    let mut out: Vec<(String, usize)> = by_key
        .into_values()
        .map(|(n, spellings)| {
            let name = spellings
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(s, _)| s.to_string())
                .unwrap_or_default();
            (name, n)
        })
        .collect();
    out.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });
    out
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
        assert!(matches!(
            select(&e, "nope"),
            Err(Failure::NoSuchEntry { .. })
        ));
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

    #[test]
    fn uuids_in_any_common_spelling() {
        let e = vec![entry("", "Bank", "ab3be06b-edf0-4d6d-9274-4ec75b5c5f4c")];
        for q in [
            "uuid:ab3be06b-edf0-4d6d-9274-4ec75b5c5f4c",
            "uuid:{AB3BE06B-EDF0-4D6D-9274-4EC75B5C5F4C}",
            "uuid:ab3be06bedf04d6d92744ec75b5c5f4c",
        ] {
            assert_eq!(select(&e, q).unwrap().title, "Bank", "{q}");
        }
    }

    #[test]
    fn empty_names_match_nothing() {
        let mut e = sample();
        e.push(entry("", "", "d")); // an untitled entry at the root
        assert!(matches!(select(&e, ""), Err(Failure::NotFound(_))));
        assert!(matches!(select(&e, "  "), Err(Failure::NotFound(_))));
        assert!(matches!(select(&e, "uuid:"), Err(Failure::NotFound(_))));
    }

    #[test]
    fn an_empty_search_lists_everything() {
        let e = sample();
        assert_eq!(search(&e, "").len(), e.len());
    }

    #[test]
    fn suggests_close_names() {
        let e = sample();
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("bnak", "bank"), 1);
        assert_eq!(suggestions(&e, "Bnak"), ["Bank"]);
        assert_eq!(suggestions(&e, "work/githb"), ["Work/GitHub"]);
        assert!(suggestions(&e, "completely different").is_empty());
        assert!(suggestions(&e, "").is_empty());
    }

    #[test]
    fn tag_filter_is_exact_but_ignores_case() {
        let mut e = sample();
        e[0].tags = vec!["Cloud".into(), "dev".into()];
        e[1].tags = vec!["cloudy".into()];
        let all: Vec<&Entry> = e.iter().collect();
        let hits = with_tag(&all, "cloud");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].uuid, "a");
    }

    #[test]
    fn tags_are_counted_case_insensitively() {
        let mut e = sample();
        e[0].tags = vec!["Cloud".into(), "dev".into()];
        e[1].tags = vec!["cloud".into()];
        e[2].tags = vec!["Cloud".into(), "bank".into()];
        assert_eq!(
            tag_counts(&e),
            [
                ("Cloud".to_string(), 3),
                ("bank".to_string(), 1),
                ("dev".to_string(), 1)
            ]
        );
        assert!(tag_counts(&[]).is_empty());
    }

    #[test]
    fn non_ascii_names_match_without_case() {
        let e = vec![entry("Büro", "Ärztekammer", "x"), entry("", "ÉCOLE", "y")];
        assert_eq!(select(&e, "büro/ärztekammer").unwrap().uuid, "x");
        assert_eq!(select(&e, "école").unwrap().uuid, "y");
        assert_eq!(search(&e, "ärzte").len(), 1);
    }
}
