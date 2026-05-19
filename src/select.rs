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
    fn not_found() {
        let e = sample();
        assert!(matches!(select(&e, "nope"), Err(Failure::NotFound(_))));
        assert!(matches!(select(&e, "uuid:zz"), Err(Failure::NotFound(_))));
    }
}
