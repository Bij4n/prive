//! Turning what the user typed into exactly one entry.
//!
//! Accepted forms, tried in order:
//! - `uuid:<uuid>`
//! - a full path, `Group/Sub/Title` (a leading `/` is ignored)
//! - a title, if exactly one entry has it
//!
//! Comparisons ignore case. There is no fuzzy guessing here: `pick` is the fuzzy way in.

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
    if let Some(e) = entries.iter().find(|e| e.path().to_lowercase() == wanted) {
        return Ok(e);
    }
    entries
        .iter()
        .find(|e| e.title.to_lowercase() == wanted)
        .ok_or_else(|| Failure::NotFound(query.to_string()))
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
        vec![entry("Work", "GitHub", "a"), entry("", "Bank", "c")]
    }

    #[test]
    fn title_path_and_uuid() {
        let e = sample();
        assert_eq!(select(&e, "bank").unwrap().uuid, "c");
        assert_eq!(select(&e, "/work/github").unwrap().uuid, "a");
        assert_eq!(select(&e, "uuid:C").unwrap().title, "Bank");
    }

    #[test]
    fn not_found() {
        let e = sample();
        assert!(matches!(select(&e, "nope"), Err(Failure::NotFound(_))));
        assert!(matches!(select(&e, "uuid:zz"), Err(Failure::NotFound(_))));
    }
}
