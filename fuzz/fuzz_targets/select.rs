//! Entry selection and search over arbitrary names and queries: never a panic, and whatever
//! `select` returns really carries the name that was asked for.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prive::entry::Entry;
use prive::select::{in_group, search, select, suggestions};

fuzz_target!(|input: (Vec<(String, String)>, String)| {
    let (names, query) = input;
    let entries: Vec<Entry> = names
        .into_iter()
        .take(32)
        .enumerate()
        .map(|(i, (group, title))| Entry {
            uuid: format!("{i:032x}"),
            group,
            title,
            ..Entry::default()
        })
        .collect();
    if let Ok(e) = select(&entries, &query) {
        let q = query.trim_start_matches('/').to_lowercase();
        let ok = q.starts_with("uuid:")
            || query.starts_with("uuid:")
            || e.path().to_lowercase() == q
            || e.title.to_lowercase() == q;
        assert!(ok, "select returned {:?} for {query:?}", e.path());
    }
    let _ = search(&entries, &query);
    let _ = in_group(&entries, &query);
    let _ = suggestions(&entries, &query);
});
