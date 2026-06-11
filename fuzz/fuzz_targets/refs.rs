//! Field references over arbitrary text and entries: never a panic, always an answer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prive::entry::Entry;

fuzz_target!(|input: (String, Vec<(String, String)>)| {
    let (value, raw) = input;
    let entries: Vec<Entry> = raw
        .into_iter()
        .take(16)
        .enumerate()
        .map(|(i, (title, password))| Entry {
            uuid: format!("{i:032x}"),
            title,
            password: zeroize::Zeroizing::new(password),
            ..Entry::default()
        })
        .collect();
    let _ = prive::refs::resolve(&entries, &value);
});
