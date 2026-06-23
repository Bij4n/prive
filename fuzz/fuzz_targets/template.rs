//! `get --format` templates over arbitrary text and entries: never a panic, and text with no
//! braces comes back unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prive::entry::{CustomField, Entry};

fuzz_target!(|input: (String, String, String, Vec<(String, String)>)| {
    let (template, username, password, fields) = input;
    let e = Entry {
        uuid: "0".repeat(32),
        title: "T".into(),
        username,
        password: zeroize::Zeroizing::new(password),
        custom: fields
            .into_iter()
            .take(8)
            .map(|(name, value)| CustomField {
                name,
                value: zeroize::Zeroizing::new(value),
                protected: true,
            })
            .collect(),
        ..Entry::default()
    };
    let all = [e];
    match prive::template::render(&template, &all[0], &all) {
        Ok(out) if !template.contains('{') => assert_eq!(*out, template),
        _ => {}
    }
});
