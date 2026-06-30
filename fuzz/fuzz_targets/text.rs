//! What reaches a terminal or the disk: `visible` never lets a control character through
//! (other than a newline or tab), conflict-copy name matching never panics, and an exported
//! file's path never leaves its directory.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (String, String)| {
    let (text, name) = input;
    let shown = prive::output::visible(&text);
    assert!(
        !shown
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    );
    let _ = prive::sync::is_conflict_copy(&text, &name);
    // An exported file's path never leaves its directory, whatever the entry is called.
    let e = prive::entry::Entry {
        group: text.clone(),
        title: name.clone(),
        ..Default::default()
    };
    let dir = std::path::Path::new("/export");
    let p = prive::export::attachment_path(dir, &e, &text);
    assert!(p.starts_with(dir));
    assert!(p
        .strip_prefix(dir)
        .unwrap()
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_))));
});
