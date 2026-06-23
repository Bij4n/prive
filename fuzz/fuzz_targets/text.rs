//! What reaches a terminal: `visible` never lets a control character through (other than a
//! newline or tab), and conflict-copy name matching never panics.
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
});
