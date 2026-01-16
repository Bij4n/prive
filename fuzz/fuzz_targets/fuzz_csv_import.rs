#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Should not panic on any input
        let _ = prive::vault::import::import_csv(s);
    }
});
