#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Should not panic on any input
        let report = prive::crypto::strength::analyze_strength(s);
        assert!(report.score <= 100);
    }
});
