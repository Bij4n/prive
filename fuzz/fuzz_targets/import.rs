//! Every importer over arbitrary text: never a panic, and a one-time code that comes out is
//! always one prive can read.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prive::import::Format;

fuzz_target!(|text: &str| {
    // Every format there is, so a new one is fuzzed from the start.
    for format in Format::ALL {
        if let Ok((records, _)) = format.parse(text, &[]) {
            for r in &records {
                if let Some(uri) = &r.otp {
                    assert!(prive::otp::parse_otpauth(uri).is_some());
                }
            }
        }
    }
    let _ = Format::detect(text);
});
