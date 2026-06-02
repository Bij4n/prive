//! otpauth URIs and base32 secrets from arbitrary text: never a panic, and any code produced
//! has the shape its settings promise.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prive::otp::{Encoder, decode_base32, parse_otpauth};

fuzz_target!(|text: &str| {
    let _ = decode_base32(text);
    for uri in [text.to_string(), format!("otpauth://totp/x?{text}")] {
        if let Some(t) = parse_otpauth(&uri) {
            let code = t.code_at(1_700_000_000);
            match t.encoder {
                Encoder::Digits(d) => assert_eq!(code.len(), d as usize),
                Encoder::Steam => assert_eq!(code.len(), 5),
            }
        }
    }
});
