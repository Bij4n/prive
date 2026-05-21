//! Property tests: invariants that must hold for any input.

use prive::otp::{Algorithm, Encoder, Totp};
use proptest::prelude::*;

fn algorithm() -> impl Strategy<Value = Algorithm> {
    prop_oneof![
        Just(Algorithm::Sha1),
        Just(Algorithm::Sha256),
        Just(Algorithm::Sha512)
    ]
}

proptest! {
    #[test]
    fn totp_codes_have_exactly_the_requested_digits(
        secret in prop::collection::vec(any::<u8>(), 1..64),
        digits in 4u32..=10,
        period in 1u64..=300,
        time in any::<u32>(),
        alg in algorithm(),
    ) {
        let t = Totp::new(secret, period, Encoder::Digits(digits), alg).unwrap();
        let code = t.code_at(u64::from(time));
        prop_assert_eq!(code.len(), digits as usize);
        prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn a_code_holds_for_its_whole_period(
        secret in prop::collection::vec(any::<u8>(), 1..32),
        period in 1u64..=120,
        step in 0u64..1_000_000,
    ) {
        let t = Totp::new(secret, period, Encoder::Digits(6), Algorithm::Sha1).unwrap();
        let start = step * period;
        prop_assert_eq!(t.code_at(start), t.code_at(start + period - 1));
    }
}

proptest! {
    #[test]
    fn otpauth_parsing_never_panics(s in ".{0,200}") {
        let _ = prive::otp::parse_otpauth(&s);
        let _ = prive::otp::parse_otpauth(&format!("otpauth://totp/x?{s}"));
        let _ = prive::otp::decode_base32(&s);
    }

    #[test]
    fn base32_round_trips(bytes in prop::collection::vec(any::<u8>(), 1..64)) {
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &bytes);
        prop_assert_eq!(prive::otp::decode_base32(&encoded), Some(bytes.clone()));
        prop_assert_eq!(prive::otp::decode_base32(&encoded.to_lowercase()), Some(bytes));
    }
}
