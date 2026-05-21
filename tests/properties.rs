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
