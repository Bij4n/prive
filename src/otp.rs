//! Time-based one-time passwords (RFC 6238).

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("period", &self.period)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

macro_rules! hmac_digest {
    ($hash:ty, $key:expr, $msg:expr) => {{
        let mut mac =
            <Hmac<$hash> as Mac>::new_from_slice($key).expect("HMAC accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

impl Totp {
    /// `None` for an empty secret, a zero period, or fewer than 4 / more than 10 digits.
    pub fn new(secret: Vec<u8>, period: u64, digits: u32, algorithm: Algorithm) -> Option<Totp> {
        if secret.is_empty() || period == 0 || !(4..=10).contains(&digits) {
            return None;
        }
        Some(Totp {
            secret: Zeroizing::new(secret),
            period,
            digits,
            algorithm,
        })
    }

    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = (unix_time / self.period).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac_digest!(sha1::Sha1, &self.secret, &counter),
            Algorithm::Sha256 => hmac_digest!(sha2::Sha256, &self.secret, &counter),
            Algorithm::Sha512 => hmac_digest!(sha2::Sha512, &self.secret, &counter),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let value = (u32::from(digest[offset]) & 0x7f) << 24
            | u32::from(digest[offset + 1]) << 16
            | u32::from(digest[offset + 2]) << 8
            | u32::from(digest[offset + 3]);
        let code = u64::from(value) % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], alg: Algorithm) -> Totp {
        Totp::new(secret.to_vec(), 30, 8, alg).unwrap()
    }

    // RFC 6238 appendix B test vectors.
    #[test]
    fn rfc6238_vectors() {
        let s1 = b"12345678901234567890";
        let s256 = b"12345678901234567890123456789012";
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in cases {
            assert_eq!(rfc(s1, Algorithm::Sha1).code_at(t), c1, "sha1 t={t}");
            assert_eq!(
                rfc(s256, Algorithm::Sha256).code_at(t),
                c256,
                "sha256 t={t}"
            );
            assert_eq!(
                rfc(s512, Algorithm::Sha512).code_at(t),
                c512,
                "sha512 t={t}"
            );
        }
    }

    #[test]
    fn rejects_impossible_parameters() {
        assert!(Totp::new(vec![], 30, 6, Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 0, 6, Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 30, 3, Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 30, 11, Algorithm::Sha1).is_none());
    }
}
