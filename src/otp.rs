//! Time-based one-time passwords (RFC 6238).
//!
//! The secret comes from the entry's `otp` field, holding an `otpauth://totp/...` URI as
//! KeePassXC, KeePassDX and Strongbox store it.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::entry::Entry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoder {
    Digits(u32),
    /// Steam Guard: 5 characters from a 26-letter alphabet.
    Steam,
}

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub period: u64,
    pub encoder: Encoder,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("period", &self.period)
            .field("encoder", &self.encoder)
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
    pub fn new(
        secret: Vec<u8>,
        period: u64,
        encoder: Encoder,
        algorithm: Algorithm,
    ) -> Option<Totp> {
        if secret.is_empty() || period == 0 {
            return None;
        }
        if let Encoder::Digits(d) = encoder
            && !(4..=10).contains(&d)
        {
            return None;
        }
        Some(Totp {
            secret: Zeroizing::new(secret),
            period,
            encoder,
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
        let mut value = (u32::from(digest[offset]) & 0x7f) << 24
            | u32::from(digest[offset + 1]) << 16
            | u32::from(digest[offset + 2]) << 8
            | u32::from(digest[offset + 3]);
        match self.encoder {
            Encoder::Digits(d) => {
                let code = u64::from(value) % 10u64.pow(d);
                format!("{code:0width$}", width = d as usize)
            }
            Encoder::Steam => {
                let mut out = String::with_capacity(5);
                for _ in 0..5 {
                    out.push(STEAM_ALPHABET[value as usize % STEAM_ALPHABET.len()] as char);
                    value /= STEAM_ALPHABET.len() as u32;
                }
                out
            }
        }
    }

    pub fn from_entry(entry: &Entry) -> Option<Totp> {
        let value = entry.field("otp")?.trim();
        if value.is_empty() {
            return None;
        }
        parse_otpauth(value)
    }
}

/// `otpauth://totp/Label?secret=...&period=30&digits=6&algorithm=SHA1`
pub fn parse_otpauth(uri: &str) -> Option<Totp> {
    let rest = uri
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
        .and_then(|_| uri.get(10..))?;
    let (kind, rest) = rest.split_once('/')?;
    if !kind.eq_ignore_ascii_case("totp") {
        return None; // HOTP needs a counter written back after every use.
    }
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut secret = None;
    let mut period = 30;
    let mut digits = 6;
    let mut algorithm = Algorithm::Sha1;
    let mut steam = false;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v),
            "period" => period = v.parse().ok()?,
            "digits" => digits = v.parse().ok()?,
            "algorithm" => algorithm = parse_algorithm(&v)?,
            // KeePassXC writes Steam entries with `encoder=steam`.
            "encoder" => steam = v.eq_ignore_ascii_case("steam"),
            _ => {}
        }
    }
    let encoder = if steam {
        Encoder::Steam
    } else {
        Encoder::Digits(digits)
    };
    Totp::new(decode_base32(&secret?)?, period, encoder, algorithm)
}

fn parse_algorithm(v: &str) -> Option<Algorithm> {
    match v.to_ascii_uppercase().as_str() {
        "SHA1" => Some(Algorithm::Sha1),
        "SHA256" => Some(Algorithm::Sha256),
        "SHA512" => Some(Algorithm::Sha512),
        _ => None,
    }
}

/// Base32 as authenticator apps write it: any case, spaces or dashes, padding optional.
pub fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        return None;
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned).filter(|b| !b.is_empty())
}

fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes
                    .get(i + 1)
                    .copied()
                    .and_then(hex)
                    .zip(bytes.get(i + 2).copied().and_then(hex));
                if let Some((hi, lo)) = pair {
                    out.push(hi << 4 | lo);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], alg: Algorithm) -> Totp {
        Totp::new(secret.to_vec(), 30, Encoder::Digits(8), alg).unwrap()
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
        let d = Encoder::Digits;
        assert!(Totp::new(vec![], 30, d(6), Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 0, d(6), Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 30, d(3), Algorithm::Sha1).is_none());
        assert!(Totp::new(vec![1], 30, d(11), Algorithm::Sha1).is_none());
    }

    #[test]
    fn otpauth_parameters_are_honoured() {
        let t = parse_otpauth(
            "otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60&digits=8&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(
            (t.period, t.encoder, t.algorithm),
            (60, Encoder::Digits(8), Algorithm::Sha256)
        );
    }

    #[test]
    fn otpauth_defaults_case_and_padding() {
        let t = parse_otpauth("OTPAUTH://TOTP/GitHub:demo?secret=JBSWY3DPEHPK3PXP%3D%3D").unwrap();
        assert_eq!(
            (t.period, t.encoder, t.algorithm),
            (30, Encoder::Digits(6), Algorithm::Sha1)
        );
        assert!(parse_otpauth("otpauth://totp/x?secret=jbsw%20y3dp%20ehpk3pxp").is_some());
    }

    #[test]
    fn otpauth_rejects_bad_input() {
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_none());
        assert!(parse_otpauth("otpauth://totp/x?secret=").is_none());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99").is_none());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").is_none());
        assert!(parse_otpauth("https://example.com").is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a+b%2"), "a b%2");
    }

    #[test]
    fn reads_the_otp_field() {
        let e = Entry {
            custom: vec![crate::entry::CustomField {
                name: "otp".into(),
                value: Zeroizing::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                protected: true,
            }],
            ..Entry::default()
        };
        assert_eq!(Totp::from_entry(&e).unwrap().encoder, Encoder::Digits(6));
        assert!(Totp::from_entry(&Entry::default()).is_none());
    }

    #[test]
    fn steam_codes_use_the_steam_alphabet() {
        let t =
            parse_otpauth("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
        assert_eq!(t.encoder, Encoder::Steam);
        for time in [0, 59, 1_700_000_000, 2_000_000_000] {
            let code = t.code_at(time);
            assert_eq!(code.len(), 5);
            assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        }
    }
}
