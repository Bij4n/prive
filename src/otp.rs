//! Time-based one-time passwords (RFC 6238).
//!
//! The secret comes from the entry's `otp` field: an `otpauth://totp/...` URI as KeePassXC,
//! KeePassDX and Strongbox store it, the older KeeOtp form
//! `key=...&step=30&size=6&otpHashMode=sha256`, or a bare base32 secret. Failing that, the
//! KeePass 2.47+ fields `TimeOtp-Secret-Base32` / `-Hex` / `-Base64` / `TimeOtp-Secret`, with
//! `TimeOtp-Length`, `TimeOtp-Period` and `TimeOtp-Algorithm`; then the legacy KeePassXC
//! fields `TOTP Seed` and `TOTP Settings` (`30;6`, or `30;S` for Steam).

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

    /// "6 digits every 30 s, SHA-1", for people.
    pub fn describe(&self) -> String {
        let shape = match self.encoder {
            Encoder::Digits(d) => format!("{d} digits"),
            Encoder::Steam => "Steam Guard".to_string(),
        };
        let alg = match self.algorithm {
            Algorithm::Sha1 => "SHA-1",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha512 => "SHA-512",
        };
        format!("{shape} every {} s, {alg}", self.period)
    }

    /// The current code and how many seconds it stays valid.
    pub fn now(&self) -> (String, u64) {
        let t = unix_now();
        (self.code_at(t), self.period - (t % self.period))
    }

    pub fn from_entry(entry: &Entry) -> Option<Totp> {
        match entry.field("otp").map(str::trim) {
            Some(v) if !v.is_empty() => parse_otp_field(v),
            _ => from_keepass_native(entry).or_else(|| from_legacy_keepassxc(entry)),
        }
    }
}

/// Whether an entry has any of the fields a one-time code is read from, readable or not.
pub fn has_otp_settings(entry: &Entry) -> bool {
    [
        "otp",
        "TimeOtp-Secret-Base32",
        "TimeOtp-Secret-Hex",
        "TimeOtp-Secret-Base64",
        "TimeOtp-Secret",
        "TOTP Seed",
    ]
    .iter()
    .any(|f| entry.field(f).is_some_and(|v| !v.trim().is_empty()))
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_otp_field(value: &str) -> Option<Totp> {
    if value.to_ascii_lowercase().starts_with("otpauth://") {
        return parse_otpauth(value);
    }
    if value.contains("key=") {
        return parse_keeotp(value);
    }
    Totp::new(
        decode_base32(value)?,
        30,
        Encoder::Digits(6),
        Algorithm::Sha1,
    )
}

fn from_keepass_native(entry: &Entry) -> Option<Totp> {
    let secret = if let Some(s) = entry.field("TimeOtp-Secret-Base32") {
        decode_base32(s)?
    } else if let Some(s) = entry.field("TimeOtp-Secret-Hex") {
        hex::decode(s.split_whitespace().collect::<String>()).ok()?
    } else if let Some(s) = entry.field("TimeOtp-Secret-Base64") {
        decode_base64(s)?
    } else {
        entry.field("TimeOtp-Secret")?.as_bytes().to_vec()
    };
    let number = |name: &str, default: u64| {
        entry
            .field(name)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(default)
    };
    let digits = u32::try_from(number("TimeOtp-Length", 6)).ok()?;
    let algorithm = match entry.field("TimeOtp-Algorithm") {
        Some(a) => parse_algorithm(a)?,
        None => Algorithm::Sha1,
    };
    Totp::new(
        secret,
        number("TimeOtp-Period", 30),
        Encoder::Digits(digits),
        algorithm,
    )
}

fn from_legacy_keepassxc(entry: &Entry) -> Option<Totp> {
    let seed = entry.field("TOTP Seed")?;
    let settings = entry.field("TOTP Settings").unwrap_or("30;6");
    let (period, size) = settings.split_once(';').unwrap_or((settings, "6"));
    let encoder = if size.trim().eq_ignore_ascii_case("s") {
        Encoder::Steam
    } else {
        Encoder::Digits(size.trim().parse().ok()?)
    };
    Totp::new(
        decode_base32(seed)?,
        period.trim().parse().ok()?,
        encoder,
        Algorithm::Sha1,
    )
}

/// Standard or URL-safe base64, padding optional. Used for one rarely seen KeePass field, so a
/// few lines here rather than another dependency.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
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

/// KeeOtp plugin format: `key=BASE32&step=30&size=6&otpHashMode=sha256`.
fn parse_keeotp(value: &str) -> Option<Totp> {
    let mut secret = None;
    let mut period = 30;
    let mut digits = 6;
    let mut algorithm = Algorithm::Sha1;
    for pair in value.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "key" => secret = Some(v),
            "step" => period = v.parse().ok()?,
            "size" => digits = v.parse().ok()?,
            "otphashmode" => algorithm = parse_algorithm(&v)?,
            _ => {}
        }
    }
    Totp::new(
        decode_base32(&secret?)?,
        period,
        Encoder::Digits(digits),
        algorithm,
    )
}

/// `SHA1`, `sha256`, `HMAC-SHA-512` and similar spellings.
fn parse_algorithm(v: &str) -> Option<Algorithm> {
    let norm: String = v
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    match norm.trim_start_matches("hmac") {
        "sha1" => Some(Algorithm::Sha1),
        "sha256" => Some(Algorithm::Sha256),
        "sha512" => Some(Algorithm::Sha512),
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

    fn with_otp(value: &str) -> Entry {
        Entry {
            custom: vec![crate::entry::CustomField {
                name: "otp".into(),
                value: Zeroizing::new(value.into()),
                protected: true,
            }],
            ..Entry::default()
        }
    }

    #[test]
    fn keeotp_and_bare_secrets() {
        let t = Totp::from_entry(&with_otp(
            "key=JBSWY3DPEHPK3PXP&step=45&size=7&otpHashMode=sha512",
        ))
        .unwrap();
        assert_eq!(
            (t.period, t.encoder, t.algorithm),
            (45, Encoder::Digits(7), Algorithm::Sha512)
        );
        let bare = Totp::from_entry(&with_otp("JBSW Y3DP EHPK 3PXP")).unwrap();
        assert_eq!((bare.period, bare.encoder), (30, Encoder::Digits(6)));
        assert!(Totp::from_entry(&with_otp("not base32 !!")).is_none());
    }

    fn with_fields(fields: &[(&str, &str)]) -> Entry {
        Entry {
            custom: fields
                .iter()
                .map(|(k, v)| crate::entry::CustomField {
                    name: (*k).into(),
                    value: Zeroizing::new((*v).into()),
                    protected: true,
                })
                .collect(),
            ..Entry::default()
        }
    }

    #[test]
    fn keepass_native_fields() {
        // RFC 6238's SHA-256 secret in each of KeePass's encodings gives the RFC code.
        let ascii = "12345678901234567890123456789012";
        let cases = [
            ("TimeOtp-Secret", ascii.to_string()),
            ("TimeOtp-Secret-Hex", hex::encode(ascii)),
            (
                "TimeOtp-Secret-Base32",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".to_string(),
            ),
            (
                "TimeOtp-Secret-Base64",
                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=".to_string(),
            ),
        ];
        for (field, secret) in cases {
            let e = with_fields(&[
                (field, &secret),
                ("TimeOtp-Length", "8"),
                ("TimeOtp-Algorithm", "HMAC-SHA-256"),
            ]);
            let t = Totp::from_entry(&e).unwrap_or_else(|| panic!("{field} not read"));
            assert_eq!(t.code_at(59), "46119246", "{field}");
        }
    }

    #[test]
    fn algorithm_spellings() {
        assert_eq!(parse_algorithm("HMAC-SHA-256"), Some(Algorithm::Sha256));
        assert_eq!(parse_algorithm("sha1"), Some(Algorithm::Sha1));
        assert_eq!(parse_algorithm("SHA-512"), Some(Algorithm::Sha512));
        assert_eq!(parse_algorithm("MD5"), None);
    }

    #[test]
    fn legacy_keepassxc_fields() {
        let t = Totp::from_entry(&with_fields(&[
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "60;8"),
        ]))
        .unwrap();
        assert_eq!((t.period, t.encoder), (60, Encoder::Digits(8)));
        let steam = Totp::from_entry(&with_fields(&[
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;S"),
        ]))
        .unwrap();
        assert_eq!(steam.encoder, Encoder::Steam);
        let default = Totp::from_entry(&with_fields(&[("TOTP Seed", "JBSWY3DPEHPK3PXP")])).unwrap();
        assert_eq!((default.period, default.encoder), (30, Encoder::Digits(6)));
    }

    #[test]
    fn the_otp_field_wins_over_older_fields() {
        let e = with_fields(&[
            ("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
        ]);
        assert_eq!(Totp::from_entry(&e).unwrap().encoder, Encoder::Digits(7));
    }

    #[test]
    fn now_reports_time_left_in_the_period() {
        let t = Totp::new(
            b"12345678901234567890".to_vec(),
            30,
            Encoder::Digits(6),
            Algorithm::Sha1,
        )
        .unwrap();
        let (code, left) = t.now();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&left));
    }

    #[test]
    fn describes_itself() {
        let t = Totp::new(vec![1], 60, Encoder::Digits(8), Algorithm::Sha256).unwrap();
        assert_eq!(t.describe(), "8 digits every 60 s, SHA-256");
        let s = Totp::new(vec![1], 30, Encoder::Steam, Algorithm::Sha1).unwrap();
        assert_eq!(s.describe(), "Steam Guard every 30 s, SHA-1");
    }

    #[test]
    fn labels_and_issuers_do_not_get_in_the_way() {
        let t = parse_otpauth(
            "otpauth://totp/ACME%20Co:jane%40example.com?issuer=ACME%20Co&secret=JBSWY3DPEHPK3PXP&digits=6",
        )
        .unwrap();
        assert_eq!(t.encoder, Encoder::Digits(6));
        // Parameters in any order, unknown ones ignored.
        assert!(
            parse_otpauth("otpauth://totp/x?image=https%3A%2F%2Fx&secret=JBSWY3DPEHPK3PXP")
                .is_some()
        );
        // No label at all.
        assert!(parse_otpauth("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").is_some());
    }

    #[test]
    fn a_blank_otp_field_falls_back_to_older_fields() {
        let e = with_fields(&[("otp", "   "), ("TOTP Seed", "JBSWY3DPEHPK3PXP")]);
        assert_eq!(Totp::from_entry(&e).unwrap().encoder, Encoder::Digits(6));
    }

    #[test]
    fn settings_present_even_when_unreadable() {
        let broken = with_fields(&[("otp", "otpauth://totp/x?secret=&digits=99")]);
        assert!(has_otp_settings(&broken));
        assert!(Totp::from_entry(&broken).is_none());
        assert!(!has_otp_settings(&Entry::default()));
    }
}
