//! One-time code secrets from other apps, in the form KeePassXC, KeePassDX and Strongbox
//! store: an `otpauth://totp/...` URI in the `otp` field.

use zeroize::Zeroizing;

fn encode_label(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `Some(uri)` when `raw` is a usable TOTP secret: an otpauth URI prive can read, or a bare
/// base32 secret (made into a 30-second, 6-digit SHA-1 URI, the defaults every authenticator
/// app assumes). `None` when it can't be read; the caller keeps the raw value as a field.
pub fn normalize(raw: &str, title: &str, username: &str) -> Option<Zeroizing<String>> {
    let raw = raw.trim();
    if raw.to_ascii_lowercase().starts_with("otpauth://") {
        crate::otp::parse_otpauth(raw)?;
        return Some(Zeroizing::new(raw.to_string()));
    }
    let secret: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    crate::otp::decode_base32(&secret)?;
    let label = if username.is_empty() {
        encode_label(title)
    } else {
        format!("{}:{}", encode_label(title), encode_label(username))
    };
    Some(Zeroizing::new(format!(
        "otpauth://totp/{label}?secret={secret}&period=30&digits=6&algorithm=SHA1&issuer={}",
        encode_label(title)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_secrets_become_uris_that_give_the_same_code() {
        let uri = normalize("jbsw y3dp ehpk 3pxp", "Git Hub", "me@x.invalid").unwrap();
        assert!(uri.starts_with("otpauth://totp/Git%20Hub:me@x.invalid?secret=JBSWY3DPEHPK3PXP"));
        let parsed = crate::otp::parse_otpauth(&uri).unwrap();
        let direct = crate::otp::Totp::new(
            crate::otp::decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            30,
            crate::otp::Encoder::Digits(6),
            crate::otp::Algorithm::Sha1,
        )
        .unwrap();
        assert_eq!(parsed.code_at(1_700_000_000), direct.code_at(1_700_000_000));
    }

    #[test]
    fn uris_pass_through_and_junk_is_refused() {
        let u = "otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&digits=8";
        assert_eq!(normalize(u, "A", "").unwrap().as_str(), u);
        assert!(normalize("otpauth://totp/A?secret=", "A", "").is_none());
        assert!(normalize("not a secret!", "A", "").is_none());
        assert!(normalize("", "A", "").is_none());
    }
}
