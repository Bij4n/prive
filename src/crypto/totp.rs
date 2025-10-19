use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub fn generate_totp(secret: &[u8], time_step: u64, digits: u32) -> Result<String, String> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Time error: {e}"))?
        .as_secs();

    generate_totp_at(secret, time, time_step, digits)
}

pub fn generate_totp_at(
    secret: &[u8],
    unix_time: u64,
    time_step: u64,
    digits: u32,
) -> Result<String, String> {
    let counter = unix_time / time_step;
    let counter_bytes = counter.to_be_bytes();

    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|e| format!("HMAC init error: {e}"))?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let modulo = 10u32.pow(digits);
    let otp = code % modulo;

    Ok(format!("{:0>width$}", otp, width = digits as usize))
}

pub fn decode_base32_secret(encoded: &str) -> Result<Vec<u8>, String> {
    let cleaned = encoded.replace(' ', "").replace('-', "").to_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &cleaned))
        .ok_or_else(|| "Invalid base32 encoding".to_string())
}

pub fn time_remaining(time_step: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    time_step - (now % time_step)
}

pub fn parse_otpauth_uri(uri: &str) -> Result<TotpParams, String> {
    if !uri.starts_with("otpauth://totp/") {
        return Err("Invalid otpauth URI — must start with otpauth://totp/".to_string());
    }

    let rest = &uri["otpauth://totp/".len()..];
    let (label, query) = rest
        .split_once('?')
        .ok_or_else(|| "Missing query parameters in URI".to_string())?;

    let label = urldecode(label);

    let mut secret = None;
    let mut issuer = None;
    let mut digits = 6u32;
    let mut period = 30u64;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key.to_lowercase().as_str() {
                "secret" => secret = Some(value.to_string()),
                "issuer" => issuer = Some(urldecode(value)),
                "digits" => digits = value.parse().unwrap_or(6),
                "period" => period = value.parse().unwrap_or(30),
                _ => {}
            }
        }
    }

    let secret = secret.ok_or_else(|| "Missing 'secret' parameter in URI".to_string())?;

    Ok(TotpParams {
        label,
        secret,
        issuer,
        digits,
        period,
    })
}

fn urldecode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Some(decoded) = u8::from_str_radix(&hex, 16).ok().map(|b| b as char) {
                result.push(decoded);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

pub struct TotpParams {
    pub label: String,
    pub secret: String,
    pub issuer: Option<String>,
    pub digits: u32,
    pub period: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_rfc6238_vector() {
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 59, 30, 8).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_totp_6_digits() {
        let secret = b"12345678901234567890";
        let code = generate_totp_at(secret, 59, 30, 6).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_different_times() {
        let secret = b"testsecret123456";
        let code1 = generate_totp_at(secret, 1000, 30, 6).unwrap();
        let code2 = generate_totp_at(secret, 2000, 30, 6).unwrap();
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_totp_same_time_step() {
        let secret = b"testsecret123456";
        let code1 = generate_totp_at(secret, 30, 30, 6).unwrap();
        let code2 = generate_totp_at(secret, 59, 30, 6).unwrap();
        assert_eq!(code1, code2);
    }

    #[test]
    fn test_decode_base32() {
        let decoded = decode_base32_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_decode_base32_with_spaces() {
        let decoded = decode_base32_secret("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!(decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert_eq!(params.issuer, Some("Example".to_string()));
    }

    #[test]
    fn test_parse_otpauth_uri_minimal() {
        let uri = "otpauth://totp/myapp?secret=ABC123";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.secret, "ABC123");
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
    }

    #[test]
    fn test_parse_otpauth_invalid() {
        let result = parse_otpauth_uri("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_time_remaining() {
        let remaining = time_remaining(30);
        assert!(remaining > 0 && remaining <= 30);
    }

    #[test]
    fn test_urldecode() {
        assert_eq!(urldecode("hello%20world"), "hello world");
        assert_eq!(urldecode("test+value"), "test value");
        assert_eq!(urldecode("no%encoding"), "no%encoding"); // invalid hex
    }
}
