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
