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
