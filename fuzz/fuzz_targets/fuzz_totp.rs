#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Use first 8 bytes as time, next byte as digits, rest as secret
    let time = u64::from_be_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]);
    let digits = (data[8] % 6) as u32 + 4; // 4-9 digits
    let secret = &data[9..];

    // Should not panic
    let _ = prive::crypto::totp::generate_totp_at(secret, time, 30, digits);
});
