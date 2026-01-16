#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let length = (data[0] as usize % 200) + 1;
    let flags = data[1];

    let include_upper = flags & 0x01 != 0;
    let include_numbers = flags & 0x02 != 0;
    let include_symbols = flags & 0x04 != 0;

    let pw = prive::crypto::password_gen::generate_password(
        length, include_upper, include_numbers, include_symbols,
    );
    assert_eq!(pw.len(), length);

    // Also fuzz entropy calculation
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = prive::crypto::password_gen::password_entropy(s);
    }
});
