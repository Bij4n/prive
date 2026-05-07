#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Should not panic regardless of input
    let _ = pgp::SignedPublicKey::from_string(s);
    let _ = pgp::SignedSecretKey::from_string(s);

    // Also fuzz the keyring import path
    let dir = tempfile::tempdir().unwrap();
    let keyring = prive::pgp::keyring::Keyring::open_at(dir.path()).unwrap();
    let _ = keyring.import_key(s);
});
