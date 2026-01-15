#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // Write fuzz data to a temp file and try to validate it as a vault
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fuzz.pv");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(data).unwrap();
    drop(f);

    // Should not panic regardless of input
    let _ = prive::vault::migrate::validate_vault_header(&path);
    let _ = prive::vault::migrate::vault_version(&path);
    let _ = prive::vault::migrate::needs_migration(&path);
});
