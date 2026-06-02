# Fuzzing

Needs nightly Rust and `cargo install cargo-fuzz`. From the repository root:

```bash
cargo +nightly fuzz run otpauth      # otpauth URIs and base32 secrets
cargo +nightly fuzz run select       # entry selection, search, suggestions
```

Targets live in `fuzz_targets/`. Crashes are saved under `fuzz/artifacts/` (ignored by git);
turn any you find into a regular test.
