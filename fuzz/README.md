# Fuzzing

Needs nightly Rust and `cargo install cargo-fuzz`. From the repository root:

```bash
cargo +nightly fuzz run otpauth      # otpauth URIs and base32 secrets
cargo +nightly fuzz run select       # entry selection, search, suggestions
cargo +nightly fuzz run import       # every importer over arbitrary text
cargo +nightly fuzz run refs         # field references
cargo +nightly fuzz run template     # get --format templates
cargo +nightly fuzz run text         # what reaches a terminal; conflict-copy names
```

Targets live in `fuzz_targets/`. Crashes are saved under `fuzz/artifacts/` (ignored by git);
turn any you find into a regular test.
