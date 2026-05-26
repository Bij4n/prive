**What this changes and why**

**How it was tested**

- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass
- [ ] Nothing new prints, logs or `Debug`-formats a secret
- [ ] If it writes to a database: fields it doesn't understand are kept (tested against a
      KeePassXC-made file)
- [ ] Docs and CHANGELOG updated if behaviour changed
