# Contributing to prive

Thanks for helping. prive is small on purpose: a fast terminal client for KeePass databases
that one person can keep correct. Changes that make it more reliable, clearer or safer are
the most welcome.

## Before you start

- For anything bigger than a fix, open an issue first so we can agree on the shape.
- prive reads and writes files other apps depend on (KeePassXC, KeePassDX, Strongbox).
  Anything that writes must keep every field it does not understand.

## Building and testing

```bash
cargo test                                  # unit, integration and property tests
cargo clippy --all-targets -- -D warnings   # must be clean
cargo fmt --check
```

The test databases in `tests/fixtures/` are made by KeePassXC from `source.xml`; rebuild them
with `tests/fixtures/make.sh` (needs `keepassxc-cli`). Never commit real data.

## Ground rules

- stdout is for results only; prompts, notices and errors go to stderr.
- Exit codes are an interface (`docs/exit-codes.md`); don't change their meaning.
- Never print, log or `Debug`-format a secret. Wrap secrets in `zeroize::Zeroizing`.
- No new network access without discussion. Today the only request prive makes is the
  optional Have I Been Pwned range lookup.
- Keep dependencies few and well maintained; say why in the pull request when adding one.

## Licence

By contributing you agree that your work is released under the MIT licence in `LICENSE`.
