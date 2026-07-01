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

Documentation lives in `docs/`, with an index in `docs/README.md`. A new page goes in the
index; `tests/docs.rs` fails when a link between pages points at a file that does not exist.

## Adding a command

- The definition goes in `src/cli.rs`, the work in the matching file of `src/commands/`
  (entries, codes, agent, reports, tools), and anything it prints in `src/output.rs`. `tests/cli.rs` checks the definition with clap's own `debug_assert`.
- Text for people goes through `output::print_human` (control characters made visible);
  values a script reads, through `output::print`; coloured reports, `output::print_styled`.
- A row in `docs/commands.md`, a line in `CHANGELOG.md`, and the command's name in the
  completions and man page tests (`tests/cli.rs`, `tests/man.rs`).
- If it reads entries, a test against the KeePassXC-made fixtures in `tests/commands.rs`.

## Speed

A change meant to make something faster, or that might make it slower, gets measured before
and after with `cargo run --release --example bench -- DB < password` on a large database
(the 5,000-entry one in `tests/interop.rs` is a good start); put the numbers in the pull
request, and in `docs/performance.md` if they move.

## Ground rules

- stdout is for results only; prompts, notices and errors go to stderr.
- Exit codes are an interface (`docs/exit-codes.md`); don't change their meaning.
- Never print, log or `Debug`-format a secret. Wrap secrets in `zeroize::Zeroizing`.
- No `unsafe`. The lint is denied crate-wide; the one exception (marking standard handles
  non-inheritable on Windows, in `clip.rs`) carries a `SAFETY` comment.
- No new network access without discussion. Today the only request prive makes is the
  optional Have I Been Pwned range lookup.
- Keep dependencies few and well maintained; say why in the pull request when adding one.

## Licence

By contributing you agree that your work is released under the MIT licence in `LICENSE`.
