# prive

A fast, scriptable terminal client for **KeePass** password databases.

prive opens the same `.kdbx` file as KeePassXC, KeePassDX (Android) and Strongbox (iOS), so
your passwords live in one file you own: those apps cover the phone and the browser, prive
covers the terminal. It prints exactly what you ask for, nothing else, so it fits in scripts.

> **Status: rewrite in progress (0.6).** Reading works: `ls`, `search`, `show`, `get`, `otp`,
> `pick`, `audit` and `gen`. Unlock-once, imports from other password managers, file
> encryption and editing are next; see the [roadmap](docs/roadmap.md).
>
> The old 0.5 line (its own `.pv` vault format and a PGP toolkit) is kept at the tag
> `legacy-0.5.0`. It had serious problems, PGP secret keys stored unencrypted among them;
> please don't use it for real secrets.

## Install

There are no packaged releases yet. With a recent stable Rust (1.88 or later):

```bash
cargo install --git https://github.com/Bij4n/prive --locked
```

## License

MIT. The passphrase word list is the EFF large word list (CC BY 3.0 US); see `assets/`.
