# KeePass compatibility

prive works on KeePass databases (`.kdbx`), the format used by KeePassXC (desktop and
browser extension), KeePassDX (Android), Strongbox and KeePassium (iOS and macOS) and
KeePass 2 itself. Your passwords stay in one file you own; those apps cover the phone and the
browser, prive covers the terminal.

> Status: prive reads databases (`ls`, `search`, `show`, `get`, `otp`, `pick`, `audit`).
> Creating and changing them comes later; see the [roadmap](roadmap.md).

## Formats

| Format | Read | Notes |
|---|---|---|
| KDBX 4.1 | yes | KeePassXC 2.7's format when entries use 4.1 features |
| KDBX 4.0 | yes | |
| KDBX 3.1 | yes | KeePassXC still writes it when nothing needs 4.x |
| KDB (KeePass 1) | no | convert it with KeePassXC first |

Key derivation: Argon2d, Argon2id and AES-KDF. Unlocking: password, key file (XML v1/v2,
binary or hashed), or both. Hardware keys (YubiKey challenge-response) are not supported yet.

## What prive reads

Title, username, password, URL, notes, tags, custom fields (with their "protected" flag),
attachments, earlier versions (history), modification and expiry times, the "exclude from
reports" flag, and
two-factor secrets in every format KeePass apps store them (see [totp.md](totp.md)).
Extra addresses saved in KeePassXC's browser settings
(the `KP2A_URL`, `KP2A_URL_1`, ... fields KeePassXC and Keepass2Android share) count as the
entry's URLs for `search` and `git-credential`. Entries in the recycle bin are left out. Field references (`{REF:P@I:...}`) are resolved
when a value is used; see [references.md](references.md).

## Tested against

The test suite opens databases written by KeePassXC itself (`tests/fixtures/`): the same
entries saved as KDBX 3.1, 4.0 and 4.1 must read back identically, field for field, including
tags, attachments and history. CI also compares prive's one-time codes, field references and
listings with `keepassxc-cli`'s for the same databases, up to five thousand entries.
