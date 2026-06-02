# Test databases

Built by `./make.sh` from `source.xml` with `keepassxc-cli` (KeePassXC 2.7), so they are
real KeePassXC files, not files written by the library prive uses. Invented data only.

Password for every database: `fixture-pass`. `keyfile.kdbx` also needs `keyfile.keyx`.

| File | Format | Contents |
|---|---|---|
| `kdbx31.kdbx` | KDBX 3.1, AES-KDF | `source.xml` without the report-exclusion flag (a 4.1 field) |
| `kdbx40.kdbx` | KDBX 4.0, AES-KDF | the same plus entry custom data, which needs format 4 |
| `kdbx41.kdbx` | KDBX 4.1, AES-KDF | all of `source.xml` |
| `keyfile.kdbx` | KDBX 3.1, password + key file | one entry |
| `keyonly.kdbx` | KDBX 3.1, key file only (`keyonly.keyx`), no password | one entry |

KeePassXC writes the oldest format that holds the data, which is how one source gives three
formats.

What `source.xml` covers: nested groups (`Work/Cloud`), a title used twice (`GitHub` in
`Work` and in `Personal`), TOTP in each stored form (otpauth SHA-1 and SHA-256/8-digit/60 s,
Steam, legacy `TOTP Seed`), a protected and an unprotected custom field, history, an
attachment, an expired entry, an entry excluded from reports, a reused weak password and a
recycle bin with a deleted entry.

KeePassXC's own answers for spot checks: `show -t Work/Cloud/Steam` gives a 5-letter Steam
code; `Bank` gives 8 digits every 60 seconds.
