# Performance

A release build on a database of 5,000 entries in 50 groups, written by KeePassXC (KDBX 3.1,
AES-KDF with KeePassXC's default 1,000,000 rounds):

| Command | Time | Memory |
|---|---|---|
| `prive ls` | 0.10 s | 24 MB |
| `prive audit --max-age 0` (strength of every password) | 0.47 s | 25 MB |
| `prive info` | 0.10 s | 25 MB |
| `prive diff` against a second copy of 5,000 entries | 0.23 s | 29 MB |

`diff` opens both files, so it pays the key derivation twice; pairing the 5,000 entries
takes about 3 ms.

Most of `ls`'s time is the key derivation, which is the database's own setting: Argon2 with
a large memory cost (KeePassXC's default for KDBX 4) takes about a second by design, on
every open. That is what `prive unlock` is for: after it, commands skip key derivation and
answer from memory.

Inside one process, stage by stage (`cargo run --release --example bench -- DB < password`):

| Stage, 5,000 entries | Time |
|---|---|
| open: key derivation (AES-KDF, 1,000,000 rounds), decrypt, read every entry | 107 ms |
| render `ls` | 2 ms |
| find one entry by path | 0.3 ms |
| `codes`, every one-time code | 0.7 ms |
| `audit`, the strength of every password | 345 ms |
| `diff` against a copy | 6 ms |
| `export` as CSV | 4 ms |

The test suite checks a 5,000-entry database on every CI run (`tests/interop.rs`), with
generous limits, so a change that makes anything grow badly with database size is caught.
