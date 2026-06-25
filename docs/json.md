# JSON output

Every command that reports something has `--json`: pretty-printed JSON on stdout, one
trailing newline, nothing else. The keys below are part of prive's interface, like the exit
codes: new keys may be added, existing ones keep their name and meaning. A test checks each
command still has them (`tests/json.rs`).

Times are ISO 8601 in UTC, as KeePass stores them, without a zone suffix
(`2026-05-26T17:00:00`), or `null`.
Secrets are only ever present where noted.

## Entries: `ls`, `search`

A list of entries:

| Key | |
|---|---|
| `path` | `Group/Sub/Title`, or the title at the root |
| `title`, `group`, `username`, `url` | as stored; `group` is `""` at the root |
| `tags` | list of strings |
| `uuid` | `00000000-0000-0000-0000-000000000010` |
| `has_otp` | whether `prive otp` can make a code for it |
| `modified`, `expires` | times, `expires` only when expiry is on |
| `attachments` | how many files are attached |

No password or protected value appears, ever.

## One entry: `show`

The keys of a listed entry, and:

| Key | |
|---|---|
| `password` | `null`, or the password with `--reveal` |
| `notes` | the notes |
| `fields` | list of `{ "name", "value", "protected" }`; protected values are `null` unless `--reveal` |

## Codes: `otp`, `codes`

`otp`: `{ "code", "seconds_left", "period" }`. `codes`: a list of the same with `path`.

## `history`

A list of earlier versions, newest first: `saved` (time), `username`,
`password_changed_after` (whether the next version has another password), and `password`
(`null` unless `--reveal`).

## `tags`

A list of `{ "tag", "entries" }`, most used first.

## `audit`

| Key | |
|---|---|
| `checked`, `skipped` | entries looked at, and left out (excluded from reports, no password) |
| `findings` | list of `{ "path", "issues" }`, worst first |
| `database` | list of issues with the file's own settings |

Each issue has a `kind` and its details: `breached` (`count`), `weak` (`score` 0-2),
`reused` (`with`: how many other entries), `expired`, `expiring` (`days`), `old` (`days`);
for the database, `aes_kdf` (`rounds`), `weak_argon2` (`memory_mib`, `passes`),
`no_inner_cipher`.

## `info`

`path`, `size` (bytes), `entries`, `groups`, `recycled`, `name`, `description`, `format`
(`KDBX 4.1`), `cipher`, `inner_cipher`, `compressed`, `generator`, `key_changed`, and `kdf`:
`{ "algorithm", "iterations", "memory_kib", "parallelism" }`. With `--time`, also
`open_seconds`.

## `diff`

`{ "here", "there", "differences" }`; each difference has `kind` (`only_here`,
`only_there`, `changed`), `path`, `uuid`, and when they apply `other_path` (moved or
renamed), `fields` (names only), `newer` (`here`, `there` or `unknown`) and
`recycled_in_other`.

## `doctor`

A list of checks: `{ "name", "status", "detail" }`, `status` being `ok`, `warn`, `fail` or
`skip`. With `--all`, a list of `{ "database", "checks" }`, `database` being `null` for the
checks that aren't about one database.

## `status`, `config`, `gen`

- `status`: `unlocked`, `databases` (list of `{ "path", "name" }`), `db` and `name` (the one
  unlocked last), `seconds_left`.
- `config`: `config_file`, `config_file_exists`, `database`, `database_from`, `keyfile`,
  `password_from`, `clipboard_seconds`, `agent_minutes`, `agent_dir`, `databases`.
- `gen`: `{ "value", "entropy_bits" }`.
