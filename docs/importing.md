# Bringing passwords in from other apps

> Status: prive can read these exports already; writing them into a new KeePass database
> (`prive import`) comes next. Until then KeePassXC's own CSV import works.

| From | How to export | Read by prive | One-time codes |
|---|---|---|---|
| Google Password Manager / Chrome | Settings, Passwords, Export passwords | yes | not in Google's export |
| Apple Passwords / Safari | File, Export, All Passwords | yes | yes (`OTPAuth` column) |
| Proton Pass | Settings, Export, CSV | yes | yes |
| LastPass | Advanced, Export | yes (folders, favourites, secure notes) | yes |
| Bitwarden, 1Password, Dashlane, others | their CSV export | yes, as `--from csv` | when the export has a code column |

Check what an export would give before anything is written:

```bash
prive import --check ~/Downloads/Proton\ Pass_export.csv
prive import --check --list ~/Downloads/Proton\ Pass_export.csv   # and every entry, no passwords
# Proton Pass export: 412 entries, 37 with one-time codes, in 3 group(s)
#   2 note item(s): Proton's CSV only has their name and note; its JSON export has the rest
```

The app is recognised from the header line; `--from proton|apple|google|lastpass|csv` names
it. For any other CSV, prive guesses which column is which from the usual names (`title` or
`name`, `username` or `login`, `url` or `website`, ...), lists what it used, and
`--map field=Column` corrects a guess:

```bash
prive import --check export.csv --from csv --map title=Site --map password=Secret
```

Fields: `title`, `group`, `username`, `password`, `url`, `notes`, `otp`, `tags`.

One-time codes are stored the way KeePassXC, KeePassDX and Strongbox read them (an otpauth
URI in the `otp` field). A code prive can't read is kept on its entry as a field named
`otp (unreadable)` and listed in the report, never dropped.

Columns are matched by name, ignoring case and order, so small changes in an exporter's
layout don't break the import. Columns prive has no place for are kept as custom fields
rather than dropped, except the ones apps keep for themselves (KeePassXC's Icon and dates,
Bitwarden's type and reprompt): a Favorite or Archived flag that is set becomes a
`favorite` or `archived` tag.

Every export is a file with all your passwords in plain text. Export to an encrypted disk,
import, check the result, and delete the export.

## Leaving

Your passwords are in a KeePass file, so any KeePass app opens them as they are. To move to
something else, `prive export` writes everything out in plain text:

```bash
prive export --plaintext -o passwords.csv              # KeePassXC's CSV columns
prive export --plaintext --format json -o passwords.json
```

The CSV has KeePassXC's columns (Group, Title, Username, Password, URL, Notes, TOTP, ...),
which Bitwarden, 1Password and most others can map on import; the JSON has every custom
field and tag as well. References are resolved, one-time codes come out as otpauth URIs,
the recycle bin is left out, and attachments and earlier versions are not included.

The file holds every password unencrypted. prive makes it readable only by you, never
replaces an existing file and refuses to print it on a terminal; import it, then delete it
(`shred -u passwords.csv` on Linux).

