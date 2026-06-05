# Bringing passwords in from other apps

> Status: prive can read these exports already; writing them into a new KeePass database
> (`prive import`) comes next. Until then KeePassXC's own CSV import works.

| From | How to export | Read by prive | One-time codes |
|---|---|---|---|
| Google Password Manager / Chrome | Settings, Passwords, Export passwords | yes | not in Google's export |
| Apple Passwords / Safari | File, Export, All Passwords | yes | yes (`OTPAuth` column) |
| Proton Pass | Settings, Export | coming | yes |
| LastPass | Advanced, Export | coming | yes |

Columns are matched by name, ignoring case and order, so small changes in an exporter's
layout don't break the import. Columns prive has no place for are kept as custom fields
rather than dropped.

Every export is a file with all your passwords in plain text. Export to an encrypted disk,
import, check the result, and delete the export.
