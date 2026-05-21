# Clipboard

`--clip` copies a secret instead of printing it, then clears it after a timeout
(`clipboard_seconds` in the config file, 20 seconds by default, 1 to 600 allowed).

How it works: a command-line program exits as soon as it is done, and on Linux the clipboard
contents disappear with the program that set them. So prive starts a small helper (the same
binary, `prive __clip`) that holds the clipboard, waits, and clears it. It clears only if the
clipboard still holds the secret it copied: if you have copied something else since, that is
left alone.

Clipboard history: copies are marked "don't keep in history" where the system supports it
(macOS, Windows, and on Linux the `x-kde-passwordManagerHint` used by KDE). Some Linux
clipboard managers ignore the hint and keep a copy anyway; if yours does, prefer printing to
the terminal or a pipe over `--clip`.

On Windows the copy is also excluded from cloud clipboard sync and from clipboard monitoring
apps.
