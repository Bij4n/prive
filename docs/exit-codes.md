# Exit codes

prive's exit codes are part of its interface: scripts can rely on them.

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Any other error (unreadable file, bad option value, network failure, ...) |
| 2 | Usage error: unknown command or option, missing argument |
| 3 | Not there: no entry matches the name given, or the entry has no such field, attachment or one-time code, or there is no such group or named database |
| 4 | The name matches more than one entry; the candidates are listed on stderr |
| 5 | Wrong password or key file, or a password was needed but stdin is not a terminal |
| 130 | You cancelled an interactive choice (Esc or Ctrl-C in `pick`), as with fzf |

`prive doctor` exits 1 when any of its checks fails (a warning alone still exits 0), so
`prive doctor >/dev/null || ...` works in a setup script.

Errors are printed to stderr, prefixed with `prive:`. Nothing is printed to stdout when a
command fails, so `$(prive get ...)` is empty on failure rather than holding an error message.

## Examples

```bash
pw=$(prive get "Work/GitHub")
status=$?
case $status in
  0) ;;
  3) echo "no such entry" ;;
  4) echo "be more specific" ;;
  5) echo "wrong password" ;;
  *) echo "prive failed ($status)" ;;
esac
```

Read `$?` straight after the command. Inside `if ! pw=$(...)` it is already the negated
status, always 0, so a `case $?` there never matches.
