# Running commands with secrets

`prive run` starts a command with secrets in its environment. They never appear on the
command line (where `ps` shows them to everyone), in your shell history, or in a file.

```bash
# A password and a field into two variables
prive run -e GITHUB_TOKEN=Work/GitHub:token -e GITHUB_USER=Work/GitHub:username -- gh repo list

# Every upper-case custom field of an entry: keep AWS_ACCESS_KEY_ID and
# AWS_SECRET_ACCESS_KEY as fields on one entry, then
prive run --from Work/AWS -- aws s3 ls

# Both: --env wins over a field of the same name
prive run --from Work/AWS -e AWS_REGION=Work/AWS:region-eu -- terraform plan
```

- `-e NAME=ENTRY` sets NAME to the entry's password; `NAME=ENTRY:FIELD` to a field
  (`username`, `url`, `notes`, or a custom field's name). An entry title that itself contains
  `:` still works: the whole value is tried as an entry name first.
- `--from ENTRY` exports every custom field whose name is written like an environment
  variable: upper-case letters, digits and `_`. One-time code settings and KeePassXC's
  extra addresses (`KP2A_URL`, `KP2A_URL_1`, ...) are never exported.
- The command's exit code becomes prive's, so `prive run ... -- make deploy` works in scripts
  and CI. On Linux and macOS prive replaces itself with the command (signals reach it
  directly); on Windows it waits for it.
- With `prive unlock`, no password is asked for.

The secrets do live in the child process's environment, which other processes of the same
user can read (on Linux, `/proc/<pid>/environ`). That is the same exposure as any tool that
takes credentials from the environment, and much less than a file or the command line.
