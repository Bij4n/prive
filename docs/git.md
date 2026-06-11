# prive as git's credential helper

Git asks a credential helper for the username and password of HTTPS remotes. prive can
answer from your KeePass database:

```bash
git config --global credential.helper '!prive git-credential'
prive unlock              # git can't ask you for the master password, so unlock first
git push                  # the password for github.com comes from the entry whose URL is github.com
```

How the entry is chosen:

- its URL's host is the remote's host (`www.` doesn't matter, a port does);
- if the URL has a scheme, it is the remote's (`https://...`); a bare `github.com` fits any;
- if the remote URL names a user (`https://demo@github.com/...`), the entry's username is
  that user.

When two entries still fit, prive answers nothing and says so on stderr (git then asks you
as usual). Put the username in the remote URL, or set `git config credential.useHttpPath
true` and give the entries URLs with their paths.

`git credential store` and `erase` are accepted and ignored: prive never changes your
database for git. For a token, keep it as the entry's password (GitHub's personal access
tokens work this way).

Without `prive unlock`, `PRIVE_PASSWORD_FILE` works too; `--password-stdin` doesn't, because
git uses stdin to talk to its helper.
