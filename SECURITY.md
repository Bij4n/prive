# Security policy

prive handles password databases, so security reports get priority.

## Reporting

Please **do not** open a public issue with the details of a vulnerability. Open an issue that
just says you have a security report and asks for a private contact, or use GitHub's
"Report a vulnerability" button on the repository's Security tab.

Include what you found, how to reproduce it, and which version or commit you used.
You'll get an answer within a week. Fixes for confirmed problems are released as soon as
they're ready, with credit if you want it.

## Supported versions

Fixes go into the latest release and `master`. The 0.5 line (`legacy-0.5.0`, its own vault
format and PGP toolkit) gets none: it had known serious problems, and the README says not to
use it for real secrets.

## Scope

In scope: anything that could expose a secret (database contents, master password, key file,
TOTP secrets, clipboard), corrupt a database, or let someone else's input make prive act
against its user.

Out of scope: attacks that already run code as the same user, and weaknesses in a database's
own settings (a short master password, a weak key-derivation setting) that prive did not
choose.

See [`docs/security.md`](docs/security.md) for what prive does and doesn't protect against.
