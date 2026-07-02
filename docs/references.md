# Field references

KeePass lets one entry use another's values: a field holding `{REF:P@I:46C9B1FF...}` means
"the password of the entry with that UUID". It is how one password is shared between several
entries, so changing it in one place changes it everywhere. KeePassXC, KeePass 2 and
KeePassDX resolve these when the value is used, and so does prive: in `get`, `run`, `pick`,
`open`, `git-credential` and `show --reveal`.

The form is `{REF:<field>@<search>:<text>}`:

| Field | | Search | |
|---|---|---|---|
| `T` | title | `I` | the entry with this UUID (hex, no dashes) |
| `U` | username | `T`, `U`, `P`, `A`, `N` | the first entry whose title, username, password, URL or notes contain the text |
| `P` | password | | |
| `A` | URL | | |
| `N` | notes | | |
| `I` | UUID | | |

A reference may point at another reference; prive follows up to ten in a row, as KeePass
does. One that points at nothing is left as written, so you can see what to fix.

`audit` checks a referenced password at its source entry only, so a shared password isn't
reported as "reused" by every entry that refers to it.

## Limits

A reference to a reference is followed up to ten levels deep, as KeePass does. One value
expands at most 1,000 references in all and grows to at most 1 MiB; anything past that is
left as written. No real database comes near either, but without them a value that refers to
itself several times would double at every level and could run prive out of memory.
\n