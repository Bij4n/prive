# Questions

**Can I use prive while KeePassXC has the database open?**
Yes. prive only reads the file. When KeePassXC (or a sync tool) saves a new version, prive's
agent notices and asks for the password again rather than answer from the old copy.

**Is it safe to leave a database unlocked in the agent?**
As safe as your user account. The agent answers only processes running as you, over a socket
in a directory only you can open, and forgets the database after `agent_minutes` unused
(15 by default) or with `prive lock`. Anything that already runs as you could read your
keystrokes too, so lock before you leave a machine others use. See [agent.md](agent.md).

**Does prive send anything over the network?**
Only when you run `prive audit --hibp`: the first five characters of each password's SHA-1
hash go to Have I Been Pwned, and the match happens on your machine. Nothing else, ever.

**Why can't prive add or change entries?**
Not yet. A KeePass file holds things prive doesn't use (icons, auto-type settings, plugin
data), and saving must keep all of them. Writing comes once a round-trip test against files
KeePassXC made proves nothing is lost; until then, edit in KeePassXC. See the
[roadmap](roadmap.md).

**What about my phone and the browser?**
Use the KeePass apps made for them, on the same file: KeePassDX on Android, Strongbox or
KeePassium on iOS, KeePassXC's browser extension on the desktop. Sync the file with
anything (Syncthing, Nextcloud, iCloud Drive); [sync.md](sync.md) covers conflict copies.

**Over SSH there's no clipboard. Now what?**
Print instead: `prive get`, `prive otp`, `prive open --print` for the address. `prive run`
hands secrets to a command without printing them at all.

**Can I avoid typing the master password?**
Put a `password_command` in the config file that asks the system keyring, `pass` or a
password manager's CLI for it ([config.md](config.md#password-command)), or unlock once a
session with `prive unlock`.

**Does it work with a YubiKey?**
Not yet; challenge-response unlock is on the roadmap. Databases with a password and/or a key
file work.

**Why Rust?**
A password tool handles secrets in memory and parses files other programs wrote. Rust
removes whole classes of memory bugs there, and gives one self-contained binary that starts
in milliseconds (a 5,000-entry database lists in a tenth of a second, most of it the key
derivation).

**Something doesn't work.**
Run `prive doctor`, then see [troubleshooting.md](troubleshooting.md).
