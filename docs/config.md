# Configuration

prive needs no configuration. The optional config file lives at `$PRIVE_CONFIG`, or
`<config dir>/prive/config.toml`:

| System | Default location |
|---|---|
| Linux | `~/.config/prive/config.toml` |
| macOS | `~/Library/Application Support/prive/config.toml` |
| Windows | `%APPDATA%\prive\config.toml` |

```toml
# Database opened when neither --db nor PRIVE_DB is given.
db = "/home/me/Passwords.kdbx"

# Key file for that database, if it uses one. Not used with --db.
keyfile = "/home/me/Passwords.keyx"

# Seconds before a copied secret is cleared from the clipboard (1-600, default 20).
clipboard_seconds = 20
```

Unknown keys are ignored, so a config written for a newer prive still works with an older one.
