# Installing

## From source

You need Rust 1.88 or later (`rustup update stable`).

```bash
cargo install --git https://github.com/Bij4n/prive --locked
prive --version
```

The binary is self-contained: no OpenSSL or other system library is needed at run time.
On Linux the clipboard works on X11 and on Wayland compositors that support the
data-control protocol (wlroots-based ones, KDE, recent GNOME).

## Shell completions

```bash
# bash
prive completions bash > ~/.local/share/bash-completion/completions/prive
# zsh (any directory on $fpath)
prive completions zsh > ~/.zfunc/_prive
# fish
prive completions fish > ~/.config/fish/completions/prive.fish
# PowerShell: add to your profile
prive completions powershell | Out-String | Invoke-Expression
```

## Man pages

From a checkout of the repository:

```bash
cargo run --example man -- ~/.local/share/man/man1
man prive
```

## Packages

Homebrew, AUR and WinGet packages will come with 1.0.
