# Shell tips

## Entry names on Tab

`prive completions` completes commands and options. To complete entry names as well, ask
prive for them when the database is unlocked (`prive unlock`); `--no-agent` is not used here,
and without the agent the completion just offers nothing rather than prompting.

**bash** (in `~/.bashrc`, after loading prive's completions):

```bash
_prive_entries() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  case ${COMP_WORDS[1]} in
    get|show|otp|open|file|history)
      local IFS=$'\n'
      COMPREPLY=($(compgen -W "$(prive ls --paths 2>/dev/null </dev/null)" -- "$cur"))
      return ;;
  esac
  _prive "$@"
}
complete -o filenames -F _prive_entries prive
```

**zsh** (in `~/.zshrc`):

```zsh
_prive_entry_names() { compadd -- ${(f)"$(prive ls --paths 2>/dev/null </dev/null)"} }
compdef '_arguments "1: :(get show otp open file history)" "2: :_prive_entry_names"' prive
```

## Short functions

```bash
pw()  { prive get "$1" --clip; }          # pw Work/GitHub
otp() { prive otp "$1" --clip; }          # otp Bank
pp()  { prive pick "$@"; }                # fuzzy-find and copy
```

## With fzf

```bash
prive get "$(prive ls --paths | fzf)" --clip
```

(`prive pick` does the same without fzf.)
