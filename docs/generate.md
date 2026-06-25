# Generating passwords

`prive gen` needs no database. It prints one value and a newline; with `--clip` it copies
instead, and with `--json` prints `{"value": ..., "entropy_bits": ...}`.

| Kind | Command | Strength |
|---|---|---|
| Random characters (default 24) | `prive gen --length 32` | about 6.5 bits per character with all classes |
| Passphrase (EFF large list) | `prive gen --words 6` | 12.9 bits per word: 6 words is about 77 bits |
| PIN | `prive gen --pin 6` | 3.3 bits per digit |

Guarantees:

- Randomness comes from `rand`'s thread generator: ChaCha12, a cryptographic generator
  seeded from the operating system and reseeded regularly.
- With lower-case, upper-case, digits and symbols on, every class appears at least once
  (drawn uniformly, retried until true, so no position is predictable).
- `--avoid-ambiguous` leaves out `0 O 1 l I |`.
- `--symbols '!@#$'` uses only those symbols, for a site that allows some and rejects the
  rest; `--exclude '<>&"'` never uses the characters given, from any class. If an exclusion
  leaves a class empty (`--exclude 0123456789`), prive says so instead of guessing; use
  `--no-digits` for that.
- The entropy figure assumes an attacker knows exactly how the password was made; it is the
  honest number, not a guess based on how the result looks.

`--word-list FILE` takes the words from a file of your own instead, for a passphrase in
another language or from the EFF short lists: one word a line, or numbered lines like the
EFF lists. Duplicates and blank lines are ignored, and a list needs at least 1,024 different
words. The entropy shown is the honest one for that list's size (a 7,776-word list gives
12.9 bits a word, a 2,048-word list 11).

Four words in the EFF list contain a hyphen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`),
so with the default `-` separator a passphrase can look one word longer than it is. That
changes nothing about its strength; use `--separator ' '` if you'd rather see the words apart.

Options: `--no-symbols`, `--no-digits`, `--no-upper`, `--symbols CHARS`, `--exclude CHARS`,
`--separator` and `--capitalize` (for passphrases).

```bash
prive gen --length 16 --symbols '!@#$%'     # a bank that allows five symbols
prive gen --exclude '<>&;'                  # for a form that mangles markup characters
```
