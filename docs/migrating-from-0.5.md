# Moving from prive 0.5

prive 0.5 kept passwords in its own `.pv` vault. 1.0 works on KeePass databases instead, so
your passwords move once into a `.kdbx` file that KeePassXC, KeePassDX and Strongbox can also
open.

1. With 0.5 still installed (`cargo install --git https://github.com/Bij4n/prive --tag
   legacy-0.5.0 --locked`), export the vault to CSV:

   ```bash
   prive export --format csv --output vault.csv
   ```

   The file holds every password in plain text. Keep it on an encrypted disk, and delete it
   (`shred -u vault.csv` on Linux) as soon as step 2 is done.

2. In KeePassXC: Database, Import, CSV File, pick `vault.csv`, and map the columns (name to
   Title, username, password, url, notes). Save the new database with a strong master
   password.

3. Point prive 1.0 at it:

   ```bash
   prive --db ~/Passwords.kdbx ls
   ```

What doesn't come across: 0.5's TOTP secrets are not in its CSV export, and its attachments,
secure notes and password history aren't either. Re-add two-factor secrets in KeePassXC
(Entry, TOTP, Set up). If you used 0.5's PGP keys: they were stored without a passphrase, so
treat them as exposed and make new ones.

prive 1.0 will have its own importer; until then, KeePassXC's CSV import does the job.
