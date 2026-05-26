#!/usr/bin/env bash
# Rebuild the test databases from source.xml with keepassxc-cli, so they are written by
# KeePassXC itself rather than by the library prive reads them with.
#
#   kdbx3.kdbx    KDBX 3.1, AES-KDF (KeePassXC's default for an XML import)
#   kdbx4.kdbx    KDBX 4.0: the same entries plus entry custom data, which makes KeePassXC
#                 write format 4
#   keyfile.kdbx  password + key file (keyfile.keyx), one entry
#
# Password for all three: fixture-pass
set -euo pipefail
cd "$(dirname "$0")"
pw=fixture-pass
command -v keepassxc-cli >/dev/null || { echo "keepassxc-cli not found" >&2; exit 1; }
rm -f kdbx3.kdbx kdbx4.kdbx keyfile.kdbx keyfile.keyx

printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli import -q -p source.xml kdbx3.kdbx

sed 's#<Tags>dev;cloud</Tags>#<Tags>dev;cloud</Tags><CustomData><Item><Key>fixture</Key><Value>kdbx4</Value></Item></CustomData>#' \
  source.xml > .source4.xml
printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli import -q -p .source4.xml kdbx4.kdbx
rm -f .source4.xml

printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli db-create -q -p --set-key-file keyfile.keyx keyfile.kdbx
printf '%s\n' "$pw" | keepassxc-cli add -q -k keyfile.keyx -u kfuser --url https://example.invalid \
  keyfile.kdbx "Key file entry"

for f in kdbx3.kdbx kdbx4.kdbx keyfile.kdbx; do
  printf '%s: %s\n' "$f" "$(head -c 12 "$f" | od -An -tx1 | tr -d ' \n')"
done
