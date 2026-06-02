#!/usr/bin/env bash
# Rebuild the test databases from source.xml with keepassxc-cli, so they are written by
# KeePassXC itself rather than by the library prive reads them with.
#
# KeePassXC picks the oldest format that can hold the data, so each file drops or adds what
# decides that:
#   kdbx31.kdbx   KDBX 3.1: source without QualityCheck (a 4.1-only field)
#   kdbx40.kdbx   KDBX 4.0: same, plus entry custom data (needs format 4)
#   kdbx41.kdbx   KDBX 4.1: the full source, including an entry excluded from reports
#   keyfile.kdbx  KDBX 3.1, password + key file (keyfile.keyx), one entry
#   keyonly.kdbx  KDBX 3.1, key file only (keyonly.keyx), no password, one entry
#
# Password for all of them: fixture-pass. Needs keepassxc-cli 2.7 or later.
set -euo pipefail
cd "$(dirname "$0")"
pw=fixture-pass
command -v keepassxc-cli >/dev/null || { echo "keepassxc-cli not found" >&2; exit 1; }
rm -f kdbx31.kdbx kdbx40.kdbx kdbx41.kdbx keyfile.kdbx keyfile.keyx keyonly.kdbx keyonly.keyx
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT

import() { printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli import -q -p "$1" "$2" 2>/dev/null; }

sed '/<QualityCheck>False<\/QualityCheck>/d' source.xml > "$tmp/31.xml"
import "$tmp/31.xml" kdbx31.kdbx

sed 's#<Tags>dev;cloud</Tags>#<Tags>dev;cloud</Tags><CustomData><Item><Key>fixture</Key><Value>kdbx4</Value></Item></CustomData>#' \
  "$tmp/31.xml" > "$tmp/40.xml"
import "$tmp/40.xml" kdbx40.kdbx

import source.xml kdbx41.kdbx

printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli db-create -q -p --set-key-file keyfile.keyx keyfile.kdbx 2>/dev/null
printf '%s\n' "$pw" | keepassxc-cli add -q -k keyfile.keyx -u kfuser --url https://example.invalid \
  keyfile.kdbx "Key file entry" 2>/dev/null

keepassxc-cli db-create -q --set-key-file keyonly.keyx keyonly.kdbx 2>/dev/null
keepassxc-cli add -q --no-password -k keyonly.keyx -u keyonly keyonly.kdbx "Key only entry" 2>/dev/null

for f in kdbx31.kdbx kdbx40.kdbx kdbx41.kdbx keyfile.kdbx keyonly.kdbx; do
  v="$(head -c 12 "$f" | od -An -tx1 | tr -d ' \n')"
  printf '%-13s version %s.%s\n' "$f" "$((16#${v:22:2}${v:20:2}))" "$((16#${v:18:2}${v:16:2}))"
done
