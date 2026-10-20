#!/usr/bin/env sh
# Adds a vault key for a purpose (ADR-013): prepends a new X25519 private key to
# secrets/keyrings/<purpose>.keyring and prints the public key line to put in .env.
# The private key never leaves the keyring file. Usage: vault-keygen.sh <purpose> [key id]
set -eu
cd "$(dirname "$0")/.."
purpose=${1:-}
key_id=${2:-k$(date -u +%Y%m%d%H%M)}
case "$purpose" in
  llm|source|connector|webhook) ;;
  *) echo "usage: $0 llm|source|connector|webhook [key id]" >&2; exit 2 ;;
esac
case "$key_id" in
  ""|-*|*[!a-z0-9-]*) echo "key id: lowercase letters, digits and dashes" >&2; exit 2 ;;
esac
umask 077
dir=secrets/keyrings
mkdir -p "$dir"
chmod 700 secrets "$dir"
file="$dir/$purpose.keyring"
if [ -f "$file" ] && grep -q "^$key_id:" "$file"; then
  echo "key $key_id already exists in $file" >&2
  exit 1
fi
der=$(mktemp)
trap 'rm -f "$der" "$file.tmp"' EXIT
openssl genpkey -algorithm X25519 -outform DER -out "$der"
# Raw keys are the last 32 bytes of the PKCS#8 and SubjectPublicKeyInfo encodings.
private=$(tail -c 32 "$der" | base64 | tr -d '\n')
public=$(openssl pkey -inform DER -in "$der" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
{
  printf '%s:%s\n' "$key_id" "$private"
  if [ -f "$file" ]; then cat "$file"; fi
} > "$file.tmp"
# Readable by the non-root containers it is mounted into; the directory stays 700.
chmod 644 "$file.tmp"
mv "$file.tmp" "$file"
printf 'VV_VAULT_PUBLIC_KEY_%s=%s:%s\n' "$(printf '%s' "$purpose" | tr a-z A-Z)" "$key_id" "$public"
