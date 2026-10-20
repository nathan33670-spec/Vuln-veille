#!/usr/bin/env sh
# Creates .env from .env.example with fresh random secrets. Refuses to overwrite.
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  echo ".env already exists; remove it first if you really want new secrets" >&2
  exit 1
fi
if ls secrets/keyrings/*.keyring >/dev/null 2>&1; then
  echo "secrets/keyrings already holds vault keys: they decrypt existing secrets." >&2
  echo "Restore the matching .env from your backup instead of generating a new one." >&2
  exit 1
fi
umask 077
public_keys=$(mktemp)
trap 'rm -f "$public_keys"' EXIT
for purpose in llm source connector webhook; do
  ./scripts/vault-keygen.sh "$purpose" "k$(date -u +%Y%m%d)" >> "$public_keys"
done
secret() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
aes_key() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
while IFS= read -r line; do
  case "$line" in
    VV_SMTP_PASSWORD=) printf '%s\n' "$line" ;;
    VV_SECRET_KEY=) printf '%s%s%s\n' "$line" "$(secret)" "$(secret)" ;;
    VV_KEK_*=) printf '%s%s\n' "$line" "$(aes_key)" ;;
    VV_VAULT_PUBLIC_KEY_*=) grep "^$line" "$public_keys" ;;
    *PASSWORD*=) printf '%s%s\n' "$line" "$(secret)" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.example > .env
echo "wrote .env (mode 600) and the vault keyrings in secrets/keyrings"
echo "Back up .env and secrets/ offline: without them, stored secrets are lost."
