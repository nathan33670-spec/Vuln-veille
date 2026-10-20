#!/usr/bin/env sh
# Creates .env from .env.example with fresh random secrets. Refuses to overwrite.
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  echo ".env already exists; remove it first if you really want new secrets" >&2
  exit 1
fi
umask 077
secret() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
aes_key() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
while IFS= read -r line; do
  case "$line" in
    VV_SMTP_PASSWORD=) printf '%s\n' "$line" ;;
    VV_SECRET_KEY=) printf '%s%s%s\n' "$line" "$(secret)" "$(secret)" ;;
    VV_KEK_*=) printf '%s%s\n' "$line" "$(aes_key)" ;;
    *PASSWORD*=) printf '%s%s\n' "$line" "$(secret)" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.example > .env
echo "wrote .env (mode 600)"
