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
while IFS= read -r line; do
  case "$line" in
    *PASSWORD*=) printf '%s%s\n' "$line" "$(secret)" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.example > .env
echo "wrote .env (mode 600)"
