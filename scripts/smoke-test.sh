#!/usr/bin/env sh
# Smoke test of a running stack (make up): TLS front, both APIs, security headers,
# back-office API absent from the portal host. Exits non-zero on the first failure.
#
# Optional: VV_SMOKE_LLM_CONNECTOR=<engine connector id> (and VV_SMOKE_LLM_MODEL) asks
# that AI engine one question from the ai worker's container, through the egress proxy:
# it proves the vault keyring, the approved private range, smokescreen's allow_ranges
# and the internal CA of a self-hosted model (docs/DEPLOYMENT.md §7 bis).
set -eu

BO="${VV_BACKOFFICE_HOST:-backoffice.localhost}"
PO="${VV_PORTAL_HOST:-portal.localhost}"
PORT="${VV_HTTPS_PORT:-443}"
CURL="curl -sk --max-time 10 --resolve $BO:$PORT:127.0.0.1 --resolve $PO:$PORT:127.0.0.1"

fail() { echo "FAIL: $*" >&2; exit 1; }

$CURL "https://$BO:$PORT/healthz" | grep -q '"service":"backoffice"' || fail "back-office /healthz"
$CURL "https://$PO:$PORT/healthz" | grep -q '"service":"portal"' || fail "portal /healthz"

code=$($CURL -o /dev/null -w '%{http_code}' "https://$PO:$PORT/api/v1/openapi.json")
[ "$code" = "404" ] || fail "back-office API reachable on the portal host ($code)"

headers=$($CURL -D - -o /dev/null "https://$PO:$PORT/")
for header in content-security-policy strict-transport-security x-content-type-options x-frame-options; do
  echo "$headers" | grep -qi "^$header:" || fail "missing $header"
done
echo "$headers" | grep -qi "^server:" && fail "server header exposed"

if [ -n "${VV_SMOKE_LLM_CONNECTOR:-}" ]; then
  COMPOSE="docker compose -f deploy/docker-compose.yml --env-file .env"
  set -- --connector "$VV_SMOKE_LLM_CONNECTOR"
  [ -n "${VV_SMOKE_LLM_MODEL:-}" ] && set -- "$@" --model "$VV_SMOKE_LLM_MODEL"
  $COMPOSE run --rm --no-deps -T worker-ai python -m app.cli llm-check "$@" \
    || fail "AI engine $VV_SMOKE_LLM_CONNECTOR did not answer"
  echo "AI engine answered"
fi

echo "smoke test passed"
