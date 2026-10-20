#!/usr/bin/env sh
# Smoke test of a running stack (make up): TLS front, both APIs, security headers,
# back-office API absent from the portal host. Exits non-zero on the first failure.
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

echo "smoke test passed"
