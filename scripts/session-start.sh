#!/usr/bin/env bash
# Claude Code SessionStart hook: prepares a fresh cloud container so that
# `make lint typecheck test` (and integration tests) work right away.
# Local sessions are left untouched.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/..}"

(cd backend && uv sync --frozen --quiet)
(cd frontend && pnpm install --frozen-lockfile --silent)

# Integration tests need a Docker daemon; start one if the container allows it.
if command -v dockerd >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
  (nohup dockerd >/tmp/dockerd.log 2>&1 &) || true
fi

echo "Vuln-Veille: dependencies installed. Read CLAUDE.md, then docs/PROGRESS.md."
