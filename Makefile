# Vuln-Veille — developer entry points. Run `make help`.
SHELL := /bin/sh
.DEFAULT_GOAL := help

COMPOSE := docker compose -f deploy/docker-compose.yml --env-file .env
BACKEND := cd backend &&
FRONTEND := cd frontend &&

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: install
install: ## Install backend and frontend dependencies
	$(BACKEND) uv sync --frozen
	$(FRONTEND) pnpm install --frozen-lockfile

.PHONY: env
env: ## Create .env with random secrets (refuses to overwrite)
	./scripts/gen-env.sh

.PHONY: up
up: ## Build and start the whole stack (Docker)
	$(COMPOSE) up -d --build

.PHONY: dev
dev: ## Start the stack with development extras (Mailpit)
	$(COMPOSE) --profile dev up -d --build

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) --profile dev down

.PHONY: logs
logs: ## Follow logs
	$(COMPOSE) logs -f --tail=100

.PHONY: migrate
migrate: ## Provision database roles and apply migrations
	$(COMPOSE) run --rm migrate

.PHONY: lint
lint: ## Lint and format checks
	$(BACKEND) uv run ruff check . && uv run ruff format --check .
	$(FRONTEND) pnpm lint

.PHONY: format
format: ## Auto-format code
	$(BACKEND) uv run ruff check --fix . && uv run ruff format .
	$(FRONTEND) pnpm format

.PHONY: typecheck
typecheck: ## Static type checks
	$(BACKEND) uv run mypy
	$(FRONTEND) pnpm typecheck

.PHONY: test
test: ## Unit and security tests (no Docker needed)
	$(BACKEND) uv run pytest -m "not integration"
	$(FRONTEND) pnpm test

.PHONY: test-integration
test-integration: ## Integration tests (needs Docker)
	$(BACKEND) uv run pytest -m integration

.PHONY: api-client
api-client: ## Regenerate OpenAPI schemas and the TypeScript client
	$(BACKEND) uv run python -m app.cli export-openapi --output-dir ../openapi >/dev/null
	$(FRONTEND) pnpm --filter @vv/api-client generate

GITLEAKS_IMAGE := zricethezav/gitleaks:v8.30.0@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9

.PHONY: security
security: ## Dependency audits and secret scan (gitleaks needs Docker)
	$(BACKEND) uv export --frozen --no-dev --no-hashes --no-emit-project --format requirements-txt -o .audit-requirements.txt >/dev/null \
		&& uv run pip-audit --strict --progress-spinner off --disable-pip --no-deps -r .audit-requirements.txt; \
		status=$$?; rm -f .audit-requirements.txt; exit $$status
	$(FRONTEND) pnpm audit --prod
	docker run --rm -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) git /repo --no-banner --redact

.PHONY: check
check: lint typecheck test ## Everything CI runs without Docker
