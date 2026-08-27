# xavyo Developer Makefile
# Dependency security audit targets + local dev shortcuts (#100)

.PHONY: audit audit-fix deny deny-licenses deny-bans deny-sources dev dev-setup dev-run smoke

POSTGRES_PORT ?= 5434

## One-command local dev: env + docker services + build (#100)
dev: dev-setup
	@echo ""
	@echo "Run the API: make dev-run"
	@echo "Then verify: curl http://localhost:8080/readyz"
	@echo "Login: admin@xavyo.local / Admin@1234"
	@echo "Tenant: 00000000-0000-0000-0000-000000000001"

dev-setup:
	@bash scripts/setup-dev-env.sh
	@POSTGRES_PORT=$(POSTGRES_PORT) bash scripts/dev-env.sh start
	@POSTGRES_PORT=$(POSTGRES_PORT) bash scripts/wait-for-services.sh --postgres-only
	@bash scripts/cargo-dev.sh build -p idp-api

dev-run:
	@set -a && . ./.env && set +a && bash scripts/cargo-dev.sh run -p idp-api

smoke:
	@bash tests/smoke/golden-path.sh

## Run full security audit (cargo-deny enforces policy; cargo-audit shows details)
audit:
	cargo deny check
	@echo ""
	@echo "=== Informational: cargo audit output (exempted advisories may appear) ==="
	-cargo audit

## Auto-fix vulnerabilities by updating Cargo.lock
audit-fix:
	cargo audit fix

## Run all cargo-deny checks (advisories, licenses, bans, sources)
deny:
	cargo deny check

## Check license compliance only
deny-licenses:
	cargo deny check licenses

## Check banned crates only
deny-bans:
	cargo deny check bans

## Check source restrictions only
deny-sources:
	cargo deny check sources
