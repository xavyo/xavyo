# xavyo Developer Makefile
# Dependency security audit targets

.PHONY: audit audit-fix deny deny-licenses deny-bans deny-sources

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
