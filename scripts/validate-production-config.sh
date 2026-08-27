#!/usr/bin/env bash
# Verify production config validation rejects insecure defaults (#103).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_ROOT/docker/keys"

if [[ ! -f "$KEYS_DIR/jwt_private.pem" ]]; then
  bash "$PROJECT_ROOT/docker/generate-keys.sh"
fi

export APP_ENV=production
export DATABASE_URL="postgres://xavyo:xavyo_test_password@localhost:5432/xavyo_test"
export ISSUER_URL="https://idp.example.com"
export FRONTEND_URL="https://app.example.com"
export CORS_ORIGINS="https://app.example.com"
export JWT_PRIVATE_KEY="$(cat "$KEYS_DIR/jwt_private.pem")"
export JWT_PUBLIC_KEY="$(cat "$KEYS_DIR/jwt_public.pem")"
# Intentionally omit custom encryption keys — defaults must be rejected in production.

echo "[config-validate] Building idp-api..."
SQLX_OFFLINE=true cargo build -p idp-api --quiet

echo "[config-validate] Expecting startup failure with insecure encryption keys..."
set +e
output="$("$PROJECT_ROOT/target/debug/idp-api" 2>&1)"
code=$?
set -e

if [[ "$code" -eq 0 ]]; then
  echo "[config-validate] FAIL: idp-api started with insecure production config"
  echo "$output"
  exit 1
fi

if ! echo "$output" | grep -q "FATAL:.*insecure default"; then
  echo "[config-validate] FAIL: expected FATAL insecure-default message"
  echo "$output"
  exit 1
fi

echo "[config-validate] PASS: production mode rejected insecure defaults"
