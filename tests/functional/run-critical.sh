#!/usr/bin/env bash
# Minimum critical auth + tenant isolation tests for CI (#102).
set -euo pipefail

API="${API_BASE:-http://localhost:8080}"
SYS_TENANT="00000000-0000-0000-0000-000000000001"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@xavyo.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@1234}"

pass=0
fail=0

assert_status() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "[critical] PASS: $name (HTTP $actual)"
    pass=$((pass + 1))
  else
    echo "[critical] FAIL: $name (expected HTTP $expected, got $actual)"
    fail=$((fail + 1))
  fi
}

echo "[critical] === Admin login (tenant A) ==="
login_a="$(curl -s -w "\n%{http_code}" -X POST "${API}/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${SYS_TENANT}" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
code_a="$(echo "$login_a" | tail -n1)"
body_a="$(echo "$login_a" | sed '$d')"
assert_status "admin login" "200" "$code_a"
token_a="$(echo "$body_a" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"

if [[ -z "$token_a" ]]; then
  echo "[critical] FAIL: no access_token in login response"
  fail=$((fail + 1))
else
  echo "[critical] PASS: received access_token"
  pass=$((pass + 1))
fi

echo "[critical] === Login without tenant header (must fail) ==="
no_tenant="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${API}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
assert_status "login without tenant" "401" "$no_tenant"

echo "[critical] === Authenticated GET /me/profile with correct tenant ==="
if [[ -n "$token_a" ]]; then
  me_ok="$(curl -s -o /dev/null -w "%{http_code}" "${API}/me/profile" \
    -H "Authorization: Bearer ${token_a}" \
    -H "X-Tenant-ID: ${SYS_TENANT}")"
  assert_status "GET /me/profile" "200" "$me_ok"
fi

echo "[critical] === Summary: ${pass} passed, ${fail} failed ==="
[[ "$fail" -eq 0 ]]
