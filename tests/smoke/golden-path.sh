#!/usr/bin/env bash
# Golden path smoke test: readyz + bootstrap admin login (#101).
set -euo pipefail

API="${API_BASE:-http://localhost:8080}"
SYS_TENANT="00000000-0000-0000-0000-000000000001"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@xavyo.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@1234}"
TIMEOUT="${SMOKE_TIMEOUT:-120}"

echo "[smoke] Waiting for ${API}/readyz (timeout ${TIMEOUT}s)..."
deadline=$((SECONDS + TIMEOUT))
until curl -sf "${API}/readyz" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "[smoke] FAIL: readyz not healthy within ${TIMEOUT}s"
    exit 1
  fi
  sleep 2
done
echo "[smoke] readyz OK"

health="$(curl -sf "${API}/health")"
echo "[smoke] health: ${health}"

login_response="$(curl -sf -w "\n%{http_code}" -X POST "${API}/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${SYS_TENANT}" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")"

http_code="$(echo "$login_response" | tail -n1)"
body="$(echo "$login_response" | sed '$d')"

if [[ "$http_code" != "200" ]]; then
  echo "[smoke] FAIL: login returned HTTP ${http_code}"
  echo "$body"
  exit 1
fi

if ! echo "$body" | grep -q '"access_token"'; then
  echo "[smoke] FAIL: login response missing access_token"
  echo "$body"
  exit 1
fi

echo "[smoke] admin login OK"

if [[ -n "${DATABASE_URL:-}" ]] && command -v psql &>/dev/null; then
  echo "[smoke] Verifying bootstrap admin in database (#110)..."
  admin_role="$(psql "$DATABASE_URL" -tAc \
    "SELECT ur.role_name FROM users u JOIN user_roles ur ON ur.user_id = u.id \
     WHERE u.tenant_id = '${SYS_TENANT}' AND lower(u.email) = lower('${ADMIN_EMAIL}') LIMIT 1")"
  admin_role="$(echo "$admin_role" | tr -d '[:space:]')"
  if [[ "$admin_role" != "super_admin" ]]; then
    echo "[smoke] FAIL: expected super_admin role, got '${admin_role}'"
    exit 1
  fi
  echo "[smoke] bootstrap admin has super_admin role"
fi

echo "[smoke] PASS — golden path verified"
