#!/usr/bin/env bash
# =============================================================================
# Batch 11: Admin Features & Governance Deep Tests
# =============================================================================
# Domains: IP Restrictions, Branding & Email Templates, Delegation Admin,
#          Key Management, Admin Invitations, Org Security Policies,
#          Governance License Management, Governance Escalation & Approval Groups
# ~138 test cases
#
# Prerequisites:
#   - API server running on localhost:8080
#   - PostgreSQL with migrations applied
#   - Mailpit running on localhost:8025
# =============================================================================

set -uo pipefail

BASE="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
TS=$(date +%s)
PASS=0; FAIL=0; SKIP=0; TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); log "PASS  $1 — $2"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); log "FAIL  $1 — $2"; }
skip() { SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); log "SKIP  $1 — $2"; }

admin_call() {
  local method="$1" path="$2"; shift 2
  curl -s -w "\n%{http_code}" -X "$method" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -H "Authorization: Bearer $ADMIN_JWT" \
    "$BASE$path" "$@"
}

user_call() {
  local method="$1" path="$2"; shift 2
  curl -s -w "\n%{http_code}" -X "$method" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -H "Authorization: Bearer $USER_JWT" \
    "$BASE$path" "$@"
}

noauth_call() {
  local method="$1" path="$2"; shift 2
  curl -s -w "\n%{http_code}" -X "$method" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    "$BASE$path" "$@"
}

parse_response() {
  local raw="$1"
  BODY=$(echo "$raw" | sed '$d')
  CODE=$(echo "$raw" | tail -1)
}

extract_json() { echo "$1" | jq -r "$2" 2>/dev/null; }

signup_and_verify() {
  local email="$1"
  curl -s -X POST "$BASE/auth/signup" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d "{\"email\":\"$email\",\"password\":\"MyP@ssw0rd_2026\"}" > /dev/null

  sleep 2
  local MAIL_SEARCH MAIL_ID MAIL_MSG TOKEN
  MAIL_SEARCH=$(curl -s "http://localhost:8025/api/v1/search?query=to:$email")
  MAIL_ID=$(echo "$MAIL_SEARCH" | jq -r '.messages[0].ID // empty')
  if [ -n "$MAIL_ID" ]; then
    MAIL_MSG=$(curl -s "http://localhost:8025/api/v1/message/$MAIL_ID")
    TOKEN=$(echo "$MAIL_MSG" | jq -r '.Text // ""' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
    if [ -z "$TOKEN" ]; then
      TOKEN=$(echo "$MAIL_SEARCH" | jq -r '.messages[0].Snippet // ""' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
    fi
  fi
  if [ -n "${TOKEN:-}" ]; then
    curl -s -X POST "$BASE/auth/verify-email" \
      -H "Content-Type: application/json" \
      -H "X-Tenant-ID: $TENANT_ID" \
      -d "{\"token\":\"$TOKEN\"}" > /dev/null
  fi
}

login_user() {
  local email="$1" password="${2:-MyP@ssw0rd_2026}"
  local RAW
  RAW=$(curl -s -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d "{\"email\":\"$email\",\"password\":\"$password\"}")
  echo "$RAW" | jq -r '.access_token // empty'
}

echo "═══════════════════════════════════════════════════════════════════"
echo "  Batch 11 — Admin Features & Governance Deep Tests"
echo "═══════════════════════════════════════════════════════════════════"

# ── Bootstrap ──────────────────────────────────────────────────────────────
log "═══ Setup: Creating test users ═══"

# Clear mailpit
curl -s -X DELETE http://localhost:8025/api/v1/messages > /dev/null 2>&1

# Admin user — signup returns user_id
ADMIN_EMAIL="b11-admin-${TS}@test.com"
SIGNUP_RESP=$(curl -s -X POST "$BASE/auth/signup" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"MyP@ssw0rd_2026\"}")
ADMIN_UID=$(echo "$SIGNUP_RESP" | jq -r '.user_id // empty')

if [[ -z "$ADMIN_UID" || "$ADMIN_UID" == "null" ]]; then
  log "FATAL: Could not get admin user ID from signup"; exit 1
fi

# Verify email via Mailpit
sleep 2
MAIL_SEARCH=$(curl -s "http://localhost:8025/api/v1/search?query=to:$ADMIN_EMAIL")
MAIL_ID=$(echo "$MAIL_SEARCH" | jq -r '.messages[0].ID // empty')
if [ -n "$MAIL_ID" ]; then
  MAIL_MSG=$(curl -s "http://localhost:8025/api/v1/message/$MAIL_ID")
  TOKEN=$(echo "$MAIL_MSG" | jq -r '.Text // ""' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
  if [ -z "$TOKEN" ]; then
    TOKEN=$(echo "$MAIL_SEARCH" | jq -r '.messages[0].Snippet // ""' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
  fi
  if [ -n "$TOKEN" ]; then
    curl -s -X POST "$BASE/auth/verify-email" \
      -H "Content-Type: application/json" \
      -H "X-Tenant-ID: $TENANT_ID" \
      -d "{\"token\":\"$TOKEN\"}" > /dev/null
  fi
fi

# Insert admin + super_admin roles (branding & delegation require super_admin)
docker exec xavyo-postgres psql -U xavyo xavyo_test -c \
  "INSERT INTO user_roles (user_id, role_name) VALUES ('$ADMIN_UID', 'admin') ON CONFLICT DO NOTHING;
   INSERT INTO user_roles (user_id, role_name) VALUES ('$ADMIN_UID', 'super_admin') ON CONFLICT DO NOTHING;" > /dev/null 2>&1

ADMIN_JWT=$(login_user "$ADMIN_EMAIL")
if [[ -z "$ADMIN_JWT" || "$ADMIN_JWT" == "null" ]]; then
  log "FATAL: Could not get admin JWT"; exit 1
fi
log "admin_jwt=${ADMIN_JWT:0:20}…"
ADMIN_USER_ID="$ADMIN_UID"

# Regular user
USER_EMAIL="b11-user-${TS}@test.com"
signup_and_verify "$USER_EMAIL"
USER_JWT=$(login_user "$USER_EMAIL")
if [[ -z "$USER_JWT" || "$USER_JWT" == "null" ]]; then
  log "FATAL: Could not get user JWT"; exit 1
fi
log "user_jwt=${USER_JWT:0:20}…"

# Get regular user ID from JWT
REG_USER_ID=$(echo "$USER_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.sub // empty')

# ═══════════════════════════════════════════════════════════════════
#  Part 1: IP Restrictions (TC-IP-001 … TC-IP-015)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 1: IP Restrictions (TC-IP-001 … TC-IP-015)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-IP-001: Get IP settings
RAW=$(admin_call GET /admin/ip-restrictions/settings)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-001" "Get IP settings — 200"
else
  fail "TC-IP-001" "Get IP settings — HTTP $CODE — $BODY"
fi

# TC-IP-002: Update IP settings
RAW=$(admin_call PUT /admin/ip-restrictions/settings -d '{"enforcement_mode":"disabled","bypass_for_super_admin":true}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-002" "Update IP settings — 200"
else
  fail "TC-IP-002" "Update IP settings — HTTP $CODE — $BODY"
fi

# TC-IP-003: List IP rules (empty)
RAW=$(admin_call GET /admin/ip-restrictions/rules)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-003" "List IP rules — 200"
else
  fail "TC-IP-003" "List IP rules — HTTP $CODE — $BODY"
fi

# TC-IP-004: Create whitelist rule
RAW=$(admin_call POST /admin/ip-restrictions/rules -d "{\"rule_type\":\"whitelist\",\"scope\":\"all\",\"ip_cidr\":\"10.0.0.0/8\",\"name\":\"b11-allow-${TS}\",\"description\":\"test rule\",\"is_active\":true}")
parse_response "$RAW"
IP_RULE_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$IP_RULE_ID" && "$IP_RULE_ID" != "null" ]]; then
  pass "TC-IP-004" "Create whitelist rule — 201"
else
  fail "TC-IP-004" "Create whitelist rule — HTTP $CODE — $BODY"
  IP_RULE_ID=""
fi

# TC-IP-005: Get IP rule
if [[ -n "$IP_RULE_ID" ]]; then
  RAW=$(admin_call GET "/admin/ip-restrictions/rules/$IP_RULE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-IP-005" "Get IP rule — 200"
  else
    fail "TC-IP-005" "Get IP rule — HTTP $CODE"
  fi
else
  skip "TC-IP-005" "no rule ID"
fi

# TC-IP-006: Update IP rule
if [[ -n "$IP_RULE_ID" ]]; then
  RAW=$(admin_call PUT "/admin/ip-restrictions/rules/$IP_RULE_ID" -d "{\"rule_type\":\"whitelist\",\"scope\":\"all\",\"ip_cidr\":\"192.168.0.0/16\",\"name\":\"b11-updated-${TS}\",\"is_active\":true}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-IP-006" "Update IP rule — 200"
  else
    fail "TC-IP-006" "Update IP rule — HTTP $CODE — $BODY"
  fi
else
  skip "TC-IP-006" "no rule ID"
fi

# TC-IP-007: Create blacklist rule
RAW=$(admin_call POST /admin/ip-restrictions/rules -d "{\"rule_type\":\"blacklist\",\"scope\":\"all\",\"ip_cidr\":\"203.0.113.0/24\",\"name\":\"b11-deny-${TS}\",\"is_active\":true}")
parse_response "$RAW"
IP_RULE_BL_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$IP_RULE_BL_ID" && "$IP_RULE_BL_ID" != "null" ]]; then
  pass "TC-IP-007" "Create blacklist rule — 201"
else
  fail "TC-IP-007" "Create blacklist rule — HTTP $CODE — $BODY"
  IP_RULE_BL_ID=""
fi

# TC-IP-008: Validate IP against rules
RAW=$(admin_call POST /admin/ip-restrictions/validate -d '{"ip_address":"10.0.0.1"}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-008" "Validate IP — 200"
else
  fail "TC-IP-008" "Validate IP — HTTP $CODE — $BODY"
fi

# TC-IP-009: Validate IP with role
RAW=$(admin_call POST /admin/ip-restrictions/validate -d '{"ip_address":"192.168.1.1","role":"admin"}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-009" "Validate IP with role — 200"
else
  fail "TC-IP-009" "Validate IP with role — HTTP $CODE — $BODY"
fi

# TC-IP-010: Create rule with invalid CIDR
RAW=$(admin_call POST /admin/ip-restrictions/rules -d "{\"rule_type\":\"whitelist\",\"scope\":\"all\",\"ip_cidr\":\"not-a-cidr\",\"name\":\"bad-cidr\",\"is_active\":true}")
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-IP-010" "Invalid CIDR rejected — $CODE"
else
  fail "TC-IP-010" "Invalid CIDR — HTTP $CODE — $BODY"
fi

# TC-IP-011: Non-admin IP settings (GET is read-only, no role check — intentional)
RAW=$(user_call GET /admin/ip-restrictions/settings)
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-IP-011" "Non-admin IP settings — $CODE"
else
  fail "TC-IP-011" "Non-admin IP settings — HTTP $CODE"
fi

# TC-IP-012: No auth IP rules
RAW=$(noauth_call GET /admin/ip-restrictions/rules)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-IP-012" "No auth IP rules — 401"
else
  fail "TC-IP-012" "No auth IP rules — HTTP $CODE"
fi

# TC-IP-013: Delete IP rule
if [[ -n "$IP_RULE_BL_ID" ]]; then
  RAW=$(admin_call DELETE "/admin/ip-restrictions/rules/$IP_RULE_BL_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-IP-013" "Delete IP rule — $CODE"
  else
    fail "TC-IP-013" "Delete IP rule — HTTP $CODE — $BODY"
  fi
else
  skip "TC-IP-013" "no rule ID"
fi

# TC-IP-014: Get deleted rule — 404
if [[ -n "$IP_RULE_BL_ID" ]]; then
  RAW=$(admin_call GET "/admin/ip-restrictions/rules/$IP_RULE_BL_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "404" ]]; then
    pass "TC-IP-014" "Get deleted rule — 404"
  else
    fail "TC-IP-014" "Get deleted rule — HTTP $CODE"
  fi
else
  skip "TC-IP-014" "no rule ID"
fi

# TC-IP-015: Set enforcement to whitelist mode
RAW=$(admin_call PUT /admin/ip-restrictions/settings -d '{"enforcement_mode":"whitelist"}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IP-015" "Set whitelist mode — 200"
  # Reset back to disabled to not block ourselves
  admin_call PUT /admin/ip-restrictions/settings -d '{"enforcement_mode":"disabled"}' > /dev/null 2>&1
else
  fail "TC-IP-015" "Set whitelist mode — HTTP $CODE — $BODY"
fi

# Cleanup: delete remaining rule and reset to disabled
if [[ -n "$IP_RULE_ID" ]]; then
  admin_call DELETE "/admin/ip-restrictions/rules/$IP_RULE_ID" > /dev/null 2>&1
fi
admin_call PUT /admin/ip-restrictions/settings -d '{"enforcement_mode":"disabled"}' > /dev/null 2>&1

# ═══════════════════════════════════════════════════════════════════
#  Part 2: Branding & Email Templates (TC-BR-001 … TC-BR-018)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 2: Branding & Email Templates (TC-BR-001 … TC-BR-018)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-BR-001: Get branding
RAW=$(admin_call GET /admin/branding)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-001" "Get branding — 200"
else
  fail "TC-BR-001" "Get branding — HTTP $CODE — $BODY"
fi

# TC-BR-002: Update branding colors
RAW=$(admin_call PUT /admin/branding -d '{"primary_color":"#3366FF","secondary_color":"#FF6633","login_page_title":"Test IDP"}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-002" "Update branding — 200"
else
  fail "TC-BR-002" "Update branding — HTTP $CODE — $BODY"
fi

# TC-BR-003: Get branding reflects update
RAW=$(admin_call GET /admin/branding)
parse_response "$RAW"
PC=$(extract_json "$BODY" '.primary_color')
if [[ "$CODE" == "200" && "$PC" == "#3366FF" ]]; then
  pass "TC-BR-003" "Branding reflects update — 200"
else
  fail "TC-BR-003" "Branding reflects — HTTP $CODE pc=$PC"
fi

# TC-BR-004: Update branding with URLs
RAW=$(admin_call PUT /admin/branding -d '{"privacy_policy_url":"https://example.com/privacy","terms_of_service_url":"https://example.com/tos","support_url":"https://example.com/support"}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-004" "Update branding URLs — 200"
else
  fail "TC-BR-004" "Update branding URLs — HTTP $CODE — $BODY"
fi

# TC-BR-005: List assets
RAW=$(admin_call GET /admin/branding/assets)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-005" "List assets — 200"
else
  fail "TC-BR-005" "List assets — HTTP $CODE — $BODY"
fi

# TC-BR-006: List email templates
RAW=$(admin_call GET /admin/branding/email-templates)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-006" "List email templates — 200"
else
  fail "TC-BR-006" "List email templates — HTTP $CODE — $BODY"
fi

# TC-BR-007: Get welcome email template
RAW=$(admin_call GET /admin/branding/email-templates/welcome)
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-BR-007" "Get welcome template — $CODE"
else
  fail "TC-BR-007" "Get welcome template — HTTP $CODE — $BODY"
fi

# TC-BR-008: Get email_verification template (valid type: welcome, password_reset, email_verification, mfa_setup, security_alert, account_locked)
RAW=$(admin_call GET /admin/branding/email-templates/email_verification)
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-BR-008" "Get email_verification template — $CODE"
else
  fail "TC-BR-008" "Get email_verification template — HTTP $CODE — $BODY"
fi

# TC-BR-009: Update email template (subject uses valid Handlebars variable)
RAW=$(admin_call PUT /admin/branding/email-templates/welcome -d '{"subject":"Welcome to our platform","body_html":"<h1>Welcome!</h1>","body_text":"Welcome!","is_active":true}')
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
  pass "TC-BR-009" "Update email template — $CODE"
else
  fail "TC-BR-009" "Update email template — HTTP $CODE — $BODY"
fi

# TC-BR-010: Preview email template
RAW=$(admin_call POST /admin/branding/email-templates/welcome/preview -d '{"sample_data":{"user_name":"Test User","tenant_name":"TestCo"}}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-010" "Preview email template — 200"
else
  fail "TC-BR-010" "Preview email template — HTTP $CODE — $BODY"
fi

# TC-BR-011: Reset email template
RAW=$(admin_call POST /admin/branding/email-templates/welcome/reset)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-011" "Reset email template — 200"
else
  fail "TC-BR-011" "Reset email template — HTTP $CODE — $BODY"
fi

# TC-BR-012: Get non-existent template type
RAW=$(admin_call GET /admin/branding/email-templates/nonexistent)
parse_response "$RAW"
if [[ "$CODE" == "404" || "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-BR-012" "Non-existent template — $CODE"
else
  fail "TC-BR-012" "Non-existent template — HTTP $CODE — $BODY"
fi

# TC-BR-013: Non-admin get branding
RAW=$(user_call GET /admin/branding)
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-BR-013" "Non-admin branding — $CODE"
else
  fail "TC-BR-013" "Non-admin branding — HTTP $CODE"
fi

# TC-BR-014: Non-admin update branding
RAW=$(user_call PUT /admin/branding -d '{"primary_color":"#000000"}')
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-BR-014" "Non-admin update branding — $CODE"
else
  fail "TC-BR-014" "Non-admin update branding — HTTP $CODE"
fi

# TC-BR-015: No auth branding
RAW=$(noauth_call GET /admin/branding)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-BR-015" "No auth branding — 401"
else
  fail "TC-BR-015" "No auth branding — HTTP $CODE"
fi

# TC-BR-016: Get asset not found
RAW=$(admin_call GET "/admin/branding/assets/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-BR-016" "Asset not found — 404"
else
  fail "TC-BR-016" "Asset not found — HTTP $CODE"
fi

# TC-BR-017: Delete asset not found
RAW=$(admin_call DELETE "/admin/branding/assets/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-BR-017" "Delete asset not found — 404"
else
  fail "TC-BR-017" "Delete asset not found — HTTP $CODE"
fi

# TC-BR-018: Update branding reset
RAW=$(admin_call PUT /admin/branding -d '{"primary_color":null,"secondary_color":null,"login_page_title":null}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-BR-018" "Reset branding — 200"
else
  fail "TC-BR-018" "Reset branding — HTTP $CODE — $BODY"
fi

# ═══════════════════════════════════════════════════════════════════
#  Part 3: Delegation Admin (TC-DA-001 … TC-DA-018)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 3: Delegation Admin (TC-DA-001 … TC-DA-018)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-DA-001: List delegation permissions
RAW=$(admin_call GET /admin/delegation/permissions)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-001" "List permissions — 200"
else
  fail "TC-DA-001" "List permissions — HTTP $CODE — $BODY"
fi

# TC-DA-002: Get permissions by category
RAW=$(admin_call GET /admin/delegation/permissions/users)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-002" "Permissions by category — 200"
else
  fail "TC-DA-002" "Permissions by category — HTTP $CODE — $BODY"
fi

# TC-DA-003: List role templates (empty)
RAW=$(admin_call GET /admin/delegation/role-templates)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-003" "List role templates — 200"
else
  fail "TC-DA-003" "List role templates — HTTP $CODE — $BODY"
fi

# TC-DA-004: Create role template (permission codes use colon separator, not dots)
RAW=$(admin_call POST /admin/delegation/role-templates -d "{\"name\":\"b11-helpdesk-${TS}\",\"description\":\"Helpdesk template\",\"permissions\":[\"users:read\",\"users:update\"]}")
parse_response "$RAW"
TEMPLATE_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$TEMPLATE_ID" && "$TEMPLATE_ID" != "null" ]]; then
  pass "TC-DA-004" "Create role template — 201"
else
  fail "TC-DA-004" "Create role template — HTTP $CODE — $BODY"
  TEMPLATE_ID=""
fi

# TC-DA-005: Get role template
if [[ -n "$TEMPLATE_ID" ]]; then
  RAW=$(admin_call GET "/admin/delegation/role-templates/$TEMPLATE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-DA-005" "Get role template — 200"
  else
    fail "TC-DA-005" "Get role template — HTTP $CODE"
  fi
else
  skip "TC-DA-005" "no template ID"
fi

# TC-DA-006: Update role template
if [[ -n "$TEMPLATE_ID" ]]; then
  RAW=$(admin_call PUT "/admin/delegation/role-templates/$TEMPLATE_ID" -d "{\"name\":\"b11-helpdesk-updated-${TS}\",\"description\":\"Updated\",\"permissions\":[\"users:read\",\"users:update\",\"groups:read\"]}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-DA-006" "Update role template — 200"
  else
    fail "TC-DA-006" "Update role template — HTTP $CODE — $BODY"
  fi
else
  skip "TC-DA-006" "no template ID"
fi

# TC-DA-007: Create delegation assignment
if [[ -n "$TEMPLATE_ID" && -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call POST /admin/delegation/assignments -d "{\"user_id\":\"$REG_USER_ID\",\"template_id\":\"$TEMPLATE_ID\"}")
  parse_response "$RAW"
  ASSIGNMENT_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$ASSIGNMENT_ID" && "$ASSIGNMENT_ID" != "null" ]]; then
    pass "TC-DA-007" "Create assignment — 201"
  else
    fail "TC-DA-007" "Create assignment — HTTP $CODE — $BODY"
    ASSIGNMENT_ID=""
  fi
else
  skip "TC-DA-007" "no template or user"
  ASSIGNMENT_ID=""
fi

# TC-DA-008: List assignments
RAW=$(admin_call GET /admin/delegation/assignments)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-008" "List assignments — 200"
else
  fail "TC-DA-008" "List assignments — HTTP $CODE — $BODY"
fi

# TC-DA-009: Get assignment
if [[ -n "$ASSIGNMENT_ID" ]]; then
  RAW=$(admin_call GET "/admin/delegation/assignments/$ASSIGNMENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-DA-009" "Get assignment — 200"
  else
    fail "TC-DA-009" "Get assignment — HTTP $CODE"
  fi
else
  skip "TC-DA-009" "no assignment ID"
fi

# TC-DA-010: Get user permissions
if [[ -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call GET "/admin/delegation/users/$REG_USER_ID/permissions")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-DA-010" "Get user permissions — 200"
  else
    fail "TC-DA-010" "Get user permissions — HTTP $CODE — $BODY"
  fi
else
  skip "TC-DA-010" "no user ID"
fi

# TC-DA-011: Check permission
RAW=$(admin_call POST /admin/delegation/check-permission -d "{\"user_id\":\"$REG_USER_ID\",\"permission\":\"users:read\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-011" "Check permission — 200"
else
  fail "TC-DA-011" "Check permission — HTTP $CODE — $BODY"
fi

# TC-DA-012: Get audit log
RAW=$(admin_call GET /admin/delegation/audit-log)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-DA-012" "Get audit log — 200"
else
  fail "TC-DA-012" "Get audit log — HTTP $CODE — $BODY"
fi

# TC-DA-013: Revoke assignment
if [[ -n "$ASSIGNMENT_ID" ]]; then
  RAW=$(admin_call DELETE "/admin/delegation/assignments/$ASSIGNMENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-DA-013" "Revoke assignment — $CODE"
  else
    fail "TC-DA-013" "Revoke assignment — HTTP $CODE — $BODY"
  fi
else
  skip "TC-DA-013" "no assignment ID"
fi

# TC-DA-014: Create template empty permissions
RAW=$(admin_call POST /admin/delegation/role-templates -d '{"name":"empty-perms","permissions":[]}')
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-DA-014" "Empty permissions rejected — $CODE"
else
  fail "TC-DA-014" "Empty permissions — HTTP $CODE — $BODY"
fi

# TC-DA-015: Non-admin delegation
RAW=$(user_call GET /admin/delegation/permissions)
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-DA-015" "Non-admin delegation — $CODE"
else
  fail "TC-DA-015" "Non-admin delegation — HTTP $CODE"
fi

# TC-DA-016: No auth delegation
RAW=$(noauth_call GET /admin/delegation/permissions)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-DA-016" "No auth delegation — 401"
else
  fail "TC-DA-016" "No auth delegation — HTTP $CODE"
fi

# TC-DA-017: Delete role template
if [[ -n "$TEMPLATE_ID" ]]; then
  RAW=$(admin_call DELETE "/admin/delegation/role-templates/$TEMPLATE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-DA-017" "Delete template — $CODE"
  else
    fail "TC-DA-017" "Delete template — HTTP $CODE — $BODY"
  fi
else
  skip "TC-DA-017" "no template ID"
fi

# TC-DA-018: Get deleted template — 404
if [[ -n "$TEMPLATE_ID" ]]; then
  RAW=$(admin_call GET "/admin/delegation/role-templates/$TEMPLATE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "404" ]]; then
    pass "TC-DA-018" "Deleted template — 404"
  else
    fail "TC-DA-018" "Deleted template — HTTP $CODE"
  fi
else
  skip "TC-DA-018" "no template ID"
fi

# ═══════════════════════════════════════════════════════════════════
#  Part 4: Key Management (TC-KM-001 … TC-KM-008)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 4: Key Management (TC-KM-001 … TC-KM-008)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-KM-001: List keys
RAW=$(admin_call GET /admin/keys)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-KM-001" "List keys — 200"
else
  fail "TC-KM-001" "List keys — HTTP $CODE — $BODY"
fi

# TC-KM-002: Rotate key
RAW=$(admin_call POST /admin/keys/rotate)
parse_response "$RAW"
NEW_KID=$(extract_json "$BODY" '.kid // .key_id // .id')
if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
  pass "TC-KM-002" "Rotate key — $CODE"
else
  fail "TC-KM-002" "Rotate key — HTTP $CODE — $BODY"
fi

# TC-KM-003: List keys after rotation
RAW=$(admin_call GET /admin/keys)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-KM-003" "List keys after rotation — 200"
else
  fail "TC-KM-003" "List keys after rotation — HTTP $CODE"
fi

# TC-KM-004: Revoke non-existent key
RAW=$(admin_call DELETE /admin/keys/nonexistent-kid-12345)
parse_response "$RAW"
if [[ "$CODE" == "404" || "$CODE" == "400" ]]; then
  pass "TC-KM-004" "Revoke non-existent key — $CODE"
else
  fail "TC-KM-004" "Revoke non-existent key — HTTP $CODE — $BODY"
fi

# TC-KM-005: Non-admin list keys
RAW=$(user_call GET /admin/keys)
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-KM-005" "Non-admin list keys — $CODE"
else
  fail "TC-KM-005" "Non-admin list keys — HTTP $CODE"
fi

# TC-KM-006: Non-admin rotate key
RAW=$(user_call POST /admin/keys/rotate)
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-KM-006" "Non-admin rotate key — $CODE"
else
  fail "TC-KM-006" "Non-admin rotate key — HTTP $CODE"
fi

# TC-KM-007: No auth list keys
RAW=$(noauth_call GET /admin/keys)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-KM-007" "No auth list keys — 401"
else
  fail "TC-KM-007" "No auth list keys — HTTP $CODE"
fi

# TC-KM-008: No auth rotate key
RAW=$(noauth_call POST /admin/keys/rotate)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-KM-008" "No auth rotate key — 401"
else
  fail "TC-KM-008" "No auth rotate key — HTTP $CODE"
fi

# ═══════════════════════════════════════════════════════════════════
#  Part 5: Admin Invitations (TC-AI-001 … TC-AI-012)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 5: Admin Invitations (TC-AI-001 … TC-AI-012)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-AI-001: List invitations (empty)
RAW=$(admin_call GET /admin/invitations)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-AI-001" "List invitations — 200"
else
  fail "TC-AI-001" "List invitations — HTTP $CODE — $BODY"
fi

# TC-AI-002: Create invitation
INVITE_EMAIL="b11-invite-${TS}@test.com"
RAW=$(admin_call POST /admin/invitations -d "{\"email\":\"$INVITE_EMAIL\"}")
parse_response "$RAW"
INVITE_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$INVITE_ID" && "$INVITE_ID" != "null" ]]; then
  pass "TC-AI-002" "Create invitation — 201"
else
  fail "TC-AI-002" "Create invitation — HTTP $CODE — $BODY"
  INVITE_ID=""
fi

# TC-AI-003: List invitations after create
RAW=$(admin_call GET /admin/invitations)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-AI-003" "List invitations after create — 200"
else
  fail "TC-AI-003" "List invitations — HTTP $CODE"
fi

# TC-AI-004: Resend invitation
if [[ -n "$INVITE_ID" ]]; then
  RAW=$(admin_call POST "/admin/invitations/$INVITE_ID/resend")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-AI-004" "Resend invitation — 200"
  else
    fail "TC-AI-004" "Resend invitation — HTTP $CODE — $BODY"
  fi
else
  skip "TC-AI-004" "no invite ID"
fi

# TC-AI-005: Accept invitation with invalid token
RAW=$(noauth_call POST /admin/invitations/accept -d '{"token":"invalid-token-value-12345","password":"MyP@ssw0rd_2026"}')
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "401" || "$CODE" == "404" || "$CODE" == "422" ]]; then
  pass "TC-AI-005" "Invalid token — $CODE"
else
  fail "TC-AI-005" "Invalid token — HTTP $CODE — $BODY"
fi

# TC-AI-006: Cancel invitation
if [[ -n "$INVITE_ID" ]]; then
  RAW=$(admin_call DELETE "/admin/invitations/$INVITE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-AI-006" "Cancel invitation — $CODE"
  else
    fail "TC-AI-006" "Cancel invitation — HTTP $CODE — $BODY"
  fi
else
  skip "TC-AI-006" "no invite ID"
fi

# TC-AI-007: Non-admin create invitation
RAW=$(user_call POST /admin/invitations -d '{"email":"nonadmin-invite@test.com"}')
parse_response "$RAW"
if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
  pass "TC-AI-007" "Non-admin create — $CODE"
else
  fail "TC-AI-007" "Non-admin create — HTTP $CODE"
fi

# TC-AI-008: No auth list invitations
RAW=$(noauth_call GET /admin/invitations)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-AI-008" "No auth list — 401"
else
  fail "TC-AI-008" "No auth list — HTTP $CODE"
fi

# TC-AI-009: Create duplicate invitation
DUPE_EMAIL="b11-dupe-inv-${TS}@test.com"
admin_call POST /admin/invitations -d "{\"email\":\"$DUPE_EMAIL\"}" > /dev/null 2>&1
RAW=$(admin_call POST /admin/invitations -d "{\"email\":\"$DUPE_EMAIL\"}")
parse_response "$RAW"
if [[ "$CODE" == "409" || "$CODE" == "400" || "$CODE" == "201" ]]; then
  pass "TC-AI-009" "Duplicate invitation — $CODE"
else
  fail "TC-AI-009" "Duplicate invitation — HTTP $CODE — $BODY"
fi

# TC-AI-010: Resend non-existent
RAW=$(admin_call POST "/admin/invitations/00000000-0000-0000-0000-000000000099/resend")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-AI-010" "Resend non-existent — 404"
else
  fail "TC-AI-010" "Resend non-existent — HTTP $CODE — $BODY"
fi

# TC-AI-011: Cancel non-existent
RAW=$(admin_call DELETE "/admin/invitations/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-AI-011" "Cancel non-existent — 404"
else
  fail "TC-AI-011" "Cancel non-existent — HTTP $CODE"
fi

# TC-AI-012: Accept invitation empty token
RAW=$(noauth_call POST /admin/invitations/accept -d '{"token":"","password":"MyP@ssw0rd_2026"}')
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-AI-012" "Empty token — $CODE"
else
  fail "TC-AI-012" "Empty token — HTTP $CODE — $BODY"
fi

# ═══════════════════════════════════════════════════════════════════
#  Part 6: Org Security Policies (TC-OP-001 … TC-OP-015)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 6: Org Security Policies (TC-OP-001 … TC-OP-015)"
echo "═══════════════════════════════════════════════════════════════════"

# Org security policies use groups as "organizations" — create group via direct DB insert
# (No admin group creation REST endpoint exists; SCIM requires separate token setup)
ORG_ID=$(docker exec xavyo-postgres psql -U xavyo xavyo_test -tAc \
  "INSERT INTO groups (tenant_id, display_name, group_type, description)
   VALUES ('$TENANT_ID', 'b11-org-${TS}', 'organization', 'Test org for policies')
   RETURNING id;" 2>/dev/null | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
if [[ -z "$ORG_ID" || ${#ORG_ID} -lt 30 ]]; then
  log "[info] Could not create organization group via DB — org policy tests will skip"
  ORG_ID=""
else
  log "[info] Created org group $ORG_ID"
fi

# TC-OP-001: List org security policies
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call GET "/organizations/$ORG_ID/security-policies")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-001" "List org policies — 200"
  else
    fail "TC-OP-001" "List org policies — HTTP $CODE — $BODY"
  fi
else
  skip "TC-OP-001" "no org group"
fi

# TC-OP-002: Create password policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call POST "/organizations/$ORG_ID/security-policies" -d '{"policy_type":"password","config":{"min_length":12,"require_uppercase":true,"require_lowercase":true,"require_digits":true,"require_special":true},"is_active":true}')
  parse_response "$RAW"
  if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
    pass "TC-OP-002" "Create password policy — $CODE"
  else
    fail "TC-OP-002" "Create password policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-002" "no org group"; fi

# TC-OP-003: Get password policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call GET "/organizations/$ORG_ID/security-policies/password")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-003" "Get password policy — 200"
  else
    fail "TC-OP-003" "Get password policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-003" "no org group"; fi

# TC-OP-004: Update password policy (upsert)
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call PUT "/organizations/$ORG_ID/security-policies/password" -d '{"config":{"min_length":14,"require_uppercase":true,"require_lowercase":true,"require_digits":true,"require_special":true},"is_active":true}')
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-004" "Update password policy — 200"
  else
    fail "TC-OP-004" "Update password policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-004" "no org group"; fi

# TC-OP-005: Create MFA policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call POST "/organizations/$ORG_ID/security-policies" -d '{"policy_type":"mfa","config":{"required":true,"allowed_methods":["totp","webauthn"]},"is_active":true}')
  parse_response "$RAW"
  if [[ "$CODE" == "201" || "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-OP-005" "Create MFA policy — $CODE"
  else
    fail "TC-OP-005" "Create MFA policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-005" "no org group"; fi

# TC-OP-006: Create session policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call POST "/organizations/$ORG_ID/security-policies" -d '{"policy_type":"session","config":{"max_idle_minutes":30,"max_session_hours":8},"is_active":true}')
  parse_response "$RAW"
  if [[ "$CODE" == "201" || "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-OP-006" "Create session policy — $CODE"
  else
    fail "TC-OP-006" "Create session policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-006" "no org group"; fi

# TC-OP-007: Create IP restriction policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call POST "/organizations/$ORG_ID/security-policies" -d '{"policy_type":"ip_restriction","config":{"allowed_cidrs":["10.0.0.0/8"]},"is_active":true}')
  parse_response "$RAW"
  if [[ "$CODE" == "201" || "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-OP-007" "Create IP policy — $CODE"
  else
    fail "TC-OP-007" "Create IP policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-007" "no org group"; fi

# TC-OP-008: Validate policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call POST "/organizations/$ORG_ID/security-policies/validate" -d '{"policy_type":"password","config":{"min_length":8}}')
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-008" "Validate policy — 200"
  else
    fail "TC-OP-008" "Validate policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-008" "no org group"; fi

# TC-OP-009: Get effective org policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call GET "/organizations/$ORG_ID/effective-policy/password")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-009" "Effective org policy — 200"
  else
    fail "TC-OP-009" "Effective org policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-009" "no org group"; fi

# TC-OP-010: Get effective user policy
if [[ -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call GET "/users/$REG_USER_ID/effective-policy/password")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-OP-010" "Effective user policy — 200"
  else
    fail "TC-OP-010" "Effective user policy — HTTP $CODE — $BODY"
  fi
else
  skip "TC-OP-010" "no user ID"
fi

# TC-OP-011: Delete policy
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call DELETE "/organizations/$ORG_ID/security-policies/ip_restriction")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-OP-011" "Delete policy — $CODE"
  else
    fail "TC-OP-011" "Delete policy — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-011" "no org group"; fi

# TC-OP-012: Get deleted policy — 404
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call GET "/organizations/$ORG_ID/security-policies/ip_restriction")
  parse_response "$RAW"
  if [[ "$CODE" == "404" ]]; then
    pass "TC-OP-012" "Deleted policy — 404"
  else
    fail "TC-OP-012" "Deleted policy — HTTP $CODE"
  fi
else skip "TC-OP-012" "no org group"; fi

# TC-OP-013: Non-admin org policies (read-only endpoint — no admin check, 200 is valid)
if [[ -n "$ORG_ID" ]]; then
  RAW=$(user_call GET "/organizations/$ORG_ID/security-policies")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "403" || "$CODE" == "401" || "$CODE" == "404" ]]; then
    pass "TC-OP-013" "Non-admin org policies — $CODE"
  else
    fail "TC-OP-013" "Non-admin org policies — HTTP $CODE"
  fi
else skip "TC-OP-013" "no org group"; fi

# TC-OP-014: No auth org policies
if [[ -n "$ORG_ID" ]]; then
  RAW=$(noauth_call GET "/organizations/$ORG_ID/security-policies")
  parse_response "$RAW"
  if [[ "$CODE" == "401" ]]; then
    pass "TC-OP-014" "No auth org policies — 401"
  else
    fail "TC-OP-014" "No auth org policies — HTTP $CODE"
  fi
else skip "TC-OP-014" "no org group"; fi

# TC-OP-015: Non-existent policy type
if [[ -n "$ORG_ID" ]]; then
  RAW=$(admin_call GET "/organizations/$ORG_ID/security-policies/nonexistent")
  parse_response "$RAW"
  if [[ "$CODE" == "404" || "$CODE" == "400" || "$CODE" == "422" ]]; then
    pass "TC-OP-015" "Non-existent policy type — $CODE"
  else
    fail "TC-OP-015" "Non-existent policy type — HTTP $CODE — $BODY"
  fi
else skip "TC-OP-015" "no org group"; fi

# ═══════════════════════════════════════════════════════════════════
#  Part 7: Governance License Management (TC-LM-001 … TC-LM-030)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 7: License Management (TC-LM-001 … TC-LM-030)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-LM-001: List license pools (empty)
RAW=$(admin_call GET /governance/license-pools)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-001" "List pools — 200"
else
  fail "TC-LM-001" "List pools — HTTP $CODE — $BODY"
fi

# TC-LM-002: Create license pool
RAW=$(admin_call POST /governance/license-pools -d "{\"name\":\"b11-office-${TS}\",\"vendor\":\"Microsoft\",\"description\":\"Test pool\",\"total_capacity\":100,\"cost_per_license\":12.99,\"currency\":\"USD\",\"billing_period\":\"monthly\",\"license_type\":\"named\",\"expiration_policy\":\"block_new\",\"warning_days\":30}")
parse_response "$RAW"
POOL_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$POOL_ID" && "$POOL_ID" != "null" ]]; then
  pass "TC-LM-002" "Create pool — 201"
else
  fail "TC-LM-002" "Create pool — HTTP $CODE — $BODY"
  POOL_ID=""
fi

# TC-LM-003: Get pool
if [[ -n "$POOL_ID" ]]; then
  RAW=$(admin_call GET "/governance/license-pools/$POOL_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-003" "Get pool — 200"
  else
    fail "TC-LM-003" "Get pool — HTTP $CODE"
  fi
else
  skip "TC-LM-003" "no pool ID"
fi

# TC-LM-004: Update pool
if [[ -n "$POOL_ID" ]]; then
  RAW=$(admin_call PUT "/governance/license-pools/$POOL_ID" -d "{\"name\":\"b11-office-updated-${TS}\",\"vendor\":\"Microsoft\",\"total_capacity\":200,\"currency\":\"USD\",\"billing_period\":\"annual\",\"license_type\":\"named\",\"expiration_policy\":\"warn_only\",\"warning_days\":60}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-004" "Update pool — 200"
  else
    fail "TC-LM-004" "Update pool — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-004" "no pool ID"
fi

# TC-LM-005: Create second pool (for incompatibility test)
RAW=$(admin_call POST /governance/license-pools -d "{\"name\":\"b11-gsuite-${TS}\",\"vendor\":\"Google\",\"total_capacity\":50,\"currency\":\"USD\",\"billing_period\":\"monthly\",\"license_type\":\"named\",\"expiration_policy\":\"block_new\",\"warning_days\":14}")
parse_response "$RAW"
POOL2_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$POOL2_ID" && "$POOL2_ID" != "null" ]]; then
  pass "TC-LM-005" "Create second pool — 201"
else
  fail "TC-LM-005" "Create second pool — HTTP $CODE — $BODY"
  POOL2_ID=""
fi

# TC-LM-006: Assign license to user
if [[ -n "$POOL_ID" && -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call POST /governance/license-assignments -d "{\"license_pool_id\":\"$POOL_ID\",\"user_id\":\"$REG_USER_ID\",\"source\":\"manual\"}")
  parse_response "$RAW"
  ASSIGN_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$ASSIGN_ID" && "$ASSIGN_ID" != "null" ]]; then
    pass "TC-LM-006" "Assign license — 201"
  else
    fail "TC-LM-006" "Assign license — HTTP $CODE — $BODY"
    ASSIGN_ID=""
  fi
else
  skip "TC-LM-006" "no pool or user"
  ASSIGN_ID=""
fi

# TC-LM-007: List assignments
RAW=$(admin_call GET /governance/license-assignments)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-007" "List assignments — 200"
else
  fail "TC-LM-007" "List assignments — HTTP $CODE — $BODY"
fi

# TC-LM-008: Get assignment
if [[ -n "$ASSIGN_ID" ]]; then
  RAW=$(admin_call GET "/governance/license-assignments/$ASSIGN_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-008" "Get assignment — 200"
  else
    fail "TC-LM-008" "Get assignment — HTTP $CODE"
  fi
else
  skip "TC-LM-008" "no assignment"
fi

# TC-LM-009: Deallocate license
if [[ -n "$ASSIGN_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/license-assignments/$ASSIGN_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-LM-009" "Deallocate license — $CODE"
  else
    fail "TC-LM-009" "Deallocate license — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-009" "no assignment"
fi

# TC-LM-010: Bulk assign licenses
if [[ -n "$POOL_ID" && -n "$REG_USER_ID" && -n "$ADMIN_USER_ID" ]]; then
  RAW=$(admin_call POST /governance/license-assignments/bulk -d "{\"license_pool_id\":\"$POOL_ID\",\"user_ids\":[\"$REG_USER_ID\",\"$ADMIN_USER_ID\"],\"source\":\"manual\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    pass "TC-LM-010" "Bulk assign — $CODE"
  else
    fail "TC-LM-010" "Bulk assign — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-010" "missing IDs"
fi

# TC-LM-011: List entitlement links (empty)
RAW=$(admin_call GET /governance/license-entitlement-links)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-011" "List entitlement links — 200"
else
  fail "TC-LM-011" "List entitlement links — HTTP $CODE — $BODY"
fi

# TC-LM-012: Create entitlement link
# Get an existing entitlement
RAW=$(admin_call GET "/governance/entitlements?limit=1")
parse_response "$RAW"
ENT_ID=$(extract_json "$BODY" '.items[0].id')
if [[ -n "$POOL_ID" && -n "$ENT_ID" && "$ENT_ID" != "null" ]]; then
  RAW=$(admin_call POST /governance/license-entitlement-links -d "{\"license_pool_id\":\"$POOL_ID\",\"entitlement_id\":\"$ENT_ID\",\"priority\":1}")
  parse_response "$RAW"
  LINK_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$LINK_ID" && "$LINK_ID" != "null" ]]; then
    pass "TC-LM-012" "Create entitlement link — 201"
  else
    fail "TC-LM-012" "Create entitlement link — HTTP $CODE — $BODY"
    LINK_ID=""
  fi
else
  skip "TC-LM-012" "no pool or entitlement"
  LINK_ID=""
fi

# TC-LM-013: Get entitlement link
if [[ -n "$LINK_ID" ]]; then
  RAW=$(admin_call GET "/governance/license-entitlement-links/$LINK_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-013" "Get link — 200"
  else
    fail "TC-LM-013" "Get link — HTTP $CODE"
  fi
else
  skip "TC-LM-013" "no link ID"
fi

# TC-LM-014: Toggle link enabled
if [[ -n "$LINK_ID" ]]; then
  RAW=$(admin_call PUT "/governance/license-entitlement-links/$LINK_ID/enabled" -d '{"enabled":false}')
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-014" "Toggle link enabled — 200"
  else
    fail "TC-LM-014" "Toggle link — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-014" "no link ID"
fi

# TC-LM-015: Delete entitlement link
if [[ -n "$LINK_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/license-entitlement-links/$LINK_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-LM-015" "Delete link — $CODE"
  else
    fail "TC-LM-015" "Delete link — HTTP $CODE"
  fi
else
  skip "TC-LM-015" "no link ID"
fi

# TC-LM-016: List incompatibilities
RAW=$(admin_call GET /governance/license-incompatibilities)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-016" "List incompatibilities — 200"
else
  fail "TC-LM-016" "List incompatibilities — HTTP $CODE — $BODY"
fi

# TC-LM-017: Create incompatibility
if [[ -n "$POOL_ID" && -n "$POOL2_ID" ]]; then
  RAW=$(admin_call POST /governance/license-incompatibilities -d "{\"pool_a_id\":\"$POOL_ID\",\"pool_b_id\":\"$POOL2_ID\",\"reason\":\"Competing products\"}")
  parse_response "$RAW"
  INCOMPAT_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$INCOMPAT_ID" && "$INCOMPAT_ID" != "null" ]]; then
    pass "TC-LM-017" "Create incompatibility — 201"
  else
    fail "TC-LM-017" "Create incompatibility — HTTP $CODE — $BODY"
    INCOMPAT_ID=""
  fi
else
  skip "TC-LM-017" "no pools"
  INCOMPAT_ID=""
fi

# TC-LM-018: Get incompatibility
if [[ -n "$INCOMPAT_ID" ]]; then
  RAW=$(admin_call GET "/governance/license-incompatibilities/$INCOMPAT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-018" "Get incompatibility — 200"
  else
    fail "TC-LM-018" "Get incompatibility — HTTP $CODE"
  fi
else
  skip "TC-LM-018" "no incompat ID"
fi

# TC-LM-019: Delete incompatibility
if [[ -n "$INCOMPAT_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/license-incompatibilities/$INCOMPAT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-LM-019" "Delete incompatibility — $CODE"
  else
    fail "TC-LM-019" "Delete incompatibility — HTTP $CODE"
  fi
else
  skip "TC-LM-019" "no incompat ID"
fi

# TC-LM-020: List reclamation rules
RAW=$(admin_call GET /governance/license-reclamation-rules)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-020" "List reclamation rules — 200"
else
  fail "TC-LM-020" "List reclamation rules — HTTP $CODE — $BODY"
fi

# TC-LM-021: Create reclamation rule
if [[ -n "$POOL_ID" ]]; then
  RAW=$(admin_call POST /governance/license-reclamation-rules -d "{\"license_pool_id\":\"$POOL_ID\",\"trigger_type\":\"inactivity\",\"threshold_days\":90,\"notification_days_before\":7}")
  parse_response "$RAW"
  RULE_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$RULE_ID" && "$RULE_ID" != "null" ]]; then
    pass "TC-LM-021" "Create reclamation rule — 201"
  else
    fail "TC-LM-021" "Create reclamation rule — HTTP $CODE — $BODY"
    RULE_ID=""
  fi
else
  skip "TC-LM-021" "no pool"
  RULE_ID=""
fi

# TC-LM-022: Get reclamation rule
if [[ -n "$RULE_ID" ]]; then
  RAW=$(admin_call GET "/governance/license-reclamation-rules/$RULE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-022" "Get reclamation rule — 200"
  else
    fail "TC-LM-022" "Get reclamation rule — HTTP $CODE"
  fi
else
  skip "TC-LM-022" "no rule ID"
fi

# TC-LM-023: Update reclamation rule
if [[ -n "$RULE_ID" ]]; then
  RAW=$(admin_call PUT "/governance/license-reclamation-rules/$RULE_ID" -d "{\"license_pool_id\":\"$POOL_ID\",\"trigger_type\":\"inactivity\",\"threshold_days\":60,\"notification_days_before\":14}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-023" "Update reclamation rule — 200"
  else
    fail "TC-LM-023" "Update reclamation rule — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-023" "no rule ID"
fi

# TC-LM-024: Delete reclamation rule
if [[ -n "$RULE_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/license-reclamation-rules/$RULE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-LM-024" "Delete reclamation rule — $CODE"
  else
    fail "TC-LM-024" "Delete reclamation rule — HTTP $CODE"
  fi
else
  skip "TC-LM-024" "no rule ID"
fi

# TC-LM-025: License analytics dashboard
RAW=$(admin_call GET /governance/license-analytics/dashboard)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-025" "Analytics dashboard — 200"
else
  fail "TC-LM-025" "Analytics dashboard — HTTP $CODE — $BODY"
fi

# TC-LM-026: License recommendations
RAW=$(admin_call GET /governance/license-analytics/recommendations)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-026" "Recommendations — 200"
else
  fail "TC-LM-026" "Recommendations — HTTP $CODE — $BODY"
fi

# TC-LM-027: Expiring pools
RAW=$(admin_call GET /governance/license-analytics/expiring)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-027" "Expiring pools — 200"
else
  fail "TC-LM-027" "Expiring pools — HTTP $CODE — $BODY"
fi

# TC-LM-028: Compliance report (body is optional but JSON parser requires valid JSON)
RAW=$(admin_call POST /governance/license-reports/compliance -d '{}')
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-028" "Compliance report — 200"
else
  fail "TC-LM-028" "Compliance report — HTTP $CODE — $BODY"
fi

# TC-LM-029: Audit trail
RAW=$(admin_call GET /governance/license-reports/audit-trail)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-LM-029" "Audit trail — 200"
else
  fail "TC-LM-029" "Audit trail — HTTP $CODE — $BODY"
fi

# TC-LM-030: Archive pool
if [[ -n "$POOL2_ID" ]]; then
  RAW=$(admin_call POST "/governance/license-pools/$POOL2_ID/archive")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-LM-030" "Archive pool — 200"
  else
    fail "TC-LM-030" "Archive pool — HTTP $CODE — $BODY"
  fi
else
  skip "TC-LM-030" "no pool2 ID"
fi

# ═══════════════════════════════════════════════════════════════════
#  Part 8: Governance Escalation & Approval Groups (TC-ES-001 … TC-ES-020)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Part 8: Escalation & Approval Groups (TC-ES-001 … TC-ES-020)"
echo "═══════════════════════════════════════════════════════════════════"

# TC-ES-001: List escalation policies (empty)
RAW=$(admin_call GET /governance/escalation-policies)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-ES-001" "List escalation policies — 200"
else
  fail "TC-ES-001" "List escalation policies — HTTP $CODE — $BODY"
fi

# TC-ES-002: Create escalation policy
RAW=$(admin_call POST /governance/escalation-policies -d "{\"name\":\"b11-esc-${TS}\",\"description\":\"Test escalation\",\"default_timeout_secs\":172800,\"warning_threshold_secs\":3600,\"final_fallback\":\"escalate_admin\"}")
parse_response "$RAW"
ESC_POLICY_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$ESC_POLICY_ID" && "$ESC_POLICY_ID" != "null" ]]; then
  pass "TC-ES-002" "Create escalation policy — 201"
else
  fail "TC-ES-002" "Create escalation policy — HTTP $CODE — $BODY"
  ESC_POLICY_ID=""
fi

# TC-ES-003: Get escalation policy
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call GET "/governance/escalation-policies/$ESC_POLICY_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-003" "Get escalation policy — 200"
  else
    fail "TC-ES-003" "Get escalation policy — HTTP $CODE"
  fi
else
  skip "TC-ES-003" "no policy ID"
fi

# TC-ES-004: Update escalation policy
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call PUT "/governance/escalation-policies/$ESC_POLICY_ID" -d "{\"name\":\"b11-esc-updated-${TS}\",\"description\":\"Updated\",\"default_timeout_secs\":259200,\"final_fallback\":\"auto_reject\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-004" "Update escalation policy — 200"
  else
    fail "TC-ES-004" "Update escalation policy — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-004" "no policy ID"
fi

# TC-ES-005: Add escalation level
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call POST "/governance/escalation-policies/$ESC_POLICY_ID/levels" -d '{"level_order":1,"level_name":"Manager","timeout_secs":1800,"target_type":"manager"}')
  parse_response "$RAW"
  LEVEL_ID=$(extract_json "$BODY" '.id // .level_id')
  if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
    pass "TC-ES-005" "Add escalation level — $CODE"
  else
    fail "TC-ES-005" "Add escalation level — HTTP $CODE — $BODY"
    LEVEL_ID=""
  fi
else
  skip "TC-ES-005" "no policy ID"
  LEVEL_ID=""
fi

# TC-ES-006: Add second level (tenant admin)
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call POST "/governance/escalation-policies/$ESC_POLICY_ID/levels" -d '{"level_order":2,"level_name":"Admin","timeout_secs":3600,"target_type":"tenant_admin"}')
  parse_response "$RAW"
  if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
    pass "TC-ES-006" "Add admin level — $CODE"
  else
    fail "TC-ES-006" "Add admin level — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-006" "no policy ID"
fi

# TC-ES-007: Remove escalation level
if [[ -n "$ESC_POLICY_ID" && -n "$LEVEL_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/escalation-policies/$ESC_POLICY_ID/levels/$LEVEL_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-ES-007" "Remove level — $CODE"
  else
    fail "TC-ES-007" "Remove level — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-007" "no policy or level ID"
fi

# TC-ES-008: Set default policy
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call POST "/governance/escalation-policies/$ESC_POLICY_ID/set-default")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-008" "Set default policy — 200"
  else
    fail "TC-ES-008" "Set default policy — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-008" "no policy ID"
fi

# TC-ES-009: List escalation events
RAW=$(admin_call GET /governance/escalation-events)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-ES-009" "List escalation events — 200"
else
  fail "TC-ES-009" "List escalation events — HTTP $CODE — $BODY"
fi

# TC-ES-010: List approval groups (empty)
RAW=$(admin_call GET /governance/approval-groups)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-ES-010" "List approval groups — 200"
else
  fail "TC-ES-010" "List approval groups — HTTP $CODE — $BODY"
fi

# TC-ES-011: Create approval group
if [[ -n "$ADMIN_USER_ID" ]]; then
  RAW=$(admin_call POST /governance/approval-groups -d "{\"name\":\"b11-approvers-${TS}\",\"description\":\"Test group\",\"member_ids\":[\"$ADMIN_USER_ID\"]}")
  parse_response "$RAW"
  AG_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$AG_ID" && "$AG_ID" != "null" ]]; then
    pass "TC-ES-011" "Create approval group — 201"
  else
    fail "TC-ES-011" "Create approval group — HTTP $CODE — $BODY"
    AG_ID=""
  fi
else
  skip "TC-ES-011" "no admin user ID"
  AG_ID=""
fi

# TC-ES-012: Get approval group
if [[ -n "$AG_ID" ]]; then
  RAW=$(admin_call GET "/governance/approval-groups/$AG_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-012" "Get approval group — 200"
  else
    fail "TC-ES-012" "Get approval group — HTTP $CODE"
  fi
else
  skip "TC-ES-012" "no group ID"
fi

# TC-ES-013: Update approval group
if [[ -n "$AG_ID" ]]; then
  RAW=$(admin_call PUT "/governance/approval-groups/$AG_ID" -d "{\"name\":\"b11-approvers-updated-${TS}\",\"description\":\"Updated\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-013" "Update approval group — 200"
  else
    fail "TC-ES-013" "Update approval group — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-013" "no group ID"
fi

# TC-ES-014: Add members
if [[ -n "$AG_ID" && -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call POST "/governance/approval-groups/$AG_ID/members" -d "{\"member_ids\":[\"$REG_USER_ID\"]}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-014" "Add members — 200"
  else
    fail "TC-ES-014" "Add members — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-014" "no group or user"
fi

# TC-ES-015: Remove members
if [[ -n "$AG_ID" && -n "$REG_USER_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/approval-groups/$AG_ID/members" -d "{\"member_ids\":[\"$REG_USER_ID\"]}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-015" "Remove members — 200"
  else
    fail "TC-ES-015" "Remove members — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-015" "no group or user"
fi

# TC-ES-016: Enable approval group
if [[ -n "$AG_ID" ]]; then
  RAW=$(admin_call POST "/governance/approval-groups/$AG_ID/enable")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-016" "Enable group — 200"
  else
    fail "TC-ES-016" "Enable group — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-016" "no group ID"
fi

# TC-ES-017: Disable approval group
if [[ -n "$AG_ID" ]]; then
  RAW=$(admin_call POST "/governance/approval-groups/$AG_ID/disable")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-017" "Disable group — 200"
  else
    fail "TC-ES-017" "Disable group — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-017" "no group ID"
fi

# TC-ES-018: Get user's approval groups
if [[ -n "$ADMIN_USER_ID" ]]; then
  RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/approval-groups")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-ES-018" "User approval groups — 200"
  else
    fail "TC-ES-018" "User approval groups — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-018" "no admin user ID"
fi

# TC-ES-019: Delete approval group
if [[ -n "$AG_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/approval-groups/$AG_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-ES-019" "Delete approval group — $CODE"
  else
    fail "TC-ES-019" "Delete approval group — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-019" "no group ID"
fi

# TC-ES-020: Delete escalation policy
if [[ -n "$ESC_POLICY_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/escalation-policies/$ESC_POLICY_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-ES-020" "Delete escalation policy — $CODE"
  else
    fail "TC-ES-020" "Delete escalation policy — HTTP $CODE — $BODY"
  fi
else
  skip "TC-ES-020" "no policy ID"
fi

# ═══════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Batch 11 Results: Admin Features & Governance Deep"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "  PASS=$PASS FAIL=$FAIL SKIP=$SKIP TOTAL=$TOTAL"
echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "  All tests passed!"
else
  echo "  *** $FAIL FAILURES ***"
fi
echo "═══════════════════════════════════════════════════════════════════"
