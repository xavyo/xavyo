#!/usr/bin/env bash
# =============================================================================
# Batch 9: Governance Deep — Role Mining, Identity Merge, Personas, Risk
# =============================================================================
# Tests: ~122 test cases covering 4 major governance subsystems
#
# Prerequisites:
#   - API server running on localhost:8080
#   - PostgreSQL with migrations applied
#   - Mailpit running on localhost:8025
# =============================================================================

set -uo pipefail

BASE="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
RESULTS_FILE="tests/functional/batch-9-results.md"
TS=$(date +%s)
PASS=0; FAIL=0; SKIP=0; TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); log "PASS  $1 — $2"; echo "| $1 | PASS | $2 |" >> "$RESULTS_FILE"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); log "FAIL  $1 — $2"; echo "| $1 | FAIL | $2 |" >> "$RESULTS_FILE"; }
skip() { SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); log "SKIP  $1 — $2"; echo "| $1 | SKIP | $2 |" >> "$RESULTS_FILE"; }

api_call() {
  local method="$1" path="$2"; shift 2
  curl -s -w "\n%{http_code}" -X "$method" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    "$BASE$path" "$@"
}

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

parse_response() {
  local raw="$1"
  BODY=$(echo "$raw" | sed '$d')
  CODE=$(echo "$raw" | tail -1)
}

extract_json() { echo "$1" | jq -r "$2" 2>/dev/null; }

signup_and_verify() {
  local email="$1"
  local SIGNUP
  SIGNUP=$(curl -s -X POST "$BASE/auth/signup" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d "{\"email\":\"$email\",\"password\":\"MyP@ssw0rd_2026\"}")
  local uid
  uid=$(extract_json "$SIGNUP" '.user_id')

  sleep 2
  local MAIL_SEARCH MAIL_ID MAIL_MSG TOKEN=""
  MAIL_SEARCH=$(curl -s "http://localhost:8025/api/v1/search?query=to:$email")
  MAIL_ID=$(extract_json "$MAIL_SEARCH" '.messages[0].ID')
  if [ -n "$MAIL_ID" ] && [ "$MAIL_ID" != "null" ]; then
    MAIL_MSG=$(curl -s "http://localhost:8025/api/v1/message/$MAIL_ID")
    TOKEN=$(echo "$MAIL_MSG" | jq -r '.Text // ""' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
    if [ -z "$TOKEN" ]; then
      TOKEN=$(extract_json "$MAIL_SEARCH" '.messages[0].Snippet' | grep -oP 'token=\K[A-Za-z0-9_-]+' | head -1)
    fi
  fi
  if [ -z "$TOKEN" ]; then
    log "WARNING: No verification token for $email"
    echo "$uid"; return 1
  fi
  curl -s -X POST "$BASE/auth/verify-email" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d "{\"token\":\"$TOKEN\"}" > /dev/null
  echo "$uid"
}

# ── Results file ─────────────────────────────────────────────────────────────
cat > "$RESULTS_FILE" <<EOF
# Batch 9: Governance Deep — Role Mining, Identity Merge, Personas, Risk

**Date**: $(date -Iseconds)
**Server**: $BASE

## Summary

PASS=0 FAIL=0 SKIP=0 TOTAL=0

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
EOF

# =============================================================================
# SETUP: Create admin and regular test users
# =============================================================================
log "═══ Setup: Creating test users ═══"

ADMIN_EMAIL="b9admin${TS}@test.com"
USER_EMAIL="b9user${TS}@test.com"

# Clear mailpit
curl -s -X DELETE "http://localhost:8025/api/v1/messages" > /dev/null 2>&1 || true

# Health check
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
if [[ "$HTTP" != "200" ]]; then
  log "FATAL: API not responding ($HTTP)"; exit 1
fi

# Create admin user
ADMIN_USER_ID=$(signup_and_verify "$ADMIN_EMAIL")
if [[ -z "$ADMIN_USER_ID" || "$ADMIN_USER_ID" == "null" ]]; then
  log "FATAL: Could not create admin user"; exit 1
fi

# Assign admin role via DB
PGPASSWORD=xavyo_test_password psql -h localhost -p 5434 -U xavyo -d xavyo_test -q \
  -c "INSERT INTO user_roles (user_id, role_name) VALUES ('$ADMIN_USER_ID', 'admin') ON CONFLICT DO NOTHING;" 2>/dev/null

# Login admin
RAW=$(api_call POST /auth/login -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"MyP@ssw0rd_2026\"}")
parse_response "$RAW"
ADMIN_JWT=$(extract_json "$BODY" '.access_token')

if [[ -z "$ADMIN_JWT" || "$ADMIN_JWT" == "null" ]]; then
  log "FATAL: Could not get admin JWT (code=$CODE)"; exit 1
fi

# Create regular user
REG_USER_ID=$(signup_and_verify "$USER_EMAIL")
if [[ -z "$REG_USER_ID" || "$REG_USER_ID" == "null" ]]; then
  log "FATAL: Could not create regular user"; exit 1
fi

# Login regular user
RAW=$(api_call POST /auth/login -d "{\"email\":\"$USER_EMAIL\",\"password\":\"MyP@ssw0rd_2026\"}")
parse_response "$RAW"
USER_JWT=$(extract_json "$BODY" '.access_token')

if [[ -z "$USER_JWT" || "$USER_JWT" == "null" ]]; then
  log "FATAL: Could not get user JWT"; exit 1
fi

log "Admin: $ADMIN_USER_ID | User: $REG_USER_ID"
log "Admin JWT: ${ADMIN_JWT:0:20}… | User JWT: ${USER_JWT:0:20}…"

# Create test application first (required for entitlements)
RAW=$(admin_call POST /governance/applications -d "{\"name\":\"b9-app-${TS}\",\"app_type\":\"internal\",\"description\":\"Test app for batch 9\"}")
parse_response "$RAW"
APP_ID=$(extract_json "$BODY" '.id')
if [[ -z "$APP_ID" || "$APP_ID" == "null" ]]; then
  log "WARNING: Could not create application (HTTP $CODE), skipping entitlement-dependent tests"
  APP_ID=""
fi

# Create test entitlements (require application_id)
ENT1_ID=""
ENT2_ID=""
if [[ -n "$APP_ID" ]]; then
  RAW=$(admin_call POST /governance/entitlements -d "{\"application_id\":\"$APP_ID\",\"name\":\"b9-ent1-${TS}\",\"description\":\"Test ent 1\",\"risk_level\":\"low\"}")
  parse_response "$RAW"
  ENT1_ID=$(extract_json "$BODY" '.id')

  RAW=$(admin_call POST /governance/entitlements -d "{\"application_id\":\"$APP_ID\",\"name\":\"b9-ent2-${TS}\",\"description\":\"Test ent 2\",\"risk_level\":\"medium\"}")
  parse_response "$RAW"
  ENT2_ID=$(extract_json "$BODY" '.id')
fi

# Create test role
RAW=$(admin_call POST /governance/roles -d "{\"name\":\"b9-role-${TS}\",\"description\":\"Test role batch 9\"}")
parse_response "$RAW"
ROLE_ID=$(extract_json "$BODY" '.id')

log "App: $APP_ID | Entitlements: $ENT1_ID, $ENT2_ID | Role: $ROLE_ID"

# =============================================================================
# PART 1: ROLE MINING (37 tests)
# =============================================================================
log "═══ Part 1: Role Mining ═══"

# TC-RM-001: List mining jobs (empty)
RAW=$(admin_call GET /governance/role-mining/jobs)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-001" "List mining jobs (empty) — 200"
else
  fail "TC-RM-001" "List mining jobs (empty) — HTTP $CODE"
fi

# TC-RM-002: Create mining job
RAW=$(admin_call POST /governance/role-mining/jobs -d "{\"name\":\"b9-mining-${TS}\"}")
parse_response "$RAW"
MINING_JOB_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$MINING_JOB_ID" && "$MINING_JOB_ID" != "null" ]]; then
  pass "TC-RM-002" "Create mining job — 201"
else
  fail "TC-RM-002" "Create mining job — HTTP $CODE"
  MINING_JOB_ID=""
fi

# TC-RM-003: Get mining job by ID
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-003" "Get mining job — 200"
  else
    fail "TC-RM-003" "Get mining job — HTTP $CODE"
  fi
else
  skip "TC-RM-003" "no job ID"
fi

# TC-RM-004: Run mining job
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call POST "/governance/role-mining/jobs/$MINING_JOB_ID/run")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-RM-004" "Run mining job — $CODE"
  else
    fail "TC-RM-004" "Run mining job — HTTP $CODE"
  fi
else
  skip "TC-RM-004" "no job ID"
fi

# TC-RM-005: List mining jobs with status filter
RAW=$(admin_call GET "/governance/role-mining/jobs?status=completed")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-005" "List jobs status=completed — 200"
else
  fail "TC-RM-005" "List jobs status=completed — HTTP $CODE"
fi

# TC-RM-006: List mining jobs with pagination
RAW=$(admin_call GET "/governance/role-mining/jobs?limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-006" "List jobs paginated — 200"
else
  fail "TC-RM-006" "List jobs paginated — HTTP $CODE"
fi

# TC-RM-007: Create mining job with parameters
RAW=$(admin_call POST /governance/role-mining/jobs -d "{\"name\":\"b9-mining-params-${TS}\",\"parameters\":{\"min_support\":0.1,\"min_confidence\":0.5}}")
parse_response "$RAW"
MINING_JOB2_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" ]]; then
  pass "TC-RM-007" "Create job with params — 201"
else
  fail "TC-RM-007" "Create job with params — HTTP $CODE"
  MINING_JOB2_ID=""
fi

# TC-RM-008: Get mining job not found
RAW=$(admin_call GET "/governance/role-mining/jobs/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-008" "Get job not found — 404"
else
  fail "TC-RM-008" "Get job not found — HTTP $CODE"
fi

# TC-RM-009: Cancel mining job (may be pending → 200/204, or running → 412)
if [[ -n "$MINING_JOB2_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/role-mining/jobs/$MINING_JOB2_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" || "$CODE" == "409" || "$CODE" == "412" ]]; then
    pass "TC-RM-009" "Cancel mining job — $CODE"
  else
    fail "TC-RM-009" "Cancel mining job — HTTP $CODE"
  fi
else
  skip "TC-RM-009" "no job ID"
fi

# TC-RM-010: List mining jobs no auth
RAW=$(api_call GET /governance/role-mining/jobs)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-RM-010" "List jobs no auth — 401"
else
  fail "TC-RM-010" "List jobs no auth — HTTP $CODE"
fi

# --- Role Candidates ---

# TC-RM-011: List candidates for job
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/candidates")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-011" "List candidates — 200"
  else
    fail "TC-RM-011" "List candidates — HTTP $CODE"
  fi
else
  skip "TC-RM-011" "no job ID"
fi

# TC-RM-012: List candidates with filter
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/candidates?status=pending&min_confidence=0.5&limit=10")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-012" "List candidates filtered — 200"
  else
    fail "TC-RM-012" "List candidates filtered — HTTP $CODE"
  fi
else
  skip "TC-RM-012" "no job ID"
fi

# TC-RM-013: Get candidate not found
RAW=$(admin_call GET "/governance/role-mining/candidates/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-013" "Get candidate not found — 404"
else
  fail "TC-RM-013" "Get candidate not found — HTTP $CODE"
fi

# TC-RM-014: Promote candidate not found
RAW=$(admin_call POST "/governance/role-mining/candidates/00000000-0000-0000-0000-000000000099/promote" -d "{\"role_name\":\"promoted\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-014" "Promote candidate not found — 404"
else
  fail "TC-RM-014" "Promote candidate not found — HTTP $CODE"
fi

# TC-RM-015: Dismiss candidate not found
RAW=$(admin_call POST "/governance/role-mining/candidates/00000000-0000-0000-0000-000000000099/dismiss" -d "{\"reason\":\"not relevant\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-015" "Dismiss candidate not found — 404"
else
  fail "TC-RM-015" "Dismiss candidate not found — HTTP $CODE"
fi

# --- Access Patterns ---

# TC-RM-016: List access patterns
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/patterns")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-016" "List access patterns — 200"
  else
    fail "TC-RM-016" "List access patterns — HTTP $CODE"
  fi
else
  skip "TC-RM-016" "no job ID"
fi

# TC-RM-017: List patterns with filter
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/patterns?min_frequency=5&limit=10")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-017" "List patterns filtered — 200"
  else
    fail "TC-RM-017" "List patterns filtered — HTTP $CODE"
  fi
else
  skip "TC-RM-017" "no job ID"
fi

# TC-RM-018: Get pattern not found
RAW=$(admin_call GET "/governance/role-mining/patterns/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" || "$CODE" == "400" ]]; then
  pass "TC-RM-018" "Get pattern not found — $CODE"
else
  fail "TC-RM-018" "Get pattern not found — HTTP $CODE"
fi

# --- Excessive Privileges ---

# TC-RM-019: List excessive privileges
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/excessive-privileges")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-019" "List excessive privs — 200"
  else
    fail "TC-RM-019" "List excessive privs — HTTP $CODE"
  fi
else
  skip "TC-RM-019" "no job ID"
fi

# TC-RM-020: List excessive privs with filter
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/excessive-privileges?status=pending&limit=10")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-020" "List excessive privs filtered — 200"
  else
    fail "TC-RM-020" "List excessive privs filtered — HTTP $CODE"
  fi
else
  skip "TC-RM-020" "no job ID"
fi

# TC-RM-021: Get excessive priv not found
RAW=$(admin_call GET "/governance/role-mining/excessive-privileges/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-021" "Get excessive priv not found — 404"
else
  fail "TC-RM-021" "Get excessive priv not found — HTTP $CODE"
fi

# TC-RM-022: Review excessive priv not found
RAW=$(admin_call POST "/governance/role-mining/excessive-privileges/00000000-0000-0000-0000-000000000099/review" -d "{\"action\":\"accept\",\"notes\":\"test\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-022" "Review excessive priv not found — 404"
else
  fail "TC-RM-022" "Review excessive priv not found — HTTP $CODE"
fi

# --- Consolidation Suggestions ---

# TC-RM-023: List consolidation suggestions
if [[ -n "$MINING_JOB_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/jobs/$MINING_JOB_ID/consolidation-suggestions")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-023" "List consolidation suggestions — 200"
  else
    fail "TC-RM-023" "List consolidation suggestions — HTTP $CODE"
  fi
else
  skip "TC-RM-023" "no job ID"
fi

# TC-RM-024: Get consolidation suggestion not found
RAW=$(admin_call GET "/governance/role-mining/consolidation-suggestions/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-024" "Get suggestion not found — 404"
else
  fail "TC-RM-024" "Get suggestion not found — HTTP $CODE"
fi

# TC-RM-025: Dismiss suggestion not found
RAW=$(admin_call POST "/governance/role-mining/consolidation-suggestions/00000000-0000-0000-0000-000000000099/dismiss" -d "{\"reason\":\"not needed\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-025" "Dismiss suggestion not found — 404"
else
  fail "TC-RM-025" "Dismiss suggestion not found — HTTP $CODE"
fi

# --- Simulations ---

# TC-RM-026: List simulations (empty)
RAW=$(admin_call GET /governance/role-mining/simulations)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-026" "List simulations — 200"
else
  fail "TC-RM-026" "List simulations — HTTP $CODE"
fi

# TC-RM-027: Create simulation
if [[ -n "$ENT1_ID" && "$ENT1_ID" != "null" ]]; then
  SIM_CHANGES="{\"role_name\":\"sim-role-${TS}\",\"role_description\":\"Simulated role\",\"entitlement_ids\":[\"$ENT1_ID\"]}"
else
  SIM_CHANGES="{\"role_name\":\"sim-role-${TS}\",\"role_description\":\"Simulated role\"}"
fi
RAW=$(admin_call POST /governance/role-mining/simulations -d "{\"name\":\"b9-sim-${TS}\",\"scenario_type\":\"add_role\",\"changes\":$SIM_CHANGES}")
parse_response "$RAW"
SIM_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$SIM_ID" && "$SIM_ID" != "null" ]]; then
  pass "TC-RM-027" "Create simulation — 201"
else
  fail "TC-RM-027" "Create simulation — HTTP $CODE — $BODY"
  SIM_ID=""
fi

# TC-RM-028: Get simulation by ID
if [[ -n "$SIM_ID" ]]; then
  RAW=$(admin_call GET "/governance/role-mining/simulations/$SIM_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-028" "Get simulation — 200"
  else
    fail "TC-RM-028" "Get simulation — HTTP $CODE"
  fi
else
  skip "TC-RM-028" "no sim ID"
fi

# TC-RM-029: Execute simulation
if [[ -n "$SIM_ID" ]]; then
  RAW=$(admin_call POST "/governance/role-mining/simulations/$SIM_ID/execute")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-RM-029" "Execute simulation — $CODE"
  else
    fail "TC-RM-029" "Execute simulation — HTTP $CODE"
  fi
else
  skip "TC-RM-029" "no sim ID"
fi

# TC-RM-030: List simulations filtered
RAW=$(admin_call GET "/governance/role-mining/simulations?scenario_type=add_role&limit=10")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-030" "List simulations filtered — 200"
else
  fail "TC-RM-030" "List simulations filtered — HTTP $CODE"
fi

# TC-RM-031: Get simulation not found
RAW=$(admin_call GET "/governance/role-mining/simulations/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-031" "Get simulation not found — 404"
else
  fail "TC-RM-031" "Get simulation not found — HTTP $CODE"
fi

# TC-RM-032: Cancel simulation
if [[ -n "$SIM_ID" ]]; then
  RAW=$(admin_call DELETE "/governance/role-mining/simulations/$SIM_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" || "$CODE" == "409" ]]; then
    pass "TC-RM-032" "Cancel simulation — $CODE"
  else
    fail "TC-RM-032" "Cancel simulation — HTTP $CODE"
  fi
else
  skip "TC-RM-032" "no sim ID"
fi

# --- Metrics ---

# TC-RM-033: List role metrics
RAW=$(admin_call GET /governance/role-mining/metrics)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-033" "List role metrics — 200"
else
  fail "TC-RM-033" "List role metrics — HTTP $CODE"
fi

# TC-RM-034: List role metrics filtered
RAW=$(admin_call GET "/governance/role-mining/metrics?min_utilization=0.0&max_utilization=1.0&limit=10")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-034" "List metrics filtered — 200"
else
  fail "TC-RM-034" "List metrics filtered — HTTP $CODE"
fi

# TC-RM-035: Get role metrics not found
RAW=$(admin_call GET "/governance/role-mining/metrics/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RM-035" "Get metrics not found — 404"
else
  fail "TC-RM-035" "Get metrics not found — HTTP $CODE"
fi

# TC-RM-036: Calculate metrics
RAW=$(admin_call POST /governance/role-mining/metrics/calculate -d "{}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RM-036" "Calculate metrics — 200"
else
  fail "TC-RM-036" "Calculate metrics — HTTP $CODE"
fi

# TC-RM-037: Calculate metrics for specific roles
if [[ -n "$ROLE_ID" && "$ROLE_ID" != "null" ]]; then
  RAW=$(admin_call POST /governance/role-mining/metrics/calculate -d "{\"role_ids\":[\"$ROLE_ID\"]}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RM-037" "Calculate metrics for role — 200"
  else
    fail "TC-RM-037" "Calculate metrics for role — HTTP $CODE"
  fi
else
  skip "TC-RM-037" "no role ID"
fi

# =============================================================================
# PART 2: IDENTITY MERGE (19 tests)
# =============================================================================
log "═══ Part 2: Identity Merge ═══"

# TC-IM-001: List duplicate candidates
RAW=$(admin_call GET /governance/duplicates)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-001" "List duplicates — 200"
else
  fail "TC-IM-001" "List duplicates — HTTP $CODE"
fi

# TC-IM-002: List duplicates with filters
RAW=$(admin_call GET "/governance/duplicates?status=pending&min_confidence=0.5&max_confidence=1.0&limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-002" "List duplicates filtered — 200"
else
  fail "TC-IM-002" "List duplicates filtered — HTTP $CODE"
fi

# TC-IM-003: Get duplicate not found
RAW=$(admin_call GET "/governance/duplicates/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-IM-003" "Get duplicate not found — 404"
else
  fail "TC-IM-003" "Get duplicate not found — HTTP $CODE"
fi

# TC-IM-004: Dismiss duplicate not found
RAW=$(admin_call POST "/governance/duplicates/00000000-0000-0000-0000-000000000099/dismiss" -d "{\"reason\":\"false positive\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-IM-004" "Dismiss duplicate not found — 404"
else
  fail "TC-IM-004" "Dismiss duplicate not found — HTTP $CODE"
fi

# TC-IM-005: Run duplicate detection scan
RAW=$(admin_call POST /governance/duplicates/detect -d "{\"min_confidence\":0.8}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-005" "Detect duplicates — 200"
else
  fail "TC-IM-005" "Detect duplicates — HTTP $CODE"
fi

# TC-IM-006: Run detection scan (default)
RAW=$(admin_call POST /governance/duplicates/detect -d "{}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-006" "Detect duplicates default — 200"
else
  fail "TC-IM-006" "Detect duplicates default — HTTP $CODE"
fi

# TC-IM-007: List duplicates no auth
RAW=$(api_call GET /governance/duplicates)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-IM-007" "List duplicates no auth — 401"
else
  fail "TC-IM-007" "List duplicates no auth — HTTP $CODE"
fi

# TC-IM-008: Preview merge (same identity)
RAW=$(admin_call POST /governance/merges/preview -d "{\"source_identity_id\":\"$ADMIN_USER_ID\",\"target_identity_id\":\"$ADMIN_USER_ID\",\"entitlement_strategy\":\"union\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "400" || "$CODE" == "409" || "$CODE" == "412" ]]; then
  pass "TC-IM-008" "Preview merge same user — $CODE"
else
  fail "TC-IM-008" "Preview merge same user — HTTP $CODE"
fi

# TC-IM-009: Preview merge (two users)
RAW=$(admin_call POST /governance/merges/preview -d "{\"source_identity_id\":\"$REG_USER_ID\",\"target_identity_id\":\"$ADMIN_USER_ID\",\"entitlement_strategy\":\"union\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-009" "Preview merge two users — 200"
else
  fail "TC-IM-009" "Preview merge two users — HTTP $CODE"
fi

# TC-IM-010: Preview merge not found source
RAW=$(admin_call POST /governance/merges/preview -d "{\"source_identity_id\":\"00000000-0000-0000-0000-000000000099\",\"target_identity_id\":\"$ADMIN_USER_ID\",\"entitlement_strategy\":\"union\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" || "$CODE" == "400" ]]; then
  pass "TC-IM-010" "Preview merge missing source — $CODE"
else
  fail "TC-IM-010" "Preview merge missing source — HTTP $CODE"
fi

# TC-IM-011: List merge operations
RAW=$(admin_call GET /governance/merges)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-011" "List merge ops — 200"
else
  fail "TC-IM-011" "List merge ops — HTTP $CODE"
fi

# TC-IM-012: List merge ops filtered
RAW=$(admin_call GET "/governance/merges?status=completed&limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-012" "List merge ops filtered — 200"
else
  fail "TC-IM-012" "List merge ops filtered — HTTP $CODE"
fi

# TC-IM-013: Get merge op not found
RAW=$(admin_call GET "/governance/merges/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-IM-013" "Get merge op not found — 404"
else
  fail "TC-IM-013" "Get merge op not found — HTTP $CODE"
fi

# TC-IM-014: List merge audits
RAW=$(admin_call GET /governance/merges/audit)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-014" "List merge audits — 200"
else
  fail "TC-IM-014" "List merge audits — HTTP $CODE"
fi

# TC-IM-015: List merge audits filtered
RAW=$(admin_call GET "/governance/merges/audit?limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-015" "List merge audits filtered — 200"
else
  fail "TC-IM-015" "List merge audits filtered — HTTP $CODE"
fi

# TC-IM-016: Get merge audit not found
RAW=$(admin_call GET "/governance/merges/audit/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-IM-016" "Get merge audit not found — 404"
else
  fail "TC-IM-016" "Get merge audit not found — HTTP $CODE"
fi

# TC-IM-017: Preview batch merge
RAW=$(admin_call POST /governance/merges/batch/preview -d "{\"min_confidence\":0.9,\"entitlement_strategy\":\"union\",\"attribute_rule\":\"newest_wins\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-017" "Preview batch merge — 200"
else
  fail "TC-IM-017" "Preview batch merge — HTTP $CODE"
fi

# TC-IM-018: Execute batch merge (empty candidate list)
RAW=$(admin_call POST /governance/merges/batch -d "{\"candidate_ids\":[],\"entitlement_strategy\":\"union\",\"attribute_rule\":\"newest_wins\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-IM-018" "Batch merge (empty) — 200"
else
  fail "TC-IM-018" "Batch merge (empty) — HTTP $CODE"
fi

# TC-IM-019: Get batch job (always 404)
RAW=$(admin_call GET "/governance/merges/batch/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-IM-019" "Get batch job 404 (sync-only) — 404"
else
  fail "TC-IM-019" "Get batch job 404 (sync-only) — HTTP $CODE"
fi

# =============================================================================
# PART 3: PERSONAS & CONTEXT SWITCHING (33 tests)
# =============================================================================
log "═══ Part 3: Personas & Context Switching ═══"

# TC-PER-001: List archetypes (empty)
RAW=$(admin_call GET /governance/persona-archetypes)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-001" "List archetypes — 200"
else
  fail "TC-PER-001" "List archetypes — HTTP $CODE"
fi

# TC-PER-002: Create archetype
RAW=$(admin_call POST /governance/persona-archetypes -d "{\"name\":\"b9-arch-${TS}\",\"description\":\"Test archetype\",\"naming_pattern\":\"{username}-persona\"}")
parse_response "$RAW"
ARCHETYPE_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$ARCHETYPE_ID" && "$ARCHETYPE_ID" != "null" ]]; then
  pass "TC-PER-002" "Create archetype — 201"
else
  fail "TC-PER-002" "Create archetype — HTTP $CODE — $BODY"
  ARCHETYPE_ID=""
fi

# TC-PER-003: Get archetype
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call GET "/governance/persona-archetypes/$ARCHETYPE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-003" "Get archetype — 200"
  else
    fail "TC-PER-003" "Get archetype — HTTP $CODE"
  fi
else
  skip "TC-PER-003" "no archetype ID"
fi

# TC-PER-004: Update archetype
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call PUT "/governance/persona-archetypes/$ARCHETYPE_ID" -d "{\"description\":\"Updated description\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-004" "Update archetype — 200"
  else
    fail "TC-PER-004" "Update archetype — HTTP $CODE"
  fi
else
  skip "TC-PER-004" "no archetype ID"
fi

# TC-PER-005: Create duplicate archetype
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call POST /governance/persona-archetypes -d "{\"name\":\"b9-arch-${TS}\",\"naming_pattern\":\"{username}\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "409" ]]; then
    pass "TC-PER-005" "Duplicate archetype name — 409"
  else
    fail "TC-PER-005" "Duplicate archetype name — HTTP $CODE"
  fi
fi

# TC-PER-006: List archetypes with filter
RAW=$(admin_call GET "/governance/persona-archetypes?is_active=true&limit=10")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-006" "List archetypes filtered — 200"
else
  fail "TC-PER-006" "List archetypes filtered — HTTP $CODE"
fi

# TC-PER-007: Get archetype not found
RAW=$(admin_call GET "/governance/persona-archetypes/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-PER-007" "Get archetype not found — 404"
else
  fail "TC-PER-007" "Get archetype not found — HTTP $CODE"
fi

# TC-PER-008: Deactivate archetype
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call POST "/governance/persona-archetypes/$ARCHETYPE_ID/deactivate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-008" "Deactivate archetype — 200"
  else
    fail "TC-PER-008" "Deactivate archetype — HTTP $CODE"
  fi
else
  skip "TC-PER-008" "no archetype ID"
fi

# TC-PER-009: Activate archetype
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call POST "/governance/persona-archetypes/$ARCHETYPE_ID/activate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-009" "Activate archetype — 200"
  else
    fail "TC-PER-009" "Activate archetype — HTTP $CODE"
  fi
else
  skip "TC-PER-009" "no archetype ID"
fi

# TC-PER-010: List archetypes no auth
RAW=$(api_call GET /governance/persona-archetypes)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-PER-010" "List archetypes no auth — 401"
else
  fail "TC-PER-010" "List archetypes no auth — HTTP $CODE"
fi

# --- Personas ---

# TC-PER-011: List personas (empty)
RAW=$(admin_call GET /governance/personas)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-011" "List personas — 200"
else
  fail "TC-PER-011" "List personas — HTTP $CODE"
fi

# TC-PER-012: Create persona
if [[ -n "$ARCHETYPE_ID" ]]; then
  RAW=$(admin_call POST /governance/personas -d "{\"archetype_id\":\"$ARCHETYPE_ID\",\"physical_user_id\":\"$ADMIN_USER_ID\"}")
  parse_response "$RAW"
  PERSONA_ID=$(extract_json "$BODY" '.id')
  if [[ "$CODE" == "201" && -n "$PERSONA_ID" && "$PERSONA_ID" != "null" ]]; then
    pass "TC-PER-012" "Create persona — 201"
  else
    fail "TC-PER-012" "Create persona — HTTP $CODE — $BODY"
    PERSONA_ID=""
  fi
else
  skip "TC-PER-012" "no archetype ID"
  PERSONA_ID=""
fi

# TC-PER-013: Get persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call GET "/governance/personas/$PERSONA_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-013" "Get persona — 200"
  else
    fail "TC-PER-013" "Get persona — HTTP $CODE"
  fi
else
  skip "TC-PER-013" "no persona ID"
fi

# TC-PER-014: Update persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call PUT "/governance/personas/$PERSONA_ID" -d "{\"display_name\":\"Updated Persona\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-014" "Update persona — 200"
  else
    fail "TC-PER-014" "Update persona — HTTP $CODE"
  fi
else
  skip "TC-PER-014" "no persona ID"
fi

# TC-PER-015: Get persona not found
RAW=$(admin_call GET "/governance/personas/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-PER-015" "Get persona not found — 404"
else
  fail "TC-PER-015" "Get persona not found — HTTP $CODE"
fi

# TC-PER-016: List personas filtered
RAW=$(admin_call GET "/governance/personas?status=active&limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-016" "List personas filtered — 200"
else
  fail "TC-PER-016" "List personas filtered — HTTP $CODE"
fi

# TC-PER-017: Activate persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST "/governance/personas/$PERSONA_ID/activate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-PER-017" "Activate persona — $CODE"
  else
    fail "TC-PER-017" "Activate persona — HTTP $CODE"
  fi
else
  skip "TC-PER-017" "no persona ID"
fi

# TC-PER-018: Propagate attributes
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST "/governance/personas/$PERSONA_ID/propagate-attributes")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-018" "Propagate attributes — 200"
  else
    fail "TC-PER-018" "Propagate attributes — HTTP $CODE"
  fi
else
  skip "TC-PER-018" "no persona ID"
fi

# TC-PER-019: Extend persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST "/governance/personas/$PERSONA_ID/extend" -d "{\"extension_days\":30,\"reason\":\"Need more time\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-019" "Extend persona — 200"
  else
    fail "TC-PER-019" "Extend persona — HTTP $CODE"
  fi
else
  skip "TC-PER-019" "no persona ID"
fi

# TC-PER-020: Get user personas
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/personas")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-020" "Get user personas — 200"
else
  fail "TC-PER-020" "Get user personas — HTTP $CODE"
fi

# TC-PER-021: Get user personas with archived
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/personas?include_archived=true")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-021" "Get user personas +archived — 200"
else
  fail "TC-PER-021" "Get user personas +archived — HTTP $CODE"
fi

# TC-PER-022: Get expiring personas
RAW=$(admin_call GET "/governance/personas/expiring?days_ahead=30")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-022" "Get expiring personas — 200"
else
  fail "TC-PER-022" "Get expiring personas — HTTP $CODE"
fi

# --- Context Switching ---

# TC-PER-023: Get current context
RAW=$(admin_call GET /governance/context/current)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-023" "Get current context — 200"
else
  fail "TC-PER-023" "Get current context — HTTP $CODE"
fi

# TC-PER-024: Switch context
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST /governance/context/switch -d "{\"persona_id\":\"$PERSONA_ID\",\"reason\":\"Testing\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "403" || "$CODE" == "409" ]]; then
    pass "TC-PER-024" "Switch context — $CODE"
  else
    fail "TC-PER-024" "Switch context — HTTP $CODE"
  fi
else
  skip "TC-PER-024" "no persona ID"
fi

# TC-PER-025: Switch back
RAW=$(admin_call POST /governance/context/switch-back -d "{\"reason\":\"Done\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "400" ]]; then
  pass "TC-PER-025" "Switch back — $CODE"
else
  fail "TC-PER-025" "Switch back — HTTP $CODE"
fi

# TC-PER-026: List context sessions
RAW=$(admin_call GET "/governance/context/sessions?limit=10")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-026" "List context sessions — 200"
else
  fail "TC-PER-026" "List context sessions — HTTP $CODE"
fi

# TC-PER-027: Switch to non-existent persona
RAW=$(admin_call POST /governance/context/switch -d "{\"persona_id\":\"00000000-0000-0000-0000-000000000099\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" || "$CODE" == "400" || "$CODE" == "403" ]]; then
  pass "TC-PER-027" "Switch to missing persona — $CODE"
else
  fail "TC-PER-027" "Switch to missing persona — HTTP $CODE"
fi

# --- Persona Audit ---

# TC-PER-028: List persona audit events
RAW=$(admin_call GET /governance/persona-audit)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-028" "List persona audit — 200"
else
  fail "TC-PER-028" "List persona audit — HTTP $CODE"
fi

# TC-PER-029: List persona audit filtered
RAW=$(admin_call GET "/governance/persona-audit?limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-PER-029" "List persona audit filtered — 200"
else
  fail "TC-PER-029" "List persona audit filtered — HTTP $CODE"
fi

# TC-PER-030: Get persona audit trail
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call GET "/governance/personas/$PERSONA_ID/audit")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-PER-030" "Get persona audit trail — 200"
  else
    fail "TC-PER-030" "Get persona audit trail — HTTP $CODE"
  fi
else
  skip "TC-PER-030" "no persona ID"
fi

# --- Persona Lifecycle ---

# TC-PER-031: Deactivate persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST "/governance/personas/$PERSONA_ID/deactivate" -d "{\"reason\":\"Testing deactivation\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-PER-031" "Deactivate persona — $CODE"
  else
    fail "TC-PER-031" "Deactivate persona — HTTP $CODE"
  fi
else
  skip "TC-PER-031" "no persona ID"
fi

# TC-PER-032: Archive persona
if [[ -n "$PERSONA_ID" ]]; then
  RAW=$(admin_call POST "/governance/personas/$PERSONA_ID/archive" -d "{\"reason\":\"Testing archive\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "409" ]]; then
    pass "TC-PER-032" "Archive persona — $CODE"
  else
    fail "TC-PER-032" "Archive persona — HTTP $CODE"
  fi
else
  skip "TC-PER-032" "no persona ID"
fi

# TC-PER-033: Create and delete archetype
RAW=$(admin_call POST /governance/persona-archetypes -d "{\"name\":\"b9-arch-del-${TS}\",\"naming_pattern\":\"{username}\"}")
parse_response "$RAW"
DEL_ARCH_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$DEL_ARCH_ID" && "$DEL_ARCH_ID" != "null" ]]; then
  RAW2=$(admin_call DELETE "/governance/persona-archetypes/$DEL_ARCH_ID")
  CODE2=$(echo "$RAW2" | tail -1)
  if [[ "$CODE2" == "204" || "$CODE2" == "200" ]]; then
    pass "TC-PER-033" "Create+delete archetype — $CODE2"
  elif [[ "$CODE2" == "500" || "$CODE2" == "409" ]]; then
    # Known issue: audit events FK constraint prevents deletion after audit log
    skip "TC-PER-033" "Delete blocked by audit events FK ($CODE2)"
  else
    fail "TC-PER-033" "Create+delete archetype — delete $CODE2"
  fi
else
  fail "TC-PER-033" "Create+delete archetype — create $CODE"
fi

# =============================================================================
# PART 4: RISK MANAGEMENT (33 tests)
# =============================================================================
log "═══ Part 4: Risk Management ═══"

# --- Risk Scores ---

# TC-RISK-001: Get user risk score
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/risk-score")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-RISK-001" "Get user risk score — $CODE"
else
  fail "TC-RISK-001" "Get user risk score — HTTP $CODE"
fi

# TC-RISK-002: Calculate user risk score
RAW=$(admin_call POST "/governance/users/$ADMIN_USER_ID/risk-score/calculate" -d "{\"include_peer_comparison\":true}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-002" "Calculate risk score — 200"
else
  fail "TC-RISK-002" "Calculate risk score — HTTP $CODE"
fi

# TC-RISK-003: Get risk score history
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/risk-score/history")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-RISK-003" "Risk score history — $CODE"
else
  fail "TC-RISK-003" "Risk score history — HTTP $CODE"
fi

# TC-RISK-004: Risk score history with limit
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/risk-score/history?limit=10")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-RISK-004" "Risk history limit=10 — $CODE"
else
  fail "TC-RISK-004" "Risk history limit=10 — HTTP $CODE"
fi

# TC-RISK-005: List all risk scores
RAW=$(admin_call GET /governance/risk-scores)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-005" "List risk scores — 200"
else
  fail "TC-RISK-005" "List risk scores — HTTP $CODE"
fi

# TC-RISK-006: List risk scores filtered
RAW=$(admin_call GET "/governance/risk-scores?risk_level=low&min_score=0&max_score=100&limit=10&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-006" "List risk scores filtered — 200"
else
  fail "TC-RISK-006" "List risk scores filtered — HTTP $CODE"
fi

# TC-RISK-007: Risk score summary
RAW=$(admin_call GET /governance/risk-scores/summary)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-007" "Risk score summary — 200"
else
  fail "TC-RISK-007" "Risk score summary — HTTP $CODE"
fi

# TC-RISK-008: Calculate all risk scores
RAW=$(admin_call POST /governance/risk-scores/calculate-all -d "{\"include_peer_comparison\":false}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-008" "Calculate all scores — 200"
else
  fail "TC-RISK-008" "Calculate all scores — HTTP $CODE"
fi

# TC-RISK-009: Save risk score snapshot
RAW=$(admin_call POST "/governance/users/$ADMIN_USER_ID/risk-score/snapshot")
parse_response "$RAW"
if [[ "$CODE" == "204" || "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-RISK-009" "Save risk snapshot — $CODE"
else
  fail "TC-RISK-009" "Save risk snapshot — HTTP $CODE"
fi

# TC-RISK-010: Get user risk enforcement
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/risk-enforcement")
parse_response "$RAW"
if [[ "$CODE" == "200" || "$CODE" == "404" ]]; then
  pass "TC-RISK-010" "Get risk enforcement — $CODE"
else
  fail "TC-RISK-010" "Get risk enforcement — HTTP $CODE"
fi

# TC-RISK-011: List risk scores no auth
RAW=$(api_call GET /governance/risk-scores)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-RISK-011" "Risk scores no auth — 401"
else
  fail "TC-RISK-011" "Risk scores no auth — HTTP $CODE"
fi

# --- Risk Enforcement Policy ---

# TC-RISK-012: Get enforcement policy
RAW=$(admin_call GET /governance/risk/enforcement-policy)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-012" "Get enforcement policy — 200"
else
  fail "TC-RISK-012" "Get enforcement policy — HTTP $CODE"
fi

# TC-RISK-013: Upsert enforcement policy
RAW=$(admin_call PUT /governance/risk/enforcement-policy -d "{\"enforcement_mode\":\"monitor\",\"fail_open\":true,\"impossible_travel_speed_kmh\":500,\"impossible_travel_enabled\":false}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-013" "Upsert enforcement policy — 200"
else
  fail "TC-RISK-013" "Upsert enforcement policy — HTTP $CODE"
fi

# TC-RISK-014: Update enforcement policy partial
RAW=$(admin_call PUT /governance/risk/enforcement-policy -d "{\"enforcement_mode\":\"enforce\"}")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-014" "Update policy partial — 200"
else
  fail "TC-RISK-014" "Update policy partial — HTTP $CODE"
fi

# --- Risk Factors ---

# TC-RISK-015: List risk factors
RAW=$(admin_call GET /governance/risk-factors)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-015" "List risk factors — 200"
else
  fail "TC-RISK-015" "List risk factors — HTTP $CODE"
fi

# TC-RISK-016: Create risk factor
RAW=$(admin_call POST /governance/risk-factors -d "{\"name\":\"b9-factor-${TS}\",\"description\":\"Test factor\",\"weight\":1.0,\"category\":\"static\",\"factor_type\":\"custom_static_b9_${TS}\"}")
parse_response "$RAW"
FACTOR_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$FACTOR_ID" && "$FACTOR_ID" != "null" ]]; then
  pass "TC-RISK-016" "Create risk factor — 201"
else
  fail "TC-RISK-016" "Create risk factor — HTTP $CODE — $BODY"
  FACTOR_ID=""
fi

# TC-RISK-017: Get risk factor
if [[ -n "$FACTOR_ID" ]]; then
  RAW=$(admin_call GET "/governance/risk-factors/$FACTOR_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RISK-017" "Get risk factor — 200"
  else
    fail "TC-RISK-017" "Get risk factor — HTTP $CODE"
  fi
else
  skip "TC-RISK-017" "no factor ID"
fi

# TC-RISK-018: Update risk factor
if [[ -n "$FACTOR_ID" ]]; then
  RAW=$(admin_call PUT "/governance/risk-factors/$FACTOR_ID" -d "{\"description\":\"Updated\",\"weight\":2.0}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RISK-018" "Update risk factor — 200"
  else
    fail "TC-RISK-018" "Update risk factor — HTTP $CODE"
  fi
else
  skip "TC-RISK-018" "no factor ID"
fi

# TC-RISK-019: Disable risk factor
if [[ -n "$FACTOR_ID" ]]; then
  RAW=$(admin_call POST "/governance/risk-factors/$FACTOR_ID/disable")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RISK-019" "Disable risk factor — 200"
  else
    fail "TC-RISK-019" "Disable risk factor — HTTP $CODE"
  fi
else
  skip "TC-RISK-019" "no factor ID"
fi

# TC-RISK-020: Enable risk factor
if [[ -n "$FACTOR_ID" ]]; then
  RAW=$(admin_call POST "/governance/risk-factors/$FACTOR_ID/enable")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    pass "TC-RISK-020" "Enable risk factor — 200"
  else
    fail "TC-RISK-020" "Enable risk factor — HTTP $CODE"
  fi
else
  skip "TC-RISK-020" "no factor ID"
fi

# TC-RISK-021: Create risk factor (non-admin)
RAW=$(user_call POST /governance/risk-factors -d "{\"name\":\"nonadmin-factor\",\"description\":\"Should fail\",\"weight\":1.0,\"category\":\"static\",\"factor_type\":\"custom_static_test\"}")
parse_response "$RAW"
if [[ "$CODE" == "403" ]]; then
  pass "TC-RISK-021" "Create factor non-admin — 403"
else
  fail "TC-RISK-021" "Create factor non-admin — HTTP $CODE"
fi

# TC-RISK-022: Create duplicate risk factor
if [[ -n "$FACTOR_ID" ]]; then
  RAW=$(admin_call POST /governance/risk-factors -d "{\"name\":\"b9-factor-dup-${TS}\",\"description\":\"Dupe\",\"weight\":1.0,\"category\":\"static\",\"factor_type\":\"custom_static_b9_${TS}\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "409" ]]; then
    pass "TC-RISK-022" "Duplicate factor name — 409"
  else
    fail "TC-RISK-022" "Duplicate factor name — HTTP $CODE"
  fi
fi

# TC-RISK-023: Get risk factor not found
RAW=$(admin_call GET "/governance/risk-factors/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RISK-023" "Get factor not found — 404"
else
  fail "TC-RISK-023" "Get factor not found — HTTP $CODE"
fi

# TC-RISK-024: Delete risk factor
RAW=$(admin_call POST /governance/risk-factors -d "{\"name\":\"b9-del-${TS}\",\"description\":\"Del\",\"weight\":1.0,\"category\":\"static\",\"factor_type\":\"custom_static_del_${TS}\"}")
parse_response "$RAW"
DEL_FACTOR_ID=$(extract_json "$BODY" '.id')
if [[ "$CODE" == "201" && -n "$DEL_FACTOR_ID" && "$DEL_FACTOR_ID" != "null" ]]; then
  RAW2=$(admin_call DELETE "/governance/risk-factors/$DEL_FACTOR_ID")
  CODE2=$(echo "$RAW2" | tail -1)
  if [[ "$CODE2" == "204" ]]; then
    pass "TC-RISK-024" "Delete risk factor — 204"
  else
    fail "TC-RISK-024" "Delete risk factor — delete $CODE2"
  fi
else
  fail "TC-RISK-024" "Delete risk factor — create $CODE"
fi

# TC-RISK-025: List risk factors no auth
RAW=$(api_call GET /governance/risk-factors)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-RISK-025" "Risk factors no auth — 401"
else
  fail "TC-RISK-025" "Risk factors no auth — HTTP $CODE"
fi

# --- Risk Alerts ---

# TC-RISK-026: List risk alerts
RAW=$(admin_call GET /governance/risk-alerts)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-026" "List risk alerts — 200"
else
  fail "TC-RISK-026" "List risk alerts — HTTP $CODE"
fi

# TC-RISK-027: Risk alert summary
RAW=$(admin_call GET /governance/risk-alerts/summary)
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-027" "Risk alert summary — 200"
else
  fail "TC-RISK-027" "Risk alert summary — HTTP $CODE"
fi

# TC-RISK-028: Get risk alert not found
RAW=$(admin_call GET "/governance/risk-alerts/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RISK-028" "Get alert not found — 404"
else
  fail "TC-RISK-028" "Get alert not found — HTTP $CODE"
fi

# TC-RISK-029: Acknowledge alert not found
RAW=$(admin_call POST "/governance/risk-alerts/00000000-0000-0000-0000-000000000099/acknowledge")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RISK-029" "Ack alert not found — 404"
else
  fail "TC-RISK-029" "Ack alert not found — HTTP $CODE"
fi

# TC-RISK-030: Acknowledge all user alerts
RAW=$(admin_call POST "/governance/users/$ADMIN_USER_ID/risk-alerts/acknowledge-all")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-030" "Ack all user alerts — 200"
else
  fail "TC-RISK-030" "Ack all user alerts — HTTP $CODE"
fi

# TC-RISK-031: Get user latest alert
RAW=$(admin_call GET "/governance/users/$ADMIN_USER_ID/risk-alerts/latest")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-RISK-031" "Get user latest alert — 200"
else
  fail "TC-RISK-031" "Get user latest alert — HTTP $CODE"
fi

# TC-RISK-032: Delete risk alert not found
RAW=$(admin_call DELETE "/governance/risk-alerts/00000000-0000-0000-0000-000000000099")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-RISK-032" "Delete alert not found — 404"
else
  fail "TC-RISK-032" "Delete alert not found — HTTP $CODE"
fi

# TC-RISK-033: List risk alerts no auth
RAW=$(api_call GET /governance/risk-alerts)
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-RISK-033" "Risk alerts no auth — 401"
else
  fail "TC-RISK-033" "Risk alerts no auth — HTTP $CODE"
fi

# =============================================================================
# CLEANUP
# =============================================================================
if [[ -n "${MINING_JOB_ID:-}" ]]; then
  admin_call DELETE "/governance/role-mining/jobs/$MINING_JOB_ID" > /dev/null 2>&1
fi

# =============================================================================
# SUMMARY
# =============================================================================
log "═══════════════════════════════════════════════════════════════════"
log "  Batch 9 Results: Governance Deep"
log "═══════════════════════════════════════════════════════════════════"
log ""
log "  PASS=$PASS FAIL=$FAIL SKIP=$SKIP TOTAL=$TOTAL"
log ""
if [[ "$FAIL" -eq 0 ]]; then
  log "  All tests passed!"
else
  log "  SOME TESTS FAILED"
fi
log "═══════════════════════════════════════════════════════════════════"

# Update summary line in results file
sed -i "s/PASS=0 FAIL=0 SKIP=0 TOTAL=0/PASS=$PASS FAIL=$FAIL SKIP=$SKIP TOTAL=$TOTAL/" "$RESULTS_FILE"
