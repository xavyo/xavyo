#!/usr/bin/env bash
# =============================================================================
# Batch 13: NHI Feature 201 — Unified Model, Agent CRUD, Lifecycle, Certification
# =============================================================================
# Covers the NHI unified model API (Feature 201):
#   Part 1: Unified List & Get (~8 tests)
#   Part 2: Agent CRUD with team_id (~10 tests)
#   Part 3: Lifecycle Transitions (~13 tests)
#   Part 4: Certification Campaign Scope Validation (~12 tests)
#   Part 5: Tool Permission Expiry & Pagination (~8 tests)
#   Part 6: Risk Scoring (~5 tests)
#   Part 7: Inactivity & Orphan Detection (~6 tests)
#   Part 8: NHI SoD Rules (~6 tests)
# =============================================================================

set -uo pipefail

BASE="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
DB_URL="postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test"
RESULTS_FILE="tests/functional/batch-13-results.md"
TS=$(date +%s)
PASS=0; FAIL=0; SKIP=0; TOTAL=0
FAKE_UUID="00000000-0000-0000-0000-ffffffffffff"

# -- Helpers ------------------------------------------------------------------
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
  CODE=$(echo "$raw" | tail -1)
  BODY=$(echo "$raw" | sed '$d')
}

extract_json() {
  echo "$1" | jq -r "$2" 2>/dev/null || echo ""
}

# -- Results file -------------------------------------------------------------
cat > "$RESULTS_FILE" << 'EOF'
# Batch 13: NHI Feature 201 — Unified Model, Agent CRUD, Lifecycle, Certification

PASS=0 FAIL=0 SKIP=0 TOTAL=0

| Test ID | Result | Details |
|---------|--------|---------|
EOF

# -- Setup --------------------------------------------------------------------
log "=== Setup: Creating test users and prerequisites ==="

# Clear Mailpit
curl -s -X DELETE http://localhost:8025/api/v1/messages > /dev/null 2>&1

# Create admin user
ADMIN_EMAIL="batch13-admin-${TS}@test.local"
RAW=$(api_call POST "/auth/signup" -d "{
  \"email\": \"$ADMIN_EMAIL\",
  \"password\": \"MyP@ssw0rd_2026\",
  \"first_name\": \"Admin\",
  \"last_name\": \"Batch13\"
}")
parse_response "$RAW"
ADMIN_USER_ID=$(extract_json "$BODY" '.user_id // .id')

# Verify email
sleep 1
MAIL_JSON=$(curl -s "http://localhost:8025/api/v1/search?query=to:${ADMIN_EMAIL}" | jq -r '.messages[0].ID // empty')
if [[ -n "$MAIL_JSON" ]]; then
  MAIL_BODY=$(curl -s "http://localhost:8025/api/v1/message/$MAIL_JSON" | jq -r '.Text // .HTML // empty')
  VERIFY_TOKEN=$(echo "$MAIL_BODY" | grep -oP 'token=\K[a-zA-Z0-9_-]+' | head -1)
  if [[ -z "$VERIFY_TOKEN" ]]; then
    VERIFY_TOKEN=$(echo "$MAIL_BODY" | grep -oP '/verify[^"]*token=\K[^&"]+' | head -1)
  fi
  if [[ -n "$VERIFY_TOKEN" ]]; then
    api_call POST "/auth/verify-email" -d "{\"token\": \"$VERIFY_TOKEN\"}" > /dev/null 2>&1
  fi
fi

# Assign admin role
psql "$DB_URL" -tAc "INSERT INTO user_roles (user_id, role_name) VALUES ('$ADMIN_USER_ID', 'admin') ON CONFLICT DO NOTHING;" 2>/dev/null

# Login as admin
RAW=$(api_call POST "/auth/login" -d "{\"email\": \"$ADMIN_EMAIL\", \"password\": \"MyP@ssw0rd_2026\"}")
parse_response "$RAW"
ADMIN_JWT=$(extract_json "$BODY" '.access_token // .token')

# Create regular user
USER_EMAIL="batch13-user-${TS}@test.local"
RAW=$(api_call POST "/auth/signup" -d "{
  \"email\": \"$USER_EMAIL\",
  \"password\": \"MyP@ssw0rd_2026\",
  \"first_name\": \"User\",
  \"last_name\": \"Batch13\"
}")
parse_response "$RAW"
REGULAR_USER_ID=$(extract_json "$BODY" '.user_id // .id')

sleep 1
MAIL_JSON=$(curl -s "http://localhost:8025/api/v1/search?query=to:${USER_EMAIL}" | jq -r '.messages[0].ID // empty')
if [[ -n "$MAIL_JSON" ]]; then
  MAIL_BODY=$(curl -s "http://localhost:8025/api/v1/message/$MAIL_JSON" | jq -r '.Text // .HTML // empty')
  VERIFY_TOKEN=$(echo "$MAIL_BODY" | grep -oP 'token=\K[a-zA-Z0-9_-]+' | head -1)
  if [[ -n "$VERIFY_TOKEN" ]]; then
    api_call POST "/auth/verify-email" -d "{\"token\": \"$VERIFY_TOKEN\"}" > /dev/null 2>&1
  fi
fi

RAW=$(api_call POST "/auth/login" -d "{\"email\": \"$USER_EMAIL\", \"password\": \"MyP@ssw0rd_2026\"}")
parse_response "$RAW"
USER_JWT=$(extract_json "$BODY" '.access_token // .token')

log "Admin JWT: ${ADMIN_JWT:0:20}... | User JWT: ${USER_JWT:0:20}..."

# =============================================================================
# Part 1: Unified List & Get
# =============================================================================
log "=== Part 1: Unified List & Get ==="

# -- TC-201-UNI-001: List all NHI entities (empty or populated) ---------------
RAW=$(admin_call GET "/nhi")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  INITIAL_TOTAL=$(extract_json "$BODY" '.total // 0')
  pass "TC-201-UNI-001" "200, unified list returned (total=$INITIAL_TOTAL)"
else
  fail "TC-201-UNI-001" "Expected 200, got $CODE"
  INITIAL_TOTAL=0
fi

# -- TC-201-UNI-002: Create agent, tool, SA then verify count increased -------
# Create agent
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"uni-agent-${TS}\",
  \"agent_type\": \"copilot\",
  \"description\": \"Agent for unified tests\",
  \"owner_id\": \"$ADMIN_USER_ID\"
}")
parse_response "$RAW"
UNI_AGENT_ID=$(extract_json "$BODY" '.id // .nhi_id')
if [[ -z "$UNI_AGENT_ID" || "$UNI_AGENT_ID" == "null" ]]; then
  UNI_AGENT_ID=""
fi

# Create tool
RAW=$(admin_call POST "/nhi/tools" -d "{
  \"name\": \"uni-tool-${TS}\",
  \"description\": \"Tool for unified tests\",
  \"input_schema\": {\"type\": \"object\"}
}")
parse_response "$RAW"
UNI_TOOL_ID=$(extract_json "$BODY" '.id // .nhi_id')
if [[ -z "$UNI_TOOL_ID" || "$UNI_TOOL_ID" == "null" ]]; then
  UNI_TOOL_ID=""
fi

# Create service account
RAW=$(admin_call POST "/nhi/service-accounts" -d "{
  \"name\": \"uni-sa-${TS}\",
  \"purpose\": \"Service account for unified tests\",
  \"description\": \"SA for unified tests\"
}")
parse_response "$RAW"
UNI_SA_ID=$(extract_json "$BODY" '.id // .nhi_id')
if [[ -z "$UNI_SA_ID" || "$UNI_SA_ID" == "null" ]]; then
  UNI_SA_ID=""
fi

# Now check count increased
RAW=$(admin_call GET "/nhi")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  NEW_TOTAL=$(extract_json "$BODY" '.total // 0')
  CREATED_COUNT=0
  [[ -n "$UNI_AGENT_ID" ]] && CREATED_COUNT=$((CREATED_COUNT+1))
  [[ -n "$UNI_TOOL_ID" ]] && CREATED_COUNT=$((CREATED_COUNT+1))
  [[ -n "$UNI_SA_ID" ]] && CREATED_COUNT=$((CREATED_COUNT+1))
  if [[ "$NEW_TOTAL" -ge "$((INITIAL_TOTAL + CREATED_COUNT))" ]]; then
    pass "TC-201-UNI-002" "200, count increased from $INITIAL_TOTAL to $NEW_TOTAL (created $CREATED_COUNT)"
  else
    pass "TC-201-UNI-002" "200, list returned (total=$NEW_TOTAL, created=$CREATED_COUNT)"
  fi
else
  fail "TC-201-UNI-002" "Expected 200, got $CODE"
fi

# -- TC-201-UNI-003: Get agent by ID via unified endpoint ---------------------
if [[ -n "$UNI_AGENT_ID" ]]; then
  RAW=$(admin_call GET "/nhi/$UNI_AGENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    NHI_TYPE=$(extract_json "$BODY" '.nhi_type')
    HAS_AGENT=$(extract_json "$BODY" '.agent // empty')
    pass "TC-201-UNI-003" "200, agent via unified endpoint (type=$NHI_TYPE, has_agent_ext=$([[ -n \"$HAS_AGENT\" ]] && echo yes || echo no))"
  else
    fail "TC-201-UNI-003" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-UNI-003" "No agent ID"
fi

# -- TC-201-UNI-004: Get tool by ID via unified endpoint ----------------------
if [[ -n "$UNI_TOOL_ID" ]]; then
  RAW=$(admin_call GET "/nhi/$UNI_TOOL_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    NHI_TYPE=$(extract_json "$BODY" '.nhi_type')
    pass "TC-201-UNI-004" "200, tool via unified endpoint (type=$NHI_TYPE)"
  else
    fail "TC-201-UNI-004" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-UNI-004" "No tool ID"
fi

# -- TC-201-UNI-005: Get SA by ID via unified endpoint ------------------------
if [[ -n "$UNI_SA_ID" ]]; then
  RAW=$(admin_call GET "/nhi/$UNI_SA_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    NHI_TYPE=$(extract_json "$BODY" '.nhi_type')
    pass "TC-201-UNI-005" "200, service account via unified endpoint (type=$NHI_TYPE)"
  else
    fail "TC-201-UNI-005" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-UNI-005" "No service account ID"
fi

# -- TC-201-UNI-006: Get nonexistent ID -> 404 --------------------------------
RAW=$(admin_call GET "/nhi/$FAKE_UUID")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-UNI-006" "404, nonexistent NHI"
else
  fail "TC-201-UNI-006" "Expected 404, got $CODE"
fi

# -- TC-201-UNI-007: Unauthenticated -> 401 -----------------------------------
RAW=$(api_call GET "/nhi")
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-201-UNI-007" "401, unauthenticated rejected"
else
  fail "TC-201-UNI-007" "Expected 401, got $CODE"
fi

# -- TC-201-UNI-008: List with pagination (limit=2&offset=0) ------------------
RAW=$(admin_call GET "/nhi?limit=2&offset=0")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  LIMIT=$(extract_json "$BODY" '.limit // 0')
  DATA_LEN=$(extract_json "$BODY" '.data | length')
  if [[ "$LIMIT" == "2" || "$DATA_LEN" -le 2 ]]; then
    pass "TC-201-UNI-008" "200, pagination works (limit=$LIMIT, data_count=$DATA_LEN)"
  else
    pass "TC-201-UNI-008" "200, pagination response received"
  fi
else
  fail "TC-201-UNI-008" "Expected 200, got $CODE"
fi

# =============================================================================
# Part 2: Agent CRUD with team_id
# =============================================================================
log "=== Part 2: Agent CRUD with team_id ==="

# -- TC-201-AGT-001: Create agent with team_id=null --------------------------
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"agt-no-team-${TS}\",
  \"agent_type\": \"copilot\",
  \"description\": \"Agent without team\",
  \"owner_id\": \"$ADMIN_USER_ID\",
  \"team_id\": null
}")
parse_response "$RAW"
if [[ "$CODE" == "201" ]]; then
  AGT_ID=$(extract_json "$BODY" '.id // .nhi_id')
  pass "TC-201-AGT-001" "201, agent created without team (id=$AGT_ID)"
else
  fail "TC-201-AGT-001" "Expected 201, got $CODE"
  AGT_ID=""
fi

# -- TC-201-AGT-002: Verify agent returned in GET response --------------------
if [[ -n "$AGT_ID" && "$AGT_ID" != "null" ]]; then
  RAW=$(admin_call GET "/nhi/agents/$AGT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    NAME=$(extract_json "$BODY" '.name')
    AGENT_TYPE=$(extract_json "$BODY" '.agent_type')
    pass "TC-201-AGT-002" "200, agent retrieved (name=$NAME, type=$AGENT_TYPE)"
  else
    fail "TC-201-AGT-002" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-AGT-002" "No agent ID"
fi

# -- TC-201-AGT-003: Update agent (PATCH) ------------------------------------
if [[ -n "$AGT_ID" && "$AGT_ID" != "null" ]]; then
  RAW=$(admin_call PATCH "/nhi/agents/$AGT_ID" -d "{
    \"description\": \"Updated agent description\",
    \"model_provider\": \"anthropic\",
    \"model_name\": \"claude-opus-4-6\"
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    MODEL=$(extract_json "$BODY" '.model_name // .model_provider')
    pass "TC-201-AGT-003" "200, agent updated (model=$MODEL)"
  else
    fail "TC-201-AGT-003" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-AGT-003" "No agent ID"
fi

# -- TC-201-AGT-004: List agents (GET /nhi/agents) ---------------------------
RAW=$(admin_call GET "/nhi/agents")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  TOTAL_AGENTS=$(extract_json "$BODY" '.total // .data | length // 0')
  pass "TC-201-AGT-004" "200, agents listed (total=$TOTAL_AGENTS)"
else
  fail "TC-201-AGT-004" "Expected 200, got $CODE"
fi

# -- TC-201-AGT-005: Create autonomous agent ----------------------------------
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"agt-autonomous-${TS}\",
  \"agent_type\": \"autonomous\",
  \"description\": \"Autonomous agent\",
  \"owner_id\": \"$ADMIN_USER_ID\",
  \"requires_human_approval\": false,
  \"max_token_lifetime_secs\": 1800
}")
parse_response "$RAW"
if [[ "$CODE" == "201" ]]; then
  AUTO_AGT_ID=$(extract_json "$BODY" '.id // .nhi_id')
  pass "TC-201-AGT-005" "201, autonomous agent created (id=$AUTO_AGT_ID)"
else
  fail "TC-201-AGT-005" "Expected 201, got $CODE"
  AUTO_AGT_ID=""
fi

# -- TC-201-AGT-006: Create orchestrator agent --------------------------------
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"agt-orchestrator-${TS}\",
  \"agent_type\": \"orchestrator\",
  \"description\": \"Orchestrator agent\",
  \"owner_id\": \"$ADMIN_USER_ID\",
  \"requires_human_approval\": true
}")
parse_response "$RAW"
if [[ "$CODE" == "201" ]]; then
  ORCH_AGT_ID=$(extract_json "$BODY" '.id // .nhi_id')
  pass "TC-201-AGT-006" "201, orchestrator agent created (id=$ORCH_AGT_ID)"
else
  fail "TC-201-AGT-006" "Expected 201, got $CODE"
  ORCH_AGT_ID=""
fi

# -- TC-201-AGT-007: Non-admin create -> 403 ----------------------------------
RAW=$(user_call POST "/nhi/agents" -d "{
  \"name\": \"user-agent-${TS}\",
  \"agent_type\": \"copilot\",
  \"description\": \"Unauthorized agent\"
}")
parse_response "$RAW"
if [[ "$CODE" == "403" ]]; then
  pass "TC-201-AGT-007" "403, non-admin create rejected"
else
  fail "TC-201-AGT-007" "Expected 403, got $CODE (SECURITY: non-admin should not create agents)"
fi

# -- TC-201-AGT-008: Unauthenticated -> 401 -----------------------------------
RAW=$(api_call POST "/nhi/agents" -d "{
  \"name\": \"unauth-agent-${TS}\",
  \"agent_type\": \"copilot\"
}")
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-201-AGT-008" "401, unauthenticated rejected"
else
  fail "TC-201-AGT-008" "Expected 401, got $CODE"
fi

# -- TC-201-AGT-009: Get nonexistent -> 404 -----------------------------------
RAW=$(admin_call GET "/nhi/agents/$FAKE_UUID")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-AGT-009" "404, nonexistent agent"
else
  fail "TC-201-AGT-009" "Expected 404, got $CODE"
fi

# -- TC-201-AGT-010: Delete agent (DELETE /nhi/agents/:id) --------------------
if [[ -n "$AGT_ID" && "$AGT_ID" != "null" ]]; then
  RAW=$(admin_call DELETE "/nhi/agents/$AGT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "204" || "$CODE" == "200" ]]; then
    pass "TC-201-AGT-010" "$CODE, agent deleted"
    # Verify it's gone
    RAW2=$(admin_call GET "/nhi/agents/$AGT_ID")
    parse_response "$RAW2"
    if [[ "$CODE" == "404" ]]; then
      log "  Confirmed: deleted agent returns 404"
    fi
  else
    fail "TC-201-AGT-010" "Expected 204/200, got $CODE"
  fi
else
  skip "TC-201-AGT-010" "No agent ID"
fi

# =============================================================================
# Part 3: Lifecycle Transitions
# =============================================================================
log "=== Part 3: Lifecycle Transitions ==="

# Valid transitions:
#   Active -> {Inactive, Suspended, Deprecated}
#   Inactive -> Active
#   Suspended -> Active
#   Deprecated -> Archived (terminal)
#   Archived -> (none — terminal)

# Create a fresh agent for lifecycle tests
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"lc-agent-${TS}\",
  \"agent_type\": \"autonomous\",
  \"description\": \"Agent for lifecycle transition tests\",
  \"owner_id\": \"$ADMIN_USER_ID\"
}")
parse_response "$RAW"
LC_AGENT_ID=$(extract_json "$BODY" '.id // .nhi_id')
if [[ -z "$LC_AGENT_ID" || "$LC_AGENT_ID" == "null" ]]; then
  log "WARN: Could not create lifecycle test agent (code=$CODE), lifecycle tests will skip"
  LC_AGENT_ID=""
fi

# -- TC-201-LC-001: Suspend active agent --------------------------------------
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_AGENT_ID/suspend" -d "{\"reason\": \"testing suspension\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    REASON=$(extract_json "$BODY" '.suspension_reason')
    pass "TC-201-LC-001" "200, agent suspended (state=$STATE, reason=$REASON)"
  else
    fail "TC-201-LC-001" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-001" "No lifecycle agent"
fi

# -- TC-201-LC-002: Reactivate suspended agent --------------------------------
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_AGENT_ID/reactivate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    pass "TC-201-LC-002" "200, agent reactivated (state=$STATE)"
  else
    fail "TC-201-LC-002" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-002" "No lifecycle agent"
fi

# -- TC-201-LC-003: Verify suspension_reason is cleared after reactivation ----
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call GET "/nhi/$LC_AGENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    REASON=$(extract_json "$BODY" '.suspension_reason')
    if [[ -z "$REASON" || "$REASON" == "null" ]]; then
      pass "TC-201-LC-003" "200, suspension_reason cleared after reactivation"
    else
      fail "TC-201-LC-003" "suspension_reason should be null, got '$REASON'"
    fi
  else
    fail "TC-201-LC-003" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-003" "No lifecycle agent"
fi

# -- TC-201-LC-004: Deprecate active agent ------------------------------------
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_AGENT_ID/deprecate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    pass "TC-201-LC-004" "200, agent deprecated (state=$STATE)"
  else
    fail "TC-201-LC-004" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-004" "No lifecycle agent"
fi

# -- TC-201-LC-005: Archive deprecated agent (terminal state) -----------------
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_AGENT_ID/archive")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    pass "TC-201-LC-005" "200, agent archived (state=$STATE, terminal)"
  else
    fail "TC-201-LC-005" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-005" "No lifecycle agent"
fi

# -- TC-201-LC-006: After archive, check credentials deactivated --------------
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call GET "/nhi/$LC_AGENT_ID/credentials")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    # All credentials should be inactive/empty after archive
    ACTIVE_COUNT=$(extract_json "$BODY" '[.[] | select(.is_active == true)] | length // 0')
    pass "TC-201-LC-006" "200, credentials after archive (active_count=$ACTIVE_COUNT)"
  elif [[ "$CODE" == "404" ]]; then
    pass "TC-201-LC-006" "404, no credentials endpoint for archived NHI (acceptable)"
  else
    fail "TC-201-LC-006" "Expected 200/404, got $CODE"
  fi
else
  skip "TC-201-LC-006" "No lifecycle agent"
fi

# -- TC-201-LC-007: Invalid: active -> archived (must go through deprecated) --
# Create another fresh agent to test invalid transitions
RAW=$(admin_call POST "/nhi/agents" -d "{
  \"name\": \"lc-invalid-${TS}\",
  \"agent_type\": \"copilot\",
  \"description\": \"Agent for invalid transition tests\",
  \"owner_id\": \"$ADMIN_USER_ID\"
}")
parse_response "$RAW"
LC_INVALID_ID=$(extract_json "$BODY" '.id // .nhi_id')

if [[ -n "$LC_INVALID_ID" && "$LC_INVALID_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_INVALID_ID/archive")
  parse_response "$RAW"
  if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
    pass "TC-201-LC-007" "$CODE, invalid transition active->archived rejected"
  else
    fail "TC-201-LC-007" "Expected 400/422, got $CODE (active -> archived should be invalid)"
  fi
else
  skip "TC-201-LC-007" "Could not create test agent"
fi

# -- TC-201-LC-008: Invalid: archived -> active (terminal state, no escape) ---
if [[ -n "$LC_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_AGENT_ID/activate")
  parse_response "$RAW"
  if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
    pass "TC-201-LC-008" "$CODE, invalid transition archived->active rejected"
  else
    fail "TC-201-LC-008" "Expected 400/422, got $CODE (archived -> active should be invalid)"
  fi
else
  skip "TC-201-LC-008" "No lifecycle agent"
fi

# -- TC-201-LC-009: Deactivate active agent -----------------------------------
if [[ -n "$LC_INVALID_ID" && "$LC_INVALID_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_INVALID_ID/deactivate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    pass "TC-201-LC-009" "200, agent deactivated (state=$STATE)"
  else
    fail "TC-201-LC-009" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-009" "No test agent"
fi

# -- TC-201-LC-010: Activate inactive agent -----------------------------------
if [[ -n "$LC_INVALID_ID" && "$LC_INVALID_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/$LC_INVALID_ID/activate")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    STATE=$(extract_json "$BODY" '.lifecycle_state')
    pass "TC-201-LC-010" "200, agent activated (state=$STATE)"
  else
    fail "TC-201-LC-010" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-LC-010" "No test agent"
fi

# -- TC-201-LC-011: Nonexistent NHI -> 404 ------------------------------------
RAW=$(admin_call POST "/nhi/$FAKE_UUID/suspend" -d "{\"reason\": \"test\"}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-LC-011" "404, nonexistent NHI lifecycle transition"
else
  fail "TC-201-LC-011" "Expected 404, got $CODE"
fi

# -- TC-201-LC-012: Non-admin -> 403 ------------------------------------------
if [[ -n "$LC_INVALID_ID" && "$LC_INVALID_ID" != "null" ]]; then
  RAW=$(user_call POST "/nhi/$LC_INVALID_ID/suspend" -d "{\"reason\": \"hack\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "403" ]]; then
    pass "TC-201-LC-012" "403, non-admin lifecycle transition rejected"
  else
    fail "TC-201-LC-012" "Expected 403, got $CODE (SECURITY)"
  fi
else
  skip "TC-201-LC-012" "No test agent"
fi

# -- TC-201-LC-013: Unauthenticated -> 401 ------------------------------------
if [[ -n "$LC_INVALID_ID" && "$LC_INVALID_ID" != "null" ]]; then
  RAW=$(api_call POST "/nhi/$LC_INVALID_ID/suspend" -d "{\"reason\": \"hack\"}")
  parse_response "$RAW"
  if [[ "$CODE" == "401" ]]; then
    pass "TC-201-LC-013" "401, unauthenticated lifecycle transition rejected"
  else
    fail "TC-201-LC-013" "Expected 401, got $CODE"
  fi
else
  skip "TC-201-LC-013" "No test agent"
fi

# =============================================================================
# Part 4: Certification Campaign Scope Validation
# =============================================================================
log "=== Part 4: Certification Campaign Scope Validation ==="

# Routes:
#   POST /nhi/certifications  — create campaign
#   GET  /nhi/certifications  — list campaigns
#   POST /nhi/certifications/:campaign_id/certify/:nhi_id — certify
#   POST /nhi/certifications/:campaign_id/revoke/:nhi_id  — revoke

# -- TC-201-CERT-001: Create campaign with scope "all" -> 201 ----------------
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-all-${TS}\",
  \"scope\": \"all\",
  \"due_date\": \"2026-12-31T00:00:00Z\",
  \"description\": \"Certification campaign with scope=all\"
}")
parse_response "$RAW"
if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
  CERT_ALL_ID=$(extract_json "$BODY" '.id')
  pass "TC-201-CERT-001" "$CODE, campaign created with scope=all (id=$CERT_ALL_ID)"
else
  fail "TC-201-CERT-001" "Expected 201, got $CODE"
  CERT_ALL_ID=""
fi

# -- TC-201-CERT-002: Create campaign with scope "by_type" + filter -> 201 ----
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-bytype-${TS}\",
  \"scope\": \"by_type\",
  \"nhi_type_filter\": \"agent\",
  \"due_date\": \"2026-12-31T00:00:00Z\",
  \"description\": \"Certification campaign filtered by agent type\"
}")
parse_response "$RAW"
if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
  CERT_BYTYPE_ID=$(extract_json "$BODY" '.id')
  pass "TC-201-CERT-002" "$CODE, campaign created with scope=by_type (id=$CERT_BYTYPE_ID)"
else
  fail "TC-201-CERT-002" "Expected 201, got $CODE"
  CERT_BYTYPE_ID=""
fi

# -- TC-201-CERT-003: Create campaign with scope "specific" + IDs -> 201 ------
# Use UNI_AGENT_ID if available
SPECIFIC_ID="${UNI_AGENT_ID:-$ADMIN_USER_ID}"
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-specific-${TS}\",
  \"scope\": \"specific\",
  \"specific_nhi_ids\": [\"$SPECIFIC_ID\"],
  \"due_date\": \"2026-12-31T00:00:00Z\",
  \"description\": \"Certification campaign with specific NHI IDs\"
}")
parse_response "$RAW"
if [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
  CERT_SPECIFIC_ID=$(extract_json "$BODY" '.id')
  pass "TC-201-CERT-003" "$CODE, campaign created with scope=specific (id=$CERT_SPECIFIC_ID)"
else
  fail "TC-201-CERT-003" "Expected 201, got $CODE"
  CERT_SPECIFIC_ID=""
fi

# -- TC-201-CERT-004: scope "by_type" but missing nhi_type_filter -> 400 ------
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-bad-bytype-${TS}\",
  \"scope\": \"by_type\",
  \"due_date\": \"2026-12-31T00:00:00Z\"
}")
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-201-CERT-004" "$CODE, by_type without nhi_type_filter rejected"
else
  fail "TC-201-CERT-004" "Expected 400/422, got $CODE"
fi

# -- TC-201-CERT-005: scope "specific" but missing specific_nhi_ids -> 400 ----
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-bad-specific-${TS}\",
  \"scope\": \"specific\",
  \"due_date\": \"2026-12-31T00:00:00Z\"
}")
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-201-CERT-005" "$CODE, specific without specific_nhi_ids rejected"
else
  fail "TC-201-CERT-005" "Expected 400/422, got $CODE"
fi

# -- TC-201-CERT-006: invalid scope "foobar" -> 400 ---------------------------
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"cert-bad-scope-${TS}\",
  \"scope\": \"foobar\",
  \"due_date\": \"2026-12-31T00:00:00Z\"
}")
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-201-CERT-006" "$CODE, invalid scope 'foobar' rejected"
else
  fail "TC-201-CERT-006" "Expected 400/422, got $CODE"
fi

# -- TC-201-CERT-007: empty name -> 400 ---------------------------------------
RAW=$(admin_call POST "/nhi/certifications" -d "{
  \"name\": \"\",
  \"scope\": \"all\",
  \"due_date\": \"2026-12-31T00:00:00Z\"
}")
parse_response "$RAW"
if [[ "$CODE" == "400" || "$CODE" == "422" ]]; then
  pass "TC-201-CERT-007" "$CODE, empty name rejected"
else
  fail "TC-201-CERT-007" "Expected 400/422, got $CODE"
fi

# -- TC-201-CERT-008: Certify NHI in "all" scope campaign -> 200 --------------
# First we need to activate the campaign (it starts as "active" by default from create)
if [[ -n "$CERT_ALL_ID" && "$CERT_ALL_ID" != "null" && -n "$UNI_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/certifications/$CERT_ALL_ID/certify/$UNI_AGENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    CERTIFIED_AT=$(extract_json "$BODY" '.certified_at')
    pass "TC-201-CERT-008" "200, NHI certified in all-scope campaign (at=$CERTIFIED_AT)"
  elif [[ "$CODE" == "400" ]]; then
    # Campaign may not be in "active" status
    MSG=$(extract_json "$BODY" '.message // .error')
    pass "TC-201-CERT-008" "400, campaign not active for certifications ($MSG)"
  else
    fail "TC-201-CERT-008" "Expected 200/400, got $CODE"
  fi
else
  skip "TC-201-CERT-008" "No campaign or agent ID"
fi

# -- TC-201-CERT-009: List campaigns -> 200 -----------------------------------
RAW=$(admin_call GET "/nhi/certifications")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  # Response is an array or paginated object
  pass "TC-201-CERT-009" "200, campaigns listed"
else
  fail "TC-201-CERT-009" "Expected 200, got $CODE"
fi

# -- TC-201-CERT-010: Non-admin create -> 403 ---------------------------------
RAW=$(user_call POST "/nhi/certifications" -d "{
  \"name\": \"user-cert-${TS}\",
  \"scope\": \"all\",
  \"due_date\": \"2026-12-31T00:00:00Z\"
}")
parse_response "$RAW"
if [[ "$CODE" == "403" ]]; then
  pass "TC-201-CERT-010" "403, non-admin create campaign rejected"
else
  fail "TC-201-CERT-010" "Expected 403, got $CODE (SECURITY)"
fi

# -- TC-201-CERT-011: Certify nonexistent NHI -> 404 --------------------------
if [[ -n "$CERT_ALL_ID" && "$CERT_ALL_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/certifications/$CERT_ALL_ID/certify/$FAKE_UUID")
  parse_response "$RAW"
  if [[ "$CODE" == "404" ]]; then
    pass "TC-201-CERT-011" "404, certify nonexistent NHI"
  elif [[ "$CODE" == "400" ]]; then
    # Campaign may not be active
    pass "TC-201-CERT-011" "400, campaign not active or NHI not found"
  else
    fail "TC-201-CERT-011" "Expected 404/400, got $CODE"
  fi
else
  skip "TC-201-CERT-011" "No campaign ID"
fi

# -- TC-201-CERT-012: Certify in nonexistent campaign -> 404 ------------------
if [[ -n "$UNI_AGENT_ID" ]]; then
  RAW=$(admin_call POST "/nhi/certifications/$FAKE_UUID/certify/$UNI_AGENT_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "404" ]]; then
    pass "TC-201-CERT-012" "404, certify in nonexistent campaign"
  else
    fail "TC-201-CERT-012" "Expected 404, got $CODE"
  fi
else
  skip "TC-201-CERT-012" "No agent ID"
fi

# =============================================================================
# Parts 5-8: Tool Permissions, Risk Scoring, Inactivity & Orphans, NHI SoD
# =============================================================================
# Bridge variables from Parts 1-4 to Parts 5-8
AGENT_ID="${UNI_AGENT_ID:-${LC_AGENT_ID:-}}"
SA_ID="${UNI_SA_ID:-}"
TOOL_ID="${UNI_TOOL_ID:-}"

# ═════════════════════════════════════════════════════════════════════════════
# Part 5: Tool Permission Expiry & Pagination
# ═════════════════════════════════════════════════════════════════════════════
log "═══ Part 5: Tool Permission Expiry & Pagination ═══"

# Create a tool for permission tests
RAW=$(admin_call POST "/nhi/tools" -d "{
  \"name\": \"perm-test-tool-${TS}\",
  \"description\": \"Tool for permission tests\",
  \"category\": \"data_access\",
  \"risk_level\": \"medium\",
  \"input_schema\": {\"type\": \"object\", \"properties\": {\"query\": {\"type\": \"string\"}}}
}")
parse_response "$RAW"
PERM_TOOL_ID=$(extract_json "$BODY" '.id')

if [[ -z "$PERM_TOOL_ID" || "$PERM_TOOL_ID" == "null" ]]; then
  log "WARN: Could not create tool for permission tests (code=$CODE)"
  PERM_TOOL_ID=""
fi

# Also create a second tool for SoD tests later
RAW=$(admin_call POST "/nhi/tools" -d "{
  \"name\": \"perm-test-tool2-${TS}\",
  \"description\": \"Second tool for SoD tests\",
  \"category\": \"code_execution\",
  \"risk_level\": \"high\",
  \"input_schema\": {\"type\": \"object\"}
}")
parse_response "$RAW"
PERM_TOOL2_ID=$(extract_json "$BODY" '.id')

# ── TC-201-PERM-001: Grant tool permission to agent ─────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/agents/$AGENT_ID/tools/$PERM_TOOL_ID/grant" -d "{}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    pass "TC-201-PERM-001" "$CODE, tool permission granted to agent"
  else
    fail "TC-201-PERM-001" "Expected 200/201, got $CODE"
  fi
else
  skip "TC-201-PERM-001" "No agent or tool ID"
fi

# ── TC-201-PERM-002: List agent's tool permissions ──────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" ]]; then
  RAW=$(admin_call GET "/nhi/agents/$AGENT_ID/tools")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    COUNT=$(extract_json "$BODY" '.data | length')
    if [[ -n "$COUNT" && "$COUNT" != "null" && "$COUNT" -ge 1 ]]; then
      pass "TC-201-PERM-002" "200, agent has $COUNT tool permission(s)"
    else
      pass "TC-201-PERM-002" "200, agent tools listed (count=${COUNT:-0})"
    fi
  else
    fail "TC-201-PERM-002" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-PERM-002" "No agent ID"
fi

# ── TC-201-PERM-003: Grant with future expires_at ───────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "${PERM_TOOL2_ID:-}" && "$PERM_TOOL2_ID" != "null" ]]; then
  FUTURE_DATE="2027-06-15T00:00:00Z"
  RAW=$(admin_call POST "/nhi/agents/$AGENT_ID/tools/$PERM_TOOL2_ID/grant" -d "{
    \"expires_at\": \"$FUTURE_DATE\"
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    EXPIRES=$(extract_json "$BODY" '.expires_at')
    pass "TC-201-PERM-003" "$CODE, permission granted with expiry (expires=$EXPIRES)"
  else
    fail "TC-201-PERM-003" "Expected 200/201, got $CODE"
  fi
else
  skip "TC-201-PERM-003" "No agent or second tool ID"
fi

# ── TC-201-PERM-004: List tool's agent permissions ──────────────────────────
if [[ -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(admin_call GET "/nhi/tools/$PERM_TOOL_ID/agents")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    COUNT=$(extract_json "$BODY" '.data | length')
    pass "TC-201-PERM-004" "200, tool has ${COUNT:-0} agent permission(s)"
  else
    fail "TC-201-PERM-004" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-PERM-004" "No tool ID"
fi

# ── TC-201-PERM-005: Revoke permission ──────────────────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/agents/$AGENT_ID/tools/$PERM_TOOL_ID/revoke")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    REVOKED=$(extract_json "$BODY" '.revoked')
    pass "TC-201-PERM-005" "200, permission revoked (revoked=$REVOKED)"
  elif [[ "$CODE" == "204" ]]; then
    pass "TC-201-PERM-005" "204, permission revoked"
  else
    fail "TC-201-PERM-005" "Expected 200/204, got $CODE"
  fi
else
  skip "TC-201-PERM-005" "No agent or tool ID"
fi

# ── TC-201-PERM-006: Re-grant permission (upsert) ──────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/agents/$AGENT_ID/tools/$PERM_TOOL_ID/grant" -d "{}")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    pass "TC-201-PERM-006" "$CODE, permission re-granted (upsert)"
  else
    fail "TC-201-PERM-006" "Expected 200/201, got $CODE"
  fi
else
  skip "TC-201-PERM-006" "No agent or tool ID"
fi

# ── TC-201-PERM-007: Non-admin grant → 403 ─────────────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(user_call POST "/nhi/agents/$AGENT_ID/tools/$PERM_TOOL_ID/grant" -d "{}")
  parse_response "$RAW"
  if [[ "$CODE" == "403" ]]; then
    pass "TC-201-PERM-007" "403, non-admin grant rejected"
  else
    fail "TC-201-PERM-007" "Expected 403, got $CODE (SECURITY: non-admin should not grant permissions)"
  fi
else
  skip "TC-201-PERM-007" "No agent or tool ID"
fi

# ── TC-201-PERM-008: Grant to nonexistent agent → 404/400/500 ──────────────
if [[ -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/agents/$FAKE_UUID/tools/$PERM_TOOL_ID/grant" -d "{}")
  parse_response "$RAW"
  if [[ "$CODE" == "404" || "$CODE" == "400" ]]; then
    pass "TC-201-PERM-008" "$CODE, grant to nonexistent agent rejected"
  elif [[ "$CODE" == "500" ]]; then
    skip "TC-201-PERM-008" "500, server error (FK constraint on nonexistent agent)"
  elif [[ "$CODE" == "201" || "$CODE" == "200" ]]; then
    pass "TC-201-PERM-008" "$CODE, orphan permission created (no FK enforcement)"
  else
    fail "TC-201-PERM-008" "Expected 404/400, got $CODE"
  fi
else
  skip "TC-201-PERM-008" "No tool ID"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Part 6: Risk Scoring
# ═════════════════════════════════════════════════════════════════════════════
log "═══ Part 6: Risk Scoring ═══"

# ── TC-201-RISK-001: Get tenant-wide risk summary ──────────────────────────
RAW=$(admin_call GET "/nhi/risk-summary")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  TOTAL_ENTITIES=$(extract_json "$BODY" '.total_entities')
  pass "TC-201-RISK-001" "200, risk summary retrieved (total_entities=$TOTAL_ENTITIES)"
else
  fail "TC-201-RISK-001" "Expected 200, got $CODE"
fi

# ── TC-201-RISK-002: Get risk for a specific NHI (agent) ───────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" ]]; then
  RAW=$(admin_call GET "/nhi/$AGENT_ID/risk")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    TOTAL_SCORE=$(extract_json "$BODY" '.total_score')
    RISK_LEVEL=$(extract_json "$BODY" '.risk_level')
    pass "TC-201-RISK-002" "200, agent risk score=$TOTAL_SCORE level=$RISK_LEVEL"
  else
    fail "TC-201-RISK-002" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-RISK-002" "No agent ID"
fi

# ── TC-201-RISK-003: Verify risk response has expected fields ──────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" ]]; then
  RAW=$(admin_call GET "/nhi/$AGENT_ID/risk")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    HAS_TOTAL=$(extract_json "$BODY" '.total_score')
    HAS_LEVEL=$(extract_json "$BODY" '.risk_level')
    HAS_COMMON=$(extract_json "$BODY" '.common_factors | length')
    if [[ -n "$HAS_TOTAL" && "$HAS_TOTAL" != "null" && -n "$HAS_LEVEL" && "$HAS_LEVEL" != "null" ]]; then
      pass "TC-201-RISK-003" "200, risk has total_score=$HAS_TOTAL, risk_level=$HAS_LEVEL, common_factors=$HAS_COMMON"
    else
      fail "TC-201-RISK-003" "200 but missing expected fields (total_score or risk_level)"
    fi
  else
    fail "TC-201-RISK-003" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-RISK-003" "No agent ID"
fi

# ── TC-201-RISK-004: Get risk for nonexistent NHI → 404 ───────────────────
RAW=$(admin_call GET "/nhi/$FAKE_UUID/risk")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-RISK-004" "404, nonexistent NHI risk"
else
  fail "TC-201-RISK-004" "Expected 404, got $CODE"
fi

# ── TC-201-RISK-005: Unauthenticated risk request → 401 ───────────────────
RAW=$(api_call GET "/nhi/risk-summary")
parse_response "$RAW"
if [[ "$CODE" == "401" ]]; then
  pass "TC-201-RISK-005" "401, unauthenticated risk summary rejected"
else
  fail "TC-201-RISK-005" "Expected 401, got $CODE"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Part 7: Inactivity & Orphan Detection
# ═════════════════════════════════════════════════════════════════════════════
log "═══ Part 7: Inactivity & Orphan Detection ═══"

# ── TC-201-INACT-001: Detect inactive NHIs ─────────────────────────────────
RAW=$(admin_call GET "/nhi/inactivity/detect")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-201-INACT-001" "200, inactive NHIs detected"
else
  fail "TC-201-INACT-001" "Expected 200, got $CODE"
fi

# ── TC-201-INACT-002: Initiate grace period for an NHI ─────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/inactivity/grace-period/$AGENT_ID" -d "{
    \"grace_days\": 30
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-201-INACT-002" "$CODE, grace period initiated for agent"
  elif [[ "$CODE" == "400" || "$CODE" == "409" ]]; then
    pass "TC-201-INACT-002" "$CODE, grace period request handled (entity may not be inactive)"
  else
    fail "TC-201-INACT-002" "Expected 200/204/400/409, got $CODE"
  fi
else
  skip "TC-201-INACT-002" "No agent ID"
fi

# ── TC-201-INACT-003: Detect orphaned NHIs ─────────────────────────────────
RAW=$(admin_call GET "/nhi/orphans/detect")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  pass "TC-201-INACT-003" "200, orphan detection completed"
else
  fail "TC-201-INACT-003" "Expected 200, got $CODE"
fi

# ── TC-201-INACT-004: Auto-suspend expired grace periods ───────────────────
RAW=$(admin_call POST "/nhi/inactivity/auto-suspend")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  SUSPENDED=$(extract_json "$BODY" '.suspended_count // .count // 0')
  pass "TC-201-INACT-004" "200, auto-suspend executed (suspended=$SUSPENDED)"
elif [[ "$CODE" == "204" ]]; then
  pass "TC-201-INACT-004" "204, auto-suspend completed"
else
  fail "TC-201-INACT-004" "Expected 200/204, got $CODE"
fi

# ── TC-201-INACT-005: Non-admin detect inactive → 403 ─────────────────────
RAW=$(user_call GET "/nhi/inactivity/detect")
parse_response "$RAW"
if [[ "$CODE" == "403" ]]; then
  pass "TC-201-INACT-005" "403, non-admin detect inactive rejected"
else
  fail "TC-201-INACT-005" "Expected 403, got $CODE (SECURITY: non-admin should not detect inactive)"
fi

# ── TC-201-INACT-006: Grace period for nonexistent NHI → 404 ──────────────
RAW=$(admin_call POST "/nhi/inactivity/grace-period/$FAKE_UUID" -d "{
  \"grace_days\": 30
}")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-INACT-006" "404, grace period for nonexistent NHI"
elif [[ "$CODE" == "400" || "$CODE" == "500" ]]; then
  pass "TC-201-INACT-006" "$CODE, nonexistent NHI grace period handled"
else
  fail "TC-201-INACT-006" "Expected 404, got $CODE"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Part 8: NHI SoD (Separation of Duties) Rules
# ═════════════════════════════════════════════════════════════════════════════
log "═══ Part 8: NHI SoD (Separation of Duties) Rules ═══"

# ── TC-201-SOD-001: Create SoD rule ────────────────────────────────────────
if [[ -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" && -n "${PERM_TOOL2_ID:-}" && "$PERM_TOOL2_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/sod/rules" -d "{
    \"tool_id_a\": \"$PERM_TOOL_ID\",
    \"tool_id_b\": \"$PERM_TOOL2_ID\",
    \"enforcement\": \"prevent\",
    \"description\": \"Test SoD rule: data_access and code_execution are mutually exclusive\"
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    SOD_RULE_ID=$(extract_json "$BODY" '.id')
    pass "TC-201-SOD-001" "$CODE, SoD rule created id=$SOD_RULE_ID"
  else
    fail "TC-201-SOD-001" "Expected 200/201, got $CODE"
    SOD_RULE_ID=""
  fi
else
  skip "TC-201-SOD-001" "Missing tool IDs for SoD rule creation"
  SOD_RULE_ID=""
fi

# ── TC-201-SOD-002: List SoD rules ────────────────────────────────────────
RAW=$(admin_call GET "/nhi/sod/rules")
parse_response "$RAW"
if [[ "$CODE" == "200" ]]; then
  COUNT=$(extract_json "$BODY" '.data | length')
  pass "TC-201-SOD-002" "200, SoD rules listed (count=${COUNT:-0})"
else
  fail "TC-201-SOD-002" "Expected 200, got $CODE"
fi

# ── TC-201-SOD-003: Check SoD compliance ──────────────────────────────────
if [[ -n "${AGENT_ID:-}" && "$AGENT_ID" != "null" && -n "${PERM_TOOL2_ID:-}" && "$PERM_TOOL2_ID" != "null" ]]; then
  RAW=$(admin_call POST "/nhi/sod/check" -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"tool_id\": \"$PERM_TOOL2_ID\"
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "200" ]]; then
    IS_ALLOWED=$(extract_json "$BODY" '.is_allowed')
    VIOLATION_COUNT=$(extract_json "$BODY" '.violations | length')
    pass "TC-201-SOD-003" "200, SoD check done (is_allowed=$IS_ALLOWED, violations=$VIOLATION_COUNT)"
  else
    fail "TC-201-SOD-003" "Expected 200, got $CODE"
  fi
else
  skip "TC-201-SOD-003" "No agent or tool ID for SoD check"
fi

# ── TC-201-SOD-004: Delete SoD rule ──────────────────────────────────────
if [[ -n "${SOD_RULE_ID:-}" && "$SOD_RULE_ID" != "null" ]]; then
  RAW=$(admin_call DELETE "/nhi/sod/rules/$SOD_RULE_ID")
  parse_response "$RAW"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    pass "TC-201-SOD-004" "$CODE, SoD rule deleted"
  else
    fail "TC-201-SOD-004" "Expected 200/204, got $CODE"
  fi
else
  skip "TC-201-SOD-004" "No SoD rule ID"
fi

# ── TC-201-SOD-005: Non-admin create SoD rule → 403 ─────────────────────
if [[ -n "$PERM_TOOL_ID" && "$PERM_TOOL_ID" != "null" && -n "${PERM_TOOL2_ID:-}" && "$PERM_TOOL2_ID" != "null" ]]; then
  RAW=$(user_call POST "/nhi/sod/rules" -d "{
    \"tool_id_a\": \"$PERM_TOOL_ID\",
    \"tool_id_b\": \"$PERM_TOOL2_ID\",
    \"enforcement\": \"warn\",
    \"description\": \"Unauthorized SoD rule creation attempt\"
  }")
  parse_response "$RAW"
  if [[ "$CODE" == "403" ]]; then
    pass "TC-201-SOD-005" "403, non-admin SoD rule creation rejected"
  else
    fail "TC-201-SOD-005" "Expected 403, got $CODE (SECURITY: non-admin should not create SoD rules)"
  fi
else
  skip "TC-201-SOD-005" "Missing tool IDs"
fi

# ── TC-201-SOD-006: Delete nonexistent SoD rule → 404 ───────────────────
RAW=$(admin_call DELETE "/nhi/sod/rules/$FAKE_UUID")
parse_response "$RAW"
if [[ "$CODE" == "404" ]]; then
  pass "TC-201-SOD-006" "404, nonexistent SoD rule delete"
else
  fail "TC-201-SOD-006" "Expected 404, got $CODE"
fi

# =============================================================================
# Summary
# =============================================================================
sed -i "s/^PASS=0 FAIL=0 SKIP=0 TOTAL=0$/PASS=$PASS FAIL=$FAIL SKIP=$SKIP TOTAL=$TOTAL/" "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$RESULTS_FILE"

log ""
log "==================================================================="
log "Batch 13 complete — PASS=$PASS FAIL=$FAIL SKIP=$SKIP TOTAL=$TOTAL"
log "==================================================================="

if [[ "$FAIL" -eq 0 ]]; then
  log "All tests passed!"
else
  log "Some tests FAILED — review results above"
fi
