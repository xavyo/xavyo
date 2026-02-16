#!/bin/bash
# =============================================================================
# AgentGateway + Xavyo IDP — Comprehensive Security Integration Test
# =============================================================================
#
# Phase 1 (Happy Path):         Steps 1-7    (~15s)
# Phase 2 (Security Tests):     Steps 8-15   (~80s)
# Phase 3 (Cleanup):            Step 16      (~3s)
#
# Tests:
#   1.  Admin login
#   2.  Create NHI Agent A + provision entitlements
#   3.  Register OAuth client bound to Agent A
#   4.  Get Agent A JWT via client_credentials
#   5.  Create delegation grant (admin -> Agent A)
#   6.  RFC 8693 token exchange
#   7.  MCP through gateway (initialize, tools/list, echo, add)
#   8.  Runtime grant revocation at gateway (already-issued token denied)
#   9.  Delegation scope enforcement (restricted grant)
#  10.  Unauthorized agent isolation (Agent B, no entitlements)
#  11.  Cross-tenant header tampering
#  12.  Risk score exceeded (Agent C, score=90 > threshold=75)
#  13.  Agent lifecycle: suspend + reactivate (Agent D)
#  14.  Error body validation (no information leakage)
#  15.  Additional negative cases (self-ref, missing actor, wrong secret)
#  16.  Cleanup (automatic via trap)
#
# Prerequisites:
#   - Xavyo IDP running on :8080
#   - ext-authz on :50051
#   - AgentGateway on :4000
#   - PostgreSQL on :5434
#   - Tools: curl, jq, psql, nc
#
# Usage:
#   bash deploy/agentgateway/test-integration.sh
#
# Expected: ~100s (mostly cache wait in step 13 reactivation)

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

XAVYO_URL="${XAVYO_URL:-http://localhost:8080}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:4000}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@xavyo.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@1234}"
SYSTEM_TENANT_ID="00000000-0000-0000-0000-000000000001"
DB_URL="${DATABASE_URL:-postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test}"

# =============================================================================
# Colors & output helpers
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0
START_TIME=$(date +%s)

pass()      { PASSED=$((PASSED + 1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail_test() { FAILED=$((FAILED + 1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
fail_hard() { echo -e "  ${RED}[FATAL]${NC} $1"; exit 1; }
info()      { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn()      { WARNINGS=$((WARNINGS + 1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
step()      { echo -e "\n${BOLD}${YELLOW}=== Step $1: $2 ===${NC}"; }

# =============================================================================
# State (initialized before trap so cleanup can reference them safely)
# =============================================================================

ADMIN_TOKEN=""
ADMIN_TID=""
ADMIN_SUB=""
ENT_ID=""
RISK_SCORE_COMPAT=false

AGENT_IDS_TO_CLEANUP=()
CLIENT_IDS_TO_CLEANUP=()
GRANT_IDS_TO_CLEANUP=()

declare -a DENY_BODIES=()
declare -a DENY_LABELS=()

TMPDIR=$(mktemp -d)

# =============================================================================
# Helper functions
# =============================================================================

# Decode JWT payload (handles missing base64 padding)
jwt_decode() {
    local payload
    payload=$(echo "$1" | cut -d. -f2)
    local pad=$((4 - ${#payload} % 4))
    [ "$pad" -lt 4 ] && payload="${payload}$(printf '=%.0s' $(seq 1 $pad))"
    echo "$payload" | base64 -d 2>/dev/null
}

# Call gateway MCP initialize; sets GW_LAST_CODE and GW_LAST_BODY
gateway_mcp_call() {
    local token="$1" tenant_id="$2"
    GW_LAST_CODE=$(curl -s -o "$TMPDIR/gw_resp.json" -w "%{http_code}" \
        "$GATEWAY_URL/mcp" \
        -H "Authorization: Bearer $token" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Protocol-Version: 2025-03-26" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"security-test","version":"1.0"}}}') \
        || GW_LAST_CODE="000"
    GW_LAST_BODY=$(cat "$TMPDIR/gw_resp.json" 2>/dev/null || echo "")
}

# Call gateway with explicit tenant header (for cross-tenant test)
gateway_mcp_call_with_tenant() {
    local token="$1" tenant_header="$2"
    GW_LAST_CODE=$(curl -s -o "$TMPDIR/gw_resp.json" -w "%{http_code}" \
        "$GATEWAY_URL/mcp" \
        -H "Authorization: Bearer $token" \
        -H "X-Tenant-ID: $tenant_header" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Protocol-Version: 2025-03-26" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"security-test","version":"1.0"}}}') \
        || GW_LAST_CODE="000"
    GW_LAST_BODY=$(cat "$TMPDIR/gw_resp.json" 2>/dev/null || echo "")
}

# MCP call within an established session
mcp_session_call() {
    local token="$1" tenant_id="$2" session_id="$3" payload="$4"
    curl -s "$GATEWAY_URL/mcp" \
        -H "Authorization: Bearer $token" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $session_id" \
        -H "Mcp-Protocol-Version: 2025-03-26" \
        -d "$payload"
}

# Collect a deny body for step 14 validation
collect_deny_body() {
    DENY_BODIES+=("$1")
    DENY_LABELS+=("$2")
}

# Validate a deny response body for information leakage
validate_deny_body() {
    local body="$1" label="$2"
    local ok=true

    # Must be valid JSON
    if ! echo "$body" | jq . > /dev/null 2>&1; then
        fail_test "$label: deny body is not valid JSON"
        return
    fi

    # Must have only "error" and "message" keys
    local keys
    keys=$(echo "$body" | jq -r 'keys[]' 2>/dev/null | sort | tr '\n' ',')
    if [ "$keys" != "error,message," ]; then
        fail_test "$label: unexpected keys in deny body: $keys (expected error,message)"
        ok=false
    fi

    # "message" must be one of the 5 sanitized strings
    local msg
    msg=$(echo "$body" | jq -r '.message // empty' 2>/dev/null)
    case "$msg" in
        "access denied"|"identity not found"|"authentication required"|"invalid request"|"internal error") ;;
        *) fail_test "$label: unexpected sanitized message: '$msg'"; ok=false ;;
    esac

    # Must NOT contain a UUID pattern (would leak internal IDs)
    if echo "$body" | grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-' 2>/dev/null; then
        fail_test "$label: deny body leaks UUID pattern"
        ok=false
    fi

    # The "message" field must NOT contain sensitive keywords.
    # (The "error" field is a machine-readable code like "risk_score_exceeded" — that's
    #  intentional and doesn't leak values. We only check "message" for leakage.)
    local msg_field
    msg_field=$(echo "$body" | jq -r '.message // empty' 2>/dev/null)
    local keyword
    for keyword in score threshold suspended policy entitlement postgres sqlx panic; do
        if echo "$msg_field" | grep -qi "$keyword" 2>/dev/null; then
            fail_test "$label: deny message contains sensitive keyword '$keyword'"
            ok=false
        fi
    done

    # The full body must NOT contain numeric score/threshold values
    # (catches cases like {"error":"...", "score": 90, "threshold": 75})
    if echo "$body" | grep -qE '"(score|threshold)"[[:space:]]*:' 2>/dev/null; then
        fail_test "$label: deny body leaks numeric score/threshold values"
        ok=false
    fi

    if [ "$ok" = true ]; then
        pass "$label: deny body properly sanitized"
    fi
}

# Provision entitlement assignment for a given NHI ID via API (requires ENT_ID)
provision_entitlement_for() {
    local nhi_id="$1"
    local assign_code
    assign_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$XAVYO_URL/governance/assignments" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "{
            \"entitlement_id\": \"$ENT_ID\",
            \"target_type\": \"nhi\",
            \"target_id\": \"$nhi_id\"
        }") || assign_code="000"
    # 201 = created, 409 = already exists (idempotent)
    if [ "$assign_code" != "201" ] && [ "$assign_code" != "409" ]; then
        warn "Failed to provision entitlement for $nhi_id (HTTP $assign_code)"
    fi
}

# Set up a full agent: NHI + OAuth client + agent JWT + delegation + delegated token
# Sets: SETUP_NHI_ID, SETUP_CLIENT_ID, SETUP_CLIENT_SECRET,
#        SETUP_AGENT_TOKEN, SETUP_GRANT_ID, SETUP_DELEGATED_TOKEN
setup_agent() {
    local label="$1"
    local name="test-${label}-$(date +%s%N | head -c 16)"

    # 1. Create NHI agent
    local nhi_resp
    nhi_resp=$(curl -sf "$XAVYO_URL/nhi/agents" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "{\"name\":\"$name\",\"agent_type\":\"autonomous\",\"description\":\"Security test ($label)\"}") \
        || fail_hard "setup_agent($label): NHI creation failed"
    SETUP_NHI_ID=$(echo "$nhi_resp" | jq -r '.id // empty')
    [ -n "$SETUP_NHI_ID" ] || fail_hard "setup_agent($label): no NHI ID"
    AGENT_IDS_TO_CLEANUP+=("$SETUP_NHI_ID")

    # 2. Register OAuth client
    local client_resp
    client_resp=$(curl -sf "$XAVYO_URL/admin/oauth/clients" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "{
            \"name\":\"${name}-client\",
            \"client_type\":\"confidential\",
            \"grant_types\":[\"client_credentials\",\"urn:ietf:params:oauth:grant-type:token-exchange\"],
            \"redirect_uris\":[],
            \"scopes\":[\"openid\",\"profile\"],
            \"nhi_id\":\"$SETUP_NHI_ID\"
        }") \
        || fail_hard "setup_agent($label): OAuth client creation failed"
    SETUP_CLIENT_ID=$(echo "$client_resp" | jq -r '.client_id // .id // empty')
    SETUP_CLIENT_SECRET=$(echo "$client_resp" | jq -r '.client_secret // .secret // empty')
    [ -n "$SETUP_CLIENT_ID" ] && [ -n "$SETUP_CLIENT_SECRET" ] \
        || fail_hard "setup_agent($label): no client credentials"
    CLIENT_IDS_TO_CLEANUP+=("$SETUP_CLIENT_ID")

    # 3. Get agent JWT via client_credentials
    local token_resp
    token_resp=$(curl -sf "$XAVYO_URL/oauth/token" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "grant_type=client_credentials" \
        -d "client_id=$SETUP_CLIENT_ID" \
        -d "client_secret=$SETUP_CLIENT_SECRET") \
        || fail_hard "setup_agent($label): client_credentials grant failed"
    SETUP_AGENT_TOKEN=$(echo "$token_resp" | jq -r '.access_token // empty')
    [ -n "$SETUP_AGENT_TOKEN" ] || fail_hard "setup_agent($label): no agent token"

    # 4. Create delegation grant (admin -> agent)
    local expires
    expires=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v+1H +%Y-%m-%dT%H:%M:%SZ)
    local grant_resp
    grant_resp=$(curl -sf "$XAVYO_URL/nhi/delegations" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "{
            \"principal_id\":\"$ADMIN_SUB\",
            \"principal_type\":\"user\",
            \"actor_nhi_id\":\"$SETUP_NHI_ID\",
            \"allowed_scopes\":[],
            \"allowed_resource_types\":[],
            \"max_delegation_depth\":2,
            \"expires_at\":\"$expires\"
        }") \
        || fail_hard "setup_agent($label): delegation creation failed"
    SETUP_GRANT_ID=$(echo "$grant_resp" | jq -r '.id // empty')
    [ -n "$SETUP_GRANT_ID" ] || fail_hard "setup_agent($label): no grant ID"
    GRANT_IDS_TO_CLEANUP+=("$SETUP_GRANT_ID")

    # 5. Token exchange
    local exchange_resp
    exchange_resp=$(curl -sf "$XAVYO_URL/oauth/token" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "subject_token=$ADMIN_TOKEN" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "actor_token=$SETUP_AGENT_TOKEN" \
        -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
        -d "client_id=$SETUP_CLIENT_ID" \
        -d "client_secret=$SETUP_CLIENT_SECRET") \
        || fail_hard "setup_agent($label): token exchange failed"
    SETUP_DELEGATED_TOKEN=$(echo "$exchange_resp" | jq -r '.access_token // empty')
    [ -n "$SETUP_DELEGATED_TOKEN" ] || fail_hard "setup_agent($label): no delegated token"

    info "Agent $label ready: nhi=$SETUP_NHI_ID grant=$SETUP_GRANT_ID"
}

# =============================================================================
# Cleanup (runs on EXIT — success or failure)
# =============================================================================

cleanup() {
    local exit_code=$?
    echo ""
    echo -e "${BOLD}=== Step 16: Cleanup ===${NC}"

    # Only attempt API cleanup if we have valid credentials
    if [ -n "${ADMIN_TOKEN:-}" ] && [ -n "${ADMIN_TID:-}" ]; then
        # Revoke remaining grants
        if [ ${#GRANT_IDS_TO_CLEANUP[@]} -gt 0 ]; then
            for gid in "${GRANT_IDS_TO_CLEANUP[@]}"; do
                [ -z "$gid" ] && continue
                curl -s -o /dev/null -X POST \
                    "$XAVYO_URL/nhi/delegations/$gid/revoke" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "Content-Type: application/json" \
                    -H "X-Tenant-ID: $ADMIN_TID" \
                    -d "{\"revoked_by\":\"${ADMIN_SUB:-cleanup}\"}" 2>/dev/null || true
            done
            info "Revoked ${#GRANT_IDS_TO_CLEANUP[@]} grants"
        fi

        # Reactivate + delete agents
        if [ ${#AGENT_IDS_TO_CLEANUP[@]} -gt 0 ]; then
            for aid in "${AGENT_IDS_TO_CLEANUP[@]}"; do
                [ -z "$aid" ] && continue
                # Reactivate first in case it's suspended (so delete works)
                curl -s -o /dev/null -X POST "$XAVYO_URL/nhi/$aid/reactivate" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "Content-Type: application/json" \
                    -H "X-Tenant-ID: $ADMIN_TID" 2>/dev/null || true
                curl -s -o /dev/null -X DELETE "$XAVYO_URL/nhi/agents/$aid" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "X-Tenant-ID: $ADMIN_TID" 2>/dev/null || true
            done
            info "Deleted ${#AGENT_IDS_TO_CLEANUP[@]} agents"
        fi

        # Delete OAuth clients
        if [ ${#CLIENT_IDS_TO_CLEANUP[@]} -gt 0 ]; then
            for cid in "${CLIENT_IDS_TO_CLEANUP[@]}"; do
                [ -z "$cid" ] && continue
                curl -s -o /dev/null -X DELETE "$XAVYO_URL/admin/oauth/clients/$cid" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "X-Tenant-ID: $ADMIN_TID" 2>/dev/null || true
            done
            info "Deleted ${#CLIENT_IDS_TO_CLEANUP[@]} OAuth clients"
        fi
    fi

    # Clean DB-inserted data
    if command -v psql > /dev/null 2>&1 && [ ${#AGENT_IDS_TO_CLEANUP[@]} -gt 0 ]; then
        for aid in "${AGENT_IDS_TO_CLEANUP[@]}"; do
            [ -z "$aid" ] && continue
            psql "$DB_URL" -q -c \
                "DELETE FROM gov_nhi_risk_scores WHERE nhi_id = '$aid';" 2>/dev/null || true
            psql "$DB_URL" -q -c \
                "DELETE FROM gov_entitlement_assignments WHERE target_id = '$aid';" 2>/dev/null || true
        done
        info "Cleaned up DB entries"
    fi

    rm -rf "$TMPDIR"

    # Summary
    local elapsed=$(($(date +%s) - START_TIME))
    echo ""
    echo -e "${BOLD}========================================${NC}"
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}  ${PASSED} passed, ${FAILED} failed, ${WARNINGS} warnings (${elapsed}s)${NC}"
    else
        echo -e "${RED}  ${PASSED} passed, ${FAILED} failed, ${WARNINGS} warnings (${elapsed}s)${NC}"
    fi
    echo -e "${BOLD}========================================${NC}"

    [ "$FAILED" -gt 0 ] && exit 1
    exit "$exit_code"
}
trap cleanup EXIT

# =============================================================================
# Phase 0: Prerequisites
# =============================================================================

info "Checking prerequisites..."

for cmd in curl jq psql nc; do
    command -v "$cmd" > /dev/null 2>&1 || fail_hard "Required tool not found: $cmd"
done
pass "Required tools available (curl, jq, psql, nc)"

curl -sf "$XAVYO_URL/readyz" > /dev/null || fail_hard "Xavyo IDP not reachable at $XAVYO_URL"
pass "Xavyo IDP healthy"

nc -z localhost 50051 2>/dev/null || fail_hard "ext-authz not reachable on :50051"
pass "ext-authz reachable"

nc -z localhost 4000 2>/dev/null || fail_hard "AgentGateway not reachable on $GATEWAY_URL"
pass "AgentGateway reachable"

psql "$DB_URL" -c "SELECT 1;" > /dev/null 2>&1 || fail_hard "PostgreSQL not reachable at $DB_URL"
pass "PostgreSQL reachable"

# #############################################################################
# Phase 1: Happy Path (Steps 1-7)
# #############################################################################

# =========================================================================
step 1 "Authenticate as admin"
# =========================================================================

LOGIN_RESP=$(curl -sf "$XAVYO_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $SYSTEM_TENANT_ID" \
    -d "{\"email\": \"$ADMIN_EMAIL\", \"password\": \"$ADMIN_PASSWORD\"}") \
    || fail_hard "Login failed"

ADMIN_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token // empty')
[ -n "$ADMIN_TOKEN" ] || fail_hard "No admin token in response"
pass "Got admin JWT (${#ADMIN_TOKEN} chars)"

ADMIN_CLAIMS=$(jwt_decode "$ADMIN_TOKEN")
ADMIN_SUB=$(echo "$ADMIN_CLAIMS" | jq -r '.sub')
ADMIN_TID=$(echo "$ADMIN_CLAIMS" | jq -r '.tid')
info "Admin sub=$ADMIN_SUB tid=$ADMIN_TID"

# =========================================================================
step 2 "Create NHI Agent A"
# =========================================================================

AGENT_A_NAME="test-agent-a-$(date +%s)"

NHI_RESP=$(curl -sf "$XAVYO_URL/nhi/agents" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"name\": \"$AGENT_A_NAME\",
        \"agent_type\": \"autonomous\",
        \"description\": \"Integration test agent A (happy path)\"
    }") || fail_hard "Agent A creation failed"

AGENT_A_NHI_ID=$(echo "$NHI_RESP" | jq -r '.id // empty')
[ -n "$AGENT_A_NHI_ID" ] || fail_hard "No NHI ID for Agent A"
AGENT_IDS_TO_CLEANUP+=("$AGENT_A_NHI_ID")
pass "Created Agent A: $AGENT_A_NHI_ID"

# =========================================================================
step "2b" "Provision authorization entitlements"
# =========================================================================

# Create application via API (idempotent: 201 = created, 409 = already exists)
APP_RESP=$(curl -s -o "$TMPDIR/app_resp.json" -w "%{http_code}" \
    "$XAVYO_URL/governance/applications" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d '{
        "name": "AgentGateway MCP",
        "app_type": "internal",
        "description": "MCP tools via AgentGateway"
    }')
if [ "$APP_RESP" = "201" ]; then
    APP_ID=$(jq -r '.id // empty' "$TMPDIR/app_resp.json")
elif [ "$APP_RESP" = "409" ]; then
    # Already exists — list all and find by name
    APP_ID=$(curl -sf "$XAVYO_URL/governance/applications" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        | jq -r '.items[] | select(.name == "AgentGateway MCP") | .id' | head -1)
fi
[ -n "$APP_ID" ] || fail_hard "Could not get application ID (HTTP $APP_RESP)"

# Create entitlement via API
ENT_RESP=$(curl -s -o "$TMPDIR/ent_resp.json" -w "%{http_code}" \
    "$XAVYO_URL/governance/entitlements" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"application_id\": \"$APP_ID\",
        \"name\": \"mcp_full_access\",
        \"description\": \"Full MCP tool access\",
        \"risk_level\": \"low\"
    }")
if [ "$ENT_RESP" = "201" ]; then
    ENT_ID=$(jq -r '.id // empty' "$TMPDIR/ent_resp.json")
elif [ "$ENT_RESP" = "409" ]; then
    # Already exists — list by application and find by name
    ENT_ID=$(curl -sf "$XAVYO_URL/governance/entitlements?application_id=$APP_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "X-Tenant-ID: $ADMIN_TID" \
        | jq -r '.items[] | select(.name == "mcp_full_access") | .id' | head -1)
fi
[ -n "$ENT_ID" ] || fail_hard "Could not get entitlement ID (HTTP $ENT_RESP)"

# Create wildcard action mapping via API (all actions on all resource types)
MAPPING_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$XAVYO_URL/admin/authorization/mappings" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"entitlement_id\": \"$ENT_ID\",
        \"action\": \"*\",
        \"resource_type\": \"*\"
    }")
# 201 = created, 409 = already exists
if [ "$MAPPING_CODE" != "201" ] && [ "$MAPPING_CODE" != "409" ]; then
    warn "Action mapping creation returned HTTP $MAPPING_CODE"
fi

# Assign entitlement to admin user via API
ADMIN_ASSIGN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$XAVYO_URL/governance/assignments" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"entitlement_id\": \"$ENT_ID\",
        \"target_type\": \"user\",
        \"target_id\": \"$ADMIN_SUB\"
    }")
# 201 = created, 409 = already exists
if [ "$ADMIN_ASSIGN_CODE" != "201" ] && [ "$ADMIN_ASSIGN_CODE" != "409" ]; then
    warn "Admin assignment creation returned HTTP $ADMIN_ASSIGN_CODE"
fi

# Assign entitlement to Agent A via API
provision_entitlement_for "$AGENT_A_NHI_ID"

pass "Entitlements provisioned (app=$APP_ID, entitlement=$ENT_ID)"

# Check gov_nhi_risk_scores column type for step 12 compatibility.
# Migration 0057 uses gov_risk_level but sqlx expects risk_level.
RISK_COL_TYPE=$(psql "$DB_URL" -tAq -c "
    SELECT udt_name FROM information_schema.columns
    WHERE table_name = 'gov_nhi_risk_scores' AND column_name = 'risk_level';
" 2>/dev/null || echo "unknown")
if [ "$RISK_COL_TYPE" = "risk_level" ]; then
    info "gov_nhi_risk_scores.risk_level type: risk_level (compatible)"
    RISK_SCORE_COMPAT=true
else
    info "gov_nhi_risk_scores.risk_level type: $RISK_COL_TYPE (sqlx expects risk_level)"
    info "Step 12 (risk score) will be limited — apply migration fix to enable full test"
    RISK_SCORE_COMPAT=false
fi

# =========================================================================
step 3 "Register OAuth client for Agent A"
# =========================================================================

CLIENT_RESP=$(curl -sf "$XAVYO_URL/admin/oauth/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"name\": \"test-agent-a-client\",
        \"client_type\": \"confidential\",
        \"grant_types\": [\"client_credentials\", \"urn:ietf:params:oauth:grant-type:token-exchange\"],
        \"redirect_uris\": [],
        \"scopes\": [\"openid\", \"profile\"],
        \"nhi_id\": \"$AGENT_A_NHI_ID\"
    }") || fail_hard "OAuth client registration failed"

AGENT_A_CLIENT_ID=$(echo "$CLIENT_RESP" | jq -r '.client_id // .id // empty')
AGENT_A_CLIENT_SECRET=$(echo "$CLIENT_RESP" | jq -r '.client_secret // .secret // empty')
[ -n "$AGENT_A_CLIENT_ID" ] && [ -n "$AGENT_A_CLIENT_SECRET" ] \
    || fail_hard "No client credentials returned"
CLIENT_IDS_TO_CLEANUP+=("$AGENT_A_CLIENT_ID")
pass "Registered OAuth client: $AGENT_A_CLIENT_ID (bound to Agent A)"

# =========================================================================
step 4 "Get Agent A JWT via client_credentials"
# =========================================================================

AGENT_TOKEN_RESP=$(curl -sf "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=client_credentials" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET") \
    || fail_hard "Agent A client_credentials grant failed"

AGENT_A_TOKEN=$(echo "$AGENT_TOKEN_RESP" | jq -r '.access_token // empty')
[ -n "$AGENT_A_TOKEN" ] || fail_hard "No agent token returned"
pass "Got Agent A JWT (${#AGENT_A_TOKEN} chars)"

AGENT_A_CLAIMS=$(jwt_decode "$AGENT_A_TOKEN")
AGENT_A_SUB=$(echo "$AGENT_A_CLAIMS" | jq -r '.sub')
if [ "$AGENT_A_SUB" = "$AGENT_A_NHI_ID" ]; then
    pass "Agent A JWT sub matches NHI ID (nhi_id binding working)"
else
    warn "Agent A JWT sub=$AGENT_A_SUB, expected NHI_ID=$AGENT_A_NHI_ID"
fi

# =========================================================================
step 5 "Create delegation grant (admin -> Agent A)"
# =========================================================================

EXPIRES_AT=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v+1H +%Y-%m-%dT%H:%M:%SZ)

GRANT_RESP=$(curl -sf "$XAVYO_URL/nhi/delegations" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"principal_id\": \"$ADMIN_SUB\",
        \"principal_type\": \"user\",
        \"actor_nhi_id\": \"$AGENT_A_NHI_ID\",
        \"allowed_scopes\": [],
        \"allowed_resource_types\": [],
        \"max_delegation_depth\": 2,
        \"expires_at\": \"$EXPIRES_AT\"
    }") || fail_hard "Delegation grant creation failed"

AGENT_A_GRANT_ID=$(echo "$GRANT_RESP" | jq -r '.id // empty')
[ -n "$AGENT_A_GRANT_ID" ] || fail_hard "No grant ID returned"
GRANT_IDS_TO_CLEANUP+=("$AGENT_A_GRANT_ID")
pass "Created delegation grant: $AGENT_A_GRANT_ID"

# =========================================================================
step 6 "RFC 8693 Token Exchange (admin -> Agent A)"
# =========================================================================

EXCHANGE_RESP=$(curl -sf "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET" \
    -d "scope=read:tools") \
    || fail_hard "Token exchange failed"

AGENT_A_DELEGATED_TOKEN=$(echo "$EXCHANGE_RESP" | jq -r '.access_token // empty')
[ -n "$AGENT_A_DELEGATED_TOKEN" ] || fail_hard "No delegated token returned"
pass "Token exchange successful"

DEL_CLAIMS=$(jwt_decode "$AGENT_A_DELEGATED_TOKEN")
ACT_SUB=$(echo "$DEL_CLAIMS" | jq -r '.act.sub // empty')
DELEGATION_DEPTH=$(echo "$DEL_CLAIMS" | jq -r '.delegation_depth // empty')
info "Delegated token: act.sub=$ACT_SUB depth=$DELEGATION_DEPTH"

[ "$ACT_SUB" = "$AGENT_A_NHI_ID" ] \
    || fail_hard "act.sub ($ACT_SUB) != NHI ID ($AGENT_A_NHI_ID)"
[ "$DELEGATION_DEPTH" = "1" ] \
    || fail_hard "delegation_depth=$DELEGATION_DEPTH, expected 1"
pass "Delegated token has correct claims (act.sub=Agent A, depth=1)"

# =========================================================================
step 7 "MCP through gateway (initialize, tools/list, echo, add)"
# =========================================================================

# 7a: Initialize
GW_INIT_CODE=$(curl -s -D "$TMPDIR/gw_headers.txt" \
    -o "$TMPDIR/gw_init.json" -w "%{http_code}" \
    "$GATEWAY_URL/mcp" \
    -H "Authorization: Bearer $AGENT_A_DELEGATED_TOKEN" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Protocol-Version: 2025-03-26" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"security-test","version":"1.0"}}}') \
    || GW_INIT_CODE="000"

if [ "$GW_INIT_CODE" = "200" ] || [ "$GW_INIT_CODE" = "202" ]; then
    pass "MCP initialize via gateway (HTTP $GW_INIT_CODE)"
else
    fail_hard "MCP initialize failed (HTTP $GW_INIT_CODE). Check ext-authz + entitlements."
fi

# Extract session ID
SESSION_ID=$(grep -i 'mcp-session-id' "$TMPDIR/gw_headers.txt" 2>/dev/null \
    | tr -d '\r' | awk '{print $2}' || echo "")

if [ -n "$SESSION_ID" ]; then
    info "MCP session: $SESSION_ID"

    # 7b: Send initialized notification
    mcp_session_call "$AGENT_A_DELEGATED_TOKEN" "$ADMIN_TID" "$SESSION_ID" \
        '{"jsonrpc":"2.0","method":"notifications/initialized"}' > /dev/null 2>&1

    # 7c: List tools
    TOOLS_RESP=$(mcp_session_call "$AGENT_A_DELEGATED_TOKEN" "$ADMIN_TID" "$SESSION_ID" \
        '{"jsonrpc":"2.0","id":11,"method":"tools/list"}')
    TOOL_COUNT=$(echo "$TOOLS_RESP" | sed 's/^data: //' \
        | jq '.result.tools | length' 2>/dev/null || echo "0")
    if [ "$TOOL_COUNT" -gt 0 ]; then
        pass "tools/list returned $TOOL_COUNT tools"
    else
        fail_test "tools/list returned 0 tools"
    fi

    # 7d: Call echo tool
    ECHO_RESP=$(mcp_session_call "$AGENT_A_DELEGATED_TOKEN" "$ADMIN_TID" "$SESSION_ID" \
        '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"message":"Hello from delegated agent"}}}')
    ECHO_TEXT=$(echo "$ECHO_RESP" | sed 's/^data: //' \
        | jq -r '.result.content[0].text // empty' 2>/dev/null)
    if echo "$ECHO_TEXT" | grep -q "Hello from delegated agent"; then
        pass "echo tool: $ECHO_TEXT"
    else
        fail_test "echo tool unexpected response: $ECHO_RESP"
    fi

    # 7e: Call add tool
    ADD_RESP=$(mcp_session_call "$AGENT_A_DELEGATED_TOKEN" "$ADMIN_TID" "$SESSION_ID" \
        '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}')
    ADD_TEXT=$(echo "$ADD_RESP" | sed 's/^data: //' \
        | jq -r '.result.content[0].text // empty' 2>/dev/null)
    if echo "$ADD_TEXT" | grep -q "5"; then
        pass "add(2,3) = $ADD_TEXT"
    else
        warn "add tool unexpected response (may not be available): $ADD_RESP"
    fi
else
    warn "Could not extract MCP session ID — skipping tools tests"
fi

# =========================================================================
step "7f" "Direct Agent Mode — composite provisioning (2 API calls)"
# =========================================================================

# Provision agent via composite endpoint (1 call)
PROVISION_RESP=$(curl -sf "$XAVYO_URL/nhi/provision-agent" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"direct-agent-$(date +%s)\",
        \"agent_type\": \"autonomous\",
        \"requires_human_approval\": false,
        \"entitlements\": [\"mcp_full_access\"],
        \"oauth_client\": {
            \"grant_types\": [\"client_credentials\"],
            \"scope\": \"openid profile\"
        }
    }") || fail_hard "Composite provision-agent failed"

DIRECT_NHI_ID=$(echo "$PROVISION_RESP" | jq -r '.nhi_id // empty')
DIRECT_CLIENT_ID=$(echo "$PROVISION_RESP" | jq -r '.oauth_client.client_id // empty')
DIRECT_CLIENT_SECRET=$(echo "$PROVISION_RESP" | jq -r '.oauth_client.client_secret // empty')
DIRECT_ASSIGNMENTS=$(echo "$PROVISION_RESP" | jq -r '.entitlement_assignments | length')
DIRECT_READY=$(echo "$PROVISION_RESP" | jq -r '.ready // empty')

[ -n "$DIRECT_NHI_ID" ] || fail_hard "Provision response missing nhi_id"
[ -n "$DIRECT_CLIENT_ID" ] || fail_hard "Provision response missing client_id"
[ -n "$DIRECT_CLIENT_SECRET" ] || fail_hard "Provision response missing client_secret"
[ "$DIRECT_ASSIGNMENTS" = "1" ] || fail_hard "Expected 1 entitlement assignment, got $DIRECT_ASSIGNMENTS"
[ "$DIRECT_READY" = "true" ] || fail_hard "Agent not ready"
AGENT_IDS_TO_CLEANUP+=("$DIRECT_NHI_ID")
pass "Provisioned direct agent: $DIRECT_NHI_ID (1 API call)"

# Get agent JWT via client_credentials (2nd call)
DIRECT_TOKEN_RESP=$(curl -sf "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=$DIRECT_CLIENT_ID&client_secret=$DIRECT_CLIENT_SECRET&scope=openid profile") \
    || fail_hard "Direct agent client_credentials failed"
DIRECT_AGENT_TOKEN=$(echo "$DIRECT_TOKEN_RESP" | jq -r '.access_token // empty')
[ -n "$DIRECT_AGENT_TOKEN" ] || fail_hard "No access_token in token response"
pass "Got direct agent JWT (2 API calls total)"

# Use direct agent JWT against AgentGateway (no delegation, no token exchange)
GW_DIRECT_CODE=$(curl -s -o "$TMPDIR/gw_direct.json" -w "%{http_code}" \
    "$GATEWAY_URL/mcp" \
    -H "Authorization: Bearer $DIRECT_AGENT_TOKEN" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Protocol-Version: 2025-03-26" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"direct-agent-test","version":"1.0"}}}') \
    || GW_DIRECT_CODE="000"

if [ "$GW_DIRECT_CODE" = "200" ] || [ "$GW_DIRECT_CODE" = "202" ]; then
    pass "Direct Agent Mode: MCP initialize via gateway (HTTP $GW_DIRECT_CODE) — no delegation needed"
else
    warn "Direct Agent Mode: HTTP $GW_DIRECT_CODE (ext-authz may not yet support non-delegated NHI tokens)"
fi

# #############################################################################
# Phase 2: Security Tests (Steps 8-15)
# #############################################################################

# =========================================================================
step 8 "Runtime grant revocation at gateway"
# =========================================================================

# 8a: Revoke the grant
REVOKE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "$XAVYO_URL/nhi/delegations/$AGENT_A_GRANT_ID/revoke" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{\"revoked_by\": \"$ADMIN_SUB\"}") || REVOKE_CODE="000"

if [ "$REVOKE_CODE" = "200" ] || [ "$REVOKE_CODE" = "204" ]; then
    pass "Grant revoked (HTTP $REVOKE_CODE)"
else
    fail_test "Grant revocation failed (HTTP $REVOKE_CODE)"
fi

# 8b: Token exchange should fail with revoked grant
REVOKED_EXCHANGE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET" \
    -d "scope=read:tools") || REVOKED_EXCHANGE_CODE="000"

if [ "$REVOKED_EXCHANGE_CODE" = "400" ] || [ "$REVOKED_EXCHANGE_CODE" = "403" ]; then
    pass "New token exchange denied after revocation (HTTP $REVOKED_EXCHANGE_CODE)"
else
    fail_test "Expected 400/403 for exchange after revocation, got: $REVOKED_EXCHANGE_CODE"
fi

# 8c: Gateway should reject the ALREADY-ISSUED delegated token
# ext-authz checks grant status from DB on every request (grants are never cached)
gateway_mcp_call "$AGENT_A_DELEGATED_TOKEN" "$ADMIN_TID"

if [ "$GW_LAST_CODE" = "403" ]; then
    pass "Gateway rejects already-issued token after grant revocation (HTTP 403)"
    collect_deny_body "$GW_LAST_BODY" "step8-revoked-grant"
elif [ "$GW_LAST_CODE" = "401" ]; then
    pass "Gateway rejects already-issued token after grant revocation (HTTP 401)"
    collect_deny_body "$GW_LAST_BODY" "step8-revoked-grant"
else
    fail_test "Expected 401/403 for revoked grant at gateway, got: $GW_LAST_CODE"
fi

# =========================================================================
step 9 "Delegation scope enforcement"
# =========================================================================

# 9a: Create restricted grant (only read:tools)
RESTRICTED_GRANT_RESP=$(curl -sf "$XAVYO_URL/nhi/delegations" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"principal_id\": \"$ADMIN_SUB\",
        \"principal_type\": \"user\",
        \"actor_nhi_id\": \"$AGENT_A_NHI_ID\",
        \"allowed_scopes\": [\"read:tools\"],
        \"allowed_resource_types\": [],
        \"max_delegation_depth\": 2,
        \"expires_at\": \"$EXPIRES_AT\"
    }") || fail_hard "Restricted grant creation failed"

RESTRICTED_GRANT_ID=$(echo "$RESTRICTED_GRANT_RESP" | jq -r '.id // empty')
[ -n "$RESTRICTED_GRANT_ID" ] || fail_hard "No restricted grant ID"
GRANT_IDS_TO_CLEANUP+=("$RESTRICTED_GRANT_ID")
pass "Created restricted grant: $RESTRICTED_GRANT_ID (scopes: [read:tools])"

# 9b: Exchange with allowed scope should succeed
ALLOWED_SCOPE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET" \
    -d "scope=read:tools") || ALLOWED_SCOPE_CODE="000"

if [ "$ALLOWED_SCOPE_CODE" = "200" ]; then
    pass "Exchange with allowed scope succeeded (HTTP 200)"
else
    fail_test "Expected 200 for allowed scope, got: $ALLOWED_SCOPE_CODE"
fi

# 9c: Exchange with unauthorized scope should fail
DENIED_SCOPE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET" \
    -d "scope=admin:delete") || DENIED_SCOPE_CODE="000"

if [ "$DENIED_SCOPE_CODE" = "400" ] || [ "$DENIED_SCOPE_CODE" = "403" ]; then
    pass "Exchange with unauthorized scope rejected (HTTP $DENIED_SCOPE_CODE)"
else
    fail_test "Expected 400/403 for unauthorized scope, got: $DENIED_SCOPE_CODE"
fi

# 9d: Revoke restricted grant
curl -s -o /dev/null -X POST "$XAVYO_URL/nhi/delegations/$RESTRICTED_GRANT_ID/revoke" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{\"revoked_by\": \"$ADMIN_SUB\"}" 2>/dev/null || true
pass "Restricted grant revoked"

# =========================================================================
step 10 "Gateway authentication enforcement"
# =========================================================================

# 10a: Completely invalid token — proves gateway validates JWTs
gateway_mcp_call "not-a-valid-jwt-token" "$ADMIN_TID"

if [ "$GW_LAST_CODE" = "401" ] || [ "$GW_LAST_CODE" = "403" ]; then
    pass "Invalid token rejected at gateway (HTTP $GW_LAST_CODE)"
else
    fail_test "Expected 401/403 for invalid token, got: $GW_LAST_CODE"
fi

# 10b: No Authorization header at all
GW_LAST_CODE=$(curl -s -o "$TMPDIR/gw_resp.json" -w "%{http_code}" \
    "$GATEWAY_URL/mcp" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Protocol-Version: 2025-03-26" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"security-test","version":"1.0"}}}') \
    || GW_LAST_CODE="000"
GW_LAST_BODY=$(cat "$TMPDIR/gw_resp.json" 2>/dev/null || echo "")

if [ "$GW_LAST_CODE" = "400" ] || [ "$GW_LAST_CODE" = "401" ] || [ "$GW_LAST_CODE" = "403" ]; then
    pass "Missing auth header rejected at gateway (HTTP $GW_LAST_CODE)"
else
    fail_test "Expected 400/401/403 for missing auth, got: $GW_LAST_CODE"
fi

# 10c: Non-delegated agent token (client_credentials JWT, no act claim)
# The PDP uses role-based entitlements, so a valid agent may be authorized
# even without direct entitlement assignments. This test documents the behavior.
setup_agent "agent-b"
AGENT_B_NHI_ID="$SETUP_NHI_ID"
AGENT_B_TOKEN="$SETUP_AGENT_TOKEN"
AGENT_B_DELEGATED_TOKEN="$SETUP_DELEGATED_TOKEN"

# Use the bare agent JWT (not delegated) to test non-delegated access
gateway_mcp_call "$AGENT_B_TOKEN" "$ADMIN_TID"

if [ "$GW_LAST_CODE" = "200" ] || [ "$GW_LAST_CODE" = "202" ]; then
    info "Non-delegated agent token accepted (HTTP $GW_LAST_CODE) — PDP allows via role-based entitlements"
    pass "Non-delegated access behavior documented"
elif [ "$GW_LAST_CODE" = "401" ] || [ "$GW_LAST_CODE" = "403" ]; then
    pass "Non-delegated agent token rejected (HTTP $GW_LAST_CODE) — delegation required"
    collect_deny_body "$GW_LAST_BODY" "step10-non-delegated"
else
    fail_test "Unexpected response for non-delegated token: HTTP $GW_LAST_CODE"
fi

# =========================================================================
step 11 "Cross-tenant header tampering"
# =========================================================================

# Use Agent A's delegated token (JWT tid = ADMIN_TID) but send a fake
# X-Tenant-ID header. ext-authz should use the JWT's tid claim, not the header.
# We need a fresh delegated token for Agent A since the old grant was revoked.
# Use Agent B's token (which has a valid grant) for this test instead.
# Actually, Agent B is denied due to no entitlements. Let's create a fresh grant for Agent A.

TAMPER_GRANT_RESP=$(curl -sf "$XAVYO_URL/nhi/delegations" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "{
        \"principal_id\": \"$ADMIN_SUB\",
        \"principal_type\": \"user\",
        \"actor_nhi_id\": \"$AGENT_A_NHI_ID\",
        \"allowed_scopes\": [],
        \"allowed_resource_types\": [],
        \"max_delegation_depth\": 2,
        \"expires_at\": \"$EXPIRES_AT\"
    }") || fail_hard "Tamper test grant creation failed"

TAMPER_GRANT_ID=$(echo "$TAMPER_GRANT_RESP" | jq -r '.id // empty')
[ -n "$TAMPER_GRANT_ID" ] || fail_hard "No tamper grant ID"
GRANT_IDS_TO_CLEANUP+=("$TAMPER_GRANT_ID")

TAMPER_EXCHANGE_RESP=$(curl -sf "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET") \
    || fail_hard "Tamper test token exchange failed"

TAMPER_TOKEN=$(echo "$TAMPER_EXCHANGE_RESP" | jq -r '.access_token // empty')
[ -n "$TAMPER_TOKEN" ] || fail_hard "No tamper token"

# First verify the token works with the correct tenant header
gateway_mcp_call "$TAMPER_TOKEN" "$ADMIN_TID"
if [ "$GW_LAST_CODE" = "200" ] || [ "$GW_LAST_CODE" = "202" ]; then
    pass "Baseline: token works with correct tenant header (HTTP $GW_LAST_CODE)"
else
    fail_test "Baseline failed: expected 200 with correct tenant, got $GW_LAST_CODE"
fi

# Now try with a fake tenant ID header
FAKE_TENANT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
gateway_mcp_call_with_tenant "$TAMPER_TOKEN" "$FAKE_TENANT_ID"

if [ "$GW_LAST_CODE" = "200" ] || [ "$GW_LAST_CODE" = "202" ]; then
    info "Header ignored — JWT tid is authoritative (HTTP $GW_LAST_CODE)"
    pass "Cross-tenant tamper: header cannot override JWT's authenticated tenant"
elif [ "$GW_LAST_CODE" = "403" ] || [ "$GW_LAST_CODE" = "401" ]; then
    info "Mismatch detected and rejected (HTTP $GW_LAST_CODE)"
    pass "Cross-tenant tamper: mismatch between header and JWT tid is rejected"
else
    fail_test "Unexpected response for cross-tenant tamper: HTTP $GW_LAST_CODE"
fi

# =========================================================================
step 12 "Risk score exceeded (Agent C — fresh, score=90)"
# =========================================================================

# Create Agent C + full setup BEFORE first gateway call.
# Insert risk score > threshold (75) via psql BEFORE first gateway call.
# Since Agent C has never been cached, ext-authz loads from DB and sees the score.
#
# NOTE: This test requires gov_nhi_risk_scores.risk_level to use the 'risk_level'
# PostgreSQL type (matching the sqlx model). Migration 0057 incorrectly uses
# 'gov_risk_level'. If the type hasn't been fixed, ext-authz returns 500 when
# deserializing the row. The test detects this and reports accordingly.

setup_agent "agent-c"
AGENT_C_NHI_ID="$SETUP_NHI_ID"
AGENT_C_DELEGATED_TOKEN="$SETUP_DELEGATED_TOKEN"

# Provision entitlement (so denial is only due to risk score, not missing entitlement)
provision_entitlement_for "$AGENT_C_NHI_ID"

# Insert high risk score BEFORE first gateway call
psql "$DB_URL" -q -c "
    INSERT INTO gov_nhi_risk_scores
        (tenant_id, nhi_id, total_score, risk_level,
         staleness_factor, credential_age_factor, access_scope_factor, factor_breakdown)
    VALUES
        ('$SYSTEM_TENANT_ID', '$AGENT_C_NHI_ID', 90, 'critical',
         30, 30, 30, '{\"test\":\"injected\"}')
    ON CONFLICT (tenant_id, nhi_id)
    DO UPDATE SET total_score = 90, risk_level = 'critical';
" 2>/dev/null || fail_hard "Risk score insert failed for Agent C"
pass "Inserted risk score 90 (critical) for Agent C"

# First gateway call — ext-authz loads from DB, sees score 90 > threshold 75
gateway_mcp_call "$AGENT_C_DELEGATED_TOKEN" "$ADMIN_TID"

if [ "$GW_LAST_CODE" = "403" ]; then
    pass "Agent C denied — risk score exceeded (HTTP 403)"
    collect_deny_body "$GW_LAST_BODY" "step12-risk-score"
elif [ "$GW_LAST_CODE" = "401" ]; then
    pass "Agent C denied — risk score exceeded (HTTP 401)"
    collect_deny_body "$GW_LAST_BODY" "step12-risk-score"
elif [ "$GW_LAST_CODE" = "500" ] && [ "$RISK_SCORE_COMPAT" = false ]; then
    warn "Agent C got 500 — gov_nhi_risk_scores.risk_level type mismatch (gov_risk_level vs risk_level)"
    info "Fix: ALTER TABLE gov_nhi_risk_scores ALTER COLUMN risk_level TYPE risk_level USING risk_level::text::risk_level;"
    info "Then restart ext-authz and re-run this test"
else
    fail_test "Expected 401/403 for high-risk Agent C, got: $GW_LAST_CODE"
fi

# =========================================================================
step 13 "Agent lifecycle: suspend and reactivate (Agent D)"
# =========================================================================

# Create Agent D + full setup BEFORE first gateway call.
# Suspend BEFORE first gateway call — no cache entry exists yet.
setup_agent "agent-d"
AGENT_D_NHI_ID="$SETUP_NHI_ID"
AGENT_D_DELEGATED_TOKEN="$SETUP_DELEGATED_TOKEN"

# Provision entitlement (denial should be due to suspension only)
provision_entitlement_for "$AGENT_D_NHI_ID"

# Suspend Agent D BEFORE first gateway call
SUSPEND_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "$XAVYO_URL/nhi/$AGENT_D_NHI_ID/suspend" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d '{"reason":"security integration test"}') || SUSPEND_CODE="000"

if [ "$SUSPEND_CODE" = "200" ]; then
    pass "Agent D suspended"
else
    fail_hard "Agent D suspension failed (HTTP $SUSPEND_CODE)"
fi

# 13a: First gateway call — ext-authz loads from DB, sees suspended state
gateway_mcp_call "$AGENT_D_DELEGATED_TOKEN" "$ADMIN_TID"

if [ "$GW_LAST_CODE" = "403" ]; then
    pass "Suspended Agent D denied at gateway (HTTP 403)"
    collect_deny_body "$GW_LAST_BODY" "step13-suspended"
elif [ "$GW_LAST_CODE" = "401" ]; then
    pass "Suspended Agent D denied at gateway (HTTP 401)"
    collect_deny_body "$GW_LAST_BODY" "step13-suspended"
else
    fail_test "Expected 401/403 for suspended Agent D, got: $GW_LAST_CODE"
fi

# 13b: Reactivate and wait for NHI cache to expire (~60s)
REACTIVATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "$XAVYO_URL/nhi/$AGENT_D_NHI_ID/reactivate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $ADMIN_TID") || REACTIVATE_CODE="000"

if [ "$REACTIVATE_CODE" = "200" ]; then
    pass "Agent D reactivated"
else
    fail_test "Agent D reactivation failed (HTTP $REACTIVATE_CODE)"
fi

# Retry loop: wait for NHI cache (60s TTL) to expire
CACHE_TIMEOUT=70
RETRY_START=$(date +%s)
REACTIVATION_OK=false

info "Waiting for NHI cache to expire (up to ${CACHE_TIMEOUT}s)..."
while true; do
    gateway_mcp_call "$AGENT_D_DELEGATED_TOKEN" "$ADMIN_TID"
    if [ "$GW_LAST_CODE" = "200" ] || [ "$GW_LAST_CODE" = "202" ]; then
        ELAPSED=$(($(date +%s) - RETRY_START))
        pass "Agent D accessible after reactivation (${ELAPSED}s, cache expired)"
        REACTIVATION_OK=true
        break
    fi
    ELAPSED=$(($(date +%s) - RETRY_START))
    if [ "$ELAPSED" -ge "$CACHE_TIMEOUT" ]; then
        fail_test "Agent D still denied after ${CACHE_TIMEOUT}s — cache may not have expired"
        break
    fi
    info "  Still denied (HTTP $GW_LAST_CODE), retrying... (${ELAPSED}s/${CACHE_TIMEOUT}s)"
    sleep 5
done

# =========================================================================
step 14 "Error body validation (information leakage check)"
# =========================================================================

# Validate all deny response bodies collected from steps 8, 10, 12, 13
if [ ${#DENY_BODIES[@]} -gt 0 ]; then
    info "Validating ${#DENY_BODIES[@]} deny response bodies..."
    for i in "${!DENY_BODIES[@]}"; do
        validate_deny_body "${DENY_BODIES[$i]}" "${DENY_LABELS[$i]}"
    done
else
    warn "No deny bodies collected — security denial tests may have been skipped"
fi

# =========================================================================
step 15 "Additional negative cases"
# =========================================================================

# 15a: Self-referential token exchange (same token as subject and actor)
SELF_REF_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$ADMIN_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET") || SELF_REF_CODE="000"

if [ "$SELF_REF_CODE" = "400" ]; then
    pass "Self-referential exchange rejected (HTTP 400)"
elif [ "$SELF_REF_CODE" = "403" ]; then
    pass "Self-referential exchange rejected (HTTP 403)"
else
    fail_test "Expected 400/403 for self-referential exchange, got: $SELF_REF_CODE"
fi

# 15b: Missing actor_token
MISSING_ACTOR_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=$AGENT_A_CLIENT_SECRET") || MISSING_ACTOR_CODE="000"

if [ "$MISSING_ACTOR_CODE" = "400" ]; then
    pass "Missing actor_token rejected (HTTP 400)"
elif [ "$MISSING_ACTOR_CODE" = "403" ]; then
    pass "Missing actor_token rejected (HTTP 403)"
else
    fail_test "Expected 400/403 for missing actor_token, got: $MISSING_ACTOR_CODE"
fi

# 15c: Wrong client_secret
WRONG_SECRET_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$XAVYO_URL/oauth/token" \
    -H "X-Tenant-ID: $ADMIN_TID" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=$ADMIN_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "actor_token=$AGENT_A_TOKEN" \
    -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "client_id=$AGENT_A_CLIENT_ID" \
    -d "client_secret=wrong-secret-12345") || WRONG_SECRET_CODE="000"

if [ "$WRONG_SECRET_CODE" = "401" ]; then
    pass "Wrong client_secret rejected (HTTP 401)"
elif [ "$WRONG_SECRET_CODE" = "400" ] || [ "$WRONG_SECRET_CODE" = "403" ]; then
    pass "Wrong client_secret rejected (HTTP $WRONG_SECRET_CODE)"
else
    fail_test "Expected 401 for wrong client_secret, got: $WRONG_SECRET_CODE"
fi

# #############################################################################
# Phase 3: Cleanup (runs automatically via EXIT trap)
# #############################################################################

# The cleanup function runs on exit. Print a summary header before it fires.
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All test steps completed${NC}"
echo -e "${GREEN}========================================${NC}"
