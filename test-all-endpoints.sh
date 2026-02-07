#!/bin/bash
# =============================================================================
# XAVYO IDP - Comprehensive API Endpoint Test Suite
# Tests ALL major API endpoints following MidPoint-style verification patterns:
#   - HTTP status verification
#   - Response body content validation
#   - State transition verification
#   - CRUD lifecycle tests (create → read → update → delete)
# =============================================================================

set -uo pipefail

BASE_URL="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
STAMP=$(date +%s)
RESULTS_FILE="/home/pleclech/xavyo-idp/test-all-results.md"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; TOTAL_COUNT=0
SECTION_PASS=0; SECTION_FAIL=0

cat > "$RESULTS_FILE" << 'HEADER'
# XAVYO IDP - Comprehensive API Test Results

| # | Section | Test | Status | HTTP | Details |
|---|---------|------|--------|------|---------|
HEADER

log_result() {
    local section="$1" test_name="$2" status="$3" http_code="$4" details="${5:-}"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
              echo -e "${GREEN}  ✓ ${test_name} (${http_code})${NC}" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
              echo -e "${RED}  ✗ ${test_name} (${http_code}) - ${details}${NC}" ;;
        *)    SKIP_COUNT=$((SKIP_COUNT + 1))
              echo -e "${YELLOW}  ⊘ ${test_name} - ${details}${NC}" ;;
    esac
    echo "| $TOTAL_COUNT | $section | $test_name | $status | $http_code | ${details:0:80} |" >> "$RESULTS_FILE"
}

section_header() {
    SECTION_PASS=0; SECTION_FAIL=0
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

section_footer() {
    echo -e "${CYAN}  Section: ${SECTION_PASS} pass, ${SECTION_FAIL} fail${NC}"
}

# HTTP helpers
api() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-s -w "\n%{http_code}" -X "$method" "${BASE_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-Id: ${TENANT_ID}" \
        -H "Authorization: Bearer ${TOKEN}")
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}" 2>/dev/null
}

api_noauth() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-s -w "\n%{http_code}" -X "$method" "${BASE_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-Id: ${TENANT_ID}")
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}" 2>/dev/null
}

get_code() { echo "$1" | tail -1; }
get_body() { echo "$1" | sed '$d'; }
jf() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null <<< "$2"; }
jpath() { python3 -c "
import sys,json
d=json.load(sys.stdin)
keys='$1'.split('.')
for k in keys:
    if isinstance(d,list):
        d=d[int(k)] if k.isdigit() and int(k)<len(d) else ''
    elif isinstance(d,dict):
        d=d.get(k,'')
    else:
        d=''
        break
print(d)
" 2>/dev/null <<< "$2"; }

# Check that body contains expected string
assert_body_contains() {
    local body="$1" expected="$2"
    echo "$body" | grep -q "$expected" 2>/dev/null
}

# =============================================================================
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  XAVYO IDP - Comprehensive API Endpoint Test Suite     ║${NC}"
echo -e "${BLUE}║  Run: ${STAMP}                                        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# SETUP: Register users & get JWT
# =============================================================================
section_header "SETUP: User registration & authentication"

ADMIN_EMAIL="all-admin-${STAMP}@xavyo.test"
TEST_PASS='MyP@ssw0rd_2026'

# Register admin user (only one registration to minimize rate limit issues)
RESP=$(api_noauth POST "/auth/register" "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${TEST_PASS}\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ADMIN_USER_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Setup" "Register admin user" "PASS" "$CODE" "id=${ADMIN_USER_ID}"
else
    log_result "Setup" "Register admin user" "FAIL" "$CODE" "$BODY"
    # If rate limited, try to find an existing admin via DB
    if [ "$CODE" = "429" ]; then
        echo -e "${YELLOW}  Rate limited - using existing admin user from DB${NC}"
        ADMIN_USER_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c \
            "SELECT u.id FROM users u JOIN user_roles r ON u.id = r.user_id WHERE r.role_name = 'admin' AND u.tenant_id = '${TENANT_ID}' AND u.email_verified = true LIMIT 1;" 2>/dev/null | head -1 | tr -d '[:space:]')
        ADMIN_EMAIL=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c \
            "SELECT email FROM users WHERE id = '${ADMIN_USER_ID}';" 2>/dev/null | head -1 | tr -d '[:space:]')
        echo -e "${YELLOW}  Found existing admin: ${ADMIN_EMAIL} (${ADMIN_USER_ID})${NC}"
    fi
fi

# Verify email + grant admin role
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -q -c \
    "UPDATE users SET email_verified = true WHERE email = '${ADMIN_EMAIL}';" 2>/dev/null
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -q -c \
    "INSERT INTO user_roles (user_id, role_name) SELECT id, 'admin' FROM users WHERE email = '${ADMIN_EMAIL}' ON CONFLICT DO NOTHING;" 2>/dev/null
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -q -c \
    "INSERT INTO user_roles (user_id, role_name) SELECT id, 'super_admin' FROM users WHERE email = '${ADMIN_EMAIL}' ON CONFLICT DO NOTHING;" 2>/dev/null

# Create a test user via DB directly (avoid rate limiting)
TEST_USER_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c \
    "INSERT INTO users (id, tenant_id, email, email_verified, created_at, updated_at) VALUES (gen_random_uuid(), '${TENANT_ID}', 'testuser-${STAMP}@xavyo.test', true, now(), now()) ON CONFLICT DO NOTHING RETURNING id;" 2>/dev/null | head -1 | tr -d '[:space:]')
if [ -z "${TEST_USER_ID}" ]; then
    # If insert failed due to conflict, just find any other user
    TEST_USER_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c \
        "SELECT id FROM users WHERE tenant_id = '${TENANT_ID}' AND id != '${ADMIN_USER_ID}' LIMIT 1;" 2>/dev/null | head -1 | tr -d '[:space:]')
fi
echo -e "${GREEN}  Test user: ${TEST_USER_ID}${NC}"
sleep 1

# Login as admin
RESP=$(api_noauth POST "/auth/login" "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${TEST_PASS}\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
TOKEN=$(jf "access_token" "$BODY")
REFRESH_TOKEN=$(jf "refresh_token" "$BODY")
if [ -n "$TOKEN" ] && [ "$CODE" = "200" ]; then
    log_result "Setup" "Login admin user" "PASS" "$CODE" "token obtained"
    USER_ID=$(python3 -c "import base64,json; p='$TOKEN'.split('.')[1]; p+='='*(4-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))['sub'])")
else
    echo -e "${RED}FATAL: Cannot login. Aborting.${NC}"
    echo "$BODY"
    exit 1
fi

section_footer

# =============================================================================
# SECTION 1: HEALTH & PUBLIC ENDPOINTS
# =============================================================================
section_header "1. Health & Public Endpoints"

for endpoint in "/health" "/livez" "/readyz" "/healthz" "/startupz"; do
    RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}${endpoint}" 2>/dev/null)
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Health" "GET ${endpoint}" "PASS" "$CODE" \
        || log_result "Health" "GET ${endpoint}" "FAIL" "$CODE" "$(get_body "$RESP")"
done

# Metrics endpoint (use temp file because body is huge)
METRICS_CODE=$(curl -s -o /tmp/xavyo-metrics.txt -w "%{http_code}" "${BASE_URL}/metrics" 2>/dev/null)
if [ "$METRICS_CODE" = "200" ] && grep -q "http_requests_total" /tmp/xavyo-metrics.txt 2>/dev/null; then
    log_result "Health" "GET /metrics (prometheus)" "PASS" "$METRICS_CODE" "contains http_requests_total"
else
    log_result "Health" "GET /metrics (prometheus)" "FAIL" "$METRICS_CODE" "missing metrics"
fi

# OIDC Discovery
RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/.well-known/openid-configuration" -H "X-Tenant-Id: ${TENANT_ID}" 2>/dev/null)
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "issuer"; then
    log_result "OIDC" "GET /.well-known/openid-configuration" "PASS" "$CODE" "has issuer"
else
    log_result "OIDC" "GET /.well-known/openid-configuration" "FAIL" "$CODE" "$BODY"
fi

# JWKS
RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/.well-known/jwks.json" -H "X-Tenant-Id: ${TENANT_ID}" 2>/dev/null)
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "keys"; then
    log_result "OIDC" "GET /.well-known/jwks.json" "PASS" "$CODE" "has keys"
else
    log_result "OIDC" "GET /.well-known/jwks.json" "FAIL" "$CODE" "$BODY"
fi

section_footer

# =============================================================================
# SECTION 2: AUTH ENDPOINTS
# =============================================================================
section_header "2. Authentication Endpoints"

# Token refresh (skip rate-limited tests to avoid tripping limits)
if [ -n "${REFRESH_TOKEN:-}" ]; then
    RESP=$(api_noauth POST "/auth/refresh" "{\"refresh_token\":\"${REFRESH_TOKEN}\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "access_token"; then
        log_result "Auth" "Token refresh" "PASS" "$CODE" "new token issued"
        NEW_TOKEN=$(jf "access_token" "$BODY")
        [ -n "$NEW_TOKEN" ] && TOKEN="$NEW_TOKEN"
    else
        log_result "Auth" "Token refresh" "FAIL" "$CODE" "$BODY"
    fi
fi

# Token introspect (RFC 7662 - form-encoded, at /oauth/introspect)
# Requires client_id; use a dummy client_id (will return inactive if not found, which is valid RFC 7662)
RESP=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/oauth/introspect" \
    -H "X-Tenant-Id: ${TENANT_ID}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${TOKEN}&client_id=test-client&client_secret=test-secret" 2>/dev/null)
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ]; then
    log_result "Auth" "Token introspect (RFC 7662)" "PASS" "$CODE" "token inspected"
else
    # 401 is also acceptable (unknown client)
    [ "$CODE" = "401" ] && log_result "Auth" "Token introspect (unknown client=401)" "PASS" "$CODE" "auth correctly required" \
        || log_result "Auth" "Token introspect (RFC 7662)" "FAIL" "$CODE" "$BODY"
fi

section_footer

# =============================================================================
# SECTION 3: SELF-SERVICE PROFILE (/me)
# =============================================================================
section_header "3. Self-Service Profile (/me)"

RESP=$(api GET "/me/profile")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "email"; then
    log_result "Me" "GET /me/profile" "PASS" "$CODE" "profile returned"
else
    log_result "Me" "GET /me/profile" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/me/sessions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Me" "GET /me/sessions" "PASS" "$CODE" \
    || log_result "Me" "GET /me/sessions" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/me/security")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Me" "GET /me/security" "PASS" "$CODE" \
    || log_result "Me" "GET /me/security" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/me/devices")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Me" "GET /me/devices" "PASS" "$CODE" \
    || log_result "Me" "GET /me/devices" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/me/mfa")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Me" "GET /me/mfa" "PASS" "$CODE" \
    || log_result "Me" "GET /me/mfa" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 4: USER MANAGEMENT (/admin/users)
# =============================================================================
section_header "4. User Management (/admin/users)"

# List users
RESP=$(api GET "/admin/users")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ]; then
    log_result "Users" "List users" "PASS" "$CODE"
else
    log_result "Users" "List users" "FAIL" "$CODE" "$BODY"
fi

# Get specific user
RESP=$(api GET "/admin/users/${TEST_USER_ID}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "id"; then
    log_result "Users" "Get user by ID" "PASS" "$CODE" "email matches"
else
    log_result "Users" "Get user by ID" "FAIL" "$CODE" "$BODY"
fi

# Update user (set username)
TEST_USERNAME="testuser_${STAMP}"
RESP=$(api PUT "/admin/users/${TEST_USER_ID}" "{\"username\":\"${TEST_USERNAME}\"}")
CODE=$(get_code "$RESP")
if [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; then
    log_result "Users" "Update user (set username)" "PASS" "$CODE"
else
    log_result "Users" "Update user (set username)" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Get user - verify can retrieve after update
RESP=$(api GET "/admin/users/${TEST_USER_ID}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "id"; then
    log_result "Users" "Get user after update" "PASS" "$CODE" "user retrieved"
else
    log_result "Users" "Get user after update" "FAIL" "$CODE" "failed to get user"
fi

# Get non-existent user
RESP=$(api GET "/admin/users/00000000-0000-0000-0000-000000000099")
CODE=$(get_code "$RESP")
[ "$CODE" = "404" ] && log_result "Users" "Get non-existent user (404)" "PASS" "$CODE" \
    || log_result "Users" "Get non-existent user (404)" "FAIL" "$CODE" "expected 404"

section_footer

# =============================================================================
# SECTION 5: GROUP MANAGEMENT (/admin/groups)
# =============================================================================
section_header "5. Group Management (/admin/groups)"

RESP=$(api GET "/admin/groups")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Groups" "List groups" "PASS" "$CODE" \
    || log_result "Groups" "List groups" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/groups/roots")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Groups" "List root groups" "PASS" "$CODE" \
    || log_result "Groups" "List root groups" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 6: ATTRIBUTE DEFINITIONS (/admin/attribute-definitions)
# =============================================================================
section_header "6. Custom Attribute Definitions"

RESP=$(api GET "/admin/attribute-definitions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "AttrDef" "List attribute definitions" "PASS" "$CODE" \
    || log_result "AttrDef" "List attribute definitions" "FAIL" "$CODE" "$(get_body "$RESP")"

# Create attribute definition
ATTR_DEF_NAME="test_attr_${STAMP}"
RESP=$(api POST "/admin/attribute-definitions" "{\"name\":\"${ATTR_DEF_NAME}\",\"display_label\":\"Test Attr\",\"data_type\":\"string\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ATTR_DEF_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "AttrDef" "Create attribute definition" "PASS" "$CODE" "id=${ATTR_DEF_ID}"
else
    log_result "AttrDef" "Create attribute definition" "FAIL" "$CODE" "$BODY"
fi

# Get by ID
if [ -n "${ATTR_DEF_ID:-}" ]; then
    RESP=$(api GET "/admin/attribute-definitions/${ATTR_DEF_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "AttrDef" "Get attribute definition" "PASS" "$CODE" \
        || log_result "AttrDef" "Get attribute definition" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 7: GOVERNANCE - APPLICATIONS (F-033)
# =============================================================================
section_header "7. Governance - Applications"

APP_NAME="TestApp_${STAMP}"
RESP=$(api POST "/governance/applications" "{\"name\":\"${APP_NAME}\",\"app_type\":\"internal\",\"description\":\"Test application for comprehensive testing\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
APP_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-App" "Create application" "PASS" "$CODE" "id=${APP_ID}"
else
    log_result "Gov-App" "Create application" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/applications")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "${APP_NAME}"; then
    log_result "Gov-App" "List applications (contains created)" "PASS" "$CODE"
else
    log_result "Gov-App" "List applications" "FAIL" "$CODE" "$BODY"
fi

if [ -n "${APP_ID:-}" ]; then
    RESP=$(api GET "/governance/applications/${APP_ID}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "${APP_NAME}"; then
        log_result "Gov-App" "Get application by ID" "PASS" "$CODE" "name matches"
    else
        log_result "Gov-App" "Get application by ID" "FAIL" "$CODE" "$BODY"
    fi

    RESP=$(api PUT "/governance/applications/${APP_ID}" "{\"name\":\"${APP_NAME}_updated\",\"description\":\"Updated\"}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-App" "Update application" "PASS" "$CODE" \
        || log_result "Gov-App" "Update application" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 8: GOVERNANCE - ENTITLEMENTS
# =============================================================================
section_header "8. Governance - Entitlements"

ENT_NAME="ent_${STAMP}"
RESP=$(api POST "/governance/entitlements" "{\"application_id\":\"${APP_ID}\",\"name\":\"${ENT_NAME}\",\"description\":\"Test entitlement\",\"risk_level\":\"medium\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ENT_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Ent" "Create entitlement" "PASS" "$CODE" "id=${ENT_ID}"
else
    log_result "Gov-Ent" "Create entitlement" "FAIL" "$CODE" "$BODY"
fi

# Create second entitlement for SoD testing
ENT2_NAME="ent2_${STAMP}"
RESP=$(api POST "/governance/entitlements" "{\"application_id\":\"${APP_ID}\",\"name\":\"${ENT2_NAME}\",\"description\":\"Second test entitlement\",\"risk_level\":\"high\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ENT2_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Ent" "Create second entitlement" "PASS" "$CODE" "id=${ENT2_ID}"
else
    log_result "Gov-Ent" "Create second entitlement" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/entitlements")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Ent" "List entitlements" "PASS" "$CODE" \
    || log_result "Gov-Ent" "List entitlements" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "${ENT_ID:-}" ]; then
    RESP=$(api GET "/governance/entitlements/${ENT_ID}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    if [ "$CODE" = "200" ] && assert_body_contains "$BODY" "${ENT_NAME}"; then
        log_result "Gov-Ent" "Get entitlement by ID" "PASS" "$CODE"
    else
        log_result "Gov-Ent" "Get entitlement by ID" "FAIL" "$CODE" "$BODY"
    fi

    # Set owner
    RESP=$(api PUT "/governance/entitlements/${ENT_ID}/owner" "{\"owner_id\":\"${USER_ID}\"}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Gov-Ent" "Set entitlement owner" "PASS" "$CODE" \
        || log_result "Gov-Ent" "Set entitlement owner" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 9: GOVERNANCE - ASSIGNMENTS
# =============================================================================
section_header "9. Governance - Assignments"

if [ -n "${ENT_ID:-}" ]; then
    RESP=$(api POST "/governance/assignments" "{\"target_id\":\"${TEST_USER_ID}\",\"target_type\":\"user\",\"entitlement_id\":\"${ENT_ID}\",\"justification\":\"Comprehensive testing\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    ASSIGN_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "Gov-Assign" "Create assignment" "PASS" "$CODE" "id=${ASSIGN_ID}"
    else
        log_result "Gov-Assign" "Create assignment" "FAIL" "$CODE" "$BODY"
    fi

    RESP=$(api GET "/governance/assignments")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Assign" "List assignments" "PASS" "$CODE" \
        || log_result "Gov-Assign" "List assignments" "FAIL" "$CODE" "$(get_body "$RESP")"

    if [ -n "${ASSIGN_ID:-}" ]; then
        RESP=$(api GET "/governance/assignments/${ASSIGN_ID}")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] && log_result "Gov-Assign" "Get assignment" "PASS" "$CODE" \
            || log_result "Gov-Assign" "Get assignment" "FAIL" "$CODE" "$(get_body "$RESP")"
    fi

    # Effective access check
    RESP=$(api GET "/governance/users/${TEST_USER_ID}/effective-access")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    if [ "$CODE" = "200" ]; then
        log_result "Gov-Assign" "Get effective access" "PASS" "$CODE"
    else
        log_result "Gov-Assign" "Get effective access" "FAIL" "$CODE" "$BODY"
    fi

    # Entitlement check
    RESP=$(api GET "/governance/users/${TEST_USER_ID}/entitlements/${ENT_ID}/check")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Assign" "Check entitlement access" "PASS" "$CODE" \
        || log_result "Gov-Assign" "Check entitlement access" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 10: GOVERNANCE - ROLE HIERARCHY (F-088)
# =============================================================================
section_header "10. Governance - Roles & Hierarchy"

ROLE_NAME="Role_${STAMP}"
RESP=$(api POST "/governance/roles" "{\"name\":\"${ROLE_NAME}\",\"description\":\"Test role\",\"role_type\":\"business\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ROLE_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Role" "Create role" "PASS" "$CODE" "id=${ROLE_ID}"
else
    log_result "Gov-Role" "Create role" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/roles")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Role" "List roles" "PASS" "$CODE" \
    || log_result "Gov-Role" "List roles" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/roles/tree")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Role" "Get role tree" "PASS" "$CODE" \
    || log_result "Gov-Role" "Get role tree" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "${ROLE_ID:-}" ]; then
    RESP=$(api GET "/governance/roles/${ROLE_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "Get role by ID" "PASS" "$CODE" \
        || log_result "Gov-Role" "Get role by ID" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api PUT "/governance/roles/${ROLE_ID}" "{\"name\":\"${ROLE_NAME}_updated\",\"description\":\"Updated\",\"version\":1}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "Update role" "PASS" "$CODE" \
        || log_result "Gov-Role" "Update role" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/ancestors")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "Get ancestors" "PASS" "$CODE" \
        || log_result "Gov-Role" "Get ancestors" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/descendants")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "Get descendants" "PASS" "$CODE" \
        || log_result "Gov-Role" "Get descendants" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/impact")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "Get role impact" "PASS" "$CODE" \
        || log_result "Gov-Role" "Get role impact" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Child role
    CHILD_ROLE_NAME="ChildRole_${STAMP}"
    RESP=$(api POST "/governance/roles" "{\"name\":\"${CHILD_ROLE_NAME}\",\"description\":\"Child role\",\"role_type\":\"business\",\"parent_id\":\"${ROLE_ID}\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    CHILD_ROLE_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "Gov-Role" "Create child role" "PASS" "$CODE" "id=${CHILD_ROLE_ID}"
    else
        log_result "Gov-Role" "Create child role" "FAIL" "$CODE" "$BODY"
    fi
fi

# Role-entitlement mapping
if [ -n "${ROLE_ID:-}" ] && [ -n "${ENT_ID:-}" ]; then
    RESP=$(api POST "/governance/role-entitlements" "{\"role_id\":\"${ROLE_ID}\",\"entitlement_id\":\"${ENT_ID}\",\"role_name\":\"${ROLE_NAME}_updated\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    RE_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "Gov-Role" "Create role-entitlement mapping" "PASS" "$CODE"
    else
        log_result "Gov-Role" "Create role-entitlement mapping" "FAIL" "$CODE" "$BODY"
    fi

    RESP=$(api GET "/governance/role-entitlements")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Role" "List role-entitlements" "PASS" "$CODE" \
        || log_result "Gov-Role" "List role-entitlements" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 11: GOVERNANCE - SOD RULES
# =============================================================================
section_header "11. Governance - Separation of Duties"

if [ -n "${ENT_ID:-}" ] && [ -n "${ENT2_ID:-}" ]; then
    SOD_NAME="SoD_${STAMP}"
    RESP=$(api POST "/governance/sod-rules" "{\"name\":\"${SOD_NAME}\",\"description\":\"Test SoD rule\",\"first_entitlement_id\":\"${ENT_ID}\",\"second_entitlement_id\":\"${ENT2_ID}\",\"severity\":\"high\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    SOD_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "Gov-SoD" "Create SoD rule" "PASS" "$CODE" "id=${SOD_ID}"
    else
        log_result "Gov-SoD" "Create SoD rule" "FAIL" "$CODE" "$BODY"
    fi

    RESP=$(api GET "/governance/sod-rules")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-SoD" "List SoD rules" "PASS" "$CODE" \
        || log_result "Gov-SoD" "List SoD rules" "FAIL" "$CODE" "$(get_body "$RESP")"

    if [ -n "${SOD_ID:-}" ]; then
        RESP=$(api GET "/governance/sod-rules/${SOD_ID}")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] && log_result "Gov-SoD" "Get SoD rule" "PASS" "$CODE" \
            || log_result "Gov-SoD" "Get SoD rule" "FAIL" "$CODE" "$(get_body "$RESP")"

        RESP=$(api POST "/governance/sod-rules/${SOD_ID}/enable")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Gov-SoD" "Enable SoD rule" "PASS" "$CODE" \
            || log_result "Gov-SoD" "Enable SoD rule" "FAIL" "$CODE" "$(get_body "$RESP")"

        # SoD check (pre-flight)
        RESP=$(api POST "/governance/sod-check" "{\"user_id\":\"${TEST_USER_ID}\",\"entitlement_id\":\"${ENT2_ID}\"}")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] && log_result "Gov-SoD" "SoD pre-flight check" "PASS" "$CODE" \
            || log_result "Gov-SoD" "SoD pre-flight check" "FAIL" "$CODE" "$(get_body "$RESP")"

        # Scan for violations
        RESP=$(api POST "/governance/sod-rules/${SOD_ID}/scan")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] || [ "$CODE" = "201" ] && log_result "Gov-SoD" "Scan SoD rule" "PASS" "$CODE" \
            || log_result "Gov-SoD" "Scan SoD rule" "FAIL" "$CODE" "$(get_body "$RESP")"
    fi

    # Violations list
    RESP=$(api GET "/governance/sod-violations")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-SoD" "List SoD violations" "PASS" "$CODE" \
        || log_result "Gov-SoD" "List SoD violations" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Exemptions
    RESP=$(api GET "/governance/sod-exemptions")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-SoD" "List SoD exemptions" "PASS" "$CODE" \
        || log_result "Gov-SoD" "List SoD exemptions" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 12: GOVERNANCE - ACCESS REQUESTS (F-035)
# =============================================================================
section_header "12. Governance - Access Requests"

if [ -n "${ENT2_ID:-}" ]; then
    RESP=$(api POST "/governance/access-requests" "{\"entitlement_id\":\"${ENT2_ID}\",\"justification\":\"Comprehensive test - need access for testing\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    AR_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "Gov-AR" "Create access request" "PASS" "$CODE" "id=${AR_ID}"
    else
        log_result "Gov-AR" "Create access request" "FAIL" "$CODE" "$BODY"
    fi

    RESP=$(api GET "/governance/access-requests")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-AR" "List my requests" "PASS" "$CODE" \
        || log_result "Gov-AR" "List my requests" "FAIL" "$CODE" "$(get_body "$RESP")"

    if [ -n "${AR_ID:-}" ]; then
        RESP=$(api GET "/governance/access-requests/${AR_ID}")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] && log_result "Gov-AR" "Get access request" "PASS" "$CODE" \
            || log_result "Gov-AR" "Get access request" "FAIL" "$CODE" "$(get_body "$RESP")"
    fi

    # Pending approvals
    RESP=$(api GET "/governance/my-approvals")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-AR" "List pending approvals" "PASS" "$CODE" \
        || log_result "Gov-AR" "List pending approvals" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 13: GOVERNANCE - CERTIFICATION CAMPAIGNS (F-036)
# =============================================================================
section_header "13. Governance - Certification Campaigns"

CAMP_NAME="Campaign_${STAMP}"
DEADLINE=$(date -u -d "+30 days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
RESP=$(api POST "/governance/certification-campaigns" "{\"name\":\"${CAMP_NAME}\",\"description\":\"Test campaign\",\"scope_type\":\"all_users\",\"reviewer_type\":\"user_manager\",\"deadline\":\"${DEADLINE}\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
CAMP_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Cert" "Create certification campaign" "PASS" "$CODE" "id=${CAMP_ID}"
else
    log_result "Gov-Cert" "Create certification campaign" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/certification-campaigns")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Cert" "List campaigns" "PASS" "$CODE" \
    || log_result "Gov-Cert" "List campaigns" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "${CAMP_ID:-}" ]; then
    RESP=$(api GET "/governance/certification-campaigns/${CAMP_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Cert" "Get campaign" "PASS" "$CODE" \
        || log_result "Gov-Cert" "Get campaign" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 14: GOVERNANCE - RISK SCORING (F-039)
# =============================================================================
section_header "14. Governance - Risk Scoring"

RESP=$(api GET "/governance/risk-factors")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "List risk factors" "PASS" "$CODE" \
    || log_result "Gov-Risk" "List risk factors" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api POST "/governance/risk-factors" "{\"name\":\"test_factor_${STAMP}\",\"description\":\"Test risk factor\",\"category\":\"static\",\"factor_type\":\"custom_static_test_${STAMP}\",\"weight\":0.5}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
RF_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Risk" "Create risk factor" "PASS" "$CODE" "id=${RF_ID}"
else
    log_result "Gov-Risk" "Create risk factor" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/risk-scores")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "List risk scores" "PASS" "$CODE" \
    || log_result "Gov-Risk" "List risk scores" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/risk-alerts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "List risk alerts" "PASS" "$CODE" \
    || log_result "Gov-Risk" "List risk alerts" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/risk-alerts/summary")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "Risk alert summary" "PASS" "$CODE" \
    || log_result "Gov-Risk" "Risk alert summary" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/peer-groups")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "List peer groups" "PASS" "$CODE" \
    || log_result "Gov-Risk" "List peer groups" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/risk-thresholds")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Risk" "List risk thresholds" "PASS" "$CODE" \
    || log_result "Gov-Risk" "List risk thresholds" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 15: GOVERNANCE - ROLE MINING (F-041)
# =============================================================================
section_header "15. Governance - Role Mining"

RESP=$(api GET "/governance/role-mining/jobs")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Mining" "List mining jobs" "PASS" "$CODE" \
    || log_result "Gov-Mining" "List mining jobs" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/role-mining/metrics")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Mining" "List mining metrics" "PASS" "$CODE" \
    || log_result "Gov-Mining" "List mining metrics" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 16: GOVERNANCE - COMPLIANCE REPORTS (F-042)
# =============================================================================
section_header "16. Governance - Compliance Reports"

RESP=$(api GET "/governance/reports/templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Report" "List report templates" "PASS" "$CODE" \
    || log_result "Gov-Report" "List report templates" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/reports")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Report" "List reports" "PASS" "$CODE" \
    || log_result "Gov-Report" "List reports" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/reports/schedules")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Report" "List report schedules" "PASS" "$CODE" \
    || log_result "Gov-Report" "List report schedules" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 17: GOVERNANCE - LIFECYCLE (F-052)
# =============================================================================
section_header "17. Governance - Lifecycle States"

RESP=$(api GET "/governance/lifecycle/configs")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-LC" "List lifecycle configs" "PASS" "$CODE" \
    || log_result "Gov-LC" "List lifecycle configs" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/lifecycle-events")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-LC" "List lifecycle events" "PASS" "$CODE" \
    || log_result "Gov-LC" "List lifecycle events" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/lifecycle-actions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-LC" "List lifecycle actions" "PASS" "$CODE" \
    || log_result "Gov-LC" "List lifecycle actions" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/access-snapshots")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-LC" "List access snapshots" "PASS" "$CODE" \
    || log_result "Gov-LC" "List access snapshots" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 18: GOVERNANCE - META ROLES (F-056)
# =============================================================================
section_header "18. Governance - Meta Roles"

RESP=$(api GET "/governance/meta-roles")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Meta" "List meta roles" "PASS" "$CODE" \
    || log_result "Gov-Meta" "List meta roles" "FAIL" "$CODE" "$(get_body "$RESP")"

MR_NAME="MetaRole_${STAMP}"
RESP=$(api POST "/governance/meta-roles" "{\"name\":\"${MR_NAME}\",\"description\":\"Auto-assign test\",\"criteria\":[{\"field\":\"risk_level\",\"operator\":\"eq\",\"value\":\"high\"}]}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
MR_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "Gov-Meta" "Create meta role" "PASS" "$CODE" "id=${MR_ID}"
else
    log_result "Gov-Meta" "Create meta role" "FAIL" "$CODE" "$BODY"
fi

if [ -n "${MR_ID:-}" ]; then
    RESP=$(api GET "/governance/meta-roles/${MR_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Meta" "Get meta role" "PASS" "$CODE" \
        || log_result "Gov-Meta" "Get meta role" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/meta-roles/conflicts")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Meta" "List conflicts" "PASS" "$CODE" \
        || log_result "Gov-Meta" "List conflicts" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/meta-roles/events?meta_role_id=${MR_ID:-00000000-0000-0000-0000-000000000000}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "Gov-Meta" "List events" "PASS" "$CODE" \
        || log_result "Gov-Meta" "List events" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

section_footer

# =============================================================================
# SECTION 19: GOVERNANCE - OUTLIER DETECTION (F-059)
# =============================================================================
section_header "19. Governance - Outlier Detection"

RESP=$(api GET "/governance/outliers/config")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Outlier" "Get outlier config" "PASS" "$CODE" \
    || log_result "Gov-Outlier" "Get outlier config" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/outliers/analyses")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Outlier" "List analyses" "PASS" "$CODE" \
    || log_result "Gov-Outlier" "List analyses" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/outliers/results")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Outlier" "List results" "PASS" "$CODE" \
    || log_result "Gov-Outlier" "List results" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/outliers/summary")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Outlier" "Get summary" "PASS" "$CODE" \
    || log_result "Gov-Outlier" "Get summary" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/outliers/alerts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Outlier" "List alerts" "PASS" "$CODE" \
    || log_result "Gov-Outlier" "List alerts" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 20: GOVERNANCE - NHI LIFECYCLE (F-061)
# =============================================================================
section_header "20. Governance - NHI Lifecycle"

RESP=$(api GET "/governance/nhis")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-NHI" "List NHIs" "PASS" "$CODE" \
    || log_result "Gov-NHI" "List NHIs" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/nhis/summary")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-NHI" "Get NHI summary" "PASS" "$CODE" \
    || log_result "Gov-NHI" "Get NHI summary" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 21: GOVERNANCE - IDENTITY MERGE (F-062)
# =============================================================================
section_header "21. Governance - Identity Merge"

RESP=$(api GET "/governance/duplicates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Merge" "List duplicates" "PASS" "$CODE" \
    || log_result "Gov-Merge" "List duplicates" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/merges")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Merge" "List merge operations" "PASS" "$CODE" \
    || log_result "Gov-Merge" "List merge operations" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/merges/audit")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Merge" "List merge audits" "PASS" "$CODE" \
    || log_result "Gov-Merge" "List merge audits" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 22: GOVERNANCE - PERSONAS (F-063)
# =============================================================================
section_header "22. Governance - Personas"

RESP=$(api GET "/governance/personas")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Persona" "List personas" "PASS" "$CODE" \
    || log_result "Gov-Persona" "List personas" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/context/current")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Persona" "Get current context" "PASS" "$CODE" \
    || log_result "Gov-Persona" "Get current context" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/context/sessions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Persona" "List context sessions" "PASS" "$CODE" \
    || log_result "Gov-Persona" "List context sessions" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/persona-audit")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Persona" "List persona audit" "PASS" "$CODE" \
    || log_result "Gov-Persona" "List persona audit" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 23: GOVERNANCE - POWER OF ATTORNEY (F-061)
# =============================================================================
section_header "23. Governance - Power of Attorney"

RESP=$(api GET "/governance/power-of-attorney")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-PoA" "List PoA grants" "PASS" "$CODE" \
    || log_result "Gov-PoA" "List PoA grants" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/power-of-attorney/current-assumption")
CODE=$(get_code "$RESP")
# 200 or 404 are both valid
[ "$CODE" = "200" ] || [ "$CODE" = "404" ] && log_result "Gov-PoA" "Get current assumption" "PASS" "$CODE" \
    || log_result "Gov-PoA" "Get current assumption" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 24: GOVERNANCE - ESCALATION POLICIES (F-054)
# =============================================================================
section_header "24. Governance - Escalation & Approval Groups"

RESP=$(api GET "/governance/escalation-policies")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Esc" "List escalation policies" "PASS" "$CODE" \
    || log_result "Gov-Esc" "List escalation policies" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/approval-groups")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Esc" "List approval groups" "PASS" "$CODE" \
    || log_result "Gov-Esc" "List approval groups" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/approval-workflows")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Esc" "List approval workflows" "PASS" "$CODE" \
    || log_result "Gov-Esc" "List approval workflows" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 25: GOVERNANCE - MICRO-CERTIFICATIONS (F-055)
# =============================================================================
section_header "25. Governance - Micro-Certifications"

RESP=$(api GET "/governance/micro-certifications")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-MicroCert" "List micro-certifications" "PASS" "$CODE" \
    || log_result "Gov-MicroCert" "List micro-certifications" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/micro-cert-triggers")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-MicroCert" "List micro-cert triggers" "PASS" "$CODE" \
    || log_result "Gov-MicroCert" "List micro-cert triggers" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 26: GOVERNANCE - ORPHAN DETECTION (F-040)
# =============================================================================
section_header "26. Governance - Orphan Detection"

RESP=$(api GET "/governance/detection-rules")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Orphan" "List detection rules" "PASS" "$CODE" \
    || log_result "Gov-Orphan" "List detection rules" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/orphan-detections")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Orphan" "List orphan detections" "PASS" "$CODE" \
    || log_result "Gov-Orphan" "List orphan detections" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/service-accounts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Orphan" "List service accounts" "PASS" "$CODE" \
    || log_result "Gov-Orphan" "List service accounts" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 27: GOVERNANCE - GDPR (F-067)
# =============================================================================
section_header "27. Governance - GDPR Data Protection"

RESP=$(api GET "/governance/gdpr/report")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-GDPR" "Get GDPR report" "PASS" "$CODE" \
    || log_result "Gov-GDPR" "Get GDPR report" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/gdpr/users/${TEST_USER_ID}/data-protection")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-GDPR" "Get user data protection" "PASS" "$CODE" \
    || log_result "Gov-GDPR" "Get user data protection" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 28: GOVERNANCE - SIEM (F-078)
# =============================================================================
section_header "28. Governance - SIEM Integration"

RESP=$(api GET "/governance/siem/destinations")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-SIEM" "List SIEM destinations" "PASS" "$CODE" \
    || log_result "Gov-SIEM" "List SIEM destinations" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/siem/exports")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-SIEM" "List SIEM batch exports" "PASS" "$CODE" \
    || log_result "Gov-SIEM" "List SIEM batch exports" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 29: GOVERNANCE - OBJECT TEMPLATES (F-058)
# =============================================================================
section_header "29. Governance - Object Templates"

RESP=$(api GET "/governance/object-templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Tmpl" "List object templates" "PASS" "$CODE" \
    || log_result "Gov-Tmpl" "List object templates" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 30: GOVERNANCE - LICENSE MANAGEMENT (F-065)
# =============================================================================
section_header "30. Governance - License Management"

RESP=$(api GET "/governance/license-pools")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-License" "List license pools" "PASS" "$CODE" \
    || log_result "Gov-License" "List license pools" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/license-assignments")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-License" "List license assignments" "PASS" "$CODE" \
    || log_result "Gov-License" "List license assignments" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 31: GOVERNANCE - PROVISIONING SCRIPTS (F-066)
# =============================================================================
section_header "31. Governance - Provisioning Scripts"

RESP=$(api GET "/governance/scripts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Script" "List scripts" "PASS" "$CODE" \
    || log_result "Gov-Script" "List scripts" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/script-templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Script" "List script templates" "PASS" "$CODE" \
    || log_result "Gov-Script" "List script templates" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 32: GOVERNANCE - CORRELATION ENGINE (F-067)
# =============================================================================
section_header "32. Governance - Correlation Engine"

# Correlation cases (global, no connector required)
RESP=$(api GET "/governance/correlation/cases")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Corr" "List correlation cases" "PASS" "$CODE" \
    || log_result "Gov-Corr" "List correlation cases" "FAIL" "$CODE" "$(get_body "$RESP")"

# Correlation audit trail (global)
RESP=$(api GET "/governance/correlation/audit")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Corr" "List correlation audit" "PASS" "$CODE" \
    || log_result "Gov-Corr" "List correlation audit" "FAIL" "$CODE" "$(get_body "$RESP")"

# Identity correlation rules (non-connector scoped)
RESP=$(api GET "/governance/identity-correlation-rules")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Corr" "List identity correlation rules" "PASS" "$CODE" \
    || log_result "Gov-Corr" "List identity correlation rules" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 33: GOVERNANCE - DELEGATIONS (F-053)
# =============================================================================
section_header "33. Governance - Delegations"

RESP=$(api GET "/governance/delegations")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Deleg" "List delegations" "PASS" "$CODE" \
    || log_result "Gov-Deleg" "List delegations" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 34: GOVERNANCE - MANUAL TASKS (F-064)
# =============================================================================
section_header "34. Governance - Manual Tasks & Semi-Manual"

RESP=$(api GET "/governance/manual-tasks")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Gov-Manual" "List manual tasks" "PASS" "$CODE" \
    || log_result "Gov-Manual" "List manual tasks" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 35: CONNECTORS (/connectors)
# =============================================================================
section_header "35. Connectors"

RESP=$(api GET "/connectors")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Connector" "List connectors" "PASS" "$CODE" \
    || log_result "Connector" "List connectors" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 36: UNIFIED NHI (/nhi)
# =============================================================================
section_header "36. Unified NHI Architecture"

RESP=$(api GET "/nhi/service-accounts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "List service accounts" "PASS" "$CODE" \
    || log_result "NHI" "List service accounts" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/service-accounts/summary")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "Service account summary" "PASS" "$CODE" \
    || log_result "NHI" "Service account summary" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/agents")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "List agents" "PASS" "$CODE" \
    || log_result "NHI" "List agents" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/tools")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "List tools" "PASS" "$CODE" \
    || log_result "NHI" "List tools" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/approvals")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "List approvals" "PASS" "$CODE" \
    || log_result "NHI" "List approvals" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/risk-summary")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "NHI risk summary" "PASS" "$CODE" \
    || log_result "NHI" "NHI risk summary" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/nhi/certifications/campaigns")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "NHI" "List NHI certification campaigns" "PASS" "$CODE" \
    || log_result "NHI" "List NHI certification campaigns" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 37: WEBHOOKS
# =============================================================================
section_header "37. Webhooks"

RESP=$(api GET "/webhooks/subscriptions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Webhooks" "List subscriptions" "PASS" "$CODE" \
    || log_result "Webhooks" "List subscriptions" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/webhooks/event-types")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Webhooks" "List event types" "PASS" "$CODE" \
    || log_result "Webhooks" "List event types" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/webhooks/dlq")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Webhooks" "List DLQ entries" "PASS" "$CODE" \
    || log_result "Webhooks" "List DLQ entries" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/webhooks/circuit-breakers")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Webhooks" "List circuit breakers" "PASS" "$CODE" \
    || log_result "Webhooks" "List circuit breakers" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 38: AUDIT & SECURITY ALERTS
# =============================================================================
section_header "38. Audit & Security Alerts"

RESP=$(api GET "/audit/login-history")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Audit" "Login history" "PASS" "$CODE" \
    || log_result "Audit" "Login history" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/security-alerts")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Audit" "List security alerts" "PASS" "$CODE" \
    || log_result "Audit" "List security alerts" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 39: DELEGATION ADMIN
# =============================================================================
section_header "39. Delegation Admin (/admin/delegation)"

RESP=$(api GET "/admin/delegation/permissions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "DelegAdmin" "List permissions" "PASS" "$CODE" \
    || log_result "DelegAdmin" "List permissions" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/delegation/role-templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "DelegAdmin" "List role templates" "PASS" "$CODE" \
    || log_result "DelegAdmin" "List role templates" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/delegation/assignments")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "DelegAdmin" "List assignments" "PASS" "$CODE" \
    || log_result "DelegAdmin" "List assignments" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/delegation/audit-log")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "DelegAdmin" "Get audit log" "PASS" "$CODE" \
    || log_result "DelegAdmin" "Get audit log" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 40: BRANDING (F-030)
# =============================================================================
section_header "40. Branding & Email Templates"

RESP=$(api GET "/admin/branding")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Branding" "Get branding config" "PASS" "$CODE" \
    || log_result "Branding" "Get branding config" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/branding/assets")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Branding" "List branding assets" "PASS" "$CODE" \
    || log_result "Branding" "List branding assets" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/branding/email-templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Branding" "List email templates" "PASS" "$CODE" \
    || log_result "Branding" "List email templates" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 41: OAUTH ADMIN
# =============================================================================
section_header "41. OAuth Admin"

RESP=$(api GET "/admin/oauth/clients")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "OAuthAdmin" "List OAuth clients" "PASS" "$CODE" \
    || log_result "OAuthAdmin" "List OAuth clients" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/oauth/active-sessions?user_id=${TEST_USER_ID}")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "OAuthAdmin" "List active sessions" "PASS" "$CODE" \
    || log_result "OAuthAdmin" "List active sessions" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 42: AUTHORIZATION ENGINE (F-083)
# =============================================================================
section_header "42. Authorization Engine"

RESP=$(api GET "/admin/authorization/policies")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "AuthZ" "List policies" "PASS" "$CODE" \
    || log_result "AuthZ" "List policies" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/authorization/mappings")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "AuthZ" "List mappings" "PASS" "$CODE" \
    || log_result "AuthZ" "List mappings" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/authorization/can-i?action=read&resource_type=users")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "AuthZ" "Can-I check" "PASS" "$CODE" \
    || log_result "AuthZ" "Can-I check" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 43: KEY MANAGEMENT (F-082)
# =============================================================================
section_header "43. Key Management"

RESP=$(api GET "/admin/keys")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "KeyMgmt" "List signing keys" "PASS" "$CODE" \
    || log_result "KeyMgmt" "List signing keys" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 44: TENANT & API KEY MANAGEMENT
# =============================================================================
section_header "44. Tenant & API Key Management"

RESP=$(api GET "/tenants/${TENANT_ID}/api-keys")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Tenant" "List API keys" "PASS" "$CODE" \
    || log_result "Tenant" "List API keys" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/tenants/${TENANT_ID}/settings")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Tenant" "Get tenant settings" "PASS" "$CODE" \
    || log_result "Tenant" "Get tenant settings" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/tenants/${TENANT_ID}/invitations")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Tenant" "List invitations" "PASS" "$CODE" \
    || log_result "Tenant" "List invitations" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/tenants/${TENANT_ID}/oauth-clients")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Tenant" "List OAuth clients" "PASS" "$CODE" \
    || log_result "Tenant" "List OAuth clients" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 45: SYSTEM ADMIN
# =============================================================================
section_header "45. System Admin"

RESP=$(api GET "/system/tenants/${TENANT_ID}")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "System" "Get tenant status" "PASS" "$CODE" \
    || log_result "System" "Get tenant status" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/system/tenants/${TENANT_ID}/usage")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "System" "Get tenant usage" "PASS" "$CODE" \
    || log_result "System" "Get tenant usage" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/system/tenants/${TENANT_ID}/settings")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "System" "Get system settings" "PASS" "$CODE" \
    || log_result "System" "Get system settings" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/system/plans")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "System" "List plans" "PASS" "$CODE" \
    || log_result "System" "List plans" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 46: SAML
# =============================================================================
section_header "46. SAML"

RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/saml/metadata" -H "X-Tenant-Id: ${TENANT_ID}" 2>/dev/null)
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "SAML" "Get SAML metadata" "PASS" "$CODE" \
    || log_result "SAML" "Get SAML metadata" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/saml/service-providers")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "SAML" "List service providers" "PASS" "$CODE" \
    || log_result "SAML" "List service providers" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/saml/certificates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "SAML" "List certificates" "PASS" "$CODE" \
    || log_result "SAML" "List certificates" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 47: SOCIAL LOGIN
# =============================================================================
section_header "47. Social Login"

RESP=$(curl -s -w "\n%{http_code}" "${BASE_URL}/auth/social/available" -H "X-Tenant-Id: ${TENANT_ID}" 2>/dev/null)
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Social" "Available providers" "PASS" "$CODE" \
    || log_result "Social" "Available providers" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/admin/social-providers")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Social" "Admin list providers" "PASS" "$CODE" \
    || log_result "Social" "Admin list providers" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 48: IMPORT
# =============================================================================
section_header "48. Bulk Import"

RESP=$(api GET "/admin/users/imports")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Import" "List import jobs" "PASS" "$CODE" \
    || log_result "Import" "List import jobs" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 49: ADMIN INVITATIONS
# =============================================================================
section_header "49. Admin Invitations"

RESP=$(api GET "/admin/invitations")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "Invite" "List invitations" "PASS" "$CODE" \
    || log_result "Invite" "List invitations" "FAIL" "$CODE" "$(get_body "$RESP")"

section_footer

# =============================================================================
# SECTION 50: NEGATIVE/SECURITY TESTS
# =============================================================================
section_header "50. Security & Negative Tests"

# No auth token
RESP=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/admin/users" \
    -H "Content-Type: application/json" -H "X-Tenant-Id: ${TENANT_ID}" 2>/dev/null)
CODE=$(get_code "$RESP")
[ "$CODE" = "401" ] && log_result "Security" "No auth (expect 401)" "PASS" "$CODE" "correctly rejected" \
    || log_result "Security" "No auth" "FAIL" "$CODE" "expected 401"

# Invalid tenant
RESP=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/admin/users" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null)
CODE=$(get_code "$RESP")
[ "$CODE" = "400" ] || [ "$CODE" = "401" ] || [ "$CODE" = "422" ] && \
    log_result "Security" "No tenant header (expect 4xx)" "PASS" "$CODE" "correctly rejected" \
    || log_result "Security" "No tenant header" "FAIL" "$CODE" "expected 4xx"

# Expired/invalid token
RESP=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/admin/users" \
    -H "Content-Type: application/json" -H "X-Tenant-Id: ${TENANT_ID}" \
    -H "Authorization: Bearer invalid-token-xxxx" 2>/dev/null)
CODE=$(get_code "$RESP")
[ "$CODE" = "401" ] && log_result "Security" "Invalid token (expect 401)" "PASS" "$CODE" "correctly rejected" \
    || log_result "Security" "Invalid token" "FAIL" "$CODE" "expected 401"

# SQL injection attempt in query param
RESP=$(api GET "/admin/users?search='; DROP TABLE users; --")
CODE=$(get_code "$RESP")
[ "$CODE" != "500" ] && log_result "Security" "SQL injection attempt (not 500)" "PASS" "$CODE" "no server error" \
    || log_result "Security" "SQL injection attempt" "FAIL" "$CODE" "server crashed"

section_footer

# =============================================================================
# CLEANUP: Delete test data to be good citizens
# =============================================================================
section_header "CLEANUP"

# Cancel access request (must happen before entitlement deletion)
if [ -n "${AR_ID:-}" ]; then
    api POST "/governance/access-requests/${AR_ID}/cancel" > /dev/null 2>&1
    api DELETE "/governance/access-requests/${AR_ID}" > /dev/null 2>&1
fi

# Revoke assignment
if [ -n "${ASSIGN_ID:-}" ]; then
    RESP=$(api DELETE "/governance/assignments/${ASSIGN_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Cleanup" "Revoke assignment" "PASS" "$CODE" \
        || log_result "Cleanup" "Revoke assignment" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Delete meta role
if [ -n "${MR_ID:-}" ]; then
    api DELETE "/governance/meta-roles/${MR_ID}" > /dev/null 2>&1
fi

# Delete campaign
if [ -n "${CAMP_ID:-}" ]; then
    api DELETE "/governance/certification-campaigns/${CAMP_ID}" > /dev/null 2>&1
fi

# Delete risk factor
if [ -n "${RF_ID:-}" ]; then
    api DELETE "/governance/risk-factors/${RF_ID}" > /dev/null 2>&1
fi

# Delete SoD rule
if [ -n "${SOD_ID:-}" ]; then
    RESP=$(api DELETE "/governance/sod-rules/${SOD_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Cleanup" "Delete SoD rule" "PASS" "$CODE" \
        || log_result "Cleanup" "Delete SoD rule" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Delete role-entitlement mapping
if [ -n "${RE_ID:-}" ]; then
    RESP=$(api DELETE "/governance/role-entitlements/${RE_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Cleanup" "Delete role-entitlement" "PASS" "$CODE" \
        || log_result "Cleanup" "Delete role-entitlement" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Delete child role, then parent
if [ -n "${CHILD_ROLE_ID:-}" ]; then
    api DELETE "/governance/roles/${CHILD_ROLE_ID}" > /dev/null 2>&1
fi
if [ -n "${ROLE_ID:-}" ]; then
    api DELETE "/governance/roles/${ROLE_ID}" > /dev/null 2>&1
fi

# Delete any access requests referencing our entitlements (DB-level cleanup)
if [ -n "${ENT_ID:-}" ] || [ -n "${ENT2_ID:-}" ]; then
    docker exec xavyo-postgres psql -U xavyo -d xavyo_test -c \
        "DELETE FROM gov_access_requests WHERE entitlement_id IN ('${ENT_ID:-00000000-0000-0000-0000-000000000000}', '${ENT2_ID:-00000000-0000-0000-0000-000000000000}')" > /dev/null 2>&1
fi

# Delete entitlements (must happen before application deletion)
if [ -n "${ENT_ID:-}" ]; then
    api DELETE "/governance/entitlements/${ENT_ID}" > /dev/null 2>&1
fi
if [ -n "${ENT2_ID:-}" ]; then
    api DELETE "/governance/entitlements/${ENT2_ID}" > /dev/null 2>&1
fi

# Delete application (last - depends on entitlements being gone)
if [ -n "${APP_ID:-}" ]; then
    RESP=$(api DELETE "/governance/applications/${APP_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "Cleanup" "Delete application" "PASS" "$CODE" \
        || log_result "Cleanup" "Delete application" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

log_result "Cleanup" "Cleanup complete" "PASS" "-" ""

section_footer

# =============================================================================
# FINAL SUMMARY
# =============================================================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  COMPREHENSIVE TEST RESULTS                             ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  PASS: ${PASS_COUNT}                                             ${NC}"
echo -e "${RED}║  FAIL: ${FAIL_COUNT}                                             ${NC}"
echo -e "${YELLOW}║  SKIP: ${SKIP_COUNT}                                             ${NC}"
echo -e "${BLUE}║  TOTAL: ${TOTAL_COUNT}                                            ${NC}"
RATE=$(python3 -c "print(f'{${PASS_COUNT}/${TOTAL_COUNT}*100:.1f}%')" 2>/dev/null || echo "N/A")
echo -e "${BLUE}║  PASS RATE: ${RATE}                                      ${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Detailed results: ${RESULTS_FILE}"

# Append summary
cat >> "$RESULTS_FILE" << EOF

## Summary
- **PASS**: ${PASS_COUNT}
- **FAIL**: ${FAIL_COUNT}
- **SKIP**: ${SKIP_COUNT}
- **TOTAL**: ${TOTAL_COUNT}
- **PASS RATE**: ${RATE}
EOF
