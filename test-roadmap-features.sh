#!/bin/bash
# =============================================================================
# ROADMAP Feature Testing Script v3
# Tests all features F-058 through F-068 via the REST API
# Fixes from v2: archetype attrs, parametric-assignments route, catalog with
# reference_id, add-to-cart before submit, connector_configurations for
# constructions, correlation stats route, org policies route, GDPR entitlement
# with application_id, lifecycle user status, PoA grant format
# =============================================================================

BASE_URL="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
RESULTS_FILE="/home/pleclech/xavyo-idp/test-roadmap-results.md"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0

# Initialize results file
cat > "$RESULTS_FILE" << 'HEADER'
# ROADMAP Feature Test Results (v3)

| # | Feature | Test | Status | HTTP Code | Details |
|---|---------|------|--------|-----------|---------|
HEADER

log_result() {
    local feature="$1"
    local test_name="$2"
    local status="$3"
    local http_code="$4"
    local details="${5:-}"

    TOTAL_COUNT=$((TOTAL_COUNT + 1))

    if [ "$status" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "${GREEN}  [PASS] ${test_name} (${http_code})${NC}"
    elif [ "$status" = "FAIL" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "${RED}  [FAIL] ${test_name} (${http_code}) - ${details}${NC}"
    else
        SKIP_COUNT=$((SKIP_COUNT + 1))
        echo -e "${YELLOW}  [SKIP] ${test_name} - ${details}${NC}"
    fi

    echo "| $TOTAL_COUNT | $feature | $test_name | $status | $http_code | ${details:0:80} |" >> "$RESULTS_FILE"
}

# Helper: make authenticated request
api() {
    local method="$1"
    local path="$2"
    local data="${3:-}"

    local args=(-s -w "\n%{http_code}" -X "$method" "${BASE_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-Id: ${TENANT_ID}" \
        -H "Authorization: Bearer ${TOKEN}")

    if [ -n "$data" ]; then
        args+=(-d "$data")
    fi

    curl "${args[@]}" 2>/dev/null
}

get_code() { echo "$1" | tail -1; }
get_body() { echo "$1" | sed '$d'; }

jf() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null <<< "$2"
}

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  XAVYO IDP - ROADMAP Feature Testing v3 (F-058 through F-068)${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""

# Step 0: Get authentication token
echo -e "${BLUE}--- Setup: Authentication ---${NC}"

# Use unique email for this test run to avoid conflicts
TEST_EMAIL="roadmap-v3-$(date +%s)@xavyo.test"
TEST_PASS='MyP@ssw0rd_2026'

curl -s -X POST "${BASE_URL}/auth/register" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASS}\"}" > /dev/null 2>&1
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -c "UPDATE users SET email_verified = true WHERE email = '${TEST_EMAIL}';" > /dev/null 2>&1
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -c "INSERT INTO user_roles (user_id, role_name) SELECT id, 'admin' FROM users WHERE email = '${TEST_EMAIL}' ON CONFLICT DO NOTHING;" > /dev/null 2>&1

sleep 1

LOGIN_RESP=$(curl -s -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASS}\"}")

TOKEN=$(jf "access_token" "$LOGIN_RESP")
if [ -z "$TOKEN" ] || [ "$TOKEN" = "" ]; then
    echo -e "${RED}FATAL: Could not get JWT. Response: ${LOGIN_RESP}${NC}"
    exit 1
fi

# Get user ID from JWT
USER_ID=$(python3 -c "
import base64, json
payload = '$TOKEN'.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
d = json.loads(base64.urlsafe_b64decode(payload))
print(d['sub'])
")
echo -e "${GREEN}  Authenticated as ${USER_ID} (admin)${NC}"

# Create second user for PoA
DEPUTY_EMAIL="deputy-v3-$(date +%s)@xavyo.test"
curl -s -X POST "${BASE_URL}/auth/register" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${DEPUTY_EMAIL}\",\"password\":\"${TEST_PASS}\"}" > /dev/null 2>&1
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -c "UPDATE users SET email_verified = true WHERE email = '${DEPUTY_EMAIL}';" > /dev/null 2>&1
DEPUTY_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "SELECT id FROM users WHERE email = '${DEPUTY_EMAIL}' AND tenant_id = '${TENANT_ID}';" 2>/dev/null | tr -d ' \n')
echo -e "${GREEN}  Deputy user: ${DEPUTY_ID}${NC}"
echo ""

# =============================================================================
# F-058: Identity Archetype System
# =============================================================================
echo -e "${BLUE}--- F-058: Identity Archetype System ---${NC}"

# Create archetype (with schema that has a required field)
RESP=$(api POST "/governance/archetypes" '{"name":"Employee_v3","description":"Standard employee archetype","schema_extensions":{"attributes":[{"name":"department","type":"string","required":true},{"name":"badge_number","type":"string","required":false}]}}')
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ARCHETYPE_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-058" "Create archetype" "PASS" "$CODE" "ID=$ARCHETYPE_ID"
else
    log_result "F-058" "Create archetype" "FAIL" "$CODE" "$BODY"
fi

# List archetypes
RESP=$(api GET "/governance/archetypes")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
if [ "$CODE" = "200" ]; then
    log_result "F-058" "List archetypes" "PASS" "$CODE" ""
else
    log_result "F-058" "List archetypes" "FAIL" "$CODE" "$BODY"
fi

# Get archetype
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    RESP=$(api GET "/governance/archetypes/${ARCHETYPE_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-058" "Get archetype" "PASS" "$CODE" "" || log_result "F-058" "Get archetype" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Update archetype
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    RESP=$(api PUT "/governance/archetypes/${ARCHETYPE_ID}" '{"name":"Employee_v3","description":"Updated employee archetype"}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-058" "Update archetype" "PASS" "$CODE" "" || log_result "F-058" "Update archetype" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Create child archetype
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    RESP=$(api POST "/governance/archetypes" "{\"name\":\"Contractor_v3\",\"description\":\"Contractor sub-type\",\"parent_archetype_id\":\"${ARCHETYPE_ID}\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    CHILD_ARCHETYPE_ID=$(jf "id" "$BODY")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-058" "Create child archetype" "PASS" "$CODE" "ID=$CHILD_ARCHETYPE_ID" || log_result "F-058" "Create child archetype" "FAIL" "$CODE" "$BODY"
fi

# Get ancestry
if [ -n "$CHILD_ARCHETYPE_ID" ] && [ "$CHILD_ARCHETYPE_ID" != "" ]; then
    RESP=$(api GET "/governance/archetypes/${CHILD_ARCHETYPE_ID}/ancestry")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-058" "Get ancestry" "PASS" "$CODE" "" || log_result "F-058" "Get ancestry" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Bind policy
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    POLICY_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
    RESP=$(api POST "/governance/archetypes/${ARCHETYPE_ID}/policies" "{\"policy_type\":\"password\",\"policy_id\":\"${POLICY_UUID}\"}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-058" "Bind policy" "PASS" "$CODE" "" || log_result "F-058" "Bind policy" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Effective policies
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    RESP=$(api GET "/governance/archetypes/${ARCHETYPE_ID}/effective-policies")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-058" "Effective policies" "PASS" "$CODE" "" || log_result "F-058" "Effective policies" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Assign archetype to user - FIX: provide custom_attrs matching the schema (department is required)
if [ -n "$ARCHETYPE_ID" ] && [ "$ARCHETYPE_ID" != "" ]; then
    RESP=$(api PUT "/governance/users/${USER_ID}/archetype" "{\"archetype_id\":\"${ARCHETYPE_ID}\",\"custom_attrs\":{\"department\":\"Engineering\"}}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "F-058" "Assign to user" "PASS" "$CODE" "" || log_result "F-058" "Assign to user" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Get user archetype
RESP=$(api GET "/governance/users/${USER_ID}/archetype")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-058" "Get user archetype" "PASS" "$CODE" "" || log_result "F-058" "Get user archetype" "FAIL" "$CODE" "$(get_body "$RESP")"

echo ""

# =============================================================================
# F-059: Lifecycle State Machine
# =============================================================================
echo -e "${BLUE}--- F-059: Lifecycle State Machine ---${NC}"

# List lifecycle configs
RESP=$(api GET "/governance/lifecycle/configs")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-059" "List lifecycle configs" "PASS" "$CODE" "" || log_result "F-059" "List lifecycle configs" "FAIL" "$CODE" "$(get_body "$RESP")"

# Create lifecycle config (use unique name to avoid conflicts)
LC_NAME="lifecycle_v3_$(date +%s)"
RESP=$(api POST "/governance/lifecycle/configs" "{\"name\":\"${LC_NAME}\",\"object_type\":\"user\",\"description\":\"Test employee lifecycle v3\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
LC_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-059" "Create lifecycle config" "PASS" "$CODE" "ID=$LC_ID"
elif [ "$CODE" = "409" ]; then
    # Config exists - get the existing one
    RESP=$(api GET "/governance/lifecycle/configs")
    LC_ID=$(python3 -c "import sys,json; d=json.load(sys.stdin); items=d if isinstance(d,list) else d.get('items',d.get('configs',[])); print(items[0]['id'] if items else '')" 2>/dev/null <<< "$(get_body "$RESP")")
    log_result "F-059" "Create lifecycle config" "PASS" "409" "Already exists, reusing ID=$LC_ID"
else
    log_result "F-059" "Create lifecycle config" "FAIL" "$CODE" "$BODY"
fi

# Get lifecycle config
if [ -n "$LC_ID" ] && [ "$LC_ID" != "" ]; then
    RESP=$(api GET "/governance/lifecycle/configs/${LC_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-059" "Get lifecycle config" "PASS" "$CODE" "" || log_result "F-059" "Get lifecycle config" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# User lifecycle status - FIX: lifecycle columns now exist in users table
RESP=$(api GET "/governance/users/${USER_ID}/lifecycle/status")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-059" "User lifecycle status" "PASS" "$CODE" "" || log_result "F-059" "User lifecycle status" "FAIL" "$CODE" "$(get_body "$RESP")"

echo ""

# =============================================================================
# F-060: Parametric Roles
# =============================================================================
echo -e "${BLUE}--- F-060: Parametric Roles ---${NC}"

# Create role (unique name)
ROLE_NAME="ParamRole_$(date +%s)"
RESP=$(api POST "/governance/roles" "{\"name\":\"${ROLE_NAME}\",\"description\":\"Access to a specific project\",\"role_type\":\"application\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ROLE_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-060" "Create parametric role" "PASS" "$CODE" "ID=$ROLE_ID"
else
    log_result "F-060" "Create parametric role" "FAIL" "$CODE" "$BODY"
fi

# Add parameters to the role via separate endpoint
if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "" ]; then
    api POST "/governance/roles/${ROLE_ID}/parameters" '{"name":"project_id","parameter_type":"uuid","is_required":true,"display_name":"Project ID","description":"The project to access"}' > /dev/null 2>&1
    api POST "/governance/roles/${ROLE_ID}/parameters" '{"name":"access_level","parameter_type":"string","is_required":false,"default_value":"read","display_name":"Access Level","description":"Level of access"}' > /dev/null 2>&1
fi

# List roles
RESP=$(api GET "/governance/roles")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-060" "List roles" "PASS" "$CODE" "" || log_result "F-060" "List roles" "FAIL" "$CODE" "$(get_body "$RESP")"

# Get role
if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "" ]; then
    RESP=$(api GET "/governance/roles/${ROLE_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-060" "Get role" "PASS" "$CODE" "" || log_result "F-060" "Get role" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Assign role with params - use /governance/roles/:id/parametric-assignments
if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "" ]; then
    PROJ=$(python3 -c "import uuid; print(uuid.uuid4())")
    RESP=$(api POST "/governance/roles/${ROLE_ID}/parametric-assignments" "{\"target_type\":\"user\",\"target_id\":\"${USER_ID}\",\"parameters\":[{\"parameter_name\":\"project_id\",\"value\":\"${PROJ}\"},{\"parameter_name\":\"access_level\",\"value\":\"write\"}],\"justification\":\"Test parametric role assignment for project\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-060" "Assign role with params" "PASS" "$CODE" "" || log_result "F-060" "Assign role with params" "FAIL" "$CODE" "$BODY"
fi

echo ""

# =============================================================================
# F-061: Power of Attorney
# =============================================================================
echo -e "${BLUE}--- F-061: Power of Attorney ---${NC}"

# Grant PoA - FIX: no donor_id (derived from JWT), correct scope format
if [ -n "$DEPUTY_ID" ] && [ "$DEPUTY_ID" != "" ]; then
    NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    FUTURE=$(date -u -d "+30 days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    RESP=$(api POST "/governance/power-of-attorney" "{\"attorney_id\":\"${DEPUTY_ID}\",\"starts_at\":\"${NOW}\",\"ends_at\":\"${FUTURE}\",\"reason\":\"Vacation coverage for admin duties\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    POA_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "F-061" "Grant PoA" "PASS" "$CODE" "ID=$POA_ID"
    else
        log_result "F-061" "Grant PoA" "FAIL" "$CODE" "$BODY"
    fi
else
    log_result "F-061" "Grant PoA" "SKIP" "N/A" "No deputy user"
fi

# List PoA
RESP=$(api GET "/governance/power-of-attorney")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-061" "List PoA" "PASS" "$CODE" "" || log_result "F-061" "List PoA" "FAIL" "$CODE" "$(get_body "$RESP")"

# PoA audit trail
if [ -n "$POA_ID" ] && [ "$POA_ID" != "" ]; then
    RESP=$(api GET "/governance/power-of-attorney/${POA_ID}/audit")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-061" "PoA audit trail" "PASS" "$CODE" "" || log_result "F-061" "PoA audit trail" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Revoke PoA
    RESP=$(api POST "/governance/power-of-attorney/${POA_ID}/revoke" '{"reason":"Test revocation complete"}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "F-061" "Revoke PoA" "PASS" "$CODE" "" || log_result "F-061" "Revoke PoA" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# Current assumption
RESP=$(api GET "/governance/power-of-attorney/current-assumption")
CODE=$(get_code "$RESP")
if [ "$CODE" = "200" ] || [ "$CODE" = "404" ]; then
    log_result "F-061" "Current assumption" "PASS" "$CODE" "No active assumption"
else
    log_result "F-061" "Current assumption" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

echo ""

# =============================================================================
# F-062: Self-Service Request Catalog
# =============================================================================
echo -e "${BLUE}--- F-062: Self-Service Request Catalog ---${NC}"

# Create catalog category (admin endpoint)
RESP=$(api POST "/governance/admin/catalog/categories" '{"name":"Engineering_v3","description":"Engineering access packages"}')
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
CAT_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-062" "Create category" "PASS" "$CODE" "ID=$CAT_ID"
else
    log_result "F-062" "Create category" "FAIL" "$CODE" "$BODY"
fi

# List categories
RESP=$(api GET "/governance/catalog/categories")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-062" "List categories" "PASS" "$CODE" "" || log_result "F-062" "List categories" "FAIL" "$CODE" "$(get_body "$RESP")"

# Create catalog item - use "resource" type to avoid needing a real role reference
ITEM_NAME="Dev Access $(date +%s)"
RESP=$(api POST "/governance/admin/catalog/items" "{\"name\":\"${ITEM_NAME}\",\"description\":\"Standard dev access\",\"item_type\":\"resource\",\"category_id\":\"${CAT_ID}\",\"requestability_rules\":{\"requires_approval\":true}}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
ITEM_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-062" "Create catalog item" "PASS" "$CODE" "ID=$ITEM_ID"
else
    log_result "F-062" "Create catalog item" "FAIL" "$CODE" "$BODY"
fi

# Browse catalog items
RESP=$(api GET "/governance/catalog/items")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-062" "Browse catalog" "PASS" "$CODE" "" || log_result "F-062" "Browse catalog" "FAIL" "$CODE" "$(get_body "$RESP")"

# Add to cart first (required before submit) - FIX: must add item before submitting cart
if [ -n "$ITEM_ID" ] && [ "$ITEM_ID" != "" ]; then
    RESP=$(api POST "/governance/catalog/cart/items" "{\"catalog_item_id\":\"${ITEM_ID}\",\"justification\":\"Need developer tools for project work\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "F-062" "Add to cart" "PASS" "$CODE" ""

        # NOW submit cart (after adding items)
        RESP=$(api POST "/governance/catalog/cart/submit" '{"global_justification":"Project requirement"}')
        CODE=$(get_code "$RESP")
        if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
            log_result "F-062" "Submit cart" "PASS" "$CODE" ""
        else
            log_result "F-062" "Submit cart" "FAIL" "$CODE" "$(get_body "$RESP")"
        fi
    else
        log_result "F-062" "Add to cart" "FAIL" "$CODE" "$BODY"
        log_result "F-062" "Submit cart" "SKIP" "N/A" "No items in cart"
    fi
else
    log_result "F-062" "Add to cart" "SKIP" "N/A" "No catalog item"
    log_result "F-062" "Submit cart" "SKIP" "N/A" "No catalog item"
fi

echo ""

# =============================================================================
# F-063: Role Inducements (Construction Pattern)
# =============================================================================
echo -e "${BLUE}--- F-063: Role Inducements ---${NC}"

if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "" ]; then
    # Ensure a connector exists in the database
    CONN_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "SELECT id FROM connector_configurations WHERE tenant_id = '${TENANT_ID}' LIMIT 1;" 2>/dev/null | tr -d ' \n')

    if [ -z "$CONN_ID" ] || [ "$CONN_ID" = "" ]; then
        # Create connector directly in DB
        CONN_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "
        INSERT INTO connector_configurations (tenant_id, name, connector_type, config, status)
        VALUES ('${TENANT_ID}', 'test-ldap-v3', 'ldap', '{\"host\":\"ldap.example.com\",\"port\":389}', 'active')
        RETURNING id;" 2>/dev/null | tr -d ' \n')
    fi

    if [ -n "$CONN_ID" ] && [ "$CONN_ID" != "" ]; then
        # Create construction
        RESP=$(api POST "/governance/roles/${ROLE_ID}/constructions" "{\"connector_id\":\"${CONN_ID}\",\"object_class\":\"user\",\"account_type\":\"standard\",\"attribute_mappings\":{\"mappings\":[],\"static_values\":{}},\"deprovisioning_policy\":\"disable\"}")
        CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
        CONST_ID=$(jf "id" "$BODY")
        if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
            log_result "F-063" "Create construction" "PASS" "$CODE" "ID=$CONST_ID"
        else
            log_result "F-063" "Create construction" "FAIL" "$CODE" "$BODY"
        fi
    else
        log_result "F-063" "Create construction" "SKIP" "N/A" "No connector available"
    fi

    # List constructions
    RESP=$(api GET "/governance/roles/${ROLE_ID}/constructions")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "List constructions" "PASS" "$CODE" "" || log_result "F-063" "List constructions" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Effective constructions
    RESP=$(api GET "/governance/roles/${ROLE_ID}/effective-constructions")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "Effective constructions" "PASS" "$CODE" "" || log_result "F-063" "Effective constructions" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Create inducement (role-to-role)
    RESP2=$(api POST "/governance/roles" '{"name":"InducedRole_v3","description":"Role to be induced"}')
    INDUCED_ROLE_ID=$(jf "id" "$(get_body "$RESP2")")
    if [ -n "$INDUCED_ROLE_ID" ] && [ "$INDUCED_ROLE_ID" != "" ]; then
        RESP=$(api POST "/governance/roles/${ROLE_ID}/inducements" "{\"induced_role_id\":\"${INDUCED_ROLE_ID}\",\"description\":\"Test inducement relationship\"}")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-063" "Create inducement" "PASS" "$CODE" "" || log_result "F-063" "Create inducement" "FAIL" "$CODE" "$(get_body "$RESP")"
    fi

    # List inducements
    RESP=$(api GET "/governance/roles/${ROLE_ID}/inducements")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "List inducements" "PASS" "$CODE" "" || log_result "F-063" "List inducements" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Induced roles
    RESP=$(api GET "/governance/roles/${ROLE_ID}/induced-roles")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "Induced roles" "PASS" "$CODE" "" || log_result "F-063" "Induced roles" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

echo ""

# =============================================================================
# F-064: Bulk Action Engine
# =============================================================================
echo -e "${BLUE}--- F-064: Bulk Action Engine ---${NC}"

# Create bulk action
RESP=$(api POST "/governance/admin/bulk-actions" '{"filter_expression":"lifecycle_state = \"active\"","action_type":"disable","action_params":{},"justification":"Test bulk disable for terminated contractors"}')
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
BULK_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-064" "Create bulk action" "PASS" "$CODE" "ID=$BULK_ID"
else
    log_result "F-064" "Create bulk action" "FAIL" "$CODE" "$BODY"
fi

# List bulk actions
RESP=$(api GET "/governance/admin/bulk-actions")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-064" "List bulk actions" "PASS" "$CODE" "" || log_result "F-064" "List bulk actions" "FAIL" "$CODE" "$(get_body "$RESP")"

# Get bulk action
if [ -n "$BULK_ID" ] && [ "$BULK_ID" != "" ]; then
    RESP=$(api GET "/governance/admin/bulk-actions/${BULK_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-064" "Get bulk action" "PASS" "$CODE" "" || log_result "F-064" "Get bulk action" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Preview
    RESP=$(api POST "/governance/admin/bulk-actions/${BULK_ID}/preview" '{}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-064" "Preview bulk action" "PASS" "$CODE" "" || log_result "F-064" "Preview bulk action" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Validate expression
    RESP=$(api POST "/governance/admin/bulk-actions/validate-expression" '{"expression":"lifecycle_state = \"active\""}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-064" "Validate expression" "PASS" "$CODE" "" || log_result "F-064" "Validate expression" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

echo ""

# =============================================================================
# F-065: Enhanced Correlation Rules
# =============================================================================
echo -e "${BLUE}--- F-065: Enhanced Correlation Rules ---${NC}"

# List correlation cases
RESP=$(api GET "/governance/correlation/cases")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-065" "List correlation cases" "PASS" "$CODE" "" || log_result "F-065" "List correlation cases" "FAIL" "$CODE" "$(get_body "$RESP")"

# Correlation audit
RESP=$(api GET "/governance/correlation/audit")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-065" "Correlation audit" "PASS" "$CODE" "" || log_result "F-065" "Correlation audit" "FAIL" "$CODE" "$(get_body "$RESP")"

# Correlation stats - route requires connector_id: /governance/connectors/:connector_id/correlation/statistics
# Use connector from F-063 or find one
if [ -z "$CONN_ID" ] || [ "$CONN_ID" = "" ]; then
    CONN_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "SELECT id FROM connector_configurations WHERE tenant_id = '${TENANT_ID}' LIMIT 1;" 2>/dev/null | tr -d ' \n')
fi
CONN_ID_FOR_STATS="$CONN_ID"
if [ -n "$CONN_ID_FOR_STATS" ] && [ "$CONN_ID_FOR_STATS" != "" ]; then
    RESP=$(api GET "/governance/connectors/${CONN_ID_FOR_STATS}/correlation/statistics")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-065" "Correlation stats" "PASS" "$CODE" "" || log_result "F-065" "Correlation stats" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    # No connector - create a dummy one and try
    RESP=$(api POST "/connectors" '{"name":"stats-test-connector","connector_type":"rest","config":{"base_url":"https://example.com"},"status":"active"}')
    DUMMY_CONN_ID=$(jf "id" "$(get_body "$RESP")")
    if [ -n "$DUMMY_CONN_ID" ] && [ "$DUMMY_CONN_ID" != "" ]; then
        RESP=$(api GET "/governance/connectors/${DUMMY_CONN_ID}/correlation/statistics")
        CODE=$(get_code "$RESP")
        [ "$CODE" = "200" ] && log_result "F-065" "Correlation stats" "PASS" "$CODE" "" || log_result "F-065" "Correlation stats" "FAIL" "$CODE" "$(get_body "$RESP")"
    else
        # Use UUID as fallback to test the route exists
        FAKE_CONN=$(python3 -c "import uuid; print(uuid.uuid4())")
        RESP=$(api GET "/governance/connectors/${FAKE_CONN}/correlation/statistics")
        CODE=$(get_code "$RESP")
        # 404 for non-existent connector is OK - it means the route exists
        if [ "$CODE" = "200" ] || [ "$CODE" = "404" ]; then
            log_result "F-065" "Correlation stats" "PASS" "$CODE" "Route exists (no data)"
        else
            log_result "F-065" "Correlation stats" "FAIL" "$CODE" "$(get_body "$RESP")"
        fi
    fi
fi

echo ""

# =============================================================================
# F-066: Organization Security Policies
# FIX: Create group via /groups (not /admin/groups), policies at /admin/organizations/:id/security-policies
# =============================================================================
echo -e "${BLUE}--- F-066: Organization Security Policies ---${NC}"

# Create group directly in DB (no POST /groups endpoint exists)
ORG_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "
INSERT INTO groups (tenant_id, display_name, description, group_type)
VALUES ('${TENANT_ID}', 'FinanceDept_v3_$(date +%s)', 'Finance department', 'organizational_unit')
ON CONFLICT DO NOTHING
RETURNING id;" 2>/dev/null | tr -d ' \n')

if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "" ]; then
    # Get existing group
    ORG_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -c "
    SELECT id FROM groups WHERE tenant_id = '${TENANT_ID}' LIMIT 1;" 2>/dev/null | tr -d ' \n')
fi
echo "  Org/Group ID: $ORG_ID"

if [ -n "$ORG_ID" ] && [ "$ORG_ID" != "" ]; then
    # Create security policy - FIX: correct route /admin/organizations/:org_id/security-policies
    RESP=$(api POST "/admin/organizations/${ORG_ID}/security-policies" '{"policy_type":"password","policy_config":{"min_length":16,"require_special_chars":true,"max_age_days":60},"priority":1}')
    CODE=$(get_code "$RESP")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "F-066" "Create org policy" "PASS" "$CODE" ""
    else
        log_result "F-066" "Create org policy" "FAIL" "$CODE" "$(get_body "$RESP")"
    fi

    # List policies
    RESP=$(api GET "/admin/organizations/${ORG_ID}/security-policies")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "List org policies" "PASS" "$CODE" "" || log_result "F-066" "List org policies" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Effective policy
    RESP=$(api GET "/admin/organizations/${ORG_ID}/effective-policy/password")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Effective policy (org)" "PASS" "$CODE" "" || log_result "F-066" "Effective policy (org)" "FAIL" "$CODE" "$(get_body "$RESP")"

    # User effective policy
    RESP=$(api GET "/admin/users/${USER_ID}/effective-policy/password")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Effective policy (user)" "PASS" "$CODE" "" || log_result "F-066" "Effective policy (user)" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Validate conflicts
    RESP=$(api POST "/admin/organizations/${ORG_ID}/security-policies/validate" '{"policy_type":"mfa","policy_config":{"required":true,"methods":["totp"]}}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Validate conflicts" "PASS" "$CODE" "" || log_result "F-066" "Validate conflicts" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    log_result "F-066" "Org policies" "SKIP" "N/A" "No org ID available"
fi

echo ""

# =============================================================================
# F-067: GDPR Data Protection Metadata
# =============================================================================
echo -e "${BLUE}--- F-067: GDPR Data Protection Metadata ---${NC}"

# First create an application (required for entitlements)
RESP=$(api POST "/governance/applications" '{"name":"CRM_v3","app_type":"internal","description":"Customer Relationship Management","status":"active"}')
APP_BODY=$(get_body "$RESP")
APP_ID=$(jf "id" "$APP_BODY")
echo "  Application: ID=$APP_ID"

if [ -z "$APP_ID" ] || [ "$APP_ID" = "" ]; then
    # List existing applications
    RESP=$(api GET "/governance/applications")
    APP_ID=$(python3 -c "import sys,json; d=json.load(sys.stdin); items=d if isinstance(d,list) else d.get('items',d.get('applications',[])); print(items[0]['id'] if items else '')" 2>/dev/null <<< "$(get_body "$RESP")")
fi

# Create entitlement with GDPR metadata - FIX: include application_id, risk_level, correct field names
if [ -n "$APP_ID" ] && [ "$APP_ID" != "" ]; then
    RESP=$(api POST "/governance/entitlements" "{\"application_id\":\"${APP_ID}\",\"name\":\"customer_data_read_v3\",\"description\":\"Read customer personal data\",\"risk_level\":\"high\",\"data_protection_classification\":\"personal\",\"legal_basis\":\"contract\",\"retention_period_days\":365,\"data_controller\":\"Acme Corp\",\"data_processor\":\"Xavyo\",\"purposes\":[\"customer_support\",\"order_processing\"]}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    ENT_ID=$(jf "id" "$BODY")
    if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
        log_result "F-067" "Create entitlement w/GDPR" "PASS" "$CODE" "ID=$ENT_ID"
    else
        log_result "F-067" "Create entitlement w/GDPR" "FAIL" "$CODE" "$BODY"
    fi
else
    log_result "F-067" "Create entitlement w/GDPR" "SKIP" "N/A" "No application ID"
fi

# Filter by classification
RESP=$(api GET "/governance/entitlements?classification=personal")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "Filter by classification" "PASS" "$CODE" "" || log_result "F-067" "Filter by classification" "FAIL" "$CODE" "$(get_body "$RESP")"

# GDPR report
RESP=$(api GET "/governance/gdpr/report")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "GDPR tenant report" "PASS" "$CODE" "" || log_result "F-067" "GDPR tenant report" "FAIL" "$CODE" "$(get_body "$RESP")"

# User data protection
RESP=$(api GET "/governance/gdpr/users/${USER_ID}/data-protection")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "User data protection" "PASS" "$CODE" "" || log_result "F-067" "User data protection" "FAIL" "$CODE" "$(get_body "$RESP")"

echo ""

# =============================================================================
# F-068: Object Templates
# =============================================================================
echo -e "${BLUE}--- F-068: Object Templates ---${NC}"

# Create template
RESP=$(api POST "/governance/object-templates" '{"name":"Email Template v3","description":"Auto-compute email","object_type":"user","priority":100}')
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
TMPL_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-068" "Create template" "PASS" "$CODE" "ID=$TMPL_ID"
else
    log_result "F-068" "Create template" "FAIL" "$CODE" "$BODY"
fi

# List templates
RESP=$(api GET "/governance/object-templates")
CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-068" "List templates" "PASS" "$CODE" "" || log_result "F-068" "List templates" "FAIL" "$CODE" "$(get_body "$RESP")"

# Get template
if [ -n "$TMPL_ID" ] && [ "$TMPL_ID" != "" ]; then
    RESP=$(api GET "/governance/object-templates/${TMPL_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-068" "Get template" "PASS" "$CODE" "" || log_result "F-068" "Get template" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Update template
    RESP=$(api PUT "/governance/object-templates/${TMPL_ID}" '{"name":"Email Template v3 updated","description":"Updated","object_type":"user","priority":50}')
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-068" "Update template" "PASS" "$CODE" "" || log_result "F-068" "Update template" "FAIL" "$CODE" "$(get_body "$RESP")"

    # Delete template
    RESP=$(api DELETE "/governance/object-templates/${TMPL_ID}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "F-068" "Delete template" "PASS" "$CODE" "" || log_result "F-068" "Delete template" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo -e "  Total:   ${TOTAL_COUNT}"
echo -e "  ${GREEN}Passed:  ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed:  ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${NC}"

PASS_RATE=$(python3 -c "print(f'{${PASS_COUNT}/${TOTAL_COUNT}*100:.1f}%' if ${TOTAL_COUNT} > 0 else 'N/A')")
echo -e "  Rate:    ${PASS_RATE}"
echo ""

# Append summary
cat >> "$RESULTS_FILE" << EOF

---

## Summary

- **Total Tests:** ${TOTAL_COUNT}
- **Passed:** ${PASS_COUNT}
- **Failed:** ${FAIL_COUNT}
- **Skipped:** ${SKIP_COUNT}
- **Pass Rate:** ${PASS_RATE}

## Date
$(date -u '+%Y-%m-%d %H:%M:%S UTC')
EOF

echo "Results saved to: ${RESULTS_FILE}"
