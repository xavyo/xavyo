#!/bin/bash
# =============================================================================
# ROADMAP Feature Testing Script v4.1
# Tests all features F-058 through F-068 via the REST API
# All route corrections applied based on router.rs analysis
# =============================================================================

BASE_URL="http://localhost:8080"
TENANT_ID="00000000-0000-0000-0000-000000000001"
RESULTS_FILE="/home/pleclech/xavyo-idp/test-roadmap-results.md"
STAMP=$(date +%s)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; TOTAL_COUNT=0

cat > "$RESULTS_FILE" << 'HEADER'
# ROADMAP Feature Test Results (v4.1)

| # | Feature | Test | Status | HTTP Code | Details |
|---|---------|------|--------|-----------|---------|
HEADER

log_result() {
    local feature="$1" test_name="$2" status="$3" http_code="$4" details="${5:-}"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); echo -e "${GREEN}  [PASS] ${test_name} (${http_code})${NC}" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "${RED}  [FAIL] ${test_name} (${http_code}) - ${details}${NC}" ;;
        *)    SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "${YELLOW}  [SKIP] ${test_name} - ${details}${NC}" ;;
    esac
    echo "| $TOTAL_COUNT | $feature | $test_name | $status | $http_code | ${details:0:80} |" >> "$RESULTS_FILE"
}

api() {
    local method="$1" path="$2" data="${3:-}"
    local args=(-s -w "\n%{http_code}" -X "$method" "${BASE_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-Id: ${TENANT_ID}" \
        -H "Authorization: Bearer ${TOKEN}")
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}" 2>/dev/null
}
get_code() { echo "$1" | tail -1; }
get_body() { echo "$1" | sed '$d'; }
jf() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null <<< "$2"; }

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  XAVYO IDP - ROADMAP Feature Testing v4.1${NC}"
echo -e "${BLUE}  Run: ${STAMP}${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""

# =====================================
# SETUP
# =====================================
echo -e "${BLUE}--- Setup ---${NC}"
TEST_EMAIL="rm-${STAMP}@xavyo.test"
DEPUTY_EMAIL="dep-${STAMP}@xavyo.test"
TEST_PASS='MyP@ssw0rd_2026'

curl -s -X POST "${BASE_URL}/auth/register" -H "Content-Type: application/json" -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASS}\"}" > /dev/null 2>&1
curl -s -X POST "${BASE_URL}/auth/register" -H "Content-Type: application/json" -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${DEPUTY_EMAIL}\",\"password\":\"${TEST_PASS}\"}" > /dev/null 2>&1

docker exec xavyo-postgres psql -U xavyo -d xavyo_test -q -c \
    "UPDATE users SET email_verified = true WHERE email IN ('${TEST_EMAIL}','${DEPUTY_EMAIL}');"
docker exec xavyo-postgres psql -U xavyo -d xavyo_test -q -c \
    "INSERT INTO user_roles (user_id, role_name) SELECT id, 'admin' FROM users WHERE email = '${TEST_EMAIL}' ON CONFLICT DO NOTHING;"
sleep 1

LOGIN_RESP=$(curl -s -X POST "${BASE_URL}/auth/login" -H "Content-Type: application/json" -H "X-Tenant-Id: ${TENANT_ID}" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASS}\"}")
TOKEN=$(jf "access_token" "$LOGIN_RESP")
[ -z "$TOKEN" ] && { echo -e "${RED}FATAL: No JWT. ${LOGIN_RESP}${NC}"; exit 1; }

USER_ID=$(python3 -c "import base64,json; p='$TOKEN'.split('.')[1]; p+='='*(4-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))['sub'])")
DEPUTY_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c "SELECT id FROM users WHERE email='${DEPUTY_EMAIL}' AND tenant_id='${TENANT_ID}';" 2>/dev/null | head -1 | tr -d '[:space:]')
echo -e "${GREEN}  User: ${USER_ID}, Deputy: ${DEPUTY_ID}${NC}"
echo ""

# =============================================================================
# F-058: Identity Archetype System
# Routes: /governance/archetypes, /governance/users/:user_id/archetype
# =============================================================================
echo -e "${BLUE}--- F-058: Identity Archetype System ---${NC}"

ANAME="Emp_${STAMP}"
RESP=$(api POST "/governance/archetypes" "{\"name\":\"${ANAME}\",\"description\":\"Employee\",\"schema_extensions\":{\"attributes\":[{\"name\":\"department\",\"type\":\"string\",\"required\":true}]}}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); ARCHETYPE_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-058" "Create archetype" "PASS" "$CODE" "ID=$ARCHETYPE_ID"
else
    log_result "F-058" "Create archetype" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/archetypes"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-058" "List archetypes" "PASS" "$CODE" || log_result "F-058" "List archetypes" "FAIL" "$CODE" "$(get_body "$RESP")"

# Assign archetype to user (correct route: PUT /governance/users/:id/archetype)
if [ -n "$ARCHETYPE_ID" ]; then
    RESP=$(api PUT "/governance/users/${USER_ID}/archetype" "{\"archetype_id\":\"${ARCHETYPE_ID}\",\"custom_attrs\":{\"department\":\"Engineering\"}}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "F-058" "Assign user archetype" "PASS" "$CODE" || log_result "F-058" "Assign user archetype" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

RESP=$(api GET "/governance/users/${USER_ID}/archetype"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-058" "Get user archetype" "PASS" "$CODE" || log_result "F-058" "Get user archetype" "FAIL" "$CODE" "$(get_body "$RESP")"

# =============================================================================
# F-059: Lifecycle State Machine
# Routes: /governance/lifecycle/configs, /governance/users/:id/lifecycle/status
# =============================================================================
echo -e "${BLUE}--- F-059: Lifecycle State Machine ---${NC}"

RESP=$(api GET "/governance/lifecycle/configs"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-059" "List lifecycle configs" "PASS" "$CODE" || log_result "F-059" "List lifecycle configs" "FAIL" "$CODE" "$(get_body "$RESP")"

LC_NAME="UserLC_${STAMP}"
RESP=$(api POST "/governance/lifecycle/configs" "{\"name\":\"${LC_NAME}\",\"description\":\"User lifecycle\",\"object_type\":\"user\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); LC_ID=$(jf "id" "$BODY")
if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    log_result "F-059" "Create lifecycle config" "PASS" "$CODE" "ID=$LC_ID"
elif [ "$CODE" = "409" ]; then
    log_result "F-059" "Create lifecycle config" "PASS" "$CODE" "Already exists"
    # Extract first config ID from list
    LIST_RESP=$(api GET "/governance/lifecycle/configs"); LIST_BODY=$(get_body "$LIST_RESP")
    LC_ID=$(echo "$LIST_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); items=d if isinstance(d,list) else d.get('items',d.get('configs',[])); print(items[0]['id'] if items else '')" 2>/dev/null)
else
    log_result "F-059" "Create lifecycle config" "FAIL" "$CODE" "$BODY"
fi

if [ -n "$LC_ID" ]; then
    RESP=$(api GET "/governance/lifecycle/configs/${LC_ID}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-059" "Get lifecycle config" "PASS" "$CODE" || log_result "F-059" "Get lifecycle config" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    log_result "F-059" "Get lifecycle config" "SKIP" "N/A" "No LC ID"
fi

RESP=$(api GET "/governance/users/${USER_ID}/lifecycle/status"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-059" "User lifecycle status" "PASS" "$CODE" || log_result "F-059" "User lifecycle status" "FAIL" "$CODE" "$(get_body "$RESP")"

# =============================================================================
# F-060: Parametric Roles
# Routes: /governance/roles, /governance/roles/:id/parameters, /governance/roles/:id/parametric-assignments
# =============================================================================
echo -e "${BLUE}--- F-060: Parametric Roles ---${NC}"

# Ensure an application exists for parametric role entitlement auto-creation
APP_RESP=$(api POST "/governance/applications" "{\"name\":\"DefaultApp_${STAMP}\",\"description\":\"Default app\"}")
APP_ID=$(jf "id" "$(get_body "$APP_RESP")")
if [ -z "$APP_ID" ]; then
    APPS_RESP=$(api GET "/governance/applications")
    APP_ID=$(echo "$(get_body "$APPS_RESP")" | python3 -c "import sys,json; d=json.load(sys.stdin); items=d if isinstance(d,list) else d.get('items',d.get('applications',[])); print(items[0]['id'] if items else '')" 2>/dev/null)
fi

RNAME="ProjMember_${STAMP}"
RESP=$(api POST "/governance/roles" "{\"name\":\"${RNAME}\",\"description\":\"Project member with params\",\"role_type\":\"business\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); ROLE_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-060" "Create role" "PASS" "$CODE" "ID=$ROLE_ID" || log_result "F-060" "Create role" "FAIL" "$CODE" "$BODY"

if [ -n "$ROLE_ID" ]; then
    RESP=$(api POST "/governance/roles/${ROLE_ID}/parameters" "{\"name\":\"project_id\",\"parameter_type\":\"string\",\"is_required\":true,\"description\":\"Project ID\"}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-060" "Add role parameter" "PASS" "$CODE" || log_result "F-060" "Add role parameter" "FAIL" "$CODE" "$BODY"
fi

RESP=$(api GET "/governance/roles"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-060" "List roles" "PASS" "$CODE" || log_result "F-060" "List roles" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$ROLE_ID" ]; then
    RESP=$(api GET "/governance/roles/${ROLE_ID}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-060" "Get role" "PASS" "$CODE" || log_result "F-060" "Get role" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api POST "/governance/roles/${ROLE_ID}/parametric-assignments" "{\"target_type\":\"user\",\"target_id\":\"${USER_ID}\",\"parameters\":[{\"parameter_name\":\"project_id\",\"value\":\"PROJ-001\"}]}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-060" "Assign role with params" "PASS" "$CODE" || log_result "F-060" "Assign role with params" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# =============================================================================
# F-061: Power of Attorney
# =============================================================================
echo -e "${BLUE}--- F-061: Power of Attorney ---${NC}"

STARTS_AT=$(python3 -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")
ENDS_AT=$(python3 -c "from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)+timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ'))")

RESP=$(api POST "/governance/power-of-attorney" "{\"attorney_id\":\"${DEPUTY_ID}\",\"starts_at\":\"${STARTS_AT}\",\"ends_at\":\"${ENDS_AT}\",\"reason\":\"Vacation\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); POA_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-061" "Grant PoA" "PASS" "$CODE" "ID=$POA_ID" || log_result "F-061" "Grant PoA" "FAIL" "$CODE" "$BODY"

RESP=$(api GET "/governance/power-of-attorney"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-061" "List PoA" "PASS" "$CODE" || log_result "F-061" "List PoA" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/power-of-attorney/current-assumption"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-061" "Current assumption" "PASS" "$CODE" || log_result "F-061" "Current assumption" "FAIL" "$CODE" "$(get_body "$RESP")"

# =============================================================================
# F-062: Self-Service Request Catalog
# Admin routes: /governance/admin/catalog/categories
# User routes: /governance/catalog/categories, /governance/catalog/items
# =============================================================================
echo -e "${BLUE}--- F-062: Self-Service Request Catalog ---${NC}"

CNAME="Engineering_${STAMP}"
RESP=$(api POST "/governance/admin/catalog/categories" "{\"name\":\"${CNAME}\",\"description\":\"Engineering resources\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); CAT_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-062" "Create category" "PASS" "$CODE" "ID=$CAT_ID" || log_result "F-062" "Create category" "FAIL" "$CODE" "$BODY"

RESP=$(api GET "/governance/catalog/categories"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-062" "List categories" "PASS" "$CODE" || log_result "F-062" "List categories" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$CAT_ID" ]; then
    INAME="VPN_${STAMP}"
    RESP=$(api POST "/governance/admin/catalog/items" "{\"name\":\"${INAME}\",\"description\":\"VPN access\",\"category_id\":\"${CAT_ID}\",\"item_type\":\"resource\",\"requestability_rules\":{\"self_request\":true,\"manager_request\":false}}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); ITEM_ID=$(jf "id" "$BODY")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-062" "Create catalog item" "PASS" "$CODE" "ID=$ITEM_ID" || log_result "F-062" "Create catalog item" "FAIL" "$CODE" "$BODY"
else
    log_result "F-062" "Create catalog item" "SKIP" "N/A" "No category ID"
fi

RESP=$(api GET "/governance/catalog/items"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-062" "Browse catalog" "PASS" "$CODE" || log_result "F-062" "Browse catalog" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$ITEM_ID" ]; then
    RESP=$(api POST "/governance/catalog/cart/items" "{\"catalog_item_id\":\"${ITEM_ID}\",\"justification\":\"Need VPN for remote access\"}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-062" "Add to cart" "PASS" "$CODE" || log_result "F-062" "Add to cart" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api POST "/governance/catalog/cart/submit" "{}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "201" ] && log_result "F-062" "Submit cart" "PASS" "$CODE" || log_result "F-062" "Submit cart" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    log_result "F-062" "Add to cart" "SKIP" "N/A" "No item"
    log_result "F-062" "Submit cart" "SKIP" "N/A" "No item"
fi

# =============================================================================
# F-063: Inducement / Construction
# Routes: /governance/roles/:id/constructions, /governance/roles/:id/inducements
# /governance/roles/:id/effective-constructions, /governance/users/:id/effective-constructions
# =============================================================================
echo -e "${BLUE}--- F-063: Inducement / Construction ---${NC}"

# Create connector in DB
CONN_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c "
    INSERT INTO connector_configurations (tenant_id, name, connector_type, config, credentials_encrypted, credentials_key_version, status)
    VALUES ('${TENANT_ID}', 'TestConn_${STAMP}', 'rest', '{}', E'\\\\x00', 1, 'active')
    ON CONFLICT DO NOTHING RETURNING id;" 2>/dev/null | head -1 | tr -d '[:space:]')

if [ -z "$CONN_ID" ]; then
    CONN_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c "SELECT id FROM connector_configurations WHERE tenant_id='${TENANT_ID}' LIMIT 1;" 2>/dev/null | head -1 | tr -d '[:space:]')
fi

if [ -n "$CONN_ID" ] && [ -n "$ROLE_ID" ]; then
    RESP=$(api POST "/governance/roles/${ROLE_ID}/constructions" "{\"connector_id\":\"${CONN_ID}\",\"object_class\":\"user\",\"account_type\":\"default\",\"attribute_mappings\":{\"mappings\":[],\"static_values\":{}}}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-063" "Create construction" "PASS" "$CODE" || log_result "F-063" "Create construction" "FAIL" "$CODE" "$BODY"
else
    log_result "F-063" "Create construction" "SKIP" "N/A" "No connector ($CONN_ID) or role ($ROLE_ID)"
fi

if [ -n "$ROLE_ID" ]; then
    RESP=$(api GET "/governance/roles/${ROLE_ID}/constructions"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "List constructions" "PASS" "$CODE" || log_result "F-063" "List constructions" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/effective-constructions"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "Effective constructions" "PASS" "$CODE" || log_result "F-063" "Effective constructions" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/inducements"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "List inducements" "PASS" "$CODE" || log_result "F-063" "List inducements" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/governance/roles/${ROLE_ID}/induced-roles"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-063" "Induced roles" "PASS" "$CODE" || log_result "F-063" "Induced roles" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    log_result "F-063" "List constructions" "SKIP" "N/A" "No role"
    log_result "F-063" "Effective constructions" "SKIP" "N/A" "No role"
    log_result "F-063" "List inducements" "SKIP" "N/A" "No role"
    log_result "F-063" "Induced roles" "SKIP" "N/A" "No role"
fi

# =============================================================================
# F-064: Bulk Action Engine
# Routes: /governance/admin/bulk-actions
# =============================================================================
echo -e "${BLUE}--- F-064: Bulk Action Engine ---${NC}"

RESP=$(api POST "/governance/admin/bulk-actions" "{\"filter_expression\":\"is_active = true\",\"action_type\":\"disable\",\"action_params\":{},\"justification\":\"Quarterly review: disabling inactive accounts for compliance\"}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); BULK_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-064" "Create bulk action" "PASS" "$CODE" "ID=$BULK_ID" || log_result "F-064" "Create bulk action" "FAIL" "$CODE" "$BODY"

RESP=$(api GET "/governance/admin/bulk-actions"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-064" "List bulk actions" "PASS" "$CODE" || log_result "F-064" "List bulk actions" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$BULK_ID" ]; then
    RESP=$(api GET "/governance/admin/bulk-actions/${BULK_ID}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-064" "Get bulk action" "PASS" "$CODE" || log_result "F-064" "Get bulk action" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api POST "/governance/admin/bulk-actions/${BULK_ID}/preview" "{}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-064" "Preview bulk action" "PASS" "$CODE" || log_result "F-064" "Preview bulk action" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

RESP=$(api POST "/governance/admin/bulk-actions/validate-expression" "{\"expression\":\"is_active = true\",\"target_type\":\"user\"}"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-064" "Validate expression" "PASS" "$CODE" || log_result "F-064" "Validate expression" "FAIL" "$CODE" "$(get_body "$RESP")"

# =============================================================================
# F-065: Identity Correlation
# =============================================================================
echo -e "${BLUE}--- F-065: Identity Correlation ---${NC}"

RESP=$(api GET "/governance/correlation/cases"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-065" "List correlation cases" "PASS" "$CODE" || log_result "F-065" "List correlation cases" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/correlation/audit"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-065" "Correlation audit" "PASS" "$CODE" || log_result "F-065" "Correlation audit" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$CONN_ID" ]; then
    RESP=$(api GET "/governance/connectors/${CONN_ID}/correlation/statistics"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-065" "Correlation stats" "PASS" "$CODE" || log_result "F-065" "Correlation stats" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    log_result "F-065" "Correlation stats" "SKIP" "N/A" "No connector"
fi

# =============================================================================
# F-066: Organization-Level Security Policies
# Routes: /organizations/:org_id/security-policies
# =============================================================================
echo -e "${BLUE}--- F-066: Organization Security Policies ---${NC}"

ORG_ID=$(docker exec xavyo-postgres psql -U xavyo -d xavyo_test -t -A -c "
    INSERT INTO groups (tenant_id, display_name, description, group_type)
    VALUES ('${TENANT_ID}', 'TestOrg_${STAMP}', 'Test org', 'organizational_unit')
    ON CONFLICT DO NOTHING RETURNING id;" 2>/dev/null | head -1 | tr -d '[:space:]')

if [ -n "$ORG_ID" ]; then
    echo -e "${GREEN}  Org created: ${ORG_ID}${NC}"

    # Create password policy for org
    RESP=$(api POST "/organizations/${ORG_ID}/security-policies" "{\"policy_type\":\"password\",\"config\":{\"min_length\":12,\"require_uppercase\":true,\"require_lowercase\":true,\"require_digit\":true},\"is_active\":true}")
    CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP")
    [ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-066" "Create org policy" "PASS" "$CODE" || log_result "F-066" "Create org policy" "FAIL" "$CODE" "$BODY"

    RESP=$(api GET "/organizations/${ORG_ID}/security-policies"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "List org policies" "PASS" "$CODE" || log_result "F-066" "List org policies" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/organizations/${ORG_ID}/effective-policy/password"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Effective policy (org)" "PASS" "$CODE" || log_result "F-066" "Effective policy (org)" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api GET "/users/${USER_ID}/effective-policy/password"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Effective policy (user)" "PASS" "$CODE" || log_result "F-066" "Effective policy (user)" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api POST "/organizations/${ORG_ID}/security-policies/validate" "{\"policy_type\":\"password\",\"config\":{\"min_length\":12},\"is_active\":true}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-066" "Validate conflicts" "PASS" "$CODE" || log_result "F-066" "Validate conflicts" "FAIL" "$CODE" "$(get_body "$RESP")"
else
    echo -e "${RED}  Could not create org${NC}"
    log_result "F-066" "Create org policy" "SKIP" "N/A" "No org"
    log_result "F-066" "List org policies" "SKIP" "N/A" "No org"
    log_result "F-066" "Effective policy (org)" "SKIP" "N/A" "No org"
    log_result "F-066" "Effective policy (user)" "SKIP" "N/A" "No org"
    log_result "F-066" "Validate conflicts" "SKIP" "N/A" "No org"
fi

# =============================================================================
# F-067: GDPR / Data Protection Metadata
# =============================================================================
echo -e "${BLUE}--- F-067: GDPR / Data Protection ---${NC}"

APP_RESP=$(api POST "/governance/applications" "{\"name\":\"App_${STAMP}\",\"description\":\"Test app\"}")
APP_ID=$(jf "id" "$(get_body "$APP_RESP")")
if [ -z "$APP_ID" ]; then
    APPS_RESP=$(api GET "/governance/applications")
    APP_ID=$(echo "$(get_body "$APPS_RESP")" | python3 -c "import sys,json; d=json.load(sys.stdin); items=d if isinstance(d,list) else d.get('items',d.get('applications',[])); print(items[0]['id'] if items else '')" 2>/dev/null)
fi

ENAME="cust_read_${STAMP}"
if [ -n "$APP_ID" ]; then
    RESP=$(api POST "/governance/entitlements" "{\"name\":\"${ENAME}\",\"description\":\"Read customer data\",\"application_id\":\"${APP_ID}\",\"risk_level\":\"high\",\"data_protection_classification\":\"personal\",\"legal_basis\":\"consent\",\"retention_period_days\":365}")
else
    RESP=$(api POST "/governance/entitlements" "{\"name\":\"${ENAME}\",\"description\":\"Read customer data\",\"risk_level\":\"high\",\"data_protection_classification\":\"personal\",\"legal_basis\":\"consent\",\"retention_period_days\":365}")
fi
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); ENT_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-067" "Create entitlement w/GDPR" "PASS" "$CODE" "ID=$ENT_ID" || log_result "F-067" "Create entitlement w/GDPR" "FAIL" "$CODE" "$BODY"

RESP=$(api GET "/governance/entitlements?data_protection_classification=personal"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "Filter by classification" "PASS" "$CODE" || log_result "F-067" "Filter by classification" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/gdpr/report"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "GDPR tenant report" "PASS" "$CODE" || log_result "F-067" "GDPR tenant report" "FAIL" "$CODE" "$(get_body "$RESP")"

RESP=$(api GET "/governance/gdpr/users/${USER_ID}/data-protection"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-067" "User data protection" "PASS" "$CODE" || log_result "F-067" "User data protection" "FAIL" "$CODE" "$(get_body "$RESP")"

# =============================================================================
# F-068: Object Templates
# Routes: /governance/object-templates
# =============================================================================
echo -e "${BLUE}--- F-068: Object Templates ---${NC}"

TNAME="DefUser_${STAMP}"
RESP=$(api POST "/governance/object-templates" "{\"name\":\"${TNAME}\",\"description\":\"Default user template\",\"object_type\":\"user\",\"rules\":[{\"rule_type\":\"default\",\"target_attribute\":\"department\",\"expression\":\"Engineering\"}]}")
CODE=$(get_code "$RESP"); BODY=$(get_body "$RESP"); TPL_ID=$(jf "id" "$BODY")
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] && log_result "F-068" "Create template" "PASS" "$CODE" "ID=$TPL_ID" || log_result "F-068" "Create template" "FAIL" "$CODE" "$BODY"

RESP=$(api GET "/governance/object-templates"); CODE=$(get_code "$RESP")
[ "$CODE" = "200" ] && log_result "F-068" "List templates" "PASS" "$CODE" || log_result "F-068" "List templates" "FAIL" "$CODE" "$(get_body "$RESP")"

if [ -n "$TPL_ID" ]; then
    RESP=$(api GET "/governance/object-templates/${TPL_ID}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-068" "Get template" "PASS" "$CODE" || log_result "F-068" "Get template" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api PUT "/governance/object-templates/${TPL_ID}" "{\"name\":\"${TNAME}\",\"description\":\"Updated\",\"object_type\":\"user\"}")
    CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] && log_result "F-068" "Update template" "PASS" "$CODE" || log_result "F-068" "Update template" "FAIL" "$CODE" "$(get_body "$RESP")"

    RESP=$(api DELETE "/governance/object-templates/${TPL_ID}"); CODE=$(get_code "$RESP")
    [ "$CODE" = "200" ] || [ "$CODE" = "204" ] && log_result "F-068" "Delete template" "PASS" "$CODE" || log_result "F-068" "Delete template" "FAIL" "$CODE" "$(get_body "$RESP")"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  Results Summary${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo -e "  Total:   ${TOTAL_COUNT}"
echo -e "  ${GREEN}Passed:  ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed:  ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${NC}"
RATE=0; [ "$TOTAL_COUNT" -gt 0 ] && RATE=$(python3 -c "print(f'{100*${PASS_COUNT}/${TOTAL_COUNT}:.1f}')")
echo -e "  Rate:    ${RATE}%"
echo ""

cat >> "$RESULTS_FILE" << EOF

---

## Summary

- **Total Tests:** ${TOTAL_COUNT}
- **Passed:** ${PASS_COUNT}
- **Failed:** ${FAIL_COUNT}
- **Skipped:** ${SKIP_COUNT}
- **Pass Rate:** ${RATE}%

## Date
$(date -u +'%Y-%m-%d %H:%M:%S UTC')
EOF

echo -e "${GREEN}Results: ${RESULTS_FILE}${NC}"
