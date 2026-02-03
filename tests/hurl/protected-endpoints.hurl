# Protected Endpoint Tests - Authentication Required
# Run with: hurl --test --variables-file vars.env tests/hurl/protected-endpoints.hurl
# These tests verify that protected endpoints require authentication
# Note: bypass-tunnel-reminder header is for localtunnel compatibility

# ============================================
# GOVERNANCE ENDPOINTS (F-004 to F-007)
# ============================================

# Test: Entitlements - Requires Auth
GET {{base_url}}/governance/entitlements
bypass-tunnel-reminder: true
HTTP 401

# Test: Applications - Requires Auth
GET {{base_url}}/governance/applications
bypass-tunnel-reminder: true
HTTP 401

# Test: SoD Rules - Requires Auth
GET {{base_url}}/governance/sod-rules
bypass-tunnel-reminder: true
HTTP 401

# Test: Risk Scores - Requires Auth
GET {{base_url}}/governance/risk-scores
bypass-tunnel-reminder: true
HTTP 401

# Test: Assignments - Requires Auth
GET {{base_url}}/governance/assignments
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# USER MANAGEMENT (F-034, F-035)
# ============================================

# Test: Users List - Requires Auth
GET {{base_url}}/admin/users
bypass-tunnel-reminder: true
HTTP 401

# Test: Groups List - Requires Auth
GET {{base_url}}/admin/groups
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# AUTHORIZATION (F-018 to F-020)
# ============================================

# Test: Authorization Policies - Requires Auth
GET {{base_url}}/admin/authorization/policies
bypass-tunnel-reminder: true
HTTP 401

# Test: Authorization Check - Requires Auth
GET {{base_url}}/admin/authorization/check
bypass-tunnel-reminder: true
HTTP 401

# Test: Bulk Check - Requires Auth
POST {{base_url}}/admin/authorization/bulk-check
bypass-tunnel-reminder: true
Content-Type: application/json
{"requests": []}
HTTP 401

# ============================================
# SCIM (F-036, F-037)
# ============================================

# Test: SCIM Users - Requires Auth
GET {{base_url}}/scim/v2/Users
bypass-tunnel-reminder: true
HTTP 401

# Test: SCIM Groups - Requires Auth
GET {{base_url}}/scim/v2/Groups
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# SAML (F-038 to F-040)
# ============================================

# Test: SAML Service Providers - Requires Auth
GET {{base_url}}/admin/saml/service-providers
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# SOCIAL LOGIN (F-041, F-042)
# ============================================

# Test: Social Providers Config - Requires Auth
GET {{base_url}}/admin/social-providers
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# CONNECTORS (F-043, F-044)
# ============================================

# Test: Connectors List - Requires Auth
GET {{base_url}}/connectors
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# FEDERATION (F-045, F-046)
# ============================================

# Test: Federation IdPs - Requires Auth
GET {{base_url}}/admin/federation/identity-providers
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# NHI (F-047, F-048)
# ============================================

# Test: Service Accounts - Requires Auth
GET {{base_url}}/nhi/service-accounts
bypass-tunnel-reminder: true
HTTP 401

# ============================================
# WEBHOOKS (F-028, F-029)
# ============================================

# Test: Webhooks List - Requires Auth
GET {{base_url}}/admin/webhooks
bypass-tunnel-reminder: true
HTTP 401
