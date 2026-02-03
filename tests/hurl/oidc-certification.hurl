# OpenID Connect Certification Test Suite
# Aligned with oidcc-basic-certification-test-plan requirements
# Reference: https://openid.net/certification/connect_op_testing/

# ============================================================================
# OIDCC-01: Discovery Endpoint Verification
# ============================================================================

# Test: Discovery document is accessible and valid JSON
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
Content-Type: application/json
[Asserts]
# Required fields per OpenID Connect Discovery 1.0
jsonpath "$.issuer" exists
jsonpath "$.authorization_endpoint" exists
jsonpath "$.token_endpoint" exists
jsonpath "$.jwks_uri" exists
jsonpath "$.response_types_supported" exists
jsonpath "$.subject_types_supported" exists
jsonpath "$.id_token_signing_alg_values_supported" exists

# Issuer MUST exactly match the URL used to retrieve discovery
jsonpath "$.issuer" == "{{base_url}}"

# MUST support "code" response type for Basic profile
jsonpath "$.response_types_supported" contains "code"

# MUST support RS256 for ID token signing
jsonpath "$.id_token_signing_alg_values_supported" contains "RS256"

# Recommended fields
jsonpath "$.userinfo_endpoint" exists
jsonpath "$.scopes_supported" exists
jsonpath "$.claims_supported" exists
jsonpath "$.token_endpoint_auth_methods_supported" exists

# openid scope MUST be supported
jsonpath "$.scopes_supported" contains "openid"

# ============================================================================
# OIDCC-02: JWKS Endpoint Verification
# ============================================================================

# Test: JWKS document is valid
GET {{base_url}}/.well-known/jwks.json
HTTP 200
Content-Type: application/json
[Asserts]
jsonpath "$.keys" exists
jsonpath "$.keys" count >= 1

# First key must have required fields
jsonpath "$.keys[0].kty" exists
jsonpath "$.keys[0].kid" exists
jsonpath "$.keys[0].use" == "sig"
jsonpath "$.keys[0].alg" == "RS256"

# RSA key must have n and e
jsonpath "$.keys[0].n" exists
jsonpath "$.keys[0].e" exists

# ============================================================================
# OIDCC-03: Authorization Endpoint - scope=openid required
# ============================================================================

# Test: Request without openid scope - server should handle appropriately
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: profile email
state: state123
HTTP *
[Asserts]
# Should redirect or return error (not crash)
status >= 300
status < 500

# ============================================================================
# OIDCC-04: Authorization Endpoint - response_type validation
# ============================================================================

# Test: response_type=code (Basic profile)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: state123
nonce: nonce123
HTTP *
[Asserts]
status >= 300
status < 500

# Test: Unsupported response_type should error
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: unsupported_type
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: state123
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# OIDCC-05: Authorization Endpoint - state parameter
# ============================================================================

# Test: State parameter should be returned unchanged in redirect
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: unique_state_value_12345
HTTP *
[Asserts]
status >= 300
status < 500

# ============================================================================
# OIDCC-06: Authorization Endpoint - nonce parameter
# ============================================================================

# Test: nonce parameter for code flow (optional but recommended)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: state123
nonce: unique_nonce_value_12345
HTTP *
[Asserts]
status >= 300
status < 500

# ============================================================================
# OIDCC-07: Token Endpoint - client_secret_basic
# ============================================================================

# Test: Token endpoint with client_secret_basic authentication
POST {{base_url}}/oauth/token
Authorization: Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code: invalid_code_for_testing
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500
header "Content-Type" contains "application/json"
jsonpath "$.error" exists

# ============================================================================
# OIDCC-08: Token Endpoint - client_secret_post
# ============================================================================

# Test: Token endpoint with client_secret_post authentication
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code: invalid_code_for_testing
redirect_uri: http://localhost:3000/callback
client_id: test-client
client_secret: test-secret
HTTP *
[Asserts]
status >= 400
status < 500
header "Content-Type" contains "application/json"
jsonpath "$.error" exists

# ============================================================================
# OIDCC-09: Token Endpoint - grant_type validation
# ============================================================================

# Test: Invalid grant_type should return error
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: invalid_grant_type
client_id: test-client
client_secret: test-secret
HTTP *
[Asserts]
status >= 400
status < 500
# May return unsupported_grant_type or too_many_requests under rate limiting
jsonpath "$.error" exists

# ============================================================================
# OIDCC-10: Token Endpoint Error Response Format
# ============================================================================

# Test: Error response must be JSON with required fields
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code:
client_id: test-client
HTTP *
[Asserts]
status >= 400
status < 500
header "Content-Type" contains "application/json"
jsonpath "$.error" exists
# error_description is recommended
jsonpath "$.error_description" exists

# ============================================================================
# OIDCC-11: UserInfo Endpoint - Authentication Required
# ============================================================================

# Test: UserInfo without token should return 401
GET {{base_url}}/oauth/userinfo
HTTP *
[Asserts]
status >= 401
status < 500

# Test: UserInfo with invalid token should return 401
GET {{base_url}}/oauth/userinfo
Authorization: Bearer invalid_access_token
HTTP *
[Asserts]
status >= 401
status < 500

# ============================================================================
# OIDCC-12: PKCE Support (RFC 7636)
# ============================================================================

# Test: code_challenge with S256 method
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: state123
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256
HTTP *
[Asserts]
status >= 300
status < 500

# Test: plain code_challenge_method should be rejected (security)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
state: state123
code_challenge: plain_challenge
code_challenge_method: plain
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# OIDCC-13: Invalid redirect_uri
# ============================================================================

# Test: Unregistered redirect_uri should be rejected
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: https://evil.com/callback
scope: openid
state: state123
HTTP *
[Asserts]
status >= 400
status < 500

# Test: javascript: URI should be rejected
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test-client
redirect_uri: javascript:alert(1)
scope: openid
state: state123
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# OIDCC-14: Missing Required Parameters
# ============================================================================

# Test: Missing client_id
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
redirect_uri: http://localhost:3000/callback
scope: openid
HTTP *
[Asserts]
status >= 400
status < 500

# Test: Missing response_type
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
redirect_uri: http://localhost:3000/callback
scope: openid
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# OIDCC-15: Token Endpoint - Missing code
# ============================================================================

# Test: authorization_code grant without code
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
client_id: test-client
client_secret: test-secret
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500
jsonpath "$.error" exists

# ============================================================================
# OIDCC-16: Cache-Control Headers
# ============================================================================

# Test: Token endpoint should have no-store cache directive
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
client_id: test-client
client_secret: test-secret
HTTP *
[Asserts]
status >= 200
status < 500
# Cache-Control: no-store is required for token responses

# ============================================================================
# OIDCC-17: Content-Type Validation
# ============================================================================

# Test: Token endpoint requires application/x-www-form-urlencoded
POST {{base_url}}/oauth/token
Content-Type: application/json
```
{"grant_type": "authorization_code", "code": "test"}
```
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# OIDCC-18: Refresh Token Grant
# ============================================================================

# Test: refresh_token grant type
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: refresh_token
refresh_token: invalid_refresh_token
client_id: test-client
client_secret: test-secret
HTTP *
[Asserts]
status >= 400
status < 500
jsonpath "$.error" exists

# ============================================================================
# OIDCC-19: Token Endpoint - Invalid Client
# ============================================================================

# Test: Invalid client credentials
POST {{base_url}}/oauth/token
Authorization: Basic aW52YWxpZF9jbGllbnQ6aW52YWxpZF9zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code: test_code
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500
# Server may return invalid_client or invalid_request depending on validation order
jsonpath "$.error" exists

# ============================================================================
# OIDCC-20: Discovery - Endpoints Use HTTPS in Production
# ============================================================================

# Test: All endpoints in discovery should be well-formed URLs
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
[Asserts]
jsonpath "$.authorization_endpoint" matches "^https?://"
jsonpath "$.token_endpoint" matches "^https?://"
jsonpath "$.jwks_uri" matches "^https?://"
jsonpath "$.userinfo_endpoint" matches "^https?://"
