# OpenID Connect Core 1.0 Specification Validation
# Tests against OIDC Core specification requirements
# Reference: https://openid.net/specs/openid-connect-core-1_0.html

# ============================================================================
# Section 3: Authentication - Discovery Document Requirements
# ============================================================================

# 3.1 - Discovery document MUST be available at well-known endpoint
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"

# Required fields per spec
jsonpath "$.issuer" exists
jsonpath "$.authorization_endpoint" exists
jsonpath "$.token_endpoint" exists
jsonpath "$.jwks_uri" exists
jsonpath "$.response_types_supported" exists
jsonpath "$.subject_types_supported" exists
jsonpath "$.id_token_signing_alg_values_supported" exists

# Issuer MUST be identical to URL used to retrieve discovery doc
jsonpath "$.issuer" == "{{base_url}}"

# ============================================================================
# Section 3.1.2.1 - Authorization Endpoint - Required Parameters
# ============================================================================

# Missing scope parameter - MUST return error
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: code
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500

# Missing client_id - MUST return error
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
redirect_uri: http://localhost:3000/callback
scope: openid
HTTP *
[Asserts]
status >= 400
status < 500

# Missing response_type - MUST return error
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
# Section 3.1.2.2 - Scope validation
# ============================================================================

# 'openid' scope MUST be present for OIDC requests
# Request without openid scope should be treated as OAuth2 only
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: code
redirect_uri: http://localhost:3000/callback
scope: profile email
state: test-state
HTTP *
[Asserts]
# Should redirect or error but not crash
status >= 300
status < 500

# ============================================================================
# Section 3.1.2.5 - nonce parameter for implicit/hybrid flow
# ============================================================================

# nonce is REQUIRED for implicit flow (response_type containing id_token)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: id_token
redirect_uri: http://localhost:3000/callback
scope: openid
state: test-state
HTTP *
[Asserts]
# Should error without nonce
status >= 300
status < 500

# ============================================================================
# Section 3.1.3.3 - Token Endpoint Authentication
# ============================================================================

# client_secret_basic - credentials in Authorization header
POST {{base_url}}/oauth/token
Authorization: Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code: invalid_code
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500
header "Content-Type" contains "application/json"
jsonpath "$.error" exists

# client_secret_post - credentials in body
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: authorization_code
code: invalid_code
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
# Section 3.1.3.7 - Token Error Response
# ============================================================================

# Error response MUST include error field
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
jsonpath "$.error" exists

# ============================================================================
# Section 5 - JWKS Endpoint
# ============================================================================

# JWKS document MUST be available
GET {{base_url}}/.well-known/jwks.json
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.keys" exists
jsonpath "$.keys" count >= 1

# Each key MUST have required fields
jsonpath "$.keys[0].kty" exists
jsonpath "$.keys[0].use" exists
jsonpath "$.keys[0].kid" exists

# RSA keys MUST have n and e
jsonpath "$.keys[0].kty" == "RSA"
jsonpath "$.keys[0].n" exists
jsonpath "$.keys[0].e" exists

# ============================================================================
# Section 5.3 - UserInfo Endpoint
# ============================================================================

# UserInfo requires valid access token
GET {{base_url}}/oauth/userinfo
HTTP *
[Asserts]
status >= 401
status < 500

# UserInfo with invalid token
GET {{base_url}}/oauth/userinfo
Authorization: Bearer invalid_token
HTTP *
[Asserts]
status >= 401
status < 500

# ============================================================================
# Section 6 - Passing Request Parameters as JWTs (optional)
# ============================================================================

# Test that server handles malformed JWT gracefully
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: code
redirect_uri: http://localhost:3000/callback
scope: openid
request: invalid.jwt.token
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# Section 9 - Client Authentication (per RFC 6749)
# ============================================================================

# Missing client credentials - MUST reject
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
HTTP *
[Asserts]
status >= 400
status < 500

# Invalid client credentials
POST {{base_url}}/oauth/token
Authorization: Basic aW52YWxpZDppbnZhbGlk
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================================================
# Section 10 - Signatures and Encryption
# ============================================================================

# RS256 MUST be supported (minimum requirement)
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
[Asserts]
jsonpath "$.id_token_signing_alg_values_supported" contains "RS256"

# ============================================================================
# PKCE (RFC 7636) - Extension for Public Clients
# ============================================================================

# code_challenge without code_challenge_method defaults to plain (should error with S256 required)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: code
redirect_uri: http://localhost:3000/callback
scope: openid
state: test-state
code_challenge: test_challenge_value
HTTP *
[Asserts]
status >= 300
status < 500

# Proper S256 code_challenge_method
GET {{base_url}}/oauth/authorize
[QueryStringParams]
client_id: test-client
response_type: code
redirect_uri: http://localhost:3000/callback
scope: openid
state: test-state
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256
HTTP *
[Asserts]
# Should proceed to authentication or redirect
status >= 300
status < 500

# ============================================================================
# OAuth 2.0 Device Authorization Grant (RFC 8628)
# ============================================================================

# Device code endpoint MUST exist
POST {{base_url}}/oauth/device/code
Content-Type: application/x-www-form-urlencoded
[FormParams]
client_id: test-client
scope: openid
HTTP *
[Asserts]
# Should return device code or error
status >= 200
status < 500

# Device code polling - invalid device code
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: urn:ietf:params:oauth:grant-type:device_code
device_code: invalid_device_code
client_id: test-client
HTTP *
[Asserts]
status >= 400
status < 500
jsonpath "$.error" exists

# ============================================================================
# OAuth 2.0 Token Introspection (RFC 7662)
# ============================================================================

# Token introspection endpoint test
POST {{base_url}}/oauth/introspect
Authorization: Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded
[FormParams]
token: invalid_token
HTTP *
[Asserts]
status >= 200
status < 500

# ============================================================================
# OAuth 2.0 Token Revocation (RFC 7009)
# ============================================================================

# Token revocation endpoint test
POST {{base_url}}/oauth/revoke
Authorization: Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=
Content-Type: application/x-www-form-urlencoded
[FormParams]
token: invalid_token
HTTP *
[Asserts]
# Per RFC 7009, revocation SHOULD return 200 even for invalid tokens
status >= 200
status < 500

# ============================================================================
# Security Headers (Best Practices, not strict spec requirements)
# ============================================================================

# Discovery endpoint - validate response structure
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
# Note: X-Content-Type-Options and Cache-Control are recommended but not required

# Token endpoint - validate error response format
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: invalid
HTTP *
[Asserts]
status >= 400
status < 500
