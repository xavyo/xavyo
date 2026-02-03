# Security Edge Case Tests
# Run with: hurl --test --variables-file vars.env tests/hurl/security.hurl

# ============================================
# PATH TRAVERSAL & INJECTION
# ============================================

# Test: Path Traversal Attempt
GET {{base_url}}/../../../etc/passwd
HTTP 401

# Test: Encoded Path Traversal
GET {{base_url}}/%2e%2e/%2e%2e/etc/passwd
HTTP 401

# Test: Null Byte Injection
GET {{base_url}}/oauth/token%00.json
HTTP 401

# Test: Double Slash Path (server may normalize or reject)
GET {{base_url}}//.well-known/openid-configuration
HTTP *
[Asserts]
# Server can either normalize (200) or reject (4xx)
status >= 200
status < 500

# ============================================
# HEADER INJECTION
# ============================================

# Test: OIDC Discovery with extra headers (should work normally)
GET {{base_url}}/.well-known/openid-configuration
X-Custom-Header: test-value
HTTP 200

# ============================================
# LARGE PAYLOAD PROTECTION
# ============================================

# Test: Large client_id (protection against overflow)
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
client_id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
client_secret: test
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================
# UNICODE & ENCODING
# ============================================

# Test: Unicode in Path
GET {{base_url}}/öauth/token
HTTP 401

# Test: Emoji in Parameter (should be rejected gracefully)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test🔑client
redirect_uri: http://localhost
HTTP *
[Asserts]
status >= 400
status < 500

# ============================================
# PROTOCOL TESTS
# ============================================

# Test: Accept-Encoding gzip
GET {{base_url}}/.well-known/openid-configuration
Accept-Encoding: gzip
HTTP 200

# Test: If-None-Match header
GET {{base_url}}/.well-known/openid-configuration
If-None-Match: "invalid-etag"
HTTP 200

# Test: Range header
GET {{base_url}}/.well-known/openid-configuration
Range: bytes=0-100
HTTP 200
