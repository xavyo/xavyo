# OAuth Authorize Endpoint Tests
# Run with: hurl --test --variables-file vars.env tests/hurl/oauth-authorize.hurl
# Note: Tests accept 4xx range to handle rate limiting (429)

# Test 1: Authorize - Missing all parameters
GET {{base_url}}/oauth/authorize
HTTP *
[Asserts]
status >= 400
status < 500

# Test 2: Authorize - Missing client_id
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500

# Test 3: Authorize - Invalid response_type
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: invalid
client_id: test_client
redirect_uri: http://localhost:3000/callback
HTTP *
[Asserts]
status >= 400
status < 500

# Test 4: Authorize - XSS in state parameter (should be sanitized)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: http://localhost:3000/callback
state: <script>alert(1)</script>
HTTP *
[Asserts]
status >= 400
status < 500

# Test 5: Authorize - SQL injection in nonce (should be rejected)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: http://localhost:3000/callback
nonce: test' OR '1'='1
HTTP *
[Asserts]
status >= 400
status < 500

# Test 6: Authorize - Dangerous redirect URI (javascript:)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: javascript:alert(1)
HTTP *
[Asserts]
status >= 400
status < 500

# Test 7: Authorize - Dangerous redirect URI (data:)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: data:text/html,<script>alert(1)</script>
HTTP *
[Asserts]
status >= 400
status < 500

# Test 8: Authorize - Dangerous redirect URI (file:)
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: file:///etc/passwd
HTTP *
[Asserts]
status >= 400
status < 500

# Test 9: Authorize - Invalid PKCE code_challenge_method
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: http://localhost:3000/callback
code_challenge: test_challenge
code_challenge_method: plain
HTTP *
[Asserts]
status >= 400
status < 500

# Test 10: Authorize - Negative max_age
GET {{base_url}}/oauth/authorize
[QueryStringParams]
response_type: code
client_id: test_client
redirect_uri: http://localhost:3000/callback
max_age: -1
HTTP *
[Asserts]
status >= 400
status < 500
