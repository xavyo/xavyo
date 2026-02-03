# OAuth Token Endpoint Tests
# Run with: hurl --test --variables-file vars.env tests/hurl/oauth-token.hurl
# Note: Tests accept 4xx range to handle rate limiting (429)

# Test 1: Token - Missing grant_type (empty body)
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
``
HTTP *
[Asserts]
status >= 400
status < 500

# Test 2: Token - Invalid grant_type
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: invalid_grant
HTTP *
[Asserts]
status >= 400
status < 500

# Test 3: Token - Missing client_id for client_credentials
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
HTTP *
[Asserts]
status >= 400
status < 500

# Test 4: Token - Invalid credentials
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: client_credentials
client_id: invalid_client
client_secret: invalid_secret
HTTP *
[Asserts]
status >= 400
status < 500

# Test 5: Token - Wrong Content-Type (JSON instead of form)
POST {{base_url}}/oauth/token
Content-Type: application/json
{"grant_type": "client_credentials", "client_id": "test"}
HTTP *
[Asserts]
status >= 400
status < 500

# Test 6: Token - XML Content-Type Not Supported
POST {{base_url}}/oauth/token
Content-Type: application/xml
<grant_type>client_credentials</grant_type>
HTTP *
[Asserts]
status >= 400
status < 500

# Test 7: Refresh Token - Invalid token
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: refresh_token
refresh_token: invalid_refresh_token
client_id: test
HTTP *
[Asserts]
status >= 400
status < 500

# Test 8: Refresh Token - Empty token
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: refresh_token
refresh_token:
client_id: test
HTTP *
[Asserts]
status >= 400
status < 500
