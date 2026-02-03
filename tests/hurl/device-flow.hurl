# OAuth Device Flow Tests
# Run with: hurl --test --variables-file vars.env tests/hurl/device-flow.hurl
# Note: Tests accept 4xx range to handle rate limiting (429)

# Test 1: Device Code - Missing client_id
POST {{base_url}}/oauth/device/code
Content-Type: application/x-www-form-urlencoded
``
HTTP *
[Asserts]
status >= 400
status < 500

# Test 2: Device Code - Invalid scope
POST {{base_url}}/oauth/device/code
Content-Type: application/x-www-form-urlencoded
[FormParams]
client_id: test_client
scope: invalid_scope_that_does_not_exist
HTTP *
[Asserts]
status >= 400
status < 500

# Test 3: Device Token Poll - Missing device_code
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: urn:ietf:params:oauth:grant-type:device_code
client_id: test_client
HTTP *
[Asserts]
status >= 400
status < 500

# Test 4: Device Token Poll - Invalid device_code
POST {{base_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded
[FormParams]
grant_type: urn:ietf:params:oauth:grant-type:device_code
client_id: test_client
device_code: invalid_device_code_12345
HTTP *
[Asserts]
status >= 400
status < 500
