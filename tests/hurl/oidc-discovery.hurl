# OIDC Discovery Endpoint Tests
# Run with: hurl --test --variables-file vars.env tests/hurl/oidc-discovery.hurl

# Test 1: OIDC Discovery - Valid Request
GET {{base_url}}/.well-known/openid-configuration
HTTP 200
Content-Type: application/json
[Asserts]
jsonpath "$.issuer" == "{{base_url}}"
jsonpath "$.authorization_endpoint" exists
jsonpath "$.token_endpoint" exists
jsonpath "$.userinfo_endpoint" exists
jsonpath "$.jwks_uri" exists
jsonpath "$.grant_types_supported" count >= 3
jsonpath "$.response_types_supported" contains "code"
jsonpath "$.scopes_supported" contains "openid"
jsonpath "$.id_token_signing_alg_values_supported" contains "RS256"
jsonpath "$.code_challenge_methods_supported" contains "S256"
duration < 5000

# Test 2: JWKS Endpoint - Valid Request
GET {{base_url}}/.well-known/jwks.json
HTTP 200
Content-Type: application/json
[Asserts]
jsonpath "$.keys" count >= 1
jsonpath "$.keys[0].kty" == "RSA"
jsonpath "$.keys[0].alg" == "RS256"
jsonpath "$.keys[0].use" == "sig"
jsonpath "$.keys[0].kid" exists
jsonpath "$.keys[0].n" exists
jsonpath "$.keys[0].e" exists
duration < 5000

# Test 3: JWKS - POST Method Not Allowed
POST {{base_url}}/.well-known/jwks.json
HTTP 405

# Test 4: JWKS - DELETE Method Not Allowed
DELETE {{base_url}}/.well-known/jwks.json
HTTP 405

# Test 5: OIDC Discovery - HEAD Request
HEAD {{base_url}}/.well-known/openid-configuration
HTTP 200

# Test 6: OIDC Discovery - OPTIONS (CORS)
OPTIONS {{base_url}}/.well-known/openid-configuration
HTTP 200
