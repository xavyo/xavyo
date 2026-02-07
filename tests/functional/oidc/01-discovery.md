# OIDC Discovery Functional Tests

**API Endpoints**:
- `GET /.well-known/openid-configuration` -- OpenID Provider Configuration
- `GET /.well-known/jwks.json` -- JSON Web Key Set

**Authentication**: Public (no JWT required)
**Applicable Standards**: OpenID Connect Discovery 1.0, RFC 7517 (JWK), RFC 8414 (OAuth 2.0 Authorization Server Metadata)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `TEST_TENANT`
- **Special Setup**: None -- discovery endpoints are public

---

## Nominal Cases

### TC-OIDC-DISC-001: Successful retrieval of OpenID Configuration document
- **Category**: Nominal
- **Standard**: OpenID Connect Discovery 1.0, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. Server is running with a configured issuer URL
- **Input**:
  ```
  GET /.well-known/openid-configuration
  Accept: application/json
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/json
  Body: {
    "issuer": "https://idp.xavyo.com",
    "authorization_endpoint": "https://idp.xavyo.com/oauth/authorize",
    "token_endpoint": "https://idp.xavyo.com/oauth/token",
    "userinfo_endpoint": "https://idp.xavyo.com/oauth/userinfo",
    "jwks_uri": "https://idp.xavyo.com/.well-known/jwks.json",
    "response_types_supported": ["code"],
    "grant_types_supported": [
      "authorization_code",
      "client_credentials",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code"
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email", "offline_access"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "code_challenge_methods_supported": ["S256"],
    "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name", "given_name", "family_name"]
  }
  ```

### TC-OIDC-DISC-002: Issuer matches the request origin
- **Category**: Nominal
- **Standard**: OpenID Connect Discovery 1.0, Section 4.3
- **Preconditions**: Fixtures: `TEST_TENANT`. Server configured with issuer `https://idp.xavyo.com`
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `issuer` field value exactly matches the configured server issuer URL
  - No trailing slash on the issuer value
  - All endpoint URLs are prefixed with the issuer value

### TC-OIDC-DISC-003: JWKS endpoint returns valid JSON Web Key Set
- **Category**: Nominal
- **Standard**: RFC 7517, Section 5
- **Preconditions**: Fixtures: `TEST_TENANT`. Server has at least one configured RSA signing key
- **Input**:
  ```
  GET /.well-known/jwks.json
  Accept: application/json
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/json
  Body: {
    "keys": [
      {
        "kty": "RSA",
        "kid": "<key-id>",
        "use": "sig",
        "alg": "RS256",
        "n": "<base64url-encoded-modulus>",
        "e": "<base64url-encoded-exponent>"
      }
    ]
  }
  ```

### TC-OIDC-DISC-004: JWKS contains multiple keys during key rotation
- **Category**: Nominal
- **Standard**: RFC 7517, Section 5 (key rotation)
- **Preconditions**: Fixtures: `TEST_TENANT`. Server configured with multiple signing keys (active + rotated) via F069-S5
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**:
  - `keys` array contains more than one JWK
  - Each key has a distinct `kid` value
  - All keys have `kty: "RSA"`, `use: "sig"`, `alg: "RS256"`
  - Both active and rotated keys are present for token verification during rotation window

### TC-OIDC-DISC-005: Discovery document includes device_authorization_endpoint
- **Category**: Nominal
- **Standard**: RFC 8628, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. Device code flow is enabled
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `device_authorization_endpoint` is present and equals `{issuer}/oauth/device/code`
  - `grant_types_supported` contains `"urn:ietf:params:oauth:grant-type:device_code"`

### TC-OIDC-DISC-006: Discovery document declares PKCE S256 support
- **Category**: Nominal
- **Standard**: RFC 7636, Section 4.2
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `code_challenge_methods_supported` contains `"S256"`
  - `"plain"` is NOT in `code_challenge_methods_supported` (S256 only for security)

### TC-OIDC-DISC-007: JWK modulus and exponent are valid base64url
- **Category**: Nominal
- **Standard**: RFC 7518, Section 6.3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. At least one signing key configured
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**:
  - Each key's `n` value is valid base64url (no padding `=`, uses `-` and `_`)
  - Each key's `e` value is valid base64url (typically `AQAB` for exponent 65537)
  - Decoded `n` produces a valid RSA modulus of at least 2048 bits

### TC-OIDC-DISC-008: Discovery response is cacheable
- **Category**: Nominal
- **Standard**: OpenID Connect Discovery 1.0, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - Response does not include `Cache-Control: no-store` for the discovery document itself
  - Response body is identical across repeated requests (stable configuration)
  - Content-Type is `application/json`

---

## Edge Cases

### TC-OIDC-DISC-010: Discovery with Accept header specifying XML
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  Accept: application/xml
  ```
- **Expected Output**:
  - Server returns JSON response (Content-Type: application/json) regardless of Accept header
  - Status: 200 OK
- **Rationale**: OIDC Discovery only mandates JSON; server ignores non-JSON Accept

### TC-OIDC-DISC-011: POST request to discovery endpoint
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /.well-known/openid-configuration
  ```
- **Expected Output**:
  ```
  Status: 405 Method Not Allowed
  ```
- **Rationale**: Discovery endpoint only supports GET

### TC-OIDC-DISC-012: POST request to JWKS endpoint
- **Category**: Edge Case
- **Standard**: RFC 7517, Section 5
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /.well-known/jwks.json
  ```
- **Expected Output**:
  ```
  Status: 405 Method Not Allowed
  ```

### TC-OIDC-DISC-013: JWKS endpoint with no configured signing keys
- **Category**: Edge Case
- **Standard**: RFC 7517, Section 5
- **Preconditions**: Fixtures: `TEST_TENANT`. Server started with empty signing key configuration (signing_keys is empty and public_key PEM is invalid/empty)
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "keys": [] }
  ```
- **Rationale**: Implementation logs error but returns empty JWKS rather than failing

### TC-OIDC-DISC-014: Discovery with query parameters (ignored)
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 4
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration?extra=param&foo=bar
  ```
- **Expected Output**:
  - Status: 200 OK
  - Query parameters are silently ignored
  - Response body is identical to the no-query-parameter request

### TC-OIDC-DISC-015: Large number of concurrent discovery requests
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**: 100 concurrent `GET /.well-known/openid-configuration` requests
- **Expected Output**:
  - All requests return 200 OK
  - All responses contain identical JSON
  - No 5xx errors or timeouts

### TC-OIDC-DISC-016: JWKS URI in discovery matches actual JWKS endpoint
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  1. `GET /.well-known/openid-configuration` -- extract `jwks_uri`
  2. `GET {extracted_jwks_uri}`
- **Expected Output**:
  - The URL from step 1 resolves successfully in step 2
  - Step 2 returns a valid JWK Set with at least one key

### TC-OIDC-DISC-017: All endpoint URLs in discovery are absolute
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `authorization_endpoint` starts with `https://`
  - `token_endpoint` starts with `https://`
  - `userinfo_endpoint` starts with `https://`
  - `jwks_uri` starts with `https://`
  - `device_authorization_endpoint` starts with `https://` (when present)
- **Note**: In localhost/development mode, `http://localhost` prefix is acceptable

### TC-OIDC-DISC-018: Discovery document fields are non-empty arrays where required
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `response_types_supported` has at least one entry
  - `subject_types_supported` has at least one entry
  - `id_token_signing_alg_values_supported` has at least one entry
  - `scopes_supported` contains `"openid"` at minimum
  - `claims_supported` has at least `sub` claim

### TC-OIDC-DISC-019: JWKS keys have unique kid values
- **Category**: Edge Case
- **Standard**: RFC 7517, Section 4.5
- **Preconditions**: Fixtures: `TEST_TENANT`. Multiple signing keys configured
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**:
  - All `kid` values in the `keys` array are unique
  - No two keys share the same `kid`

---

## Security Cases

### TC-OIDC-DISC-020: Discovery endpoint does not leak internal server details
- **Category**: Security
- **Standard**: OWASP ASVS 14.3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - No `Server` header revealing framework/version
  - No `X-Powered-By` header
  - No internal IP addresses or hostnames in endpoint URLs
  - Endpoint URLs use the configured public issuer, not internal addresses

### TC-OIDC-DISC-021: JWKS does not expose private key material
- **Category**: Security
- **Standard**: RFC 7517, Section 4 / OWASP Cryptographic Failures
- **Preconditions**: Fixtures: `TEST_TENANT`. Signing keys configured
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**:
  - No `d` (private exponent) field in any key
  - No `p`, `q`, `dp`, `dq`, `qi` (CRT parameters) in any key
  - Only public key components (`n`, `e`) are present
  - `use` is `"sig"` (not `"enc"`)

### TC-OIDC-DISC-022: Discovery endpoint returns security headers
- **Category**: Security
- **Standard**: OWASP ASVS 14.4
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - Response includes `Cache-Control: no-store, no-cache, must-revalidate, private` (from security headers middleware)
  - Response includes `X-Content-Type-Options: nosniff`
  - No `Access-Control-Allow-Origin: *` (CORS should be restricted)

### TC-OIDC-DISC-023: JWKS endpoint resistant to timing attacks
- **Category**: Security
- **Standard**: Cryptographic best practices
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**: Multiple rapid requests to `GET /.well-known/jwks.json`
- **Expected Output**:
  - Response time is consistent regardless of key state
  - No timing differences that could reveal key rotation status
  - Key ID is a random/opaque string (not sequential or predictable)

### TC-OIDC-DISC-024: Discovery endpoint does not support CORS wildcard
- **Category**: Security
- **Standard**: OWASP ASVS 14.5
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  Origin: https://evil.example.com
  ```
- **Expected Output**:
  - Response does NOT include `Access-Control-Allow-Origin: *`
  - If CORS headers are present, they must specify allowed origins explicitly

---

## Compliance Cases

### TC-OIDC-DISC-030: Required fields per OIDC Discovery 1.0 Section 3
- **Category**: Compliance
- **Standard**: OpenID Connect Discovery 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**: All REQUIRED fields are present:
  - `issuer` (REQUIRED)
  - `authorization_endpoint` (REQUIRED)
  - `token_endpoint` (REQUIRED unless only implicit flow)
  - `jwks_uri` (REQUIRED)
  - `response_types_supported` (REQUIRED)
  - `subject_types_supported` (REQUIRED)
  - `id_token_signing_alg_values_supported` (REQUIRED)

### TC-OIDC-DISC-031: Issuer URL uses HTTPS scheme
- **Category**: Compliance
- **Standard**: OpenID Connect Discovery 1.0, Section 3 / RFC 8414, Section 2
- **Preconditions**: Fixtures: `TEST_TENANT`. Production deployment
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `issuer` value uses the `https` scheme
  - `issuer` contains no query or fragment components
  - All endpoint URLs use the `https` scheme

### TC-OIDC-DISC-032: Issuer value contains no trailing slash
- **Category**: Compliance
- **Standard**: OpenID Connect Discovery 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `issuer` value does NOT end with `/`
  - Issuer exactly matches what was configured (no normalization artifacts)

### TC-OIDC-DISC-033: scopes_supported includes openid
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 3.1.2.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `scopes_supported` array includes `"openid"`
  - `"openid"` scope is mandatory for OIDC compliance

### TC-OIDC-DISC-034: response_types_supported includes code
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `response_types_supported` includes `"code"` (Authorization Code Flow)
  - Does NOT include `"token"` alone (Implicit Flow) for security

### TC-OIDC-DISC-035: subject_types_supported includes public
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 8
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `subject_types_supported` includes `"public"`
  - Subject identifiers are globally unique within the issuer

### TC-OIDC-DISC-036: id_token_signing_alg includes RS256
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `id_token_signing_alg_values_supported` includes `"RS256"`
  - Does NOT include `"none"` (unsigned tokens are prohibited)

### TC-OIDC-DISC-037: claims_supported includes mandatory OIDC claims
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 5.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `claims_supported` includes `"sub"` (REQUIRED)
  - `claims_supported` includes `"iss"`, `"aud"`, `"exp"`, `"iat"`
  - `claims_supported` includes `"email"`, `"email_verified"` (email scope)
  - `claims_supported` includes `"name"` (profile scope)

### TC-OIDC-DISC-038: token_endpoint_auth_methods_supported values are valid
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 9
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /.well-known/openid-configuration
  ```
- **Expected Output**:
  - `token_endpoint_auth_methods_supported` includes `"client_secret_basic"` (HTTP Basic)
  - `token_endpoint_auth_methods_supported` includes `"client_secret_post"` (form body)
  - All listed values are from the IANA registry (no custom/invalid values)

### TC-OIDC-DISC-039: JWK Set conforms to RFC 7517 structure
- **Category**: Compliance
- **Standard**: RFC 7517, Sections 4 and 5
- **Preconditions**: Fixtures: `TEST_TENANT`. At least one signing key configured
- **Input**:
  ```
  GET /.well-known/jwks.json
  ```
- **Expected Output**: Each key in the `keys` array has:
  - `kty` (REQUIRED) -- value is `"RSA"`
  - `kid` (REQUIRED for rotation) -- non-empty string identifier
  - `use` (RECOMMENDED) -- value is `"sig"`
  - `alg` (RECOMMENDED) -- value is `"RS256"`
  - `n` (REQUIRED for RSA) -- base64url-encoded RSA modulus
  - `e` (REQUIRED for RSA) -- base64url-encoded RSA public exponent
  - No fields with `null` values

---

## Cross-Reference Matrix

| Test Case | Standard Section | Category | HTTP Method | Endpoint |
|-----------|-----------------|----------|-------------|----------|
| DISC-001 | Discovery 1.0 S4 | Nominal | GET | openid-configuration |
| DISC-002 | Discovery 1.0 S4.3 | Nominal | GET | openid-configuration |
| DISC-003 | RFC 7517 S5 | Nominal | GET | jwks.json |
| DISC-004 | RFC 7517 S5 | Nominal | GET | jwks.json |
| DISC-005 | RFC 8628 S4 | Nominal | GET | openid-configuration |
| DISC-006 | RFC 7636 S4.2 | Nominal | GET | openid-configuration |
| DISC-007 | RFC 7518 S6.3.1 | Nominal | GET | jwks.json |
| DISC-008 | Discovery 1.0 S4 | Nominal | GET | openid-configuration |
| DISC-010 | Discovery 1.0 S4 | Edge | GET | openid-configuration |
| DISC-011 | Discovery 1.0 S4 | Edge | POST | openid-configuration |
| DISC-012 | RFC 7517 S5 | Edge | POST | jwks.json |
| DISC-013 | RFC 7517 S5 | Edge | GET | jwks.json |
| DISC-014 | Discovery 1.0 S4 | Edge | GET | openid-configuration |
| DISC-015 | Operational | Edge | GET | openid-configuration |
| DISC-016 | Discovery 1.0 S3 | Edge | GET | both |
| DISC-017 | Discovery 1.0 S3 | Edge | GET | openid-configuration |
| DISC-018 | Discovery 1.0 S3 | Edge | GET | openid-configuration |
| DISC-019 | RFC 7517 S4.5 | Edge | GET | jwks.json |
| DISC-020 | OWASP ASVS 14.3 | Security | GET | openid-configuration |
| DISC-021 | RFC 7517 S4 | Security | GET | jwks.json |
| DISC-022 | OWASP ASVS 14.4 | Security | GET | openid-configuration |
| DISC-023 | Crypto best practice | Security | GET | jwks.json |
| DISC-024 | OWASP ASVS 14.5 | Security | GET | openid-configuration |
| DISC-030 | Discovery 1.0 S3 | Compliance | GET | openid-configuration |
| DISC-031 | Discovery 1.0 S3 | Compliance | GET | openid-configuration |
| DISC-032 | Discovery 1.0 S3 | Compliance | GET | openid-configuration |
| DISC-033 | Core 1.0 S3.1.2.1 | Compliance | GET | openid-configuration |
| DISC-034 | Core 1.0 S3 | Compliance | GET | openid-configuration |
| DISC-035 | Core 1.0 S8 | Compliance | GET | openid-configuration |
| DISC-036 | Core 1.0 S3.1.3.7 | Compliance | GET | openid-configuration |
| DISC-037 | Core 1.0 S5.1 | Compliance | GET | openid-configuration |
| DISC-038 | Core 1.0 S9 | Compliance | GET | openid-configuration |
| DISC-039 | RFC 7517 S4,5 | Compliance | GET | jwks.json |
