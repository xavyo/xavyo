# IdP-Initiated SSO Functional Tests

**API Endpoint**: `POST /saml/initiate/:sp_id`
**Authentication**: Requires authenticated user with valid JWT (Bearer token)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <token>`, tenant context
**Applicable Standards**: SAML 2.0 Profiles (section 4.1.5 - Unsolicited Response), SAML 2.0 Core, NIST SP 800-63C, OWASP ASVS 3.7

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`
- **Special Setup**: SP must be registered with valid ACS URL; tenant must have an active IdP signing certificate for assertion signing tests

---

## Nominal Cases

### TC-SAML-IDP-001: Successful IdP-initiated SSO with valid SP ID
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1.5 (Unsolicited Response)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
  - Tenant `T1` exists with active IdP signing certificate
  - Service Provider `SP1` registered with `id=<sp_uuid>`, entity_id `https://sp.example.com/saml/metadata`, ACS URL `https://sp.example.com/saml/acs`, enabled=true
  - User `U1` authenticated with valid JWT for tenant `T1`
- **Input**:
  ```json
  POST /saml/initiate/<sp_uuid>
  Authorization: Bearer <jwt_token>
  X-Tenant-ID: <T1_uuid>
  Content-Type: application/json

  {
    "relay_state": "https://sp.example.com/dashboard"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: text/html
  Body: HTML auto-submit form containing:
    - <form method="POST" action="https://sp.example.com/saml/acs">
    - <input type="hidden" name="SAMLResponse" value="<base64 encoded SAML Response>"/>
    - <input type="hidden" name="RelayState" value="https://sp.example.com/dashboard"/>
  ```
- **SAML Response Validation** (decode base64):
  - `<samlp:Response>` with `Version="2.0"`, no `InResponseTo` attribute (unsolicited)
  - `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>`
  - `<saml:Issuer>` matches IdP entity ID
  - `<saml:Assertion>` with valid Subject, Conditions, AuthnStatement
- **Side Effects**: Audit log entry for IdP-initiated SSO event

### TC-SAML-IDP-002: IdP-initiated SSO without relay_state
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. Same as TC-SAML-IDP-001
- **Input**:
  ```json
  POST /saml/initiate/<sp_uuid>
  Authorization: Bearer <jwt_token>

  {
    "relay_state": null
  }
  ```
- **Expected Output**: Status 200, HTML form does NOT contain a `RelayState` hidden input

### TC-SAML-IDP-003: IdP-initiated SSO with empty request body
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. Same as TC-SAML-IDP-001
- **Input**:
  ```json
  POST /saml/initiate/<sp_uuid>
  Authorization: Bearer <jwt_token>

  {}
  ```
- **Expected Output**: Status 200, relay_state defaults to None, HTML form has no RelayState input

### TC-SAML-IDP-004: IdP-initiated SSO Response has no InResponseTo
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. Standard SP, authenticated user
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: Decoded SAML Response:
  - `<samlp:Response>` element does NOT have `InResponseTo` attribute
  - `<saml:SubjectConfirmationData>` does NOT have `InResponseTo` attribute
- **Verification**: Unsolicited responses must not reference a request ID

### TC-SAML-IDP-005: IdP-initiated SSO with signed assertion
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP configured with `sign_assertions=true`, tenant has active certificate
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: Decoded SAML Response `<saml:Assertion>` contains `<ds:Signature>` with:
  - Valid RSA-SHA256 signature over the Assertion
  - `<ds:X509Certificate>` element with the IdP certificate
  - Enveloped signature transform applied
- **Verification**: Signature validates against IdP public key

### TC-SAML-IDP-006: IdP-initiated SSO with unsigned assertion
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP configured with `sign_assertions=false`
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: Decoded SAML Response does not contain `<ds:Signature>` element

### TC-SAML-IDP-007: IdP-initiated SSO includes user groups in attributes
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP with `include_groups=true`, user is member of groups `["engineering", "admin"]`
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: SAML Response `<saml:AttributeStatement>` contains group attribute with two `<saml:AttributeValue>` entries: `engineering` and `admin`

### TC-SAML-IDP-008: IdP-initiated SSO omits empty groups attribute
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP with `include_groups=true`, `omit_empty_groups=true`, user has no group memberships
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: SAML Response `<saml:AttributeStatement>` does NOT contain a groups attribute
- **Verification**: When user has no groups and omit_empty_groups is true, groups attribute is absent

### TC-SAML-IDP-009: IdP-initiated SSO with group value format "name"
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP configured with `group_value_format="name"`, user in group with display_name `Engineering Team`
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: Group attribute values contain group display names (e.g., `Engineering Team`)

### TC-SAML-IDP-010: IdP-initiated SSO with NameID format persistent
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 8.3.7
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP configured with `name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"`
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**: `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` contains the user's UUID

---

## Edge Cases

### TC-SAML-IDP-011: SP ID does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /saml/initiate/00000000-0000-0000-0000-000000000099
  Authorization: Bearer <jwt_token>
  {}
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "sp_not_found",
    "message": "Service Provider not found: 00000000-0000-0000-0000-000000000099"
  }
  ```

### TC-SAML-IDP-012: SP ID is not a valid UUID
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```
  POST /saml/initiate/not-a-uuid
  Authorization: Bearer <jwt_token>
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  ```

### TC-SAML-IDP-013: SP is disabled
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP registered with `enabled=false`
- **Input**: Valid IdP-initiated SSO request with disabled SP's ID
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "disabled_sp",
    "message": "Service Provider is disabled: <entity_id>"
  }
  ```

### TC-SAML-IDP-014: SP has no ACS URLs configured
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP registered with empty `acs_urls=[]` (would require direct DB manipulation)
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**:
  ```
  Status: 500 Internal Server Error
  Body: {
    "error": "assertion_generation_failed",
    "message": "Assertion generation failed",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Responder"
  }
  ```

### TC-SAML-IDP-015: No active IdP signing certificate
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. Tenant has no active certificate in `tenant_idp_certificates`
- **Input**: Valid IdP-initiated SSO request
- **Expected Output**:
  ```
  Status: 500 Internal Server Error
  Body: {
    "error": "no_active_certificate",
    "message": "No active IdP signing certificate for tenant",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Responder"
  }
  ```

### TC-SAML-IDP-016: Concurrent IdP-initiated SSO requests for same user and SP
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. Standard SP, authenticated user
- **Input**: Two simultaneous `POST /saml/initiate/<sp_uuid>` requests
- **Expected Output**: Both return Status 200 with valid but distinct SAML Responses (unique Response IDs and Assertion IDs)

### TC-SAML-IDP-017: IdP-initiated SSO uses first ACS URL from SP configuration
- **Category**: Edge Case
- **Standard**: SAML 2.0 Profiles 4.1.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP registered with `acs_urls=["https://sp.example.com/acs-primary", "https://sp.example.com/acs-secondary"]`
- **Input**: Valid IdP-initiated SSO request (no ACS URL override possible in IdP-initiated)
- **Expected Output**: HTML form action is `https://sp.example.com/acs-primary` (first registered URL)

### TC-SAML-IDP-018: Very long relay_state value
- **Category**: Edge Case
- **Standard**: SAML 2.0 Bindings 3.4.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**:
  ```json
  { "relay_state": "<1000-character string>" }
  ```
- **Expected Output**: Status 200, full relay_state passed through in HTML form
- **Note**: SAML spec recommends <= 80 bytes but does not mandate; implementation passes through

### TC-SAML-IDP-019: relay_state with special HTML characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**:
  ```json
  { "relay_state": "state&param=value<tag>\"quoted'" }
  ```
- **Expected Output**: Status 200, relay_state is HTML-escaped in the form:
  ```html
  <input type="hidden" name="RelayState" value="state&amp;param=value&lt;tag&gt;&quot;quoted&#x27;"/>
  ```

---

## Security Cases

### TC-SAML-IDP-020: Unauthenticated user attempting IdP-initiated SSO
- **Category**: Security
- **Standard**: SAML 2.0 Profiles 4.1.5
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Input**:
  ```
  POST /saml/initiate/<sp_uuid>
  (No Authorization header)
  {}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: {
    "error": "not_authenticated",
    "message": "User not authenticated",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
  }
  ```
- **Verification**: No SAML Response is generated

### TC-SAML-IDP-021: Cross-tenant SP access attempt
- **Category**: Security
- **Standard**: Tenant Isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SP registered under tenant `T1`, user authenticated under tenant `T2`
- **Input**: `POST /saml/initiate/<T1_sp_uuid>` with T2's tenant context
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "sp_not_found", "message": "Service Provider not found: <sp_uuid>" }
  ```
- **Verification**: SP lookup includes `WHERE tenant_id = $2`; cross-tenant access is blocked

### TC-SAML-IDP-022: XSS in relay_state
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**:
  ```json
  { "relay_state": "<img src=x onerror=alert('xss')>" }
  ```
- **Expected Output**: Status 200, HTML form HTML-escapes the relay_state value
- **Verification**: Raw HTML/JS is not rendered; `<` becomes `&lt;`, `>` becomes `&gt;`

### TC-SAML-IDP-023: Expired JWT token
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Input**: `POST /saml/initiate/<sp_uuid>` with expired JWT in Authorization header
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
- **Verification**: Expired tokens do not produce SAML assertions

### TC-SAML-IDP-024: SAML Response Audience Restriction is correct
- **Category**: Security
- **Standard**: SAML 2.0 Core 2.5.1.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Valid IdP-initiated SSO request for SP with entity_id `https://sp.example.com/metadata`
- **Expected Output**: SAML Response contains:
  ```xml
  <saml:Conditions>
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com/metadata</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  ```
- **Verification**: Audience matches the target SP entity_id, preventing assertion reuse at other SPs

### TC-SAML-IDP-025: SAML Response SessionIndex is unique per SSO
- **Category**: Security
- **Standard**: SAML 2.0 Core 2.7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Two IdP-initiated SSO requests for the same user/SP
- **Expected Output**: Each SAML Response's `<saml:AuthnStatement SessionIndex="...">` has a different value
- **Verification**: SessionIndex values are UUID-based and unique

### TC-SAML-IDP-026: Error response does not leak internal details
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Request triggering database error (e.g., pool exhaustion)
- **Expected Output**: Error body contains `"message": "A database error occurred"` not the actual SQL error
- **Verification**: No stack traces, SQL queries, or connection strings in response

---

## Compliance Cases

### TC-SAML-IDP-027: Unsolicited Response conforms to SAML 2.0 structure
- **Category**: Compliance
- **Standard**: SAML 2.0 Profiles 4.1.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Valid IdP-initiated SSO
- **Expected Output**: Decoded SAML Response XML structure:
  ```xml
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_resp_<uuid>" Version="2.0" IssueInstant="<timestamp>"
      Destination="<acs_url>">
    <saml:Issuer>...</saml:Issuer>
    <samlp:Status>
      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assert_<uuid>" Version="2.0" IssueInstant="<timestamp>">
      <saml:Issuer>...</saml:Issuer>
      <saml:Subject>...</saml:Subject>
      <saml:Conditions>...</saml:Conditions>
      <saml:AuthnStatement>...</saml:AuthnStatement>
      <saml:AttributeStatement>...</saml:AttributeStatement>
    </saml:Assertion>
  </samlp:Response>
  ```

### TC-SAML-IDP-028: IdP-initiated SSO response uses PasswordProtectedTransport AuthnContext
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 2.7.2.2, NIST SP 800-63C
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Valid IdP-initiated SSO
- **Expected Output**: `<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>`
- **Verification**: AuthnContextClassRef accurately reflects the authentication method

### TC-SAML-IDP-029: SAML Response timestamps use UTC (Zulu time)
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 1.3.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Valid IdP-initiated SSO
- **Expected Output**: All timestamps in SAML Response end with `Z` (Zulu/UTC):
  - `IssueInstant` on Response and Assertion
  - `NotBefore` and `NotOnOrAfter` on Conditions
  - `AuthnInstant` on AuthnStatement

### TC-SAML-IDP-030: SAML assertion IDs conform to NCName format
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 1.3.4, XML Schema NCName
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Valid IdP-initiated SSO
- **Expected Output**: Response ID starts with `_resp_` and Assertion ID starts with `_assert_` (both begin with underscore, not a digit)
- **Verification**: IDs are valid NCName tokens per XML specification
