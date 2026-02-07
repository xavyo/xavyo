# SP-Initiated SSO Functional Tests

**API Endpoints**:
- `GET /saml/sso` (HTTP-Redirect binding)
- `POST /saml/sso` (HTTP-POST binding)

**Authentication**: Requires authenticated user session (via JWT or session cookie)
**Required Headers**: Tenant context via `X-Tenant-ID` header or subdomain routing
**Applicable Standards**: SAML 2.0 Core (OASIS, sections 3.4, 3.5), SAML 2.0 Bindings (sections 3.4, 3.5), SAML 2.0 Profiles (section 4.1), NIST SP 800-63C (Federation Assurance), OWASP ASVS 3.7

---

## Nominal Cases

### TC-SAML-SSO-001: SP-initiated SSO via HTTP-Redirect binding with valid AuthnRequest
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1.2 (SP-Initiated SSO)
- **Preconditions**:
  - Tenant `T1` exists with active IdP signing certificate
  - Service Provider `SP1` registered with entity_id `https://sp.example.com/saml/metadata`, ACS URL `https://sp.example.com/saml/acs`, enabled=true
  - User `U1` authenticated with valid JWT for tenant `T1`
- **Input**:
  ```
  GET /saml/sso?SAMLRequest=<deflate+base64 encoded AuthnRequest>&RelayState=https%3A%2F%2Fsp.example.com%2Fdashboard
  Authorization: Bearer <jwt_token>
  X-Tenant-ID: <T1_uuid>
  ```
  Where the AuthnRequest XML is:
  ```xml
  <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="_abc123"
      Version="2.0"
      IssueInstant="2026-02-07T12:00:00Z"
      AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
      ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
      <saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>
  </samlp:AuthnRequest>
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
- **SAML Response Validation** (decode base64 SAMLResponse):
  - Root element is `<samlp:Response>` with `Version="2.0"`
  - Contains `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
  - Contains `InResponseTo="_abc123"` matching the AuthnRequest ID
  - `Destination` matches ACS URL
  - `<saml:Issuer>` matches IdP entity ID
  - Contains `<saml:Assertion>` with valid conditions and subject
- **Side Effects**:
  - Audit log entry for SAML SSO event

### TC-SAML-SSO-002: SP-initiated SSO via HTTP-POST binding with valid AuthnRequest
- **Category**: Nominal
- **Standard**: SAML 2.0 Bindings 3.5 (HTTP-POST)
- **Preconditions**: Same as TC-SAML-SSO-001
- **Input**:
  ```
  POST /saml/sso
  Content-Type: application/x-www-form-urlencoded
  Authorization: Bearer <jwt_token>
  X-Tenant-ID: <T1_uuid>

  SAMLRequest=<base64 encoded AuthnRequest>&RelayState=https%3A%2F%2Fsp.example.com%2Fdashboard
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: text/html
  Body: HTML auto-submit form (same structure as TC-SAML-SSO-001)
  ```
- **SAML Response Validation**: Same as TC-SAML-SSO-001

### TC-SAML-SSO-003: SSO with NameID format emailAddress
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 8.3 (Name Identifier Format Identifiers)
- **Preconditions**: SP configured with name_id_format `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- **Input**: Valid AuthnRequest with `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>`
- **Expected Output**: SAML Response where `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>`
- **Verification**: NameID value equals the authenticated user's email address

### TC-SAML-SSO-004: SSO with NameID format persistent
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 8.3.7
- **Preconditions**: SP configured with name_id_format `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- **Input**: Valid AuthnRequest
- **Expected Output**: SAML Response where `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"><user_uuid></saml:NameID>`
- **Verification**: NameID value equals the user's UUID and remains consistent across logins

### TC-SAML-SSO-005: SSO with default attribute mapping
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 2.7.3 (Attribute Statement)
- **Preconditions**: SP has no custom attribute_mapping (empty `{}`)
- **Input**: Valid AuthnRequest from authenticated user with email `test@example.com`
- **Expected Output**: SAML Response contains `<saml:AttributeStatement>` with:
  - `<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">` with value `test@example.com`
  - `<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">` with value derived from email
- **Verification**: Default attributes are populated from user record

### TC-SAML-SSO-006: SSO with custom attribute mapping
- **Category**: Nominal
- **Preconditions**: SP configured with custom attribute_mapping:
  ```json
  {
    "name_id_source": "email",
    "attributes": [
      {"source": "email", "target_name": "mail", "target_friendly_name": "Email"},
      {"source": "user_id", "target_name": "uid", "target_friendly_name": "UserID"},
      {"source": "groups", "target_name": "memberOf", "multi_value": true}
    ]
  }
  ```
- **Input**: Valid AuthnRequest from user in groups `["admin", "users"]`
- **Expected Output**: SAML Response `<saml:AttributeStatement>` contains:
  - `<saml:Attribute Name="mail">` with email value
  - `<saml:Attribute Name="uid">` with user_id value
  - `<saml:Attribute Name="memberOf">` with two `<saml:AttributeValue>` elements

### TC-SAML-SSO-007: SSO with RelayState preserved
- **Category**: Nominal
- **Standard**: SAML 2.0 Bindings 3.4.3
- **Preconditions**: Standard SP setup
- **Input**: AuthnRequest with `RelayState=https%3A%2F%2Fsp.example.com%2Fdeep%2Flink`
- **Expected Output**: HTML form includes `<input type="hidden" name="RelayState" value="https://sp.example.com/deep/link"/>`
- **Verification**: RelayState is passed through unmodified to the auto-submit form

### TC-SAML-SSO-008: SSO without RelayState
- **Category**: Nominal
- **Preconditions**: Standard SP setup
- **Input**: AuthnRequest without RelayState parameter
- **Expected Output**: HTML form does NOT contain a RelayState hidden input
- **Verification**: Absence of RelayState input in the form

### TC-SAML-SSO-009: SSO with signed assertions enabled
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 5.4 (XML Signature Profile)
- **Preconditions**: SP configured with `sign_assertions=true`, IdP has active signing certificate
- **Input**: Valid AuthnRequest
- **Expected Output**: Decoded SAML Response contains `<ds:Signature>` element within `<saml:Assertion>`:
  - `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`
  - `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`
  - `<ds:Reference URI="#<assertion_id>">` with enveloped-signature transform
  - `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`
  - `<ds:X509Certificate>` with IdP certificate
- **Verification**: Signature validates using IdP's public key

### TC-SAML-SSO-010: SSO with unsigned assertions
- **Category**: Nominal
- **Preconditions**: SP configured with `sign_assertions=false`
- **Input**: Valid AuthnRequest
- **Expected Output**: Decoded SAML Response does NOT contain `<ds:Signature>` element
- **Verification**: No signature present in the Response or Assertion

### TC-SAML-SSO-011: SSO preserves InResponseTo in SubjectConfirmationData
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 2.4.1.2
- **Preconditions**: Standard SP setup
- **Input**: AuthnRequest with `ID="_request_abc_123"`
- **Expected Output**: SAML Response contains:
  - `<samlp:Response ... InResponseTo="_request_abc_123">`
  - `<saml:SubjectConfirmationData ... InResponseTo="_request_abc_123" Recipient="https://sp.example.com/saml/acs"/>`
- **Verification**: InResponseTo matches the original AuthnRequest ID in both locations

---

## Edge Cases

### TC-SAML-SSO-012: AuthnRequest without AssertionConsumerServiceURL
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.4.1 (ACS URL optional in AuthnRequest)
- **Preconditions**: SP registered with ACS URLs `["https://sp.example.com/saml/acs"]`
- **Input**: AuthnRequest XML without `AssertionConsumerServiceURL` attribute
- **Expected Output**: Status 200, form action uses the first configured ACS URL from SP registration
- **Verification**: `<form method="POST" action="https://sp.example.com/saml/acs">`

### TC-SAML-SSO-013: AuthnRequest with ACS URL matching one of multiple registered URLs
- **Category**: Edge Case
- **Preconditions**: SP registered with ACS URLs `["https://sp.example.com/saml/acs", "https://sp.example.com/saml/acs-alt"]`
- **Input**: AuthnRequest with `AssertionConsumerServiceURL="https://sp.example.com/saml/acs-alt"`
- **Expected Output**: Status 200, form action uses the requested ACS URL `https://sp.example.com/saml/acs-alt`

### TC-SAML-SSO-014: AuthnRequest with ACS URL not matching any registered URL
- **Category**: Edge Case
- **Standard**: SAML 2.0 Profiles 4.1.4.1
- **Preconditions**: SP registered with ACS URLs `["https://sp.example.com/saml/acs"]`
- **Input**: AuthnRequest with `AssertionConsumerServiceURL="https://evil.example.com/steal"`
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "acs_url_mismatch",
    "message": "ACS URL does not match any registered URL",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-015: AuthnRequest from unknown/unregistered SP entity ID
- **Category**: Edge Case
- **Preconditions**: No SP registered with entity_id `https://unknown-sp.example.com`
- **Input**: AuthnRequest with `<saml:Issuer>https://unknown-sp.example.com</saml:Issuer>`
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "unknown_sp",
    "message": "Unknown Service Provider: https://unknown-sp.example.com"
  }
  ```

### TC-SAML-SSO-016: AuthnRequest from disabled SP
- **Category**: Edge Case
- **Preconditions**: SP registered with `enabled=false`
- **Input**: Valid AuthnRequest from disabled SP
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "disabled_sp",
    "message": "Service Provider is disabled: <entity_id>"
  }
  ```

### TC-SAML-SSO-017: AuthnRequest with ForceAuthn=true
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.4.1 (ForceAuthn attribute)
- **Preconditions**: Standard SP, user already authenticated
- **Input**: AuthnRequest with `ForceAuthn="true"`
- **Expected Output**: Status 200 (SSO completes since user is authenticated). The `force_authn` field is parsed from the request. If re-authentication enforcement is implemented, user is prompted to re-authenticate.

### TC-SAML-SSO-018: AuthnRequest with IsPassive=true and unauthenticated user
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.4.1 (IsPassive attribute)
- **Preconditions**: No authenticated user session
- **Input**: AuthnRequest with `IsPassive="true"` and no JWT token
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: {
    "error": "not_authenticated",
    "message": "User not authenticated",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
  }
  ```
- **Note**: With IsPassive, the IdP must not interact with the user; since user is not authenticated, SSO fails

### TC-SAML-SSO-019: AuthnRequest with empty Issuer
- **Category**: Edge Case
- **Input**: AuthnRequest XML with `<saml:Issuer></saml:Issuer>` (empty element)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "invalid_request",
    "message": "Invalid SAML authentication request",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-020: AuthnRequest missing ID attribute
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.2.1 (ID is required)
- **Input**: AuthnRequest XML without `ID` attribute
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "invalid_request",
    "message": "Invalid SAML authentication request",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-021: AuthnRequest with very long RelayState (> 80 bytes)
- **Category**: Edge Case
- **Standard**: SAML 2.0 Bindings 3.4.3 (RelayState SHOULD be <= 80 bytes)
- **Input**: AuthnRequest with RelayState of 500 characters
- **Expected Output**: Status 200 (RelayState length enforcement is SHOULD, not MUST). RelayState is passed through.
- **Verification**: HTML form contains the full RelayState value

### TC-SAML-SSO-022: Malformed base64 in SAMLRequest (HTTP-POST)
- **Category**: Edge Case
- **Input**:
  ```
  POST /saml/sso
  SAMLRequest=not-valid-base64!!!&RelayState=state
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "invalid_request",
    "message": "Invalid SAML authentication request",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-023: Malformed deflate data in SAMLRequest (HTTP-Redirect)
- **Category**: Edge Case
- **Input**: `GET /saml/sso?SAMLRequest=<valid base64 but invalid deflate data>`
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "invalid_request",
    "message": "Invalid SAML authentication request",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-024: AuthnRequest with unsupported SAML Version
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.2.1
- **Input**: AuthnRequest with `Version="1.1"`
- **Expected Output**: Status 200 or 400 depending on version check enforcement. If no explicit check, the parser processes it normally.
- **Note**: The current parser does not enforce Version="2.0" validation; test documents this behavior

### TC-SAML-SSO-025: SSO when no IdP signing certificate is active
- **Category**: Edge Case
- **Preconditions**: Tenant has no active certificate, SP has `sign_assertions=true`
- **Input**: Valid AuthnRequest
- **Expected Output**:
  ```
  Status: 500 Internal Server Error
  Body: {
    "error": "no_active_certificate",
    "message": "No active IdP signing certificate for tenant",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Responder"
  }
  ```

### TC-SAML-SSO-026: AuthnRequest with NameIDPolicy requesting unsupported format
- **Category**: Edge Case
- **Standard**: SAML 2.0 Core 3.4.1.1
- **Input**: AuthnRequest with `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"/>`
- **Expected Output**: Status 200 (defaults to SP's configured name_id_format) or Status 400 if strict format enforcement is applied.
- **Note**: Current implementation falls back to email for unrecognized formats

---

## Security Cases

### TC-SAML-SSO-027: Unauthenticated user attempting SSO
- **Category**: Security
- **Standard**: SAML 2.0 Profiles 4.1.3 (Authentication Required)
- **Input**: Valid AuthnRequest with no Authorization header / no user session
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: {
    "error": "not_authenticated",
    "message": "User not authenticated",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
  }
  ```
- **Verification**: No SAML Response is generated for unauthenticated users

### TC-SAML-SSO-028: Cross-tenant SSO attempt
- **Category**: Security
- **Standard**: Tenant Isolation
- **Preconditions**: SP registered under tenant `T1`, user authenticated under tenant `T2`
- **Input**: AuthnRequest referencing SP entity_id registered to `T1`, but request sent with tenant context `T2`
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "unknown_sp", "message": "Unknown Service Provider: <entity_id>" }
  ```
- **Verification**: SP lookup is scoped by tenant_id; T2 cannot access T1's SPs

### TC-SAML-SSO-029: Signature validation required but no SP certificate configured
- **Category**: Security
- **Preconditions**: SP configured with `validate_signatures=true`, `certificate=null`
- **Input**: Valid AuthnRequest (unsigned)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "signature_validation_failed",
    "message": "Signature validation failed",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-030: Signature validation required, SP cert configured, but AuthnRequest unsigned (Redirect)
- **Category**: Security
- **Preconditions**: SP with `validate_signatures=true` and valid certificate
- **Input**: HTTP-Redirect AuthnRequest without `SigAlg` and `Signature` query parameters
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "signature_validation_failed",
    "message": "Signature validation failed",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-031: AuthnRequest with tampered signature (Redirect binding)
- **Category**: Security
- **Standard**: SAML 2.0 Bindings 3.4.4.1 (Redirect Signature Verification)
- **Preconditions**: SP with `validate_signatures=true` and valid certificate
- **Input**: HTTP-Redirect with valid `SigAlg` and `Signature` but modified `SAMLRequest` content after signing
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "signature_validation_failed",
    "message": "Signature validation failed",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SSO-032: XSS in RelayState value
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Input**: AuthnRequest with `RelayState=<script>alert('xss')</script>`
- **Expected Output**: Status 200, but the HTML auto-submit form HTML-escapes the RelayState:
  ```html
  <input type="hidden" name="RelayState" value="&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"/>
  ```
- **Verification**: No unescaped HTML/JS in the form output

### TC-SAML-SSO-033: XSS in ACS URL via AuthnRequest
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Preconditions**: SP registered with ACS URL containing the malicious value (should not happen in practice)
- **Input**: AuthnRequest with `AssertionConsumerServiceURL` containing JS injection
- **Expected Output**: ACS URL mismatch error (400) since it won't match registered URLs. If somehow registered, the HTML form HTML-escapes the `action` attribute.

### TC-SAML-SSO-034: Error responses do not leak internal details
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Input**: Various malformed requests triggering database or internal errors
- **Expected Output**: Error messages contain sanitized text:
  - Database errors return "A database error occurred" (not SQL/connection details)
  - Internal errors return "An internal error occurred" (not stack traces)
  - Private key errors return "A private key error occurred" (not key material)
- **Verification**: Response body never contains stack traces, file paths, SQL queries, or key material

### TC-SAML-SSO-035: SAML Response Conditions contain proper time bounds
- **Category**: Security
- **Standard**: SAML 2.0 Core 2.5.1 (Conditions)
- **Preconditions**: SP with `assertion_validity_seconds=300`
- **Input**: Valid AuthnRequest
- **Expected Output**: SAML Response `<saml:Conditions>` element contains:
  - `NotBefore` = approximately (now - 2 minutes) for clock skew tolerance
  - `NotOnOrAfter` = approximately (now + 300 seconds)
  - `<saml:AudienceRestriction><saml:Audience>` = SP entity_id
- **Verification**: Time window is bounded and includes audience restriction

### TC-SAML-SSO-036: SAML decompression bomb protection (HTTP-Redirect)
- **Category**: Security
- **Standard**: OWASP XML Security
- **Input**: SAMLRequest containing deflated data that expands to > 1 MB
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_request", "message": "Invalid SAML authentication request" }
  ```
- **Verification**: Server does not exhaust memory; DeflateDecoder has `take()` limit

---

## Compliance Cases

### TC-SAML-SSO-037: SAML Response Version is 2.0
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 3.2.2
- **Input**: Valid AuthnRequest
- **Expected Output**: Decoded SAML Response contains `Version="2.0"` on both `<samlp:Response>` and `<saml:Assertion>` elements

### TC-SAML-SSO-038: SAML Response contains proper namespace declarations
- **Category**: Compliance
- **Standard**: SAML 2.0 Core
- **Input**: Valid AuthnRequest
- **Expected Output**: Decoded SAML Response includes:
  - `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` on Response element
  - `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` on Assertion element

### TC-SAML-SSO-039: SAML Assertion Subject Confirmation Method is bearer
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 2.4.1.4 (Bearer)
- **Input**: Valid AuthnRequest
- **Expected Output**: `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`
- **Verification**: SubjectConfirmationData includes NotOnOrAfter and Recipient

### TC-SAML-SSO-040: SAML AuthnStatement contains AuthnContextClassRef
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 2.7.2.2
- **Input**: Valid AuthnRequest
- **Expected Output**: `<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>`

### TC-SAML-SSO-041: SAML Response IDs are unique and properly formatted
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 1.3.4 (ID Values)
- **Input**: Two successive valid AuthnRequests
- **Expected Output**: Each SAML Response has unique `ID` attributes (prefixed with `_resp_`) and each Assertion has unique `ID` attributes (prefixed with `_assert_`). IDs must not start with a digit per XML NCName specification.

### TC-SAML-SSO-042: NIST SP 800-63C federation assurance level
- **Category**: Compliance
- **Standard**: NIST SP 800-63C Section 5
- **Input**: Valid SP-initiated SSO flow
- **Verification**:
  - Assertions are signed (when configured) using RSA-SHA256
  - Subject includes NameID with format appropriate to assurance level
  - Audience restriction limits assertion to intended SP
  - Time bounds prevent assertion reuse
  - AuthnContextClassRef reflects actual authentication method

### TC-SAML-SSO-043: XML Signature uses Exclusive Canonicalization (C14N)
- **Category**: Compliance
- **Standard**: XML Signature (W3C), SAML 2.0 Core 5.4.1
- **Input**: Valid AuthnRequest with sign_assertions=true
- **Expected Output**: Signature uses:
  - `CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`
  - `Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"` (enveloped)
  - `Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"` (Exclusive C14N)
