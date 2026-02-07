# SAML Certificate Management Functional Tests

**API Endpoints**:
- `GET /admin/saml/certificates` - List IdP certificates
- `POST /admin/saml/certificates` - Upload new certificate
- `POST /admin/saml/certificates/:cert_id/activate` - Activate certificate

**Authentication**: Admin JWT required (Bearer token)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <token>`, tenant context
**Applicable Standards**: SAML 2.0 Metadata (Key Management), X.509 (RFC 5280), NIST SP 800-57 (Key Management), OWASP ASVS 6.2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Certificate upload and management requires admin-role JWT; valid PEM-encoded certificate and private key pairs needed for upload tests

---

## Nominal Cases

### TC-SAML-CERT-001: Upload a valid IdP certificate with private key
- **Category**: Nominal
- **Standard**: X.509 (RFC 5280)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin user authenticated for tenant `T1`
- **Input**:
  ```json
  POST /admin/saml/certificates
  Authorization: Bearer <admin_jwt>

  {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIC/zCCAeeg...<valid PEM>...\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...<valid PEM>...\n-----END PRIVATE KEY-----"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "key_id": "<sha256 thumbprint hex>",
    "subject_dn": "CN=test",
    "issuer_dn": "CN=test",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "is_active": true,
    "created_at": "<timestamp>"
  }
  ```
- **Side Effects**:
  - Row created in `tenant_idp_certificates`
  - Private key encrypted with AES-256-GCM and stored as `private_key_encrypted`
  - Certificate marked as active (`is_active=true`)
- **Verification**: Response does NOT contain `private_key` or `private_key_encrypted` fields

### TC-SAML-CERT-002: Upload certificate is automatically activated
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. No existing certificates for tenant
- **Input**: Valid certificate upload
- **Expected Output**: Status 201, `is_active: true`
- **Verification**: The newly uploaded certificate is immediately usable for signing assertions

### TC-SAML-CERT-003: List all certificates for tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has 3 certificates (one active, two inactive)
- **Input**:
  ```
  GET /admin/saml/certificates
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "items": [
      { "id": "<uuid1>", "key_id": "...", "is_active": true, "created_at": "<newest>" },
      { "id": "<uuid2>", "key_id": "...", "is_active": false, "created_at": "<middle>" },
      { "id": "<uuid3>", "key_id": "...", "is_active": false, "created_at": "<oldest>" }
    ]
  }
  ```
- **Verification**: Certificates ordered by `created_at DESC`; only public info returned

### TC-SAML-CERT-004: List certificates returns empty for new tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has no certificates
- **Input**: `GET /admin/saml/certificates`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [] }
  ```

### TC-SAML-CERT-005: Activate a specific certificate
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant has certificates `C1` (active) and `C2` (inactive)
- **Input**:
  ```
  POST /admin/saml/certificates/<C2_uuid>/activate
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<C2_uuid>",
    "key_id": "...",
    "is_active": true,
    ...
  }
  ```
- **Side Effects**: C2 is now active. Note: the current implementation sets `is_active=true` on C2 but does not deactivate C1 (multiple can be active).

### TC-SAML-CERT-006: Upload certificate preserves key_id as SHA-256 thumbprint
- **Category**: Nominal
- **Standard**: RFC 5280 (Certificate Thumbprints)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Valid certificate upload
- **Expected Output**: `key_id` field is a lowercase hex-encoded SHA-256 hash of the DER-encoded certificate
- **Verification**: Independently compute SHA-256 of the certificate DER bytes and compare to `key_id`

### TC-SAML-CERT-007: Upload certificate extracts subject_dn and issuer_dn
- **Category**: Nominal
- **Standard**: RFC 5280 Section 4.1.2.4, 4.1.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Upload certificate with Subject `CN=MyIdP, O=Xavyo, C=US`
- **Expected Output**: `subject_dn` contains `CN=MyIdP, O=Xavyo, C=US` and `issuer_dn` contains the certificate's issuer DN

### TC-SAML-CERT-008: Upload certificate extracts validity dates
- **Category**: Nominal
- **Standard**: RFC 5280 Section 4.1.2.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Upload certificate valid from `2026-01-01` to `2028-01-01`
- **Expected Output**: `not_before` = `2026-01-01T...Z`, `not_after` = `2028-01-01T...Z`

### TC-SAML-CERT-009: Uploaded certificate appears in IdP metadata
- **Category**: Nominal
- **Standard**: SAML 2.0 Metadata 2.4.1.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Upload a new certificate for tenant
- **Input**: `GET /saml/metadata` with same tenant context
- **Expected Output**: Metadata contains `<md:KeyDescriptor use="signing">` with the uploaded certificate's DER base64 in `<ds:X509Certificate>`
- **Verification**: Certificate in metadata matches the uploaded certificate

### TC-SAML-CERT-010: Activated certificate is used for signing SAML assertions
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
  - Certificate `C1` activated for tenant
  - SP with `sign_assertions=true`
- **Input**: SP-initiated SSO or IdP-initiated SSO request
- **Expected Output**: SAML Response signature's `<ds:X509Certificate>` matches `C1`'s certificate
- **Verification**: The certificate embedded in the signature is the same as the active certificate

---

## Edge Cases

### TC-SAML-CERT-011: Upload certificate with mismatched key pair
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  {
    "certificate": "<cert for key A>",
    "private_key": "<key B - different from cert>"
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "certificate_parse_error", "message": "Certificate parsing error" }
  ```
  OR
  ```
  Body: { "error": "private_key_error", "message": "A private key error occurred" }
  ```
- **Verification**: Mismatched key pairs are rejected during parsing

### TC-SAML-CERT-012: Upload with invalid certificate PEM
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  {
    "certificate": "not-a-valid-certificate",
    "private_key": "-----BEGIN PRIVATE KEY-----\n..."
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "certificate_parse_error", "message": "Certificate parsing error" }
  ```

### TC-SAML-CERT-013: Upload with invalid private key PEM
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "not-a-valid-key"
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "private_key_error", "message": "A private key error occurred" }
  ```

### TC-SAML-CERT-014: Upload with empty certificate field
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  { "certificate": "", "private_key": "-----BEGIN PRIVATE KEY-----\n..." }
  ```
- **Expected Output**: Status 400

### TC-SAML-CERT-015: Upload with empty private_key field
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  { "certificate": "-----BEGIN CERTIFICATE-----\n...", "private_key": "" }
  ```
- **Expected Output**: Status 400

### TC-SAML-CERT-016: Upload with missing required fields
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/certificates
  { "certificate": "-----BEGIN CERTIFICATE-----\n..." }
  ```
- **Expected Output**: Status 400 (missing `private_key`)

### TC-SAML-CERT-017: Activate nonexistent certificate
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```
  POST /admin/saml/certificates/00000000-0000-0000-0000-000000000099/activate
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "certificate_not_found",
    "message": "Certificate not found: 00000000-0000-0000-0000-000000000099"
  }
  ```

### TC-SAML-CERT-018: Activate already active certificate
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate `C1` is already active
- **Input**: `POST /admin/saml/certificates/<C1_uuid>/activate`
- **Expected Output**: Status 200, `is_active: true` (idempotent operation)

### TC-SAML-CERT-019: Upload certificate with RSA-2048 key
- **Category**: Edge Case
- **Standard**: NIST SP 800-57
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Valid RSA-2048 certificate and key pair
- **Expected Output**: Status 201, certificate accepted
- **Verification**: RSA-2048 is the minimum acceptable key size

### TC-SAML-CERT-020: Upload certificate with RSA-4096 key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Valid RSA-4096 certificate and key pair
- **Expected Output**: Status 201, certificate accepted

### TC-SAML-CERT-021: Upload self-signed certificate
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Self-signed certificate where `subject_dn == issuer_dn`
- **Expected Output**: Status 201, certificate accepted (SAML does not require CA-signed IdP certificates)

### TC-SAML-CERT-022: Upload CA-signed certificate
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Certificate signed by a CA where `issuer_dn != subject_dn`
- **Expected Output**: Status 201, both `subject_dn` and `issuer_dn` correctly extracted

---

## Security Cases

### TC-SAML-CERT-023: Private key not exposed in list response
- **Category**: Security
- **Standard**: OWASP ASVS 6.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: `GET /admin/saml/certificates`
- **Expected Output**: Each item in `items` contains only public info: `id`, `key_id`, `subject_dn`, `issuer_dn`, `not_before`, `not_after`, `is_active`, `created_at`
- **Verification**: No field named `private_key`, `private_key_encrypted`, `private_key_pem`, or `certificate` (the full PEM) in the response. The `#[serde(skip_serializing)]` annotation on `private_key_encrypted` prevents serialization.

### TC-SAML-CERT-024: Private key encrypted at rest with AES-256-GCM
- **Category**: Security
- **Standard**: NIST SP 800-57, OWASP ASVS 6.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate uploaded
- **Verification** (database level):
  - `private_key_encrypted` column is NOT plaintext PEM
  - Format is: 12 bytes IV + 16 bytes GCM tag + ciphertext
  - Decryption with wrong key fails
  - Decryption with correct `encryption_key` yields original PEM

### TC-SAML-CERT-025: Cross-tenant certificate isolation on list
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. T1 has 2 certificates, T2 has 3 certificates
- **Input**: `GET /admin/saml/certificates` with T1 admin JWT
- **Expected Output**: Only T1's 2 certificates returned
- **Verification**: T2's certificates are invisible to T1

### TC-SAML-CERT-026: Cross-tenant certificate isolation on activate
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate `C1` belongs to T1
- **Input**: `POST /admin/saml/certificates/<C1_uuid>/activate` with T2 admin JWT
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "certificate_not_found" }
  ```
- **Verification**: T2 cannot activate T1's certificates; SQL query includes `WHERE tenant_id = $2`

### TC-SAML-CERT-027: Certificate upload requires admin authentication
- **Category**: Security
- **Standard**: OWASP ASVS 4.1
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `POST /admin/saml/certificates` without Authorization header
- **Expected Output**: Status 401 Unauthorized

### TC-SAML-CERT-028: Certificate upload requires admin role
- **Category**: Security
- **Standard**: OWASP ASVS 4.2
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `POST /admin/saml/certificates` with non-admin JWT
- **Expected Output**: Status 403 Forbidden

### TC-SAML-CERT-029: Error responses do not leak encryption key or key material
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Various error-triggering certificate uploads
- **Expected Output**: Error messages never contain:
  - Encryption key bytes
  - Private key PEM content
  - OpenSSL internal error details beyond "A private key error occurred"
- **Verification**: All private-key-related errors are sanitized before response

### TC-SAML-CERT-030: Encryption key derivation uses random IV per upload
- **Category**: Security
- **Standard**: NIST SP 800-38D (GCM)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Verification** (database level): Upload two certificates; the `private_key_encrypted` column values differ in the first 12 bytes (IV) even if the same private key is uploaded twice
- **Note**: AES-GCM IV reuse with the same key is catastrophic; unique IVs are critical

---

## Compliance Cases

### TC-SAML-CERT-031: Certificate validity check (is_valid method)
- **Category**: Compliance
- **Standard**: RFC 5280 Section 4.1.2.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate with `not_before=2026-01-01`, `not_after=2028-01-01`
- **Verification**: `TenantIdpCertificate::is_valid()` returns `true` when current time is between not_before and not_after

### TC-SAML-CERT-032: Certificate expiry warning (is_expiring_soon method)
- **Category**: Compliance
- **Standard**: NIST SP 800-57 (Key Management Lifecycle)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate with `not_after` = 20 days from now
- **Verification**: `TenantIdpCertificate::is_expiring_soon()` returns `true` (threshold is 30 days)

### TC-SAML-CERT-033: Certificate not yet valid is not flagged as expiring
- **Category**: Compliance
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate with `not_before` = 1 year from now, `not_after` = 2 years from now
- **Verification**: `is_valid()` returns `false` (not yet valid), `is_expiring_soon()` returns `false`

### TC-SAML-CERT-034: SAML metadata certificate matches active certificate
- **Category**: Compliance
- **Standard**: SAML 2.0 Metadata
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active certificate `C1` uploaded for tenant
- **Input**: `GET /saml/metadata`
- **Expected Output**: The base64 content inside `<ds:X509Certificate>` decodes to the same DER bytes as `C1`'s certificate

### TC-SAML-CERT-035: Certificate rotation: new cert active, old still present
- **Category**: Compliance
- **Standard**: NIST SP 800-57 (Key Transition)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certificate `C1` active
- **Steps**:
  1. Upload new certificate `C2` (becomes active)
  2. `GET /admin/saml/certificates` lists both C1 and C2
  3. IdP metadata shows C2's certificate in KeyDescriptor
  4. SSO assertions are signed with C2
- **Verification**: C1 remains listed (for SPs that cached old metadata); C2 is used for new operations
