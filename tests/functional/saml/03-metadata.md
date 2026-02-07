# SAML Metadata Functional Tests

**API Endpoints**:
- `GET /saml/metadata` - IdP metadata XML generation
- `GET /admin/saml/service-providers` - List SPs
- `POST /admin/saml/service-providers` - Create SP
- `GET /admin/saml/service-providers/:sp_id` - Get SP
- `PUT /admin/saml/service-providers/:sp_id` - Update SP
- `DELETE /admin/saml/service-providers/:sp_id` - Delete SP

**Authentication**: Metadata endpoint requires tenant context; admin endpoints require admin JWT
**Applicable Standards**: SAML 2.0 Metadata (OASIS saml-metadata-2.0-os), SAML 2.0 Core, NIST SP 800-63C, OWASP ASVS

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Admin endpoints require admin-role JWT; metadata endpoint requires tenant context via `X-Tenant-ID` header

---

## Nominal Cases

### TC-SAML-META-001: Retrieve IdP metadata XML
- **Category**: Nominal
- **Standard**: SAML 2.0 Metadata 2.3 (IDPSSODescriptor)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` exists with active IdP signing certificate
- **Input**:
  ```
  GET /saml/metadata
  X-Tenant-ID: <T1_uuid>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/xml; charset=utf-8
  Body: Valid SAML metadata XML
  ```
- **Metadata Validation**:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="<base_url>/saml/metadata?tenant=<T1_uuid>">
    <md:IDPSSODescriptor
        WantAuthnRequestsSigned="false"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data>
            <ds:X509Certificate>...</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>
      </md:KeyDescriptor>
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
      <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
      <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
      <md:SingleSignOnService
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          Location="<base_url>/saml/sso"/>
      <md:SingleSignOnService
          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          Location="<base_url>/saml/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  ```

### TC-SAML-META-002: IdP metadata without active certificate
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`. Tenant `T1` exists but has no active certificate
- **Input**:
  ```
  GET /saml/metadata
  X-Tenant-ID: <T1_uuid>
  ```
- **Expected Output**: Status 200, metadata XML without `<md:KeyDescriptor>` element (no signing certificate info)
- **Verification**: Metadata is valid but lacks KeyInfo; SPs cannot validate signatures

### TC-SAML-META-003: IdP metadata includes both HTTP-Redirect and HTTP-POST SSO endpoints
- **Category**: Nominal
- **Standard**: SAML 2.0 Metadata 2.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: Metadata contains two `<md:SingleSignOnService>` elements:
  - One with `Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`
  - One with `Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`
  - Both with same `Location` URL

### TC-SAML-META-004: Create a new Service Provider
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin user authenticated for tenant `T1`
- **Input**:
  ```json
  POST /admin/saml/service-providers
  Authorization: Bearer <admin_jwt>

  {
    "entity_id": "https://sp.example.com/saml/metadata",
    "name": "Example SP",
    "acs_urls": ["https://sp.example.com/saml/acs"],
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "sign_assertions": true,
    "validate_signatures": false,
    "assertion_validity_seconds": 300
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "entity_id": "https://sp.example.com/saml/metadata",
    "name": "Example SP",
    "acs_urls": ["https://sp.example.com/saml/acs"],
    "certificate": null,
    "attribute_mapping": {},
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "sign_assertions": true,
    "validate_signatures": false,
    "assertion_validity_seconds": 300,
    "enabled": true,
    "metadata_url": null,
    "created_at": "<timestamp>",
    "updated_at": "<timestamp>"
  }
  ```
- **Side Effects**: Row created in `saml_service_providers` table with correct `tenant_id`

### TC-SAML-META-005: Create SP with minimal required fields
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  Authorization: Bearer <admin_jwt>

  {
    "entity_id": "https://minimal-sp.example.com",
    "name": "Minimal SP",
    "acs_urls": ["https://minimal-sp.example.com/acs"]
  }
  ```
- **Expected Output**: Status 201, SP created with defaults:
  - `name_id_format`: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
  - `sign_assertions`: `true`
  - `validate_signatures`: `false`
  - `assertion_validity_seconds`: `300`
  - `enabled`: `true`

### TC-SAML-META-006: Create SP with custom attribute mapping
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://custom-sp.example.com",
    "name": "Custom Attrs SP",
    "acs_urls": ["https://custom-sp.example.com/acs"],
    "attribute_mapping": {
      "name_id_source": "email",
      "attributes": [
        {"source": "email", "target_name": "mail", "target_friendly_name": "Email"},
        {"source": "user_id", "target_name": "uid"},
        {"source": "groups", "target_name": "memberOf", "multi_value": true}
      ]
    }
  }
  ```
- **Expected Output**: Status 201, `attribute_mapping` stored as provided

### TC-SAML-META-007: List service providers with pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 5 SPs registered for tenant `T1`
- **Input**:
  ```
  GET /admin/saml/service-providers?limit=2&offset=0
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "items": [ <2 SP objects> ],
    "total": 5,
    "limit": 2,
    "offset": 0
  }
  ```

### TC-SAML-META-008: List service providers filtered by enabled status
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 3 enabled and 2 disabled SPs for tenant `T1`
- **Input**:
  ```
  GET /admin/saml/service-providers?enabled=true
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**: Status 200, `total=3`, all items have `enabled: true`

### TC-SAML-META-009: Get a specific service provider by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```
  GET /admin/saml/service-providers/<sp_uuid>
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<sp_uuid>", "entity_id": "...", "name": "...", ... }
  ```

### TC-SAML-META-010: Update a service provider (partial update)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP exists with `name="Old Name"`, `sign_assertions=true`
- **Input**:
  ```json
  PUT /admin/saml/service-providers/<sp_uuid>
  Authorization: Bearer <admin_jwt>

  {
    "name": "New Name",
    "sign_assertions": false
  }
  ```
- **Expected Output**: Status 200, response shows `name="New Name"`, `sign_assertions=false`, all other fields unchanged

### TC-SAML-META-011: Delete a service provider
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP exists
- **Input**:
  ```
  DELETE /admin/saml/service-providers/<sp_uuid>
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```
- **Side Effects**: Row deleted from `saml_service_providers`
- **Verification**: Subsequent `GET /admin/saml/service-providers/<sp_uuid>` returns 404

### TC-SAML-META-012: Create SP with SP certificate for signature validation
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://signed-sp.example.com",
    "name": "Signed SP",
    "acs_urls": ["https://signed-sp.example.com/acs"],
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIC/z...\n-----END CERTIFICATE-----",
    "validate_signatures": true
  }
  ```
- **Expected Output**: Status 201, `certificate` field populated, `validate_signatures=true`

### TC-SAML-META-013: Create SP with metadata_url
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://meta-sp.example.com",
    "name": "Meta SP",
    "acs_urls": ["https://meta-sp.example.com/acs"],
    "metadata_url": "https://meta-sp.example.com/saml/metadata"
  }
  ```
- **Expected Output**: Status 201, `metadata_url` stored correctly

---

## Edge Cases

### TC-SAML-META-014: Create SP with duplicate entity_id
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP already exists with entity_id `https://existing-sp.example.com`
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://existing-sp.example.com",
    "name": "Duplicate SP",
    "acs_urls": ["https://dup-sp.example.com/acs"]
  }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: {
    "error": "entity_id_conflict",
    "message": "Entity ID already exists: https://existing-sp.example.com"
  }
  ```

### TC-SAML-META-015: Create SP with empty acs_urls
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://no-acs-sp.example.com",
    "name": "No ACS SP",
    "acs_urls": []
  }
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

### TC-SAML-META-016: Get nonexistent SP
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```
  GET /admin/saml/service-providers/00000000-0000-0000-0000-000000000099
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "error": "sp_not_found",
    "message": "Service Provider not found: 00000000-0000-0000-0000-000000000099"
  }
  ```

### TC-SAML-META-017: Delete nonexistent SP
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```
  DELETE /admin/saml/service-providers/00000000-0000-0000-0000-000000000099
  Authorization: Bearer <admin_jwt>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "sp_not_found" }
  ```

### TC-SAML-META-018: Update SP - change entity_id not supported
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP exists
- **Input**:
  ```json
  PUT /admin/saml/service-providers/<sp_uuid>
  { "entity_id": "https://new-entity-id.example.com" }
  ```
- **Expected Output**: Status 200, but `entity_id` remains unchanged (entity_id is not in the UPDATE query)
- **Verification**: entity_id is immutable after creation

### TC-SAML-META-019: Create SP with multiple ACS URLs
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**:
  ```json
  POST /admin/saml/service-providers
  {
    "entity_id": "https://multi-acs-sp.example.com",
    "name": "Multi ACS SP",
    "acs_urls": [
      "https://sp.example.com/saml/acs",
      "https://sp.example.com/saml/acs-alt",
      "https://staging.sp.example.com/saml/acs"
    ]
  }
  ```
- **Expected Output**: Status 201, all three ACS URLs stored in `acs_urls` array

### TC-SAML-META-020: List SPs with default pagination
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: `GET /admin/saml/service-providers` (no limit/offset query params)
- **Expected Output**: Status 200, `limit=20` (default), `offset=0`

### TC-SAML-META-021: IdP metadata entityID includes tenant ID
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. Tenant UUID is `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`
- **Input**: `GET /saml/metadata` with tenant context
- **Expected Output**: `entityID` in metadata contains the tenant UUID:
  ```
  entityID="<base_url>/saml/metadata?tenant=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  ```

### TC-SAML-META-022: Update SP to disable it
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP exists with `enabled=true`
- **Input**:
  ```json
  PUT /admin/saml/service-providers/<sp_uuid>
  { "enabled": false }
  ```
- **Expected Output**: Status 200, `enabled: false`
- **Verification**: Subsequent SSO attempts to this SP return 404 (disabled_sp)

---

## Security Cases

### TC-SAML-META-023: Admin endpoints require authentication
- **Category**: Security
- **Standard**: OWASP ASVS 4.1
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /admin/saml/service-providers` without Authorization header
- **Expected Output**: Status 401 Unauthorized

### TC-SAML-META-024: Admin endpoints require admin role
- **Category**: Security
- **Standard**: OWASP ASVS 4.2
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `POST /admin/saml/service-providers` with non-admin JWT
- **Expected Output**: Status 403 Forbidden

### TC-SAML-META-025: Cross-tenant SP isolation on list
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. T1 has 3 SPs, T2 has 2 SPs
- **Input**: `GET /admin/saml/service-providers` with T1 admin JWT
- **Expected Output**: Only T1's 3 SPs are returned; T2's SPs are not visible
- **Verification**: `total=3` and all returned items belong to T1

### TC-SAML-META-026: Cross-tenant SP isolation on get
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP `SP1` belongs to T1
- **Input**: `GET /admin/saml/service-providers/<SP1_uuid>` with T2 admin JWT
- **Expected Output**: Status 404 (not found, not 403)
- **Verification**: T2 cannot even determine if SP exists in T1

### TC-SAML-META-027: Cross-tenant SP isolation on delete
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SP `SP1` belongs to T1
- **Input**: `DELETE /admin/saml/service-providers/<SP1_uuid>` with T2 admin JWT
- **Expected Output**: Status 404 (not found, not affected)
- **Verification**: SP1 still exists in T1 after the request

### TC-SAML-META-028: XSS in SP entity_id via metadata
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: Create SP with `entity_id` containing `<script>alert('xss')</script>`
- **Expected Output**: If SP creation succeeds (no validation), the entity_id is XML-escaped in metadata output
- **Verification**: No unescaped HTML/JS in metadata XML

### TC-SAML-META-029: Metadata Content-Type header prevents MIME sniffing
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: Response includes `Content-Type: application/xml; charset=utf-8`
- **Verification**: Browser treats response as XML, not HTML (prevents stored XSS via metadata)

### TC-SAML-META-030: SP certificate field does not expose private key material
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`.
- **Input**: `GET /admin/saml/service-providers/<sp_uuid>` for SP with certificate
- **Expected Output**: `certificate` field contains only the public certificate (PEM), never contains `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`

---

## Compliance Cases

### TC-SAML-META-031: Metadata uses correct namespace
- **Category**: Compliance
- **Standard**: SAML 2.0 Metadata
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: Root element uses `xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"`

### TC-SAML-META-032: Metadata IDPSSODescriptor has correct protocol enumeration
- **Category**: Compliance
- **Standard**: SAML 2.0 Metadata 2.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`

### TC-SAML-META-033: Metadata advertises all supported NameID formats
- **Category**: Compliance
- **Standard**: SAML 2.0 Metadata 2.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: Three `<md:NameIDFormat>` elements:
  - `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
  - `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
  - `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`

### TC-SAML-META-034: Metadata KeyDescriptor uses correct signing use
- **Category**: Compliance
- **Standard**: SAML 2.0 Metadata 2.4.1.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active certificate exists
- **Input**: `GET /saml/metadata`
- **Expected Output**: `<md:KeyDescriptor use="signing">` with `<ds:X509Certificate>` containing the DER-encoded certificate in base64

### TC-SAML-META-035: Metadata is well-formed XML
- **Category**: Compliance
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /saml/metadata`
- **Expected Output**: Response body parses as valid well-formed XML
- **Verification**: An XML parser can parse the document without errors; all tags are properly closed, attributes quoted, and special characters escaped
