# SCIM 2.0 Schemas, ServiceProviderConfig, and ResourceTypes Functional Tests

**API Endpoints**:
- `GET /scim/v2/Schemas`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/ServiceProviderConfig`
**Authentication**: Bearer token (SCIM token via `Authorization: Bearer xscim_...`)
**Applicable Standards**: RFC 7643 Section 7 (Schema Definition), RFC 7644 Section 4 (Service Provider Configuration)

---

## Nominal Cases

### TC-SCIM-SCHEMA-001: Get ServiceProviderConfig
- **Category**: Nominal
- **Standard**: RFC 7644 Section 4
- **Preconditions**: Valid SCIM Bearer token for tenant
- **Input**:
  ```
  GET /scim/v2/ServiceProviderConfig
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "patch": {
      "supported": true
    },
    "bulk": {
      "supported": true,
      "maxOperations": 1000,
      "maxPayloadSize": 1048576
    },
    "filter": {
      "supported": true,
      "maxResults": 100
    },
    "changePassword": {
      "supported": false
    },
    "sort": {
      "supported": true
    },
    "etag": {
      "supported": false
    },
    "authenticationSchemes": [
      {
        "type": "oauthbearertoken",
        "name": "OAuth Bearer Token",
        "description": "Authentication scheme using SCIM Bearer tokens",
        "specUri": "https://tools.ietf.org/html/rfc6750"
      }
    ],
    "meta": {
      "resourceType": "ServiceProviderConfig",
      "location": "https://<host>/scim/v2/ServiceProviderConfig"
    }
  }
  ```

### TC-SCIM-SCHEMA-002: Get Schemas endpoint
- **Category**: Nominal
- **Standard**: RFC 7643 Section 7
- **Input**:
  ```
  GET /scim/v2/Schemas
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": <N>,
    "Resources": [
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:User",
        "name": "User",
        "description": "SCIM 2.0 User Schema",
        "attributes": [ ... ]
      },
      {
        "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "name": "Group",
        "description": "SCIM 2.0 Group Schema",
        "attributes": [ ... ]
      },
      ...
    ]
  }
  ```
- **Verification**: At minimum, User and Group schemas are present

### TC-SCIM-SCHEMA-003: Get ResourceTypes endpoint
- **Category**: Nominal
- **Standard**: RFC 7644 Section 4
- **Input**:
  ```
  GET /scim/v2/ResourceTypes
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 2,
    "Resources": [
      {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
        "schemaExtensions": [
          {
            "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            "required": false
          }
        ],
        "meta": {
          "resourceType": "ResourceType",
          "location": "https://<host>/scim/v2/ResourceTypes/User"
        }
      },
      {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "meta": {
          "resourceType": "ResourceType",
          "location": "https://<host>/scim/v2/ResourceTypes/Group"
        }
      }
    ]
  }
  ```

### TC-SCIM-SCHEMA-004: User schema contains required attributes
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.1
- **Input**:
  ```
  GET /scim/v2/Schemas
  ```
- **Expected Output**: User schema includes these attributes:
  - `userName` (required, string, uniqueness: server)
  - `name` (complex: givenName, familyName, formatted, middleName, honorificPrefix, honorificSuffix)
  - `displayName` (string)
  - `active` (boolean)
  - `emails` (multi-valued complex: value, type, primary)
  - `groups` (multi-valued complex, readOnly)
  - `externalId` (string)
  - `meta` (complex, readOnly)

### TC-SCIM-SCHEMA-005: Group schema contains required attributes
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.2
- **Input**:
  ```
  GET /scim/v2/Schemas
  ```
- **Expected Output**: Group schema includes these attributes:
  - `displayName` (required, string)
  - `members` (multi-valued complex: value, display, type, $ref)
  - `externalId` (string)
  - `meta` (complex, readOnly)

### TC-SCIM-SCHEMA-006: ServiceProviderConfig declares supported features
- **Category**: Nominal
- **Standard**: RFC 7644 Section 4
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: Response declares:
  - `patch.supported = true` (the server supports PATCH operations)
  - `bulk.supported = true` (the server supports Bulk operations)
  - `filter.supported = true` (the server supports filtering)
  - `sort.supported = true` (the server supports sorting)

### TC-SCIM-SCHEMA-007: ServiceProviderConfig bulk limits
- **Category**: Nominal
- **Standard**: RFC 7644 Section 4
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: `bulk.maxOperations` is a positive integer (1000); `bulk.maxPayloadSize` is a positive integer (1048576 bytes = 1 MB)

### TC-SCIM-SCHEMA-008: ServiceProviderConfig authenticationSchemes
- **Category**: Nominal
- **Standard**: RFC 7644 Section 4
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: `authenticationSchemes` is a non-empty array containing at least one scheme with `type`, `name`, and `description` fields

---

## Edge Cases

### TC-SCIM-SCHEMA-020: ServiceProviderConfig response includes schemas array
- **Category**: Edge Case
- **Standard**: RFC 7643 Section 3
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: Response body contains:
  ```json
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]
  ```

### TC-SCIM-SCHEMA-021: Schemas endpoint returns ListResponse format
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2
- **Input**: `GET /scim/v2/Schemas`
- **Expected Output**: Response uses ListResponse schema:
  ```json
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
  ```
  With `totalResults`, `Resources` array

### TC-SCIM-SCHEMA-022: ResourceTypes endpoint returns ListResponse format
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2
- **Input**: `GET /scim/v2/ResourceTypes`
- **Expected Output**: Response uses ListResponse schema with `totalResults` and `Resources`

### TC-SCIM-SCHEMA-023: Enterprise User extension schema present
- **Category**: Edge Case
- **Standard**: RFC 7643 Section 4.3
- **Input**: `GET /scim/v2/Schemas`
- **Expected Output**: Schemas list includes `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` with attributes: `department`, `costCenter`, `employeeNumber`, `organization`, `division`, `manager`

### TC-SCIM-SCHEMA-024: Xavyo Group extension schema present
- **Category**: Edge Case
- **Input**: `GET /scim/v2/Schemas`
- **Expected Output**: Schemas list includes `urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group` with attributes: `groupType`, `parentExternalId`

---

## Compliance Cases

### TC-SCIM-SCHEMA-030: RFC 7643 required User schema URI
- **Category**: Compliance
- **Standard**: RFC 7643 Section 4.1
- **Input**: Create or retrieve any user resource
- **Expected Output**: `schemas` array contains `"urn:ietf:params:scim:schemas:core:2.0:User"`
- **Verification**: This is the canonical IETF-registered schema URI; any deviation breaks interop

### TC-SCIM-SCHEMA-031: RFC 7643 required Group schema URI
- **Category**: Compliance
- **Standard**: RFC 7643 Section 4.2
- **Input**: Create or retrieve any group resource
- **Expected Output**: `schemas` array contains `"urn:ietf:params:scim:schemas:core:2.0:Group"`

### TC-SCIM-SCHEMA-032: RFC 7644 error schema URI
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.12
- **Input**: Any request that returns an error response
- **Expected Output**: Error response contains:
  ```json
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"]
  ```
- **Verification**: All SCIM errors use this exact schema URI

### TC-SCIM-SCHEMA-033: RFC 7644 ListResponse schema URI
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.4.2
- **Input**: Any list endpoint (GET /Users, GET /Groups, GET /Schemas, GET /ResourceTypes)
- **Expected Output**: Response contains:
  ```json
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
  ```

### TC-SCIM-SCHEMA-034: RFC 7644 PatchOp schema URI
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.5.2
- **Input**: PATCH request body
- **Expected Output**: Must include:
  ```json
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
  ```
- **Verification**: Server rejects PATCH requests missing this schema

### TC-SCIM-SCHEMA-035: RFC 7644 BulkRequest/BulkResponse schema URIs
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.7
- **Input**: Bulk request and response
- **Expected Output**:
  - Request schema: `"urn:ietf:params:scim:api:messages:2.0:BulkRequest"`
  - Response schema: `"urn:ietf:params:scim:api:messages:2.0:BulkResponse"`

### TC-SCIM-SCHEMA-036: Content-Type application/scim+json on all responses
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.1
- **Input**: Any SCIM endpoint call
- **Expected Output**: `Content-Type: application/scim+json` in response headers
- **Verification**: Implementation sets `application/scim+json` via `SCIM_CONTENT_TYPE` constant

### TC-SCIM-SCHEMA-037: SCIM error response fields (detail and status as string)
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.12
- **Input**: Any error-producing request
- **Expected Output**: Error body contains:
  - `"detail"`: human-readable string
  - `"status"`: HTTP status code as a **string** (e.g., `"404"`, not integer 404)
  - `"scimType"` (optional): one of the RFC-defined error types

### TC-SCIM-SCHEMA-038: ServiceProviderConfig meta.resourceType
- **Category**: Compliance
- **Standard**: RFC 7644 Section 4
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: `meta.resourceType` is `"ServiceProviderConfig"`

---

## Interoperability Tests

### TC-SCIM-SCHEMA-040: Azure AD/Entra ID discovery compatibility
- **Category**: Compliance
- **Standard**: Microsoft SCIM implementation guide
- **Input**: Azure AD SCIM client performs discovery:
  1. `GET /scim/v2/ServiceProviderConfig`
  2. `GET /scim/v2/Schemas`
  3. `GET /scim/v2/ResourceTypes`
- **Expected Output**: All three endpoints return valid SCIM responses with correct schema URIs, enabling Azure AD automatic configuration

### TC-SCIM-SCHEMA-041: Okta SCIM discovery compatibility
- **Category**: Compliance
- **Standard**: Okta SCIM provisioning protocol
- **Input**: Okta SCIM client performs:
  1. `GET /scim/v2/Users?startIndex=1&count=1` (connectivity test)
  2. `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: Valid SCIM ListResponse for users; valid ServiceProviderConfig

### TC-SCIM-SCHEMA-042: ServiceProviderConfig filter.maxResults
- **Category**: Compliance
- **Standard**: RFC 7644 Section 4
- **Input**: `GET /scim/v2/ServiceProviderConfig`
- **Expected Output**: `filter.maxResults` matches the server's actual maximum count per page (100)
- **Verification**: The value must be consistent with `ScimPagination::MAX_COUNT`

### TC-SCIM-SCHEMA-043: User schema userName uniqueness declaration
- **Category**: Compliance
- **Standard**: RFC 7643 Section 7
- **Input**: `GET /scim/v2/Schemas`
- **Expected Output**: In the User schema, the `userName` attribute has `"uniqueness": "server"` indicating the server enforces uniqueness

### TC-SCIM-SCHEMA-044: User schema groups attribute is readOnly
- **Category**: Compliance
- **Standard**: RFC 7643 Section 4.1
- **Input**: `GET /scim/v2/Schemas`
- **Expected Output**: The `groups` attribute in User schema has `"mutability": "readOnly"` (groups are managed via Group endpoints, not User)
