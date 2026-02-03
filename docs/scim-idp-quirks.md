# SCIM IdP Quirks and Workarounds

This document catalogs known deviations from the SCIM 2.0 specification (RFC 7643/7644) exhibited by major identity providers and the workarounds implemented in our SCIM server.

## Overview

Identity providers (IdPs) often implement SCIM with variations from the standard specification. Understanding these quirks is essential for building a compatible SCIM server that works reliably with all major IdPs.

### Severity Levels

| Level | Description |
|-------|-------------|
| **High** | Significant impact, may affect core functionality |
| **Medium** | Moderate impact, requires specific handling |
| **Low** | Minor inconvenience, easy workaround |

---

## Okta Quirks

Okta is one of the most widely used IdPs for SCIM provisioning. The following quirks have been observed:

### OKTA-001: Empty Strings for Optional Attributes

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | Okta sends empty strings for optional attributes instead of omitting them |
| **Impact** | Empty strings may be stored instead of null |
| **Workaround** | Treat empty strings as null during parsing |

**Example Request:**
```json
{
  "userName": "user@example.com",
  "displayName": "",
  "nickName": "",
  "title": ""
}
```

### OKTA-002: PATCH Operations Use Value Arrays

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Description** | PATCH operations use value array even for single values |
| **Impact** | Parser may fail if expecting scalar value |
| **Workaround** | Accept both array and scalar in PATCH value field |

**Example Request:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "replace",
    "path": "active",
    "value": [true]
  }]
}
```

### OKTA-003: String ID Format Expected

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Description** | Okta expects `id` in response to be a string, not UUID format |
| **Impact** | Client may fail to parse UUID-formatted IDs |
| **Workaround** | Always return IDs as strings without UUID formatting |

**Correct Response:**
```json
{
  "id": "abc123",
  "userName": "user@example.com"
}
```

**Incorrect Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "userName": "user@example.com"
}
```

### OKTA-004: Retry Behavior on 5xx Errors

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | Okta retries on 5xx with exponential backoff (up to 5 times) |
| **Impact** | Server may receive duplicate requests |
| **Workaround** | Return consistent errors, use idempotency |

### OKTA-005: Soft Delete via PATCH

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Description** | Okta sends `active: false` for deactivation instead of DELETE |
| **Impact** | Users may not be properly deactivated if expecting DELETE |
| **Workaround** | Support soft-delete via PATCH `active=false` |

**Deactivation Request:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{
    "op": "replace",
    "path": "active",
    "value": [false]
  }]
}
```

---

## Azure AD Quirks

Azure Active Directory (now Microsoft Entra ID) has its own set of SCIM implementation quirks.

### AAD-001: Missing Schemas Field

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Description** | Azure AD sends requests without `schemas` in payload (sometimes) |
| **Impact** | Request may be rejected for missing required field |
| **Workaround** | Make `schemas` field optional in parser |

**Example Request (missing schemas):**
```json
{
  "userName": "user@example.com",
  "displayName": "Test User"
}
```

### AAD-002: Legacy Schema URIs

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Description** | Uses non-standard `urn:scim:schemas:extension:enterprise:1.0` sometimes |
| **Impact** | Enterprise extension may not be recognized |
| **Workaround** | Accept both 1.0 and 2.0 schema URIs |

**Legacy URI Example:**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "urn:scim:schemas:extension:enterprise:1.0": {
    "department": "Engineering"
  }
}
```

### AAD-003: Full Resource in PATCH Replace

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Description** | PATCH replace operations may include full resource |
| **Impact** | Parser may fail expecting partial update |
| **Workaround** | Accept full resource in PATCH replace |

### AAD-004: Exact Schema Match in ServiceProviderConfig

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Description** | Expects exact schema match in ServiceProviderConfig |
| **Impact** | Config endpoint may fail Azure AD validation |
| **Workaround** | Match Azure's expected format exactly |

### AAD-005: Filter Whitespace

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | Sends filter with extra spaces around operators |
| **Impact** | Filter parsing may fail on whitespace |
| **Workaround** | Trim filter tokens during parsing |

**Example Filter:**
```
userName  eq  "user@example.com"
```

### AAD-006: Duplicate Requests on Timeout

| Field | Value |
|-------|-------|
| **Severity** | High |
| **Description** | May send duplicate requests on timeout (no idempotency key) |
| **Impact** | Duplicate users may be created |
| **Workaround** | Use `externalId` for deduplication |

---

## OneLogin Quirks

OneLogin's SCIM client has the following known deviations.

### OL-001: Explicit Nulls for Optional Fields

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | OneLogin sends `null` explicitly for optional fields |
| **Impact** | Null handling may differ from field omission |
| **Workaround** | Accept explicit nulls same as omitted fields |

**Example Request:**
```json
{
  "userName": "user@example.com",
  "nickName": null,
  "title": null,
  "profileUrl": null
}
```

### OL-002: Array Notation in PATCH Paths

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Description** | PATCH path syntax uses array notation for single values |
| **Impact** | Path parsing may fail on `members[value eq "x"]` syntax |
| **Workaround** | Parse array notation in PATCH paths |

**Example Request:**
```json
{
  "Operations": [{
    "op": "add",
    "path": "members[value eq \"user-123\"]"
  }]
}
```

### OL-003: Meta Field Omission

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | May omit `meta` from resource responses |
| **Impact** | Client may expect `meta` field presence |
| **Workaround** | Make `meta` optional in response parsing |

### OL-004: Date Format Variations

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Description** | Uses different date format (ISO 8601 with timezone) |
| **Impact** | Date parsing may fail |
| **Workaround** | Accept multiple date formats |

**Example Date:**
```
2024-01-15T10:30:00-08:00
```

### OL-005: Lowercase Filter Operators

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Description** | Filter `and`/`or` operators must be lowercase |
| **Impact** | Case-sensitive filter parsing may fail |
| **Workaround** | Normalize filter operators to lowercase |

---

## Compatibility Matrix

| Feature | Okta | Azure AD | OneLogin | SCIM Spec |
|---------|------|----------|----------|-----------|
| User CRUD | ✅ | ✅ | ✅ | ✅ |
| Group CRUD | ✅ | ✅ | ✅ | ✅ |
| PATCH Operations | ✅ (array values) | ✅ (full resource) | ✅ (array notation) | ✅ |
| Filter Support | ✅ | ✅ (extra whitespace) | ✅ (lowercase) | ✅ |
| Pagination | ✅ | ✅ | ✅ | ✅ |
| Schema Discovery | ✅ | ✅ (strict) | ✅ | ✅ |
| Soft Delete | ✅ (preferred) | ✅ | ✅ | ✅ |
| Hard Delete | ✅ | ✅ | ✅ | ✅ |
| Enterprise Extension | ✅ | ✅ (1.0 + 2.0) | ✅ | ✅ |

## Testing Recommendations

1. **Use Mock Clients**: Use the mock IdP clients in `tests/mocks/` to verify your SCIM server handles each quirk correctly.

2. **Enable All Quirks**: Test with all quirks enabled to ensure maximum compatibility.

3. **Run CI Tests**: The quirks validation tests in `tests/quirks_validation.rs` verify mock accuracy.

4. **Manual Testing**: Before production, test against actual IdP sandboxes:
   - Okta Developer Account
   - Azure AD Free Tier
   - OneLogin Developer Account

## References

- [RFC 7643 - SCIM Core Schema](https://tools.ietf.org/html/rfc7643)
- [RFC 7644 - SCIM Protocol](https://tools.ietf.org/html/rfc7644)
- [Okta SCIM Documentation](https://developer.okta.com/docs/reference/scim/)
- [Azure AD SCIM Documentation](https://docs.microsoft.com/en-us/azure/active-directory/app-provisioning/)
- [OneLogin SCIM Documentation](https://developers.onelogin.com/scim)
