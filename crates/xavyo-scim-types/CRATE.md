# xavyo-scim-types

> SCIM 2.0 (RFC 7643/7644) data-transfer objects, shared by the SCIM server and the outbound SCIM client.

## Purpose

The single source of truth for SCIM 2.0 wire types in xavyo. Pure
`serde`-(de)serializable DTOs for SCIM Users, Groups, list/patch responses, and
the xavyo group extension — no DB, no HTTP, no business logic. Sharing them
keeps `xavyo-api-scim` (the inbound SCIM server) and `xavyo-scim-client` (the
outbound provisioning client) from drifting on schema shape.

## Layer

domain (a leaf: depends on no internal crates, depended on by the SCIM crates)

## Status

🟢 **stable**

Complete coverage of the SCIM 2.0 core schema (User, Group, ListResponse,
PatchOp) with round-trip serialization tests. The shape is RFC-pinned, so the
API is stable; it is production-proven via `xavyo-scim-client`.

## Dependencies

### Internal (xavyo)
- None — deliberately dependency-light so both the server and client can share
  it without a layering cycle.

### External (key)
- `serde` / `serde_json` — the entire purpose: SCIM JSON (de)serialization
- `chrono` — `meta.created` / `meta.lastModified` timestamps

## Public API

### Types

```rust
// SCIM User (RFC 7643 §4.1) + requests
pub struct ScimUser { /* userName, name, emails, meta, groups, … */ }
pub struct CreateScimUserRequest;
pub struct ReplaceScimUserRequest;
pub struct ScimName;   // formatted, familyName, givenName, …
pub struct ScimEmail;  // value, type, primary
pub struct ScimMeta;   // resourceType, created, lastModified, location
pub struct ScimUserGroup;

// SCIM Group (RFC 7643 §4.2) + requests
pub struct ScimGroup { /* displayName, members, … */ }
pub struct ScimGroupMember;
pub struct CreateScimGroupRequest;
pub struct ReplaceScimGroupRequest;
pub struct XavyoGroupExtension; // xavyo-specific group attributes

// Protocol envelopes (RFC 7644)
pub struct ScimListResponse<T>;       // generic list envelope
pub struct ScimUserListResponse;
pub struct ScimGroupListResponse;
pub struct ScimPagination;            // startIndex, count, totalResults
pub struct ScimPatchRequest;          // PATCH (§3.5.2)
pub struct ScimPatchOp;               // add | remove | replace
```

## Usage Example

```rust
use xavyo_scim_types::{ScimUser, ScimUserListResponse};

// Server: serialize a user into a SCIM response.
let body = serde_json::to_string(&user)?;

// Client: parse a SCIM list response from a downstream IdP.
let page: ScimUserListResponse = serde_json::from_str(&resp_body)?;
```

## Integration Points

- **Consumed by**: `xavyo-api-scim` (inbound SCIM 2.0 server) and
  `xavyo-scim-client` (outbound SCIM provisioning).
- **Provides**: the canonical SCIM DTOs both sides (de)serialize.

## Feature Flags

None.

## Anti-Patterns

- Don't add `xavyo-db`, `xavyo-tenant`, or any HTTP/business-logic dependency
  here — this crate is pure wire types. Validation and persistence belong in the
  consuming crates.
- Don't fork a near-duplicate SCIM struct in `xavyo-api-scim` or
  `xavyo-scim-client`; extend the shared type so both sides stay in sync.

## Related Crates

- `xavyo-api-scim` — inbound SCIM 2.0 server that emits/consumes these types
- `xavyo-scim-client` — outbound SCIM provisioning client
