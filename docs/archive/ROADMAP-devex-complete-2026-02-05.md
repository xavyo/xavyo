# Xavyo Developer Experience Roadmap

This document defines the functional requirements to enhance developer self-service capabilities and CLI tooling. Each requirement is speckit-compatible for use with `/specify` command and suitable for ralph loop execution.

## Current Status

| Status | Count | Focus Area |
|--------|-------|------------|
| 🎯 In Progress | 0 | - |
| 📋 Planned | 0 | - |
| ✅ Complete | 57 | F-049 through F-057 + Crate Stabilization (archived) |

### Previous Roadmap
The crate stabilization roadmap (F-001 to F-048) has been archived to `docs/archive/ROADMAP-crate-stabilization-complete-2026-02-04.md`. All 32 crates are now at beta or stable status.

---

## Timeline Overview

| Phase | Focus Area | Duration | Features |
|-------|------------|----------|----------|
| 1 | API Key Self-Service | Week 1 | F-049, F-050 |
| 2 | CLI Dogfooding | Weeks 2-3 | F-051, F-052, F-053 |
| 3 | Developer Portal APIs | Weeks 4-5 | F-054, F-055 |
| 4 | Tenant Self-Service | Weeks 6-7 | F-056, F-057 |

---

## Phase 1: API Key Self-Service (Week 1)

Enable developers to create and manage their own API keys programmatically.

### F-049: API Key Creation Endpoint ✅

**Crate:** `xavyo-api-tenants`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 3-4 hours
**Dependencies:** None

**Description:**
Implement `POST /tenants/{tenant_id}/api-keys` endpoint that allows users with appropriate permissions to create new API keys for managing NHI agents.

**User Story:**
> As a developer in a tenant, I want to create API keys with specific scopes so I can programmatically manage NHI agents without using my personal credentials.

**Acceptance Criteria:**
- [X] Add `CreateApiKeyRequest` DTO with name, scopes, expires_at fields
- [X] Add `CreateApiKeyResponse` DTO with id, name, key_prefix, api_key (plaintext), scopes, expires_at, created_at
- [X] Implement `create_api_key_handler` following rotate pattern (lines 50-174)
- [X] Add scope validation for `nhi:*` format
- [X] Add POST route at `/tenants/:tenant_id/api-keys`
- [X] Audit log via `AdminAuditLog::create()` with Create action
- [X] Add 10+ unit tests for request validation (14 tests added)
- [X] Security: Plaintext key shown only once in response

**Scope Format:**
| Scope | Grants |
|-------|--------|
| `nhi:agents:read` | View agents |
| `nhi:agents:create` | Create agents |
| `nhi:agents:update` | Update agents |
| `nhi:agents:delete` | Delete agents |
| `nhi:agents:*` | All agent operations |
| `nhi:credentials:rotate` | Rotate credentials |
| `nhi:credentials:*` | All credential operations |
| `nhi:*` | Full NHI access |

**Files to Modify:**
- `crates/xavyo-api-tenants/src/models/api_keys.rs` - Add DTOs
- `crates/xavyo-api-tenants/src/handlers/api_keys.rs` - Add handler
- `crates/xavyo-api-tenants/src/handlers/mod.rs` - Export handler
- `crates/xavyo-api-tenants/src/router.rs` - Add POST route

**Existing Code to Reuse:**
- `ApiKeyService::create_key_pair()` at `services/api_key_service.rs`
- `ApiKey::create()` at `xavyo-db/src/models/api_key.rs:84`
- `CreateApiKey` struct at `xavyo-db/src/models/api_key.rs:54`
- `AdminAuditLog::create()` at `xavyo-db/src/models/admin_audit_log.rs`
- `SYSTEM_TENANT_ID` at `xavyo-db/src/bootstrap.rs`
- Handler auth pattern at `handlers/api_keys.rs:56-66`

---

### F-050: CLI API Key Commands ✅

**Crate:** `xavyo-cli`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 2-3 hours
**Dependencies:** F-049

**Description:**
Add CLI commands for API key management, enabling dogfooding of the new endpoint.

**User Story:**
> As a developer, I want to create and manage API keys from the CLI so I can automate my development workflow.

**Acceptance Criteria:**
- [X] Add `create_api_key()` method to API client
- [X] Implement `xavyo api-keys create <name> [--scopes <scopes>] [--expires-in <days>]`
- [X] Implement `xavyo api-keys list [--json]`
- [X] Implement `xavyo api-keys rotate <key-id> [--deactivate-old]`
- [X] Implement `xavyo api-keys delete <key-id>`
- [X] Add --json output format for scripting
- [X] Add 8+ CLI integration tests (16 tests added)
- [X] Show warning about one-time key display

**Files Modified:**
- `apps/xavyo-cli/src/models/api_key.rs` - DTOs (new)
- `apps/xavyo-cli/src/api/api_keys.rs` - API methods (new)
- `apps/xavyo-cli/src/commands/api_keys.rs` - Command module (new)
- `apps/xavyo-cli/src/api/mod.rs` - Export module
- `apps/xavyo-cli/src/models/mod.rs` - Export module
- `apps/xavyo-cli/src/commands/mod.rs` - Export module
- `apps/xavyo-cli/src/main.rs` - Register command
- `apps/xavyo-cli/CRATE.md` - Documentation

**Example Usage:**
```bash
# Create API key with NHI scopes
xavyo api-keys create "ci-pipeline" --scopes nhi:agents:* --json

# List keys
xavyo api-keys list

# Rotate key
xavyo api-keys rotate abc123 --deactivate-old

# Delete key
xavyo api-keys delete abc123
```

---

## Phase 2: CLI Dogfooding (Weeks 2-3)

Enhance CLI to use xavyo APIs for all operations.

### F-051: CLI Agent Management Commands ✅

**Crate:** `xavyo-cli`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 4-5 hours
**Dependencies:** F-049, F-050

**Description:**
Add comprehensive CLI commands for NHI agent management.

**Acceptance Criteria:**
- [X] Implement `xavyo agents list [--type <type>] [--status <status>]`
- [X] Implement `xavyo agents create --name <name> --type <type> [--description <desc>]`
- [X] Implement `xavyo agents get <agent-id>`
- [X] Implement `xavyo agents update <agent-id> [--name <name>] [--status <status>]`
- [X] Implement `xavyo agents delete <agent-id>`
- [X] Add filtering and pagination support
- [X] Add 10+ CLI tests (12 tests added)

**Files Modified:**
- `apps/xavyo-cli/src/commands/agents.rs` - Extended with filter, pagination, update
- `apps/xavyo-cli/src/api/agents.rs` - Updated list_agents(), added update_agent()
- `apps/xavyo-cli/src/api/client.rs` - Added patch_json() method
- `apps/xavyo-cli/src/models/agent.rs` - Added UpdateAgentRequest DTO
- `apps/xavyo-cli/CRATE.md` - Updated documentation

---

### F-052: CLI Credential Management Commands ✅

**Crate:** `xavyo-cli`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 3-4 hours
**Dependencies:** F-051

**Description:**
Add CLI commands for managing NHI credentials (rotate, view status).

**Acceptance Criteria:**
- [X] Implement `xavyo credentials list <agent-id>`
- [X] Implement `xavyo credentials rotate <credential-id> -a <agent-id>`
- [X] Implement `xavyo credentials status <credential-id> -a <agent-id>`
- [X] Implement `xavyo credentials expire <credential-id> -a <agent-id> --at <datetime>`
- [X] Add warning for credentials expiring soon (7-day threshold)
- [X] Add 8+ CLI tests (17 tests added)

**Files Modified:**
- `apps/xavyo-cli/src/commands/credentials.rs` - New module (580 lines)
- `apps/xavyo-cli/src/commands/mod.rs` - Export credentials module
- `apps/xavyo-cli/src/main.rs` - Register Credentials command
- `apps/xavyo-cli/src/models/agent.rs` - Added with_expires_at() builder method
- `apps/xavyo-cli/CRATE.md` - Updated documentation

---

### F-053: CLI Interactive Mode ✅

**Crate:** `xavyo-cli`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 4-5 hours
**Dependencies:** F-050, F-051, F-052

**Description:**
Add interactive mode for guided workflows (create agent, rotate credentials).

**Acceptance Criteria:**
- [X] Implement `xavyo agents create --interactive`
- [X] Implement `xavyo api-keys create --interactive`
- [X] Implement `xavyo credentials rotate --interactive -a <agent-id>`
- [X] Add dialoguer prompts for required fields
- [X] Add confirmation before destructive operations (--yes flag)
- [X] Add scope selection via checkbox prompt
- [X] Add 5+ interactive mode tests (20 tests added)

**Files Modified:**
- `apps/xavyo-cli/src/interactive/mod.rs` - New module for prompts (module exports)
- `apps/xavyo-cli/src/interactive/prompts.rs` - TTY detection, prompt helpers, option constants
- `apps/xavyo-cli/src/interactive/scopes.rs` - Scope options with descriptions
- `apps/xavyo-cli/src/commands/agents.rs` - Add --interactive flag, --yes flag for delete
- `apps/xavyo-cli/src/commands/api_keys.rs` - Add --interactive flag with scope multiselect
- `apps/xavyo-cli/src/commands/credentials.rs` - Add --interactive flag with grace period selection
- `apps/xavyo-cli/src/main.rs` - Register interactive module
- `apps/xavyo-cli/CRATE.md` - Updated documentation

---

## Phase 3: Developer Portal APIs (Weeks 4-5)

APIs for developer self-service portal functionality.

### F-054: API Key Usage Statistics ✅

**Crate:** `xavyo-api-tenants`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 4-5 hours
**Dependencies:** F-049

**Description:**
Add endpoint to retrieve API key usage statistics for monitoring and quota management.

**Acceptance Criteria:**
- [X] Add `GET /tenants/{tenant_id}/api-keys/{key_id}/usage` endpoint
- [X] Track request count per day/hour
- [X] Track last used timestamp
- [X] Track error rate (4xx, 5xx responses)
- [X] Add response with usage metrics
- [X] Add 10+ unit tests (17 tests added)

**Files Modified:**
- `crates/xavyo-api-tenants/src/handlers/api_keys.rs` - Added get_api_key_usage_handler
- `crates/xavyo-api-tenants/src/models/api_keys.rs` - Added usage DTOs
- `crates/xavyo-api-tenants/src/router.rs` - Added GET route
- `crates/xavyo-db/src/models/api_key_usage.rs` - New usage tracking models
- `crates/xavyo-db/migrations/997_api_key_usage.sql` - Usage tracking tables

---

### F-055: API Key Scope Introspection ✅

**Crate:** `xavyo-api-tenants`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 2-3 hours
**Dependencies:** F-049

**Description:**
Add endpoint to introspect what scopes an API key has and what operations they enable.

**Acceptance Criteria:**
- [X] Add `GET /api-keys/introspect` endpoint (uses current key)
- [X] Return granted scopes with descriptions
- [X] Return allowed operations per scope
- [X] Return key metadata (name, expires_at, created_at)
- [X] Add 6+ unit tests (7 tests added)

**Files Modified:**
- `crates/xavyo-api-tenants/src/handlers/api_keys.rs` - Added introspect_api_key_handler
- `crates/xavyo-api-tenants/src/handlers/mod.rs` - Export handler
- `crates/xavyo-api-tenants/src/models/api_keys.rs` - Added DTOs, SCOPE_DEFINITIONS constant, get_scope_info()
- `crates/xavyo-api-tenants/src/models/mod.rs` - Export new types
- `crates/xavyo-api-tenants/src/router.rs` - Added GET route

---

## Phase 4: Tenant Self-Service (Weeks 6-7)

Enable tenant admins to manage their own settings.

### F-056: Tenant Settings API ✅

**Crate:** `xavyo-api-tenants`
**Current Status:** 🟢 Complete
**Target Status:** Beta
**Estimated Effort:** 5-6 hours
**Dependencies:** None

**Description:**
Add endpoints for tenant admins to view and update their own tenant settings.

**Acceptance Criteria:**
- [X] Add `GET /tenants/{tenant_id}/settings` for tenant users (not just system admin)
- [X] Add `PATCH /tenants/{tenant_id}/settings` with limited scope
- [X] Restrict modifiable settings (display name, logo, custom attributes)
- [X] Prevent modification of plan, quotas, security settings
- [X] Add audit logging for setting changes
- [X] Add 14 F-056 unit tests (exceeds 12+ requirement)

**Files Modified:**
- `crates/xavyo-api-tenants/src/handlers/settings.rs` - Added get_tenant_user_settings_handler, update_tenant_user_settings_handler
- `crates/xavyo-api-tenants/src/models/settings.rs` - Added TenantUserUpdateSettingsRequest, RESTRICTED_SETTINGS_FIELDS, check_restricted_fields()
- `crates/xavyo-api-tenants/src/models/mod.rs` - Export new types
- `crates/xavyo-api-tenants/src/handlers/mod.rs` - Export new handlers
- `crates/xavyo-api-tenants/src/router.rs` - Added GET/PATCH routes to api_keys_router
- `crates/xavyo-api-tenants/src/error.rs` - Added ValidationWithField error variant
- `crates/xavyo-api-tenants/Cargo.toml` - Added url dependency

---

### F-057: Tenant User Invitation ✅

**Crate:** `xavyo-api-tenants`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 4-5 hours
**Dependencies:** F-056

**Description:**
Allow tenant admins to invite users to their tenant via email.

**Acceptance Criteria:**
- [X] Add `POST /tenants/{tenant_id}/invitations` endpoint
- [X] Add `GET /tenants/{tenant_id}/invitations` to list pending
- [X] Add `DELETE /tenants/{tenant_id}/invitations/{id}` to cancel
- [X] Secure token with 256-bit entropy (SHA-256 hashed for storage)
- [X] Token expires after 7 days (FR-003)
- [X] Add 29 unit tests (exceeds 10+ requirement)

**Files Modified:**
- `crates/xavyo-api-tenants/src/handlers/invitations.rs` - New (handlers for all 4 endpoints)
- `crates/xavyo-api-tenants/src/models/invitations.rs` - New (DTOs with validation)
- `crates/xavyo-api-tenants/src/services/invitation_service.rs` - New (TenantInvitationService)
- `crates/xavyo-api-tenants/src/error.rs` - Added Gone error variant (HTTP 410)
- `crates/xavyo-api-tenants/src/router.rs` - Added invitation routes
- `crates/xavyo-api-tenants/Cargo.toml` - Added base64 dependency
- Reused existing UserInvitation model from xavyo-db (no migration needed)

---

## Summary

| Phase | Requirements | Features | Duration |
|-------|--------------|----------|----------|
| 1 | F-049, F-050 | API Key Self-Service | 1 week |
| 2 | F-051, F-052, F-053 | CLI Dogfooding | 2 weeks |
| 3 | F-054, F-055 | Developer Portal APIs | 2 weeks |
| 4 | F-056, F-057 | Tenant Self-Service | 2 weeks |

**Total: 9 functional requirements over 7 weeks**

---

## Using This Roadmap

### With `/specify` Command

Each F-XXX requirement is designed to be used with the `/specify` command:

```bash
/specify F-049: API Key Creation Endpoint
```

### With Ralph Loop

Requirements can be executed in order using ralph loop:

```bash
/ralph-loop
```

### Tracking Progress

Update this document as requirements are completed:
- [X] F-049 - API Key Creation Endpoint
- [X] F-050 - CLI API Key Commands
- [X] F-051 - CLI Agent Management Commands
- [X] F-052 - CLI Credential Management Commands
- [X] F-053 - CLI Interactive Mode
- [X] F-054 - API Key Usage Statistics
- [X] F-055 - API Key Scope Introspection
- [X] F-056 - Tenant Settings API
- [X] F-057 - Tenant User Invitation

---

## Appendix: Crate Focus

This roadmap focuses primarily on:

```
xavyo-api-tenants  - API key and tenant self-service endpoints
xavyo-cli          - CLI commands for developer experience
```

Both crates are already at stable status, so this roadmap adds new functionality rather than stabilizing existing code.
