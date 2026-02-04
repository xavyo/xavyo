# Xavyo CLI Roadmap

This document defines the functional requirements to enhance the `xavyo-cli` to production-ready status. Each requirement is speckit-compatible for use with `/specify` command and suitable for ralph loop execution.

## Current Status

| Metric | Value |
|--------|-------|
| **Version** | 0.1.0 (alpha) |
| **Commands** | 18 implemented |
| **Test Coverage** | 611 tests (354 unit + 79 integration + 53 MFA + 73 WebAuthn + 23 Sessions + 16 Credential Rotation + 29 Offline Mode + 23 Batch + 16 REPL + 18 CLI help) ✅ |
| **Documentation** | CRATE.md ✅ |

### Implemented Commands

| Command | Description | Status |
|---------|-------------|--------|
| `setup` | Interactive setup wizard | ✅ Implemented |
| `signup` | Create new account | ✅ Implemented |
| `login` | Authenticate with platform | ✅ Implemented |
| `logout` | Clear stored credentials | ✅ Implemented |
| `whoami` | Display current identity | ✅ Implemented |
| `init` | Provision new tenant | ✅ Implemented |
| `status` | Show tenant health | ✅ Implemented |
| `agents` | Manage AI agents (CRUD) | ✅ Implemented |
| `tools` | Manage tools (CRUD) | ✅ Implemented |
| `authorize` | Test agent-tool authorization | ✅ Implemented |
| `doctor` | Diagnose issues | ✅ Implemented |
| `apply` | Apply YAML configuration | ✅ Implemented |
| `export` | Export configuration to YAML | ✅ Implemented |
| `completions` | Generate shell completions | ✅ Implemented |
| `watch` | Watch and auto-apply changes | ✅ Implemented |
| `templates` | Pre-configured templates | ✅ Implemented |
| `upgrade` | Check for updates | ✅ Implemented |
| `shell` | Interactive REPL mode | ✅ Implemented |

### Identified Gaps

1. ~~No CRATE.md documentation~~ (CRATE.md added in C-001)
2. ~~Limited test coverage~~ (411+ tests now)
3. ~~No integration tests with live API~~ (wiremock-based tests added)
4. ~~No MFA/WebAuthn support~~ (MFA in C-004, WebAuthn in C-005)
5. ~~No offline mode / caching~~ (Added in C-008)
6. ~~No batch operations~~ (Added in C-009)
7. Limited error recovery
8. No audit logging
9. No plugin system
10. ~~No session management~~ (Added in C-006)

---

## Timeline Overview

| Phase | Focus Area | Features |
|-------|------------|----------|
| 1 | Foundation & Documentation | C-001 to C-003 |
| 2 | Authentication & Security | C-004 to C-007 |
| 3 | Usability Improvements | C-008 to C-012 |
| 4 | Advanced Features | C-013 to C-017 |
| 5 | Enterprise Features | C-018 to C-021 |

---

## Phase 1: Foundation & Documentation

### C-001: xavyo-cli - Add CRATE.md Documentation

**Crate:** `apps/xavyo-cli`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Create comprehensive CRATE.md documentation for the CLI including command reference, configuration options, and troubleshooting guide.

**Acceptance Criteria:**
- [ ] Document current maturity status (alpha → beta)
- [ ] List all 17 commands with descriptions and examples
- [ ] Document configuration options (~/.xavyo/config.yaml)
- [ ] Document credential storage backends (keyring, file)
- [ ] Add troubleshooting guide for common issues
- [ ] Add quick start guide

**Files to Create:**
- `apps/xavyo-cli/CRATE.md`

---

### C-002: xavyo-cli - Add Comprehensive Unit Tests

**Crate:** `apps/xavyo-cli`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** None

**Description:**
Add comprehensive unit tests targeting 100+ tests with >80% code coverage across all modules.

**Acceptance Criteria:**
- [ ] Add tests for all command modules (17 commands)
- [ ] Add tests for credential storage backends (keyring, file)
- [ ] Add tests for API client methods
- [ ] Add tests for configuration parsing
- [ ] Add tests for error handling
- [ ] Target: 100+ unit tests
- [ ] Target: >80% code coverage

**Files to Create:**
- `apps/xavyo-cli/src/commands/tests/*.rs`
- `apps/xavyo-cli/src/credentials/tests.rs`
- `apps/xavyo-cli/src/api/tests.rs`

---

### C-003: xavyo-cli - Add Integration Tests

**Crate:** `apps/xavyo-cli`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** C-002

**Description:**
Add wiremock-based integration tests covering full command workflows, authentication flows, and error scenarios.

**Acceptance Criteria:**
- [ ] Add wiremock-based API mock server
- [ ] Test full authentication flow (login → whoami → logout)
- [ ] Test agent CRUD workflows
- [ ] Test tool CRUD workflows
- [ ] Test apply/export round-trip
- [ ] Test error scenarios (network failure, auth expiry)
- [ ] Target: 50+ integration tests

**Files to Create:**
- `apps/xavyo-cli/tests/common/mod.rs`
- `apps/xavyo-cli/tests/auth_flow_tests.rs`
- `apps/xavyo-cli/tests/agent_tests.rs`
- `apps/xavyo-cli/tests/tool_tests.rs`
- `apps/xavyo-cli/tests/config_tests.rs`

---

## Phase 2: Authentication & Security

### C-004: xavyo-cli - Add MFA/TOTP Support ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** C-003

**Description:**
Add MFA/TOTP support for login command when MFA is required by the server.

**Acceptance Criteria:**
- [x] Add `login --mfa` flag for explicit MFA
- [x] Prompt for TOTP code when server returns MFA challenge
- [x] Handle MFA challenge responses correctly
- [x] Support remember device option (`--remember-device`)
- [x] Add 15+ tests for MFA flow (21 tests added)

**Files Modified:**
- `apps/xavyo-cli/src/commands/login.rs` - MFA integration
- `apps/xavyo-cli/src/commands/logout.rs` - Added --clear-devices
- `apps/xavyo-cli/src/api/auth.rs` - MFA verification API
- `apps/xavyo-cli/src/models/token.rs` - MFA challenge detection
- `apps/xavyo-cli/src/models/mfa.rs` - MFA types (NEW)
- `apps/xavyo-cli/src/credentials/device_trust.rs` - Device trust storage (NEW)
- `apps/xavyo-cli/src/error.rs` - MFA error variants
- `apps/xavyo-cli/tests/mfa_tests.rs` - 21 integration tests (NEW)

---

### C-005: xavyo-cli - Add WebAuthn/Passkey Support ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** C-004

**Description:**
Add WebAuthn/passkey authentication support using system authenticator or hardware keys.

**Acceptance Criteria:**
- [x] Integrate with system authenticator (Touch ID, Windows Hello) via browser handoff
- [x] Support hardware keys (YubiKey) via optional `ctap-hid-fido2` crate
- [x] Fallback to TOTP if unavailable (automatic)
- [x] Add `login --totp` flag to force TOTP over passkey
- [x] Add 20 tests for WebAuthn flow

**Files Created:**
- `apps/xavyo-cli/src/webauthn/mod.rs` - Main passkey module
- `apps/xavyo-cli/src/webauthn/detection.rs` - Environment detection
- `apps/xavyo-cli/src/webauthn/hardware.rs` - Hardware key auth (optional feature)
- `apps/xavyo-cli/src/webauthn/handoff.rs` - Browser handoff
- `apps/xavyo-cli/src/models/webauthn.rs` - WebAuthn models
- `apps/xavyo-cli/src/api/webauthn.rs` - WebAuthn API client
- `apps/xavyo-cli/tests/webauthn_tests.rs` - 20 integration tests

**Files Modified:**
- `apps/xavyo-cli/Cargo.toml` - Added optional `ctap-hid-fido2`
- `apps/xavyo-cli/src/commands/login.rs` - Passkey integration + --totp flag
- `apps/xavyo-cli/src/commands/whoami.rs` - Passkey status display
- `apps/xavyo-cli/src/error.rs` - Passkey error variants

**Optional Feature:**
- `--features hardware-keys` for USB/NFC key support (requires libudev-dev on Linux)

---

### C-006: xavyo-cli - Add Session Management ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** C-003

**Description:**
Add session management commands to list and revoke active sessions.

**Acceptance Criteria:**
- [x] Add `sessions list` command
- [x] Add `sessions revoke <session-id>` command
- [x] Add `sessions revoke --all` for bulk revocation
- [x] Show session metadata (device, location, last used)
- [x] Add 10+ tests for session management (23 tests added)

**Files Created:**
- `apps/xavyo-cli/src/commands/sessions.rs` - Session management commands
- `apps/xavyo-cli/src/api/sessions.rs` - Sessions API client
- `apps/xavyo-cli/src/models/api_session.rs` - Session models (ApiSession, Location, DeviceType)
- `apps/xavyo-cli/src/lib.rs` - Library for test access
- `apps/xavyo-cli/tests/session_tests.rs` - 23 integration tests

**Files Modified:**
- `apps/xavyo-cli/src/main.rs` - Added Sessions command
- `apps/xavyo-cli/src/commands/mod.rs` - Added sessions module
- `apps/xavyo-cli/src/api/mod.rs` - Added sessions module
- `apps/xavyo-cli/src/api/client.rs` - Added post_empty method
- `apps/xavyo-cli/src/models/mod.rs` - Added api_session module

---

### C-007: xavyo-cli - Improve Credential Rotation UX ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** C-003

**Description:**
Improve the credential rotation user experience with better progress indicators, confirmations, and rollback support.

**Acceptance Criteria:**
- [x] Add progress indicators for rotation (indicatif spinner with stage messages)
- [x] Add confirmation prompts before rotation (dialoguer::Confirm with TTY detection)
- [x] Implement rollback on failure (informational messages showing existing credentials still valid)
- [x] Add `--dry-run` flag to preview changes
- [x] Add `--yes` flag to skip confirmation
- [x] Add `--verbose` flag for detailed output
- [x] Add 10+ tests for rotation UX (16 tests added)

**Files Modified:**
- `apps/xavyo-cli/src/commands/agents.rs` - Full rotation UX implementation
- `apps/xavyo-cli/src/models/agent.rs` - DryRunRotationPreview, PlannedRotationChanges models
- `apps/xavyo-cli/src/lib.rs` - Export models for testing
- `apps/xavyo-cli/tests/credential_rotation_tests.rs` - 16 integration tests (NEW)

---

## Phase 3: Usability Improvements

### C-008: xavyo-cli - Add Offline Mode ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** C-003

**Description:**
Add offline mode with local caching to allow read-only operations when disconnected.

**Acceptance Criteria:**
- [x] Cache last-known state locally (~/.xavyo/cache/)
- [x] Detect offline and use cache automatically
- [x] Show "offline" indicator in output
- [x] Sync when back online
- [x] Add cache invalidation strategy (TTL-based with configurable duration)
- [x] Add 15+ tests for offline mode (29 tests added)

**Files Created:**
- `apps/xavyo-cli/src/cache/mod.rs` - Cache module exports
- `apps/xavyo-cli/src/cache/store.rs` - FileCacheStore implementation
- `apps/xavyo-cli/src/cache/entry.rs` - CacheEntry<T> with TTL
- `apps/xavyo-cli/src/cache/config.rs` - CacheConfig with defaults
- `apps/xavyo-cli/src/cache/status.rs` - CacheStatus for reporting
- `apps/xavyo-cli/src/cache/offline.rs` - OfflineStatus enum
- `apps/xavyo-cli/src/commands/cache.rs` - cache status/clear commands
- `apps/xavyo-cli/tests/offline_mode_tests.rs` - 29 integration tests

**Files Modified:**
- `apps/xavyo-cli/src/commands/agents.rs` - Added --offline/--refresh flags, cache integration
- `apps/xavyo-cli/src/commands/tools.rs` - Added --offline/--refresh flags, cache integration
- `apps/xavyo-cli/src/commands/status.rs` - Added --offline/--refresh flags, cache integration
- `apps/xavyo-cli/src/commands/whoami.rs` - Added --offline/--refresh flags, cache integration
- `apps/xavyo-cli/src/config/paths.rs` - Added cache_dir field
- `apps/xavyo-cli/src/error.rs` - Added cache and offline error variants
- `apps/xavyo-cli/src/main.rs` - Added Cache command

---

### C-009: xavyo-cli - Add Batch Operations ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** C-003

**Description:**
Add batch operation support for bulk create, update, and delete operations.

**Acceptance Criteria:**
- [x] Add `agents create --batch file.yaml`
- [x] Add `tools delete --all --filter "name=test-*"`
- [x] Add progress bar for batch operations
- [x] Add `--dry-run` for batch preview
- [x] Support 100+ items in batch (max 1000)
- [x] Add 15+ tests for batch operations (23 integration tests + 40+ unit tests)

**Files Created:**
- `apps/xavyo-cli/src/batch/mod.rs` - Module exports
- `apps/xavyo-cli/src/batch/result.rs` - BatchResult, BatchItemResult, BatchItemStatus
- `apps/xavyo-cli/src/batch/file.rs` - BatchFile YAML parsing, AgentBatchEntry, ToolBatchEntry
- `apps/xavyo-cli/src/batch/filter.rs` - Filter with glob pattern matching
- `apps/xavyo-cli/src/batch/progress.rs` - Progress bar wrapper
- `apps/xavyo-cli/src/batch/executor.rs` - BatchExecutor with all operations
- `apps/xavyo-cli/tests/batch_tests.rs` - 23 integration tests

**Files Modified:**
- `apps/xavyo-cli/Cargo.toml` - Added ctrlc dependency
- `apps/xavyo-cli/src/main.rs` - Added batch module
- `apps/xavyo-cli/src/lib.rs` - Export batch types for testing
- `apps/xavyo-cli/src/api/client.rs` - Added put_json method
- `apps/xavyo-cli/src/api/agents.rs` - Added update_agent method
- `apps/xavyo-cli/src/api/tools.rs` - Added update_tool method
- `apps/xavyo-cli/src/commands/agents.rs` - Added batch operations
- `apps/xavyo-cli/src/commands/tools.rs` - Added batch operations

---

### C-010: xavyo-cli - Add Interactive Mode (REPL) ✅

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta ✅
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** C-003

**Description:**
Add interactive REPL mode for exploratory use with tab completion and command history.

**Acceptance Criteria:**
- [x] Add `xavyo shell` command to enter REPL
- [x] Tab completion for commands and arguments
- [x] Command history with arrow keys (persistent across sessions)
- [x] Context-aware prompts (show current tenant)
- [x] Support `exit` and `quit` commands
- [x] Add 15+ tests for REPL mode (16 tests added)

**Files Created:**
- `apps/xavyo-cli/src/commands/shell.rs` - Shell command entry point
- `apps/xavyo-cli/src/repl/mod.rs` - REPL module exports
- `apps/xavyo-cli/src/repl/session.rs` - ShellSession state management
- `apps/xavyo-cli/src/repl/prompt.rs` - Dynamic prompt generation
- `apps/xavyo-cli/src/repl/executor.rs` - Command execution and help
- `apps/xavyo-cli/src/repl/completer.rs` - Tab completion
- `apps/xavyo-cli/tests/shell_tests.rs` - 16 integration tests

**Files Modified:**
- `apps/xavyo-cli/Cargo.toml` - Added rustyline 14.x
- `apps/xavyo-cli/src/main.rs` - Added Shell command
- `apps/xavyo-cli/src/commands/mod.rs` - Added shell module
- `apps/xavyo-cli/src/config/paths.rs` - Added history_file path
- `apps/xavyo-cli/src/error.rs` - Added rustyline error conversion
- `apps/xavyo-cli/src/lib.rs` - Export repl types for testing

**New Dependencies:**
- `rustyline = "14"` - Readline, history, and completion

---

### C-011: xavyo-cli - Improve Error Messages

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** C-003

**Description:**
Improve error messages with actionable suggestions, documentation links, and retry prompts.

**Acceptance Criteria:**
- [ ] Add actionable suggestions for common errors
- [ ] Link to documentation for complex errors
- [ ] Add retry prompts for transient errors
- [ ] Improve network error messages
- [ ] Add `--verbose` flag for detailed errors
- [ ] Add 20+ tests for error messages

**Files to Modify:**
- `apps/xavyo-cli/src/error.rs`
- `apps/xavyo-cli/src/output/printer.rs`

---

### C-012: xavyo-cli - Add Verbose/Debug Output

**Crate:** `apps/xavyo-cli`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** C-011

**Description:**
Add verbose and debug output modes for troubleshooting.

**Acceptance Criteria:**
- [ ] Add `--verbose` flag globally
- [ ] Add `--debug` for detailed logs
- [ ] Add `--trace` for HTTP request/response logging
- [ ] Respect `XAVYO_LOG` environment variable
- [ ] Add timing information in debug mode
- [ ] Add 10+ tests for output modes

**Files to Modify:**
- `apps/xavyo-cli/src/main.rs`
- `apps/xavyo-cli/src/output/mod.rs`

---

## Phase 4: Advanced Features

### C-013: xavyo-cli - Add Audit Log Viewer

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable (after C-012)
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** C-012

**Description:**
Add audit log viewer command to query and display audit logs.

**Acceptance Criteria:**
- [ ] Add `audit list` command
- [ ] Filter by date range, user, action type
- [ ] Export to JSON/CSV formats
- [ ] Add pagination support
- [ ] Add `audit tail` for live streaming
- [ ] Add 15+ tests for audit commands

**Files to Create:**
- `apps/xavyo-cli/src/commands/audit.rs`
- `apps/xavyo-cli/src/api/audit.rs`

---

### C-014: xavyo-cli - Add Config Diff/Compare

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** C-012

**Description:**
Add diff command to compare YAML configs and show what would change before apply.

**Acceptance Criteria:**
- [ ] Add `diff` command for YAML comparison
- [ ] Show what would change before `apply`
- [ ] Color-coded diff output (+ green, - red)
- [ ] Add `apply --diff` to show changes before applying
- [ ] Add 10+ tests for diff functionality

**Files to Modify:**
- `apps/xavyo-cli/src/commands/apply.rs`

**Files to Create:**
- `apps/xavyo-cli/src/commands/diff.rs`

---

### C-015: xavyo-cli - Add Rollback Support

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** C-014

**Description:**
Add rollback support to undo the last apply operation.

**Acceptance Criteria:**
- [ ] Track config versions locally
- [ ] Add `rollback` command
- [ ] Add `rollback --to <version>` for specific version
- [ ] Add confirmation before rollback
- [ ] Store last 10 versions
- [ ] Add 15+ tests for rollback

**Files to Create:**
- `apps/xavyo-cli/src/commands/rollback.rs`
- `apps/xavyo-cli/src/history/mod.rs`

---

### C-016: xavyo-cli - Add Import/Export Formats

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** C-012

**Description:**
Add support for additional import/export formats beyond YAML.

**Acceptance Criteria:**
- [ ] Support JSON export (`export --format json`)
- [ ] Support CSV export for agents/tools
- [ ] Support CSV import for bulk creation
- [ ] Add format auto-detection on import
- [ ] Add 15+ tests for format support

**Files to Modify:**
- `apps/xavyo-cli/src/commands/export.rs`
- `apps/xavyo-cli/src/commands/apply.rs`

---

### C-017: xavyo-cli - Add Plugin System

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 3 weeks
**Dependencies:** C-012

**Description:**
Add plugin system to allow third-party extensions.

**Acceptance Criteria:**
- [ ] Define plugin manifest format (plugin.yaml)
- [ ] Plugin discovery from ~/.xavyo/plugins/
- [ ] Plugin API for custom commands
- [ ] Add `plugin install <url>` command
- [ ] Add `plugin list` command
- [ ] Add `plugin remove <name>` command
- [ ] Sandboxed plugin execution
- [ ] Add 20+ tests for plugin system

**Files to Create:**
- `apps/xavyo-cli/src/plugins/mod.rs`
- `apps/xavyo-cli/src/plugins/loader.rs`
- `apps/xavyo-cli/src/plugins/api.rs`
- `apps/xavyo-cli/src/commands/plugin.rs`

---

## Phase 5: Enterprise Features

### C-018: xavyo-cli - Add Proxy Support

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** C-012

**Description:**
Add HTTP and SOCKS proxy support for corporate environments.

**Acceptance Criteria:**
- [ ] Support HTTP proxy via `HTTP_PROXY` env var
- [ ] Support HTTPS proxy via `HTTPS_PROXY` env var
- [ ] Support SOCKS5 proxy
- [ ] Support proxy authentication
- [ ] Add `--proxy` flag override
- [ ] Add 10+ tests for proxy support

**Files to Modify:**
- `apps/xavyo-cli/src/api/client.rs`
- `apps/xavyo-cli/src/config/settings.rs`

---

### C-019: xavyo-cli - Add SSO/SAML Authentication

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** C-012

**Description:**
Add SSO/SAML authentication support for enterprise identity providers.

**Acceptance Criteria:**
- [ ] Add `login --sso` flag
- [ ] Browser-based SSO flow
- [ ] SAML assertion handling
- [ ] IdP discovery support
- [ ] Add 15+ tests for SSO flow

**Files to Modify:**
- `apps/xavyo-cli/src/commands/login.rs`
- `apps/xavyo-cli/src/api/auth.rs`

---

### C-020: xavyo-cli - Add Multi-Tenant Switching

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** C-012

**Description:**
Add easy tenant switching for users with access to multiple tenants.

**Acceptance Criteria:**
- [ ] Add `tenant list` command
- [ ] Add `tenant switch <name>` command
- [ ] Quick switch without re-login
- [ ] Show current tenant in prompt
- [ ] Add 10+ tests for tenant switching

**Files to Create:**
- `apps/xavyo-cli/src/commands/tenant.rs`
- `apps/xavyo-cli/src/api/tenants.rs`

---

### C-021: xavyo-cli - Add Compliance Reporting

**Crate:** `apps/xavyo-cli`
**Current Status:** Stable
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** C-013

**Description:**
Add compliance reporting commands for security posture assessment.

**Acceptance Criteria:**
- [ ] Add `compliance report` command
- [ ] Generate security posture report
- [ ] Export compliance data (JSON, PDF)
- [ ] Support SOC2, ISO27001 templates
- [ ] Add 15+ tests for compliance reporting

**Files to Create:**
- `apps/xavyo-cli/src/commands/compliance.rs`
- `apps/xavyo-cli/src/api/compliance.rs`

---

## Summary

| Phase | Requirements | Target Status | Duration |
|-------|--------------|---------------|----------|
| 1 | C-001 to C-003 | Beta | 5 weeks |
| 2 | C-004 to C-007 | Beta | 5.5 weeks |
| 3 | C-008 to C-012 | Stable | 8.5 weeks |
| 4 | C-013 to C-017 | Stable | 8 weeks |
| 5 | C-018 to C-021 | Stable | 5.5 weeks |

**Total: 21 functional requirements over 32.5 weeks**

---

## Using This Roadmap

### With `/specify` Command

Each C-XXX requirement is designed to be used with the `/specify` command:

```bash
/specify C-001: xavyo-cli - Add CRATE.md Documentation
```

### With Ralph Loop

Requirements can be executed in order using ralph loop:

```bash
ralph loop --requirements C-001,C-002,C-003
```

### Tracking Progress

Update this document as requirements are completed:
- [x] C-001 - Add CRATE.md Documentation
- [x] C-002 - Add Comprehensive Unit Tests (206 tests, exceeds 100+ target)
- [x] C-003 - Add Integration Tests (79 tests, exceeds 50+ target)
- [x] C-004 - Add MFA/TOTP Support (21 tests, exceeds 15+ target)
- [x] C-005 - Add WebAuthn/Passkey Support (20 tests, meets target)
- [x] C-006 - Add Session Management (23 tests, exceeds 10+ target)
- [x] C-007 - Improve Credential Rotation UX (16 tests, exceeds 10+ target)
- [x] C-008 - Add Offline Mode (29 tests, exceeds 15+ target)
- [x] C-009 - Add Batch Operations (23 integration tests + 40 unit tests)
- [x] C-010 - Add Interactive Mode (REPL) (16 tests, meets 15+ target)
- [ ] C-011 - Improve Error Messages
- [ ] C-012 - Add Verbose/Debug Output
- [ ] C-013 - Add Audit Log Viewer
- [ ] C-014 - Add Config Diff/Compare
- [ ] C-015 - Add Rollback Support
- [ ] C-016 - Add Import/Export Formats
- [ ] C-017 - Add Plugin System
- [ ] C-018 - Add Proxy Support
- [ ] C-019 - Add SSO/SAML Authentication
- [ ] C-020 - Add Multi-Tenant Switching
- [ ] C-021 - Add Compliance Reporting

---

## Archived Roadmaps

- [Crate Stabilization Roadmap (2026-02)](docs/archive/ROADMAP-crate-stabilization-2026-02.md) - 48/48 features completed
