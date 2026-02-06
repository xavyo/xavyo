# Xavyo IGA Feature Parity Roadmap

This document defines the functional requirements to achieve feature parity with enterprise IGA platforms (MidPoint reference). Each requirement is speckit-compatible for use with `/specify` command and suitable for ralph loop execution.

## Current Status

| Status | Count | Focus Area |
|--------|-------|------------|
| 🎯 In Progress | 0 | - |
| 📋 Planned | 0 | - |
| ✅ Complete | 68 | F-049 through F-068 + Crate Stabilization (archived) |

### Previous Roadmap
The developer experience roadmap (F-049 to F-057) has been archived to `docs/archive/ROADMAP-devex-complete-2026-02-05.md`. All CLI and API key features are now complete.

---

## Executive Summary

**xavyo already implements ~80% of enterprise IGA capabilities**, including:
- Full RBAC with hierarchy and inheritance
- Comprehensive governance (certification, SoD, role mining, risk)
- Complete identity lifecycle management
- Multi-tenant provisioning framework

**This roadmap addresses key gaps** to achieve full feature parity:
- Archetype system for identity sub-typing
- Parametric roles for flexible role definitions
- Formal lifecycle state machine
- Power of attorney for identity delegation
- Self-service request catalog

All proposed features comply with the constitution (API-only, no UI).

---

## Timeline Overview

| Phase | Focus Area | Duration | Features |
|-------|------------|----------|----------|
| 1 | Foundation | Weeks 1-3 | F-058, F-059, F-060 |
| 2 | Advanced Governance | Weeks 4-6 | F-061, F-062, F-063 |
| 3 | Operations | Weeks 7-9 | F-064, F-065, F-066 |
| 4 | Compliance | Weeks 10-11 | F-067, F-068 |

---

## Phase 1: Foundation (Weeks 1-3)

Core architectural enhancements that extend existing models.

### F-058: Identity Archetype System

**Crate:** `xavyo-api-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~12 hours
**Dependencies:** None

**Description:**
Implement an archetype system allowing definition of identity sub-types (Employee, Contractor, Service Account, etc.) with different schemas, policies, and lifecycle models per archetype.

**User Story:**
> As an identity administrator, I want to define archetypes for different identity types so I can enforce different policies and schemas for employees vs contractors vs service accounts.

**Acceptance Criteria:**
- [x] Add `IdentityArchetype` entity with name, description, parent_archetype_id
- [x] Add `ArchetypeSchemaExtension` for per-archetype custom attributes (via schema_extensions JSONB)
- [x] Add `ArchetypePolicyBinding` linking archetypes to password/MFA/session policies
- [x] Add `ArchetypeLifecycleModel` linking archetypes to lifecycle state models (lifecycle_model_id field)
- [x] Implement archetype inheritance (child inherits parent policies if not overridden)
- [x] Add `POST /archetypes` endpoint for CRUD operations (13 endpoints total)
- [x] Add `GET /archetypes/{id}` with full policy resolution (via /effective-policies)
- [x] Add `PUT /users/{id}/archetype` to assign archetype to user
- [x] Add archetype validation on user create/update (schema validation implemented)
- [x] Add 15+ unit tests (65 tests covering models and handlers)

**Database Schema:**
```sql
CREATE TABLE identity_archetypes (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_archetype_id UUID REFERENCES identity_archetypes(id),
    schema_extensions JSONB DEFAULT '{}',
    lifecycle_model_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE archetype_policy_bindings (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    archetype_id UUID NOT NULL REFERENCES identity_archetypes(id),
    policy_type VARCHAR(50) NOT NULL, -- 'password', 'mfa', 'session'
    policy_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/identity_archetype.rs` - New model
- `crates/xavyo-db/src/models/archetype_policy_binding.rs` - New model
- `crates/xavyo-db/migrations/998_identity_archetypes.sql` - New migration
- `crates/xavyo-governance/src/services/archetype_service.rs` - New service
- `crates/xavyo-api-governance/src/handlers/archetypes.rs` - New handlers
- `crates/xavyo-api-governance/src/router.rs` - Add routes

---

### F-059: Lifecycle State Machine

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~8 hours (implemented as F-193)
**Dependencies:** F-058

**Description:**
Formalize the existing `lifecycle_state` field into a configurable state machine with transition rules, entry/exit actions, and scheduled transitions.

**User Story:**
> As an identity administrator, I want to define lifecycle state machines with automatic transitions so that identities move through states (active → pre-termination → terminated → archived) according to business rules.

**Acceptance Criteria:**
- [x] Add `LifecycleStateModel` entity with name and states array (existed in F052)
- [x] Add `LifecycleState` with name, entry_actions, exit_actions (F-193)
- [x] Add `LifecycleTransition` with from_state, to_state, conditions, required_approvals (F-193)
- [x] Add `ScheduledTransition` for time-based auto-transitions (existed in F052)
- [x] Implement state machine evaluation on user update (F-193)
- [x] Add `POST /lifecycle-models` CRUD endpoints (existed in F052)
- [x] Add `POST /users/{id}/lifecycle/transition` to trigger transitions (existed in F052)
- [x] Add transition audit logging (existed in F052)
- [x] Block invalid transitions (F-193 - condition evaluation)
- [x] Add 12+ unit tests (100+ tests covering conditions, actions, lifecycle)

**State Model Example:**
```json
{
  "name": "employee_lifecycle",
  "states": [
    {"name": "active", "entry_actions": ["enable_all_access"]},
    {"name": "pre_termination", "entry_actions": ["notify_manager", "schedule_access_review"]},
    {"name": "terminated", "entry_actions": ["disable_access", "revoke_sessions"]},
    {"name": "archived", "entry_actions": ["anonymize_data"]}
  ],
  "transitions": [
    {"from": "active", "to": "pre_termination", "conditions": ["termination_date_set"]},
    {"from": "pre_termination", "to": "terminated", "scheduled_after_days": 14},
    {"from": "terminated", "to": "archived", "scheduled_after_days": 90}
  ]
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/lifecycle_state_model.rs` - New model
- `crates/xavyo-db/migrations/999_lifecycle_state_machine.sql` - New migration
- `crates/xavyo-governance/src/services/lifecycle_service.rs` - New service
- `crates/xavyo-governance/src/services/mod.rs` - Export service
- `crates/xavyo-api-governance/src/handlers/lifecycle.rs` - New handlers

---

### F-060: Parametric Roles

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete (implemented as F-057)
**Target Status:** Beta
**Actual Effort:** ~8 hours (core implementation + tests)
**Dependencies:** None

**Description:**
Extend roles to support parameters (e.g., "Project Member" role with `project_id` parameter), enabling role reuse across different contexts.

**User Story:**
> As an identity administrator, I want to define roles with parameters so I can create a single "Project Member" role and assign it with different project IDs rather than creating separate roles per project.

**Acceptance Criteria:**
- [x] Add `RoleParameterDefinition` to `GovRole` (name, type, required, default, validation)
- [x] Add `RoleAssignmentParameter` storing parameter values on assignments
- [x] Extend entitlement mappings to reference parameters (`${param.project_id}`)
- [x] Add parameter validation on role assignment
- [x] Add `POST /roles` with parameter definitions
- [x] Add `POST /users/{id}/role-assignments` with parameter values
- [x] Add parameter substitution in entitlement evaluation
- [x] Support parameter types: string, uuid, integer, enum, date
- [x] Add 37+ unit tests (32 unit + 5 integration tests)

**Parameter Example:**
```json
{
  "role": {
    "name": "Project Member",
    "parameters": [
      {"name": "project_id", "type": "uuid", "required": true},
      {"name": "access_level", "type": "enum", "values": ["read", "write", "admin"], "default": "read"}
    ],
    "entitlements": [
      {"resource": "projects/${param.project_id}", "action": "${param.access_level}"}
    ]
  }
}
```

**Assignment Example:**
```json
{
  "role_id": "project-member-role-uuid",
  "parameters": {
    "project_id": "specific-project-uuid",
    "access_level": "write"
  }
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/gov_role_parameter.rs` - Extend existing
- `crates/xavyo-db/src/models/gov_role_assignment.rs` - Add parameters field
- `crates/xavyo-governance/src/services/role_service.rs` - Add parameter handling
- `crates/xavyo-governance/src/services/pdp.rs` - Add parameter substitution

---

## Phase 2: Advanced Governance (Weeks 4-6)

Enhanced governance capabilities for enterprise requirements.

### F-061: Power of Attorney / Identity Assumption

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete (Core Implementation)
**Target Status:** Beta
**Actual Effort:** ~10 hours
**Dependencies:** None

**Description:**
Enable users to grant another user the ability to act on their behalf with full audit trail, supporting vacation coverage and delegation scenarios.

**User Story:**
> As a manager going on vacation, I want to grant my deputy power of attorney so they can approve access requests on my behalf while I'm away, with full audit trail.

**Acceptance Criteria:**
- [x] Add `PowerOfAttorney` entity with donor_id, attorney_id, scope, valid_from, valid_until
- [x] Add `PoAScope` enum: all, approvals_only, specific_resources (scope_id field with GovDelegationScope reuse)
- [x] Implement `POST /power-of-attorney` to grant PoA
- [x] Implement `POST /power-of-attorney/{id}/revoke` to revoke (changed from DELETE for audit trail)
- [x] Implement `POST /power-of-attorney/{id}/assume` to activate (attorney action)
- [x] Implement `POST /power-of-attorney/drop` to deactivate
- [x] Track all actions taken under PoA in audit log (7 event types)
- [ ] Prevent PoA loops (A→B→A) - Not implemented
- [ ] Add notification when PoA is used - Not implemented
- [x] Add 15+ unit tests (60 tests implemented)

**Additional Implemented:**
- [x] `POST /power-of-attorney/{id}/extend` - Extend PoA duration
- [x] `GET /power-of-attorney/current-assumption` - Get current assumption status
- [x] `GET /power-of-attorney/{id}/audit` - Get PoA audit trail
- [x] Admin endpoints for list and revoke
- [x] Session termination on revoke
- [x] 90-day maximum duration validation
- [x] Self-delegation prevention

**Known Gaps:**
- PoA validity middleware for assumed requests not implemented
- Scope enforcement not fully implemented
- JWT token with acting_as claims uses placeholder (needs auth integration)

**Security Constraints:**
- PoA cannot grant higher privileges than donor has
- PoA actions are logged with both donor and attorney IDs
- PoA can be revoked at any time by donor
- Maximum PoA duration: 90 days (configurable per tenant)

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/power_of_attorney.rs` - New model
- `crates/xavyo-db/migrations/1000_power_of_attorney.sql` - New migration
- `crates/xavyo-governance/src/services/poa_service.rs` - New service
- `crates/xavyo-api-governance/src/handlers/power_of_attorney.rs` - New handlers

---

### F-062: Self-Service Request Catalog

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~12 hours
**Dependencies:** None

**Description:**
Create a catalog of requestable items (roles, entitlements, resources) with requestability rules and a shopping cart pattern.

**User Story:**
> As an employee, I want to browse a catalog of available roles and resources so I can request access to what I need through a self-service workflow.

**Acceptance Criteria:**
- [x] Add `CatalogItem` entity with type (role, entitlement, resource), metadata, requestability_rules
- [x] Add `RequestabilityRule` with conditions (who can request, for whom)
- [x] Add `CatalogCategory` for organizing items
- [x] Add `RequestCart` for multi-item requests
- [x] Implement `GET /catalog/items` with filtering and search
- [x] Implement `GET /catalog/items/{id}` with requestability check
- [x] Implement `POST /catalog/cart` to add items to cart
- [x] Implement `POST /catalog/submit` to submit cart as access request
- [x] Add request form definitions (required justification, custom fields)
- [x] Integrate with existing access request workflow
- [x] Add 15+ unit tests (40+ tests in catalog_tests.rs)

**Requestability Rules Example:**
```json
{
  "item": "developer-role",
  "rules": [
    {"type": "self_request", "allowed": true},
    {"type": "manager_request", "allowed": true},
    {"type": "department_restriction", "departments": ["engineering", "product"]},
    {"type": "requires_training", "training_ids": ["security-101"]}
  ]
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/catalog_item.rs` - New model
- `crates/xavyo-db/src/models/catalog_category.rs` - New model
- `crates/xavyo-db/src/models/request_cart.rs` - New model
- `crates/xavyo-db/migrations/1001_request_catalog.sql` - New migration
- `crates/xavyo-governance/src/services/catalog_service.rs` - New service

---

### F-063: Role Inducements (Construction Pattern)

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~12 hours
**Dependencies:** F-060

**Description:**
Allow roles to automatically trigger provisioning of accounts/resources when assigned (MidPoint's inducement/construction pattern).

**User Story:**
> As an identity administrator, I want roles to automatically create accounts in target systems when assigned so that provisioning happens automatically without manual intervention.

**Acceptance Criteria:**
- [x] Add `RoleConstruction` entity with role_id, target_connector_id, account_type, attribute_mappings
- [x] Implement construction evaluation on role assignment
- [x] Implement construction cleanup on role revocation
- [x] Add attribute mappings with parameter substitution
- [x] Support multiple constructions per role
- [x] Add `POST /roles/{id}/constructions` CRUD endpoints
- [x] Integrate with existing provisioning queue
- [x] Add construction status tracking
- [x] Add 12+ unit tests (50+ tests covering models, handlers, services)

**Additional Implemented:**
- [x] `RoleInducement` entity for role-to-role inducements with activation conditions
- [x] `RoleAssignmentService` - High-level role assignment with automatic construction triggering
- [x] `InducementTriggerService` - Evaluates all constructions (direct + induced) on assignment
- [x] Deprovisioning policies: disable, delete, retain with customizable behavior
- [x] Role effective constructions endpoint showing transitive constructions
- [x] User effective constructions endpoint for provisioning preview

**Files Created/Modified:**
- `crates/xavyo-db/src/models/role_construction.rs` - New model
- `crates/xavyo-db/src/models/role_inducement.rs` - New model
- `crates/xavyo-db/migrations/196_role_constructions.sql` - New migration
- `crates/xavyo-governance/src/services/construction_service.rs` - New service
- `crates/xavyo-api-governance/src/services/role_construction_service.rs` - API service
- `crates/xavyo-api-governance/src/services/role_inducement_service.rs` - API service
- `crates/xavyo-api-governance/src/services/inducement_trigger_service.rs` - Trigger service
- `crates/xavyo-api-governance/src/services/role_assignment_service.rs` - Assignment service
- `crates/xavyo-api-governance/src/handlers/role_constructions.rs` - Handlers
- `crates/xavyo-api-governance/src/handlers/role_inducements.rs` - Handlers
- `crates/xavyo-api-governance/src/handlers/role_assignments.rs` - Handlers

**Construction Example:**
```json
{
  "role_id": "developer-role-uuid",
  "constructions": [
    {
      "target_connector": "azure-ad",
      "account_type": "default",
      "attribute_mappings": {
        "displayName": "${user.display_name}",
        "department": "${user.department}",
        "jobTitle": "Developer"
      }
    },
    {
      "target_connector": "github",
      "account_type": "member",
      "attribute_mappings": {
        "login": "${user.username}",
        "teams": ["${param.team_name}"]
      }
    }
  ]
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/role_construction.rs` - New model
- `crates/xavyo-db/migrations/1002_role_constructions.sql` - New migration
- `crates/xavyo-governance/src/services/construction_service.rs` - New service
- `crates/xavyo-provisioning/src/queue.rs` - Integrate construction triggers

---

## Phase 3: Operations (Weeks 7-9)

Operational enhancements for large-scale identity management.

### F-064: Bulk Action Engine

**Crate:** `xavyo-governance`, `xavyo-api-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~16 hours
**Dependencies:** None

**Description:**
Add an expression-based bulk action engine for performing mass operations on identities with preview mode.

**User Story:**
> As an identity administrator, I want to perform bulk operations like assigning a role to all users in a department so I can manage access at scale without manual work.

**Acceptance Criteria:**
- [x] Add `GovBulkAction` entity with expression, action_type, parameters, status
- [x] Add expression language for filtering (department = 'engineering' AND status = 'active')
- [x] Support action types: assign_role, revoke_role, enable, disable, modify_attribute
- [x] Implement preview mode (dry-run) showing affected objects with would_change detection
- [x] Implement async execution with progress tracking (BulkActionJob)
- [x] Add `POST /admin/bulk-actions` to create action
- [x] Add `GET /admin/bulk-actions/{id}` to check status
- [x] Add `POST /admin/bulk-actions/{id}/execute` to run (after preview)
- [x] Add `POST /admin/bulk-actions/{id}/cancel` to cancel running action
- [x] Add `DELETE /admin/bulk-actions/{id}` to delete completed action
- [x] Add rate limiting for bulk operations (configurable users/second)
- [x] Add 51 tests (21 unit tests + 30 integration tests)

**Additional Implemented:**
- [x] Expression parser with recursive descent parser
- [x] ActionExecutor trait pattern for pluggable action implementations
- [x] Background job with batch processing and checkpoint persistence
- [x] Cancellation support with check in processing loop
- [x] Audit logging for each user operation
- [x] OpenAPI/Swagger annotations for all endpoints

**Expression Syntax:**
```
# Filter all active users in engineering who don't have developer role
department = 'engineering'
  AND lifecycle_state = 'active'
  AND NOT has_role('developer')

# Action
{
  "action": "assign_role",
  "role_id": "developer-role-uuid",
  "justification": "Bulk assignment per ticket INC-12345"
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/bulk_action.rs` - New model
- `crates/xavyo-db/migrations/1003_bulk_actions.sql` - New migration
- `crates/xavyo-governance/src/services/bulk_action_service.rs` - New service
- `crates/xavyo-governance/src/expression/parser.rs` - Expression parser
- `crates/xavyo-governance/src/expression/evaluator.rs` - Expression evaluator

---

### F-065: Enhanced Correlation Rules

**Crate:** `xavyo-api-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** 0 hours (already implemented as part of F-067 Correlation Engine)
**Dependencies:** None

**Description:**
Enhance identity correlation with configurable rules, confidence scoring, and manual resolution workflow.

**User Story:**
> As an identity administrator, I want configurable correlation rules with confidence scores so I can accurately match accounts from HR systems to existing identities.

**Implementation Note:**
This feature was already fully implemented as part of the F-067 Correlation Engine. All acceptance criteria are satisfied by existing code in `xavyo-api-governance` and `xavyo-db`.

**Acceptance Criteria:**
- [x] Add `CorrelationRule` entity with name, connector_id, match_type, weight - `GovCorrelationRule` model
- [x] Support match types: exact, fuzzy, weighted_multi_field - `GovMatchType` enum (Exact, Fuzzy, Phonetic, Expression)
- [x] Add confidence scoring (0-100) based on rule weights - `CorrelationEngineService::score_candidate()`
- [x] Add `CorrelationCase` for ambiguous matches requiring manual resolution - `GovCorrelationCase` model
- [x] Implement `GET /correlation-rules` CRUD endpoints - `/governance/connectors/{id}/correlation/rules`
- [x] Implement `GET /correlation-cases` for pending cases - `/governance/correlation/cases`
- [x] Implement `POST /correlation-cases/{id}/resolve` for manual resolution - confirm/reject/create-identity endpoints
- [x] Add correlation audit trail - `GovCorrelationAuditEvent` model
- [x] Add 12+ unit tests - 80+ tests in correlation_engine_service.rs

**Existing Implementation:**
- Models: `gov_correlation_rule.rs`, `gov_correlation_case.rs`, `gov_correlation_threshold.rs`, `gov_correlation_audit_event.rs`
- Services: `correlation_engine_service.rs`, `correlation_rule_service.rs`, `correlation_case_service.rs`
- Handlers: `correlation_rules.rs`, `correlation_cases.rs`, `correlation_engine.rs`, `correlation_audit.rs`
- Migration: `067_001_correlation_engine.sql`

---

### F-066: Organization-Level Security Policies

**Crate:** `xavyo-api-auth`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~10 hours
**Dependencies:** None

**Description:**
Allow different security policies (password, MFA, session) per organization unit, with inheritance from parent orgs.

**User Story:**
> As a security administrator, I want to apply stricter MFA policies to the Finance department without affecting other departments so I can meet compliance requirements for specific business units.

**Acceptance Criteria:**
- [x] Add `OrgSecurityPolicy` entity with org_id, policy_type, policy_config
- [x] Support policy types: password, mfa, session, ip_restriction
- [x] Implement policy inheritance (child org inherits parent if not overridden) via recursive CTE
- [x] Implement policy resolution (most specific wins + most restrictive across groups)
- [x] Add `GET /organizations/{id}/security-policies` endpoint (+ CRUD)
- [x] Add `GET /organizations/{id}/effective-policy/{type}` endpoint
- [x] Add `GET /users/{id}/effective-policy/{type}` endpoint
- [x] Add `POST /organizations/{id}/security-policies/validate` conflict detection
- [x] Integrate with auth flow: PasswordPolicyService, MfaService, SessionService, IP filter
- [x] Add 60+ unit tests (16 in-crate + 44 integration tests)

**Policy Example:**
```json
{
  "org_id": "finance-department-uuid",
  "policies": {
    "mfa": {
      "required": true,
      "methods": ["webauthn", "totp"],
      "grace_period_hours": 0
    },
    "session": {
      "max_duration_hours": 4,
      "require_reauthentication_for": ["financial_reports", "wire_transfers"]
    },
    "password": {
      "min_length": 16,
      "require_special_chars": true,
      "max_age_days": 60
    }
  }
}
```

**Files to Create/Modify:**
- `crates/xavyo-db/src/models/org_security_policy.rs` - New model
- `crates/xavyo-db/migrations/1004_org_security_policies.sql` - New migration
- `crates/xavyo-governance/src/services/org_policy_service.rs` - New service
- `crates/xavyo-auth/src/policy_resolver.rs` - Policy resolution for auth

---

## Phase 4: Compliance (Weeks 10-11)

Compliance and flexibility enhancements.

### F-067: GDPR/Data Protection Metadata

**Crate:** `xavyo-governance`, `xavyo-api-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Actual Effort:** ~6 hours
**Dependencies:** None

**Description:**
Add GDPR-related metadata to entitlements and roles for data protection compliance.

**User Story:**
> As a compliance officer, I want to classify entitlements by data protection level so I can track which roles grant access to personal data and ensure proper legal basis.

**Acceptance Criteria:**
- [x] Add `data_protection_classification` field to entitlements (none, personal, sensitive, special_category)
- [x] Add `legal_basis` field (consent, contract, legal_obligation, vital_interest, public_task, legitimate_interest)
- [x] Add `retention_period_days` field
- [x] Add `data_controller` and `data_processor` fields
- [x] Implement `GET /entitlements?classification=sensitive` filtering
- [x] Add GDPR report generation endpoint (`GET /governance/gdpr/report`)
- [x] Add per-user data protection summary endpoint (`GET /governance/gdpr/users/:user_id/data-protection`)
- [x] Add 9 unit tests (exceeds 8 requirement)

**Entitlement Example:**
```json
{
  "name": "customer_data_read",
  "data_protection": {
    "classification": "personal",
    "legal_basis": "contract",
    "retention_period_days": 365,
    "data_controller": "Acme Corp",
    "purposes": ["customer_support", "order_fulfillment"]
  }
}
```

**Files Created/Modified:**
- `crates/xavyo-db/src/models/gov_entitlement.rs` - Added GDPR enums + fields to model/create/update/filter
- `crates/xavyo-db/src/models/mod.rs` - Export new types
- `crates/xavyo-db/migrations/1180_gdpr_metadata.sql` - New migration (enums + columns + indexes)
- `crates/xavyo-api-governance/src/models/entitlement.rs` - GDPR fields on DTOs, validation, report models
- `crates/xavyo-api-governance/src/handlers/entitlements.rs` - Updated handlers + 2 new GDPR handlers
- `crates/xavyo-api-governance/src/services/entitlement_service.rs` - Classification filter support
- `crates/xavyo-api-governance/src/services/gdpr_report_service.rs` - New GDPR report service
- `crates/xavyo-api-governance/src/services/mod.rs` - Export service
- `crates/xavyo-api-governance/src/router.rs` - Register service + routes
- `crates/xavyo-api-governance/tests/gdpr_metadata_tests.rs` - 9 unit tests

---

### F-068: Object Templates

**Crate:** `xavyo-governance`
**Current Status:** ✅ Complete
**Target Status:** Beta
**Estimated Effort:** 6-8 hours
**Dependencies:** F-058

**Description:**
Implement object templates for default values, computed attributes, and validation rules per archetype.

**User Story:**
> As an identity administrator, I want to define templates that automatically compute attributes (like email from first+last name) and enforce validation rules so I don't have to manually set common values.

**Acceptance Criteria:**
- [x] Add `ObjectTemplate` entity with archetype_id, attribute_mappings, validation_rules
- [x] Support mapping expressions: `${firstName}.${lastName}@${tenant.domain}`
- [x] Support computed attributes from other attributes
- [x] Support default values
- [x] Support validation rules (regex, range, enum)
- [x] Apply templates on user create/update
- [x] Add `POST /object-templates` CRUD endpoints
- [x] Add template preview endpoint
- [x] Add 284 unit/integration tests (71 inline + 213 integration)

**Template Example:**
```json
{
  "archetype_id": "employee-archetype-uuid",
  "mappings": [
    {"attribute": "email", "expression": "${firstName.toLowerCase()}.${lastName.toLowerCase()}@${tenant.email_domain}"},
    {"attribute": "display_name", "expression": "${firstName} ${lastName}"},
    {"attribute": "manager_id", "source": "hr_feed.manager_employee_id", "transform": "lookup_user_by_employee_id"}
  ],
  "defaults": [
    {"attribute": "timezone", "value": "${tenant.default_timezone}"},
    {"attribute": "locale", "value": "en-US"}
  ],
  "validations": [
    {"attribute": "employee_id", "rule": "regex", "pattern": "^EMP[0-9]{6}$"},
    {"attribute": "department", "rule": "enum", "values": ["engineering", "product", "sales", "hr", "finance"]}
  ]
}
```

**Implementation (Completed):**
- 7 services: ObjectTemplateService, TemplateRuleService, TemplateScopeService, TemplateApplicationService, TemplateExpressionService, TemplateMergeService, TemplateSimulationService
- 9 DB models: GovObjectTemplate, GovTemplateRule, GovTemplateScope, GovTemplateEvent, GovTemplateApplicationEvent, GovTemplateVersion, GovTemplateMergePolicy, GovTemplateExclusion, related enums
- Expression engine: Path references (`${attr}`), functions (lowercase, uppercase, trim, substring, concat, coalesce, length, contains, starts_with, ends_with, replace, if_then_else), operators (arithmetic, comparison, logical), nested attribute access
- 5 merge strategies: SourcePrecedence, TimestampWins, ConcatenateUnique, FirstWins, ManualOnly
- Template inheritance with circular detection, rule exclusions
- Template simulation for dry-run preview
- 284 tests (71 inline + 213 integration across 7 test files)

**Files Created/Modified:**
- `crates/xavyo-db/src/models/gov_object_template.rs` - Template CRUD with versioning
- `crates/xavyo-db/src/models/gov_template_rule.rs` - Rule CRUD with filtering
- `crates/xavyo-db/src/models/gov_template_scope.rs` - Scope matching
- `crates/xavyo-db/src/models/gov_template_event.rs` - Audit events
- `crates/xavyo-db/src/models/gov_template_merge_policy.rs` - Merge policies
- `crates/xavyo-db/src/models/gov_template_exclusion.rs` - Inheritance exclusions
- `crates/xavyo-api-governance/src/services/object_template_service.rs` - Template lifecycle
- `crates/xavyo-api-governance/src/services/template_expression_service.rs` - Expression engine
- `crates/xavyo-api-governance/src/services/template_merge_service.rs` - Merge resolution
- `crates/xavyo-api-governance/src/services/template_simulation_service.rs` - Dry-run simulation
- `crates/xavyo-api-governance/src/handlers/object_templates.rs` - REST handlers
- `crates/xavyo-api-governance/src/models/object_template.rs` - API models
- `crates/xavyo-api-governance/src/router.rs` - Route registration

---

## Summary

| Phase | Requirements | Features | Duration |
|-------|--------------|----------|----------|
| 1 | F-058, F-059, F-060 | Foundation (Archetypes, Lifecycle, Parametric Roles) | 3 weeks |
| 2 | F-061, F-062, F-063 | Advanced Governance (PoA, Catalog, Inducements) | 3 weeks |
| 3 | F-064, F-065, F-066 | Operations (Bulk Actions, Correlation, Org Policies) | 3 weeks |
| 4 | F-067, F-068 | Compliance (GDPR, Templates) | 2 weeks |

**Total: 11 functional requirements over 11 weeks**

**Completed: 11 (F-058, F-059, F-060, F-061, F-062, F-063, F-064, F-065, F-066, F-067, F-068)**
**Remaining: 0**

---

## Gap Assessment Summary

| MidPoint Feature | xavyo Status | Priority | Effort | Feature |
|------------------|--------------|----------|--------|---------|
| RBAC Core | ✅ Implemented | - | - | - |
| Role Hierarchy | ✅ Implemented | - | - | - |
| Entitlements | ✅ Implemented | - | - | - |
| Meta-Roles | ✅ Implemented | - | - | - |
| Certification | ✅ Implemented | - | - | - |
| Role Mining | ✅ Implemented | - | - | - |
| SoD | ✅ Implemented | - | - | - |
| Access Requests | ✅ Implemented | - | - | - |
| Risk Scoring | ✅ Implemented | - | - | - |
| Provisioning | ✅ Implemented | - | - | - |
| **Archetypes** | ✅ Implemented | High | Medium | F-058 |
| **Lifecycle State Machine** | ✅ Implemented | High | Low | F-059 |
| **Parametric Roles** | ✅ Implemented | High | Medium | F-060 |
| **Power of Attorney** | ✅ Implemented | High | Medium | F-061 |
| **Request Catalog** | ✅ Implemented | Medium | Medium | F-062 |
| **Inducements** | ✅ Implemented | Medium | Medium | F-063 |
| **Bulk Scripting** | ✅ Implemented | Medium | Medium | F-064 |
| **Correlation Rules** | ✅ Implemented | Medium | Low | F-065 |
| **Org Policies** | ✅ Implemented | Medium | Low | F-066 |
| **GDPR Metadata** | ✅ Implemented | Low | Low | F-067 |
| **Object Templates** | ✅ Implemented | Low | Medium | F-068 |

---

## Using This Roadmap

### With `/specify` Command

Each F-XXX requirement is designed to be used with the `/specify` command:

```bash
/specify F-058: Identity Archetype System
```

### With Ralph Loop

Requirements can be executed in order using ralph loop:

```bash
/ralph-loop
```

### Tracking Progress

Update this document as requirements are completed:
- [x] F-058 - Identity Archetype System
- [x] F-059 - Lifecycle State Machine
- [x] F-060 - Parametric Roles
- [x] F-061 - Power of Attorney / Identity Assumption
- [x] F-062 - Self-Service Request Catalog
- [x] F-063 - Role Inducements (Construction Pattern)
- [x] F-064 - Bulk Action Engine
- [x] F-065 - Enhanced Correlation Rules (already implemented as F-067 Correlation Engine)
- [x] F-066 - Organization-Level Security Policies
- [x] F-067 - GDPR/Data Protection Metadata
- [x] F-068 - Object Templates

---

## Appendix: Crate Focus

This roadmap focuses primarily on:

```
xavyo-governance       - Core governance services (archetypes, lifecycle, roles, PoA, catalog)
xavyo-api-governance   - REST API handlers for governance features
xavyo-provisioning     - Correlation and construction integration
xavyo-auth             - Policy resolution for org-level security
xavyo-db               - New models and migrations
```

All features are API-only per constitution requirements.
