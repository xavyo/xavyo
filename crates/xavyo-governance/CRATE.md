# xavyo-governance

> Identity Governance and Administration (IGA) domain logic for xavyo.

## Purpose

Provides core domain logic for entitlement management including applications, entitlements, assignments, and effective access queries. Supports role-based access, certification campaigns, access requests, and SoD (Separation of Duties) rule enforcement. This crate contains domain types, services, and business logic for governance operations.

## Layer

domain

## Status

🟡 **beta**

Feature-complete with 52 tests. Implements EntitlementService, AssignmentService, and ValidationService with full CRUD, assignment, and validation capabilities. Audit logging integrated. Ready for API layer integration.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Database models (GovEntitlement, GovEntitlementAssignment)

### External (key)
- `async-trait` - Async trait definitions
- `chrono` - Timestamps and date validation
- `serde` - Serialization
- `tokio` - Async runtime (RwLock)
- `uuid` - Unique identifiers
- `moka` (optional) - Caching support

## Public API

### Services

```rust
/// Service for managing entitlements (CRUD operations)
pub struct EntitlementService {
    fn new(store: Arc<dyn EntitlementStore>, audit: Arc<dyn AuditStore>) -> Self;
    async fn create(&self, tenant_id: Uuid, input: CreateEntitlementInput, actor_id: Uuid) -> Result<Entitlement>;
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Entitlement>>;
    async fn update(&self, tenant_id: Uuid, id: Uuid, input: UpdateEntitlementInput, actor_id: Uuid) -> Result<Entitlement>;
    async fn delete(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<bool>;
    async fn list(&self, tenant_id: Uuid, filter: &EntitlementFilter, options: &ListOptions) -> Result<Vec<Entitlement>>;
    async fn count(&self, tenant_id: Uuid, filter: &EntitlementFilter) -> Result<i64>;
}

/// Service for managing entitlement assignments
pub struct AssignmentService {
    fn new(assignment_store, entitlement_store, audit_store, validation_service) -> Self;
    async fn assign(&self, tenant_id: Uuid, input: AssignEntitlementInput) -> Result<EntitlementAssignment>;
    async fn revoke(&self, tenant_id: Uuid, assignment_id: Uuid, actor_id: Uuid) -> Result<bool>;
    async fn list_user_entitlements(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<EntitlementAssignment>>;
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<EntitlementAssignment>>;
}

/// Service for validating assignment requests
pub struct ValidationService {
    fn new() -> Self;
    fn with_defaults() -> Self;  // Includes ExpiryDateValidator
    fn add_validator(&mut self, validator: Box<dyn Validator>);
    async fn validate_assignment(&self, tenant_id: Uuid, input: &AssignEntitlementInput, user_entitlements: &[Uuid]) -> ValidationResult;
}
```

### Audit

```rust
/// Trait for audit event storage backends
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn log_event(&self, input: EntitlementAuditEventInput) -> Result<EntitlementAuditEvent>;
    async fn query_events(&self, tenant_id: Uuid, filter: AuditEventFilter) -> Result<Vec<EntitlementAuditEvent>>;
    async fn get_event(&self, tenant_id: Uuid, event_id: Uuid) -> Result<Option<EntitlementAuditEvent>>;
}

/// In-memory audit store for testing
pub struct InMemoryAuditStore;

/// Actions logged by the audit system
pub enum EntitlementAuditAction {
    Created, Updated, Deleted, StatusChanged, Assigned, Revoked
}
```

### Domain Types

```rust
/// An entitlement representing an access right or permission
pub struct Entitlement {
    pub id: EntitlementId,
    pub tenant_id: Uuid,
    pub application_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub risk_level: RiskLevel,
    pub status: EntitlementStatus,
    pub owner_id: Option<Uuid>,
    pub external_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_delegable: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An entitlement assignment to a user
pub struct EntitlementAssignment {
    pub id: AssignmentId,
    pub tenant_id: Uuid,
    pub entitlement_id: Uuid,
    pub user_id: Uuid,
    pub assigned_by: Uuid,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub justification: Option<String>,
}

/// Filter for listing entitlements
pub struct EntitlementFilter {
    pub application_id: Option<Uuid>,
    pub status: Option<EntitlementStatus>,
    pub risk_level: Option<RiskLevel>,
    pub owner_id: Option<Uuid>,
    pub name_contains: Option<String>,
}

/// Pagination options
pub struct ListOptions {
    pub limit: i64,   // Default: 100
    pub offset: i64,  // Default: 0
}
```

### Validators

```rust
/// Trait for pluggable assignment validators
pub trait Validator: Send + Sync {
    fn validate(&self, input: &AssignEntitlementInput, user_entitlements: &[Uuid]) -> ValidationResult;
}

/// Built-in validators
pub struct ExpiryDateValidator;           // Validates expiry is in the future
pub struct DuplicateAssignmentValidator;  // Prevents duplicate assignments
pub struct PrerequisiteValidator;         // Requires prerequisite entitlement
pub struct JustificationRequiredValidator; // Requires justification field
```

### ID Types

```rust
pub struct ApplicationId(Uuid);
pub struct EntitlementId(Uuid);
pub struct AssignmentId(Uuid);
```

### Enums

```rust
pub enum RiskLevel { Low, Medium, High, Critical }
pub enum EntitlementStatus { Active, Inactive, PendingApproval }
pub enum AssignmentStatus { Active, PendingApproval, Revoked, Expired }
pub enum AssignmentSource { Direct, Role, Birthright }
pub enum AppType { Custom, Saas, OnPremise, Cloud }
pub enum AppStatus { Active, Inactive, Deprecated }
```

### Errors

```rust
pub enum GovernanceError {
    EntitlementNotFound(Uuid),
    EntitlementNameExists(String),
    EntitlementHasAssignments(i64),
    AssignmentNotFound(Uuid),
    AssignmentAlreadyExists(Uuid),
    ValidationFailed(Vec<String>),
    PrerequisiteNotAssigned(Uuid),
    NotFound { resource: String, id: String },
    InvalidState { current: String, expected: String },
    SodViolation { rule_id: Uuid, message: String },
    ApprovalRequired { workflow_id: Uuid },
    DatabaseError(String),
    Internal(String),
}
```

## Usage Example

```rust
use xavyo_governance::services::{
    EntitlementService, AssignmentService, ValidationService,
    CreateEntitlementInput, AssignEntitlementInput,
    entitlement::InMemoryEntitlementStore,
    assignment::InMemoryAssignmentStore,
};
use xavyo_governance::audit::InMemoryAuditStore;
use xavyo_governance::types::RiskLevel;
use std::sync::Arc;

// Create in-memory stores for testing
let entitlement_store = Arc::new(InMemoryEntitlementStore::new());
let assignment_store = Arc::new(InMemoryAssignmentStore::new());
let audit_store = Arc::new(InMemoryAuditStore::new());
let validation = Arc::new(ValidationService::with_defaults());

// Create services
let entitlement_service = EntitlementService::new(
    entitlement_store.clone(),
    audit_store.clone(),
);

let assignment_service = AssignmentService::new(
    assignment_store,
    entitlement_store,
    audit_store,
    validation,
);

// Create an entitlement
let tenant_id = uuid::Uuid::new_v4();
let actor_id = uuid::Uuid::new_v4();

let entitlement = entitlement_service.create(
    tenant_id,
    CreateEntitlementInput {
        application_id: uuid::Uuid::new_v4(),
        name: "Admin Access".to_string(),
        description: Some("Full administrative privileges".to_string()),
        risk_level: RiskLevel::Critical,
        owner_id: Some(actor_id),
        external_id: None,
        metadata: None,
        is_delegable: false,
    },
    actor_id,
).await?;

// Assign to a user
let user_id = uuid::Uuid::new_v4();
let assignment = assignment_service.assign(
    tenant_id,
    AssignEntitlementInput {
        entitlement_id: entitlement.id.into_inner(),
        user_id,
        assigned_by: actor_id,
        expires_at: None,
        justification: Some("Required for project Alpha".to_string()),
    },
).await?;
```

## Integration Points

- **Consumed by**: `xavyo-api-governance`, `xavyo-api-users`, `xavyo-provisioning`
- **Provides**: Domain services and types for IGA operations
- **Database**: Uses models from `xavyo-db` (GovEntitlement, GovEntitlementAssignment)
- **Audit**: Follows F-003 audit pattern from `xavyo-authorization`

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |
| `moka` | Enable in-memory caching | `moka` |

## Anti-Patterns

- Never assign high-risk entitlements without validation service
- Never skip SoD checks before assignment creation
- Never allow direct database access bypassing service layer
- Never create assignments without tenant context
- Never use `Uuid::nil()` as a tenant_id placeholder
- Never access entitlements across tenant boundaries

## Related Crates

- `xavyo-api-governance` - REST API for governance operations
- `xavyo-db` - Database models (GovApplication, GovEntitlement, etc.)
- `xavyo-authorization` - Policy enforcement and audit patterns
- `xavyo-provisioning` - Sync entitlements to target systems
