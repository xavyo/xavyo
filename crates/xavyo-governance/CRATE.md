# xavyo-governance

> Identity Governance and Administration (IGA) domain logic for xavyo.

## Purpose

Provides core domain logic for entitlement management including applications, entitlements, assignments, and effective access queries. Supports role-based access, certification campaigns, access requests, and SoD (Separation of Duties) rule enforcement. This crate contains domain types, services, and business logic for governance operations.

## Layer

domain

## Status

🟢 **stable**

Production-ready with 173+ tests (130 unit + 43 integration). Implements EntitlementService, AssignmentService, ValidationService, full SoD (Separation of Duties) validation with SodService, SodValidationService, and SodExemptionService, and RiskAssessmentService (F-006). Supports preventive validation (block bad assignments), detective validation (scan existing assignments), time-bound exemptions, and risk scoring based on entitlements and SoD violations. Comprehensive integration tests verify multi-tenant isolation, audit trail integrity, and performance benchmarks. Audit logging integrated.

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

/// Service for managing SoD rules (F-005)
pub struct SodService {
    fn new(rule_store: Arc<dyn SodRuleStore>, audit_store: Arc<dyn AuditStore>) -> Self;
    async fn create_rule(&self, tenant_id: Uuid, input: CreateSodRuleInput) -> Result<SodRule>;
    async fn get_rule(&self, tenant_id: Uuid, id: SodRuleId) -> Result<Option<SodRule>>;
    async fn list_rules(&self, tenant_id: Uuid) -> Result<Vec<SodRule>>;
    async fn update_rule(&self, tenant_id: Uuid, id: SodRuleId, input: UpdateSodRuleInput, actor_id: Uuid) -> Result<SodRule>;
    async fn delete_rule(&self, tenant_id: Uuid, id: SodRuleId, actor_id: Uuid) -> Result<bool>;
}

/// Service for SoD validation (preventive and detective) (F-005)
pub struct SodValidationService {
    fn new(rule_store: Arc<dyn SodRuleStore>, violation_store: Arc<dyn SodViolationStore>, exemption_store: Arc<dyn SodExemptionStore>) -> Self;
    async fn validate_preventive(&self, tenant_id: Uuid, user_id: Uuid, proposed_entitlement_id: Uuid, current_entitlements: &[Uuid]) -> Result<PreventiveValidationResult>;
    async fn get_user_violations(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodViolationInfo>>;
    async fn scan_rule(&self, tenant_id: Uuid, rule_id: SodRuleId, ...) -> Result<RuleScanResult>;
    async fn scan_all(&self, tenant_id: Uuid, ...) -> Result<DetectiveScanResult>;
}

/// Service for managing SoD exemptions (F-005)
pub struct SodExemptionService {
    fn new(exemption_store: Arc<dyn SodExemptionStore>, audit_store: Arc<dyn AuditStore>) -> Self;
    async fn grant_exemption(&self, tenant_id: Uuid, input: CreateSodExemptionInput) -> Result<SodExemption>;
    async fn revoke_exemption(&self, tenant_id: Uuid, id: SodExemptionId, revoked_by: Uuid) -> Result<SodExemption>;
    async fn is_exempted(&self, tenant_id: Uuid, rule_id: SodRuleId, user_id: Uuid) -> Result<bool>;
    async fn list_user_exemptions(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<SodExemption>>;
}

/// Service for risk assessment and scoring (F-006)
pub struct RiskAssessmentService {
    fn new(threshold_store: Arc<dyn RiskThresholdStore>, history_store: Arc<dyn RiskHistoryStore>, audit_store: Arc<dyn AuditStore>) -> Self;
    async fn calculate_user_risk(&self, tenant_id: Uuid, user_id: Uuid, entitlements: &[RiskLevel], sod_violation_count: usize) -> Result<RiskScore>;
    async fn get_risk_level(&self, tenant_id: Uuid, score: u8) -> Result<RiskLevel>;
    async fn configure_thresholds(&self, tenant_id: Uuid, thresholds: RiskThresholds, actor_id: Uuid) -> Result<RiskThresholds>;
    async fn get_thresholds(&self, tenant_id: Uuid) -> Result<RiskThresholds>;
    async fn record_risk_history(&self, tenant_id: Uuid, user_id: Uuid, score: &RiskScore) -> Result<()>;
    async fn get_risk_trend(&self, tenant_id: Uuid, user_id: Uuid, since: DateTime<Utc>) -> Result<Vec<RiskHistory>>;
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

### SoD Types (F-005)

```rust
/// An SoD rule defining prohibited or required entitlement combinations
pub struct SodRule {
    pub id: SodRuleId,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub conflict_type: SodConflictType,
    pub entitlement_ids: Vec<Uuid>,
    pub max_count: Option<u32>,  // For cardinality rules
    pub severity: SodSeverity,
    pub status: SodRuleStatus,
    pub orphaned: bool,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An SoD violation detected in the system
pub struct SodViolation {
    pub id: SodViolationId,
    pub tenant_id: Uuid,
    pub rule_id: SodRuleId,
    pub user_id: Uuid,
    pub entitlement_ids: Vec<Uuid>,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub status: SodViolationStatus,
}

/// An SoD exemption allowing a user to bypass a rule
pub struct SodExemption {
    pub id: SodExemptionId,
    pub tenant_id: Uuid,
    pub rule_id: SodRuleId,
    pub user_id: Uuid,
    pub justification: String,  // Min 10 characters
    pub granted_at: DateTime<Utc>,
    pub granted_by: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: SodExemptionStatus,
}

/// Result of preventive validation
pub struct PreventiveValidationResult {
    pub is_valid: bool,
    pub violations: Vec<SodViolationInfo>,
}

/// Information about a single SoD violation
pub struct SodViolationInfo {
    pub rule_id: SodRuleId,
    pub rule_name: String,
    pub conflicting_entitlements: Vec<Uuid>,
    pub severity: SodSeverity,
    pub message: String,
}
```

### Risk Assessment Types (F-006)

```rust
/// A calculated risk score for a user
pub struct RiskScore {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub score: u8,           // 0-100
    pub level: RiskLevel,    // Low/Medium/High/Critical
    pub factors: Vec<RiskFactorResult>,
    pub calculated_at: DateTime<Utc>,
}

/// Contribution of a single factor to the risk score
pub struct RiskFactorResult {
    pub name: String,        // e.g., "entitlements", "sod_violations"
    pub weight: f64,         // 0.0-1.0 (0.6 for entitlements, 0.4 for SoD)
    pub raw_value: f64,      // 0-100 before weighting
    pub contribution: f64,   // Weighted contribution
    pub description: Option<String>,
}

/// Per-tenant risk threshold configuration
pub struct RiskThresholds {
    pub tenant_id: Uuid,
    pub low_max: u8,         // Default: 25
    pub medium_max: u8,      // Default: 50
    pub high_max: u8,        // Default: 75
    pub updated_at: DateTime<Utc>,
    pub updated_by: Uuid,
}

/// Historical risk record for trend analysis
pub struct RiskHistory {
    pub id: RiskHistoryId,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub score: u8,
    pub level: RiskLevel,
    pub recorded_at: DateTime<Utc>,
}
```

### ID Types

```rust
pub struct ApplicationId(Uuid);
pub struct EntitlementId(Uuid);
pub struct AssignmentId(Uuid);
pub struct SodRuleId(Uuid);       // F-005
pub struct SodViolationId(Uuid);  // F-005
pub struct SodExemptionId(Uuid);  // F-005
pub struct RiskHistoryId(Uuid);   // F-006
```

### Enums

```rust
pub enum RiskLevel { Low, Medium, High, Critical }
pub enum EntitlementStatus { Active, Inactive, PendingApproval }
pub enum AssignmentStatus { Active, PendingApproval, Revoked, Expired }
pub enum AssignmentSource { Direct, Role, Birthright }
pub enum AppType { Custom, Saas, OnPremise, Cloud }
pub enum AppStatus { Active, Inactive, Deprecated }

// SoD Enums (F-005)
pub enum SodConflictType { Exclusive, Cardinality, Inclusive }
pub enum SodSeverity { Low, Medium, High, Critical }
pub enum SodRuleStatus { Active, Inactive }
pub enum SodViolationStatus { Active, Resolved }
pub enum SodExemptionStatus { Active, Revoked, Expired }
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

    // SoD Errors (F-005)
    SodRuleNotFound(Uuid),
    SodViolationNotFound(Uuid),
    SodExemptionNotFound(Uuid),
    SodRuleTooFewEntitlements(usize),
    SodRuleInvalidMaxCount(u32, usize),
    SodRuleMaxCountRequired,
    SodExemptionJustificationTooShort(usize),
    SodExemptionExpiryInPast,
    SodMultipleViolations(usize),

    // Risk Assessment Errors (F-006)
    RiskThresholdInvalid { reason: String },
    RiskCalculationFailed { reason: String },
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

## SoD Usage Example (F-005)

```rust
use xavyo_governance::services::{
    SodService, SodValidationService, SodExemptionService,
    CreateSodRuleInput, CreateSodExemptionInput,
    InMemorySodRuleStore, InMemorySodViolationStore, InMemorySodExemptionStore,
};
use xavyo_governance::types::{SodConflictType, SodSeverity};
use xavyo_governance::audit::InMemoryAuditStore;
use std::sync::Arc;

// Create stores
let rule_store = Arc::new(InMemorySodRuleStore::new());
let violation_store = Arc::new(InMemorySodViolationStore::new());
let exemption_store = Arc::new(InMemorySodExemptionStore::new());
let audit_store = Arc::new(InMemoryAuditStore::new());

// Create services
let sod_service = SodService::new(rule_store.clone(), audit_store.clone());
let validation_service = SodValidationService::new(
    rule_store.clone(),
    violation_store.clone(),
    exemption_store.clone(),
);
let exemption_service = SodExemptionService::new(exemption_store.clone(), audit_store.clone());

let tenant_id = uuid::Uuid::new_v4();
let admin_id = uuid::Uuid::new_v4();
let ap_approver_id = uuid::Uuid::new_v4();
let ap_creator_id = uuid::Uuid::new_v4();

// Create an exclusive SoD rule (AP Segregation)
let rule = sod_service.create_rule(
    tenant_id,
    CreateSodRuleInput {
        name: "AP Segregation".to_string(),
        description: Some("Prevent AP fraud".to_string()),
        conflict_type: SodConflictType::Exclusive,
        entitlement_ids: vec![ap_approver_id, ap_creator_id],
        max_count: None,
        severity: SodSeverity::Critical,
        created_by: admin_id,
    },
).await?;

// Validate before assigning
let user_id = uuid::Uuid::new_v4();
let current_entitlements = vec![ap_approver_id]; // User already has this
let result = validation_service.validate_preventive(
    tenant_id,
    user_id,
    ap_creator_id, // Trying to add this
    &current_entitlements,
).await?;

if !result.is_valid {
    for violation in &result.violations {
        println!("Violation: {} - {}", violation.rule_name, violation.message);
    }
}

// Grant exemption to bypass the rule
let exemption = exemption_service.grant_exemption(
    tenant_id,
    CreateSodExemptionInput {
        rule_id: rule.id,
        user_id,
        justification: "Approved by CFO for Q4 close".to_string(),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
        granted_by: admin_id,
    },
).await?;

// Now validation passes for exempted user
let result = validation_service.validate_preventive(
    tenant_id,
    user_id,
    ap_creator_id,
    &current_entitlements,
).await?;
assert!(result.is_valid); // Passes because of exemption
```

## Risk Assessment Usage Example (F-006)

```rust
use xavyo_governance::services::{
    RiskAssessmentService, InMemoryRiskThresholdStore, InMemoryRiskHistoryStore,
};
use xavyo_governance::types::RiskLevel;
use xavyo_governance::audit::InMemoryAuditStore;
use std::sync::Arc;

// Create stores
let threshold_store = Arc::new(InMemoryRiskThresholdStore::new());
let history_store = Arc::new(InMemoryRiskHistoryStore::new());
let audit_store = Arc::new(InMemoryAuditStore::new());

// Create service
let risk_service = RiskAssessmentService::new(
    threshold_store,
    history_store,
    audit_store,
);

let tenant_id = uuid::Uuid::new_v4();
let user_id = uuid::Uuid::new_v4();

// User's entitlement risk levels
let entitlements = vec![RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
let sod_violations = 1;

// Calculate risk
let risk = risk_service.calculate_user_risk(
    tenant_id,
    user_id,
    &entitlements,
    sod_violations,
).await?;

// Risk formula:
// EntitlementFactor = avg(10, 40, 70) = 40, * 0.6 = 24
// SodFactor = min(100, 1 * 25) = 25, * 0.4 = 10
// Total = 34 (Medium)
println!("Score: {}, Level: {:?}", risk.score, risk.level);

// Record for trending
risk_service.record_risk_history(tenant_id, user_id, &risk).await?;

// Later: Get trend for last 30 days
let since = chrono::Utc::now() - chrono::Duration::days(30);
let trend = risk_service.get_risk_trend(tenant_id, user_id, since).await?;

for entry in trend {
    println!("{}: {} ({:?})", entry.recorded_at, entry.score, entry.level);
}

// Configure custom thresholds (admin only)
let admin_id = uuid::Uuid::new_v4();
use xavyo_governance::types::RiskThresholds;

let thresholds = RiskThresholds {
    tenant_id,
    low_max: 30,      // Low: 0-30 (default: 25)
    medium_max: 60,   // Medium: 31-60 (default: 50)
    high_max: 85,     // High: 61-85 (default: 75)
    ..Default::default()
};

risk_service.configure_thresholds(tenant_id, thresholds, admin_id).await?;
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
