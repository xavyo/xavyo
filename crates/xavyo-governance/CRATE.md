# xavyo-governance

> Identity Governance and Administration (IGA) domain logic for xavyo.

## Purpose

Provides core domain logic for entitlement management including applications, entitlements, assignments, and effective access queries. Supports role-based access, certification campaigns, access requests, and SoD (Separation of Duties) rule enforcement. This crate contains domain types and logic used by the governance API layer.

## Layer

domain

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Database models

### External (key)
- `sqlx` - Database queries
- `chrono` - Timestamps
- `serde` - Serialization

## Public API

### Types

```rust
/// Application identifier
pub struct ApplicationId(Uuid);

/// Entitlement identifier
pub struct EntitlementId(Uuid);

/// Assignment identifier
pub struct AssignmentId(Uuid);

/// Application types
pub enum AppType {
    Custom,
    Saas,
    OnPremise,
    Cloud,
}

/// Application status
pub enum AppStatus {
    Active,
    Inactive,
    Deprecated,
}

/// Entitlement status
pub enum EntitlementStatus {
    Active,
    Inactive,
    PendingApproval,
}

/// Assignment target type
pub enum AssignmentTargetType {
    User,
    Group,
    Role,
}

/// Assignment status
pub enum AssignmentStatus {
    Active,
    PendingApproval,
    Revoked,
    Expired,
}

/// Source of assignment
pub enum AssignmentSource {
    Direct,       // Manually assigned
    Role,         // Inherited from role
    Birthright,   // Auto-assigned by policy
}

/// Risk level classification
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}
```

### Errors

```rust
/// Governance operation errors
pub enum GovernanceError {
    NotFound { resource: String, id: String },
    InvalidState { current: String, expected: String },
    SodViolation { rule_id: Uuid, message: String },
    ApprovalRequired { workflow_id: Uuid },
    DatabaseError(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, GovernanceError>;
```

## Usage Example

```rust
use xavyo_governance::{
    ApplicationId, EntitlementId, AssignmentId,
    AppType, RiskLevel, AssignmentSource,
    GovernanceError, Result,
};

// Create typed identifiers
let app_id = ApplicationId::new();
let entitlement_id = EntitlementId::new();

// Use risk levels for entitlements
fn classify_risk(privilege_level: u32) -> RiskLevel {
    match privilege_level {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

// Handle governance errors
fn process_assignment() -> Result<()> {
    Err(GovernanceError::SodViolation {
        rule_id: uuid::Uuid::new_v4(),
        message: "Cannot have both AP_APPROVER and AP_PROCESSOR".to_string(),
    })
}
```

## Integration Points

- **Consumed by**: `xavyo-api-governance`, `xavyo-api-users`
- **Provides**: Domain types and logic for IGA operations
- **Database**: Uses models from `xavyo-db`

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never assign high-risk entitlements without approval workflow
- Never skip SoD checks before assignment creation
- Never allow direct database access bypassing service layer
- Never create assignments without tenant context

## Related Crates

- `xavyo-api-governance` - REST API for governance operations
- `xavyo-db` - Database models (GovApplication, GovEntitlement, etc.)
- `xavyo-authorization` - Policy enforcement for entitlements
