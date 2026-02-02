# xavyo-nhi

> Core types and traits for Non-Human Identity (NHI) management.

## Purpose

Provides a unified abstraction for non-human identities including service accounts and AI agents. Both share common governance needs: ownership, lifecycle management, risk scoring, and certification campaigns. This crate defines the common trait and types that enable unified NHI governance.

## Layer

foundation

## Dependencies

### Internal (xavyo)
None (standalone foundation crate)

### External (key)
- `serde` - Serialization
- `uuid` - Identity identifiers
- `chrono` - Timestamps
- `async-trait` - Async trait support

## Public API

### Types

```rust
/// Type of non-human identity
pub enum NhiType {
    ServiceAccount,
    AiAgent,
}

/// Lifecycle status of an NHI
pub enum NhiStatus {
    Active,
    Suspended,
    Deprovisioned,
}

/// Risk level classification
pub enum NhiRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Factors contributing to risk score
pub struct RiskFactors {
    pub privilege_level: u32,      // 0-100 based on entitlements
    pub credential_age_days: u32,  // Days since credential rotation
    pub unused_days: u32,          // Days since last activity
    pub has_owner: bool,           // Whether ownership is assigned
}
```

### Traits

```rust
/// Common interface for all non-human identities
pub trait NonHumanIdentity: Send + Sync {
    /// Unique identifier
    fn id(&self) -> Uuid;

    /// Tenant this NHI belongs to
    fn tenant_id(&self) -> Uuid;

    /// Type of NHI (ServiceAccount or AiAgent)
    fn nhi_type(&self) -> NhiType;

    /// Current lifecycle status
    fn status(&self) -> NhiStatus;

    /// Human owner responsible for this NHI
    fn owner_id(&self) -> Option<Uuid>;

    /// Display name for UI
    fn display_name(&self) -> &str;

    /// When this NHI was created
    fn created_at(&self) -> DateTime<Utc>;

    /// When credentials were last rotated
    fn last_credential_rotation(&self) -> Option<DateTime<Utc>>;

    /// When this NHI was last used
    fn last_activity(&self) -> Option<DateTime<Utc>>;
}
```

### Functions

```rust
/// Calculate risk level from risk factors
pub fn calculate_risk_level(factors: &RiskFactors) -> NhiRiskLevel;
```

## Usage Example

```rust
use xavyo_nhi::{NonHumanIdentity, NhiType, NhiStatus, NhiRiskLevel, RiskFactors, calculate_risk_level};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Implement NonHumanIdentity for your types
struct ServiceAccount {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    owner_id: Option<Uuid>,
    status: NhiStatus,
    created_at: DateTime<Utc>,
    last_rotation: Option<DateTime<Utc>>,
    last_activity: Option<DateTime<Utc>>,
}

impl NonHumanIdentity for ServiceAccount {
    fn id(&self) -> Uuid { self.id }
    fn tenant_id(&self) -> Uuid { self.tenant_id }
    fn nhi_type(&self) -> NhiType { NhiType::ServiceAccount }
    fn status(&self) -> NhiStatus { self.status.clone() }
    fn owner_id(&self) -> Option<Uuid> { self.owner_id }
    fn display_name(&self) -> &str { &self.name }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn last_credential_rotation(&self) -> Option<DateTime<Utc>> { self.last_rotation }
    fn last_activity(&self) -> Option<DateTime<Utc>> { self.last_activity }
}

// Calculate risk
let factors = RiskFactors {
    privilege_level: 80,
    credential_age_days: 180,
    unused_days: 30,
    has_owner: false,
};
let risk = calculate_risk_level(&factors);
assert_eq!(risk, NhiRiskLevel::High);
```

## Integration Points

- **Consumed by**: `xavyo-db` (models), `xavyo-api-agents`, `xavyo-governance`
- **Provides**: Unified interface for NHI governance operations

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `sqlx` | Enable SQLx derives for types | sqlx |

## Anti-Patterns

- Never create NHIs without assigning an owner
- Never skip credential rotation for active NHIs
- Never ignore high-risk NHIs in certification campaigns
- Never allow NHIs to exist without tenant context

## Related Crates

- `xavyo-api-agents` - AI agent management API
- `xavyo-governance` - NHI certification campaigns
- `xavyo-db` - Persistent NHI models
