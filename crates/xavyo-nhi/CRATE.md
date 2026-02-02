# xavyo-nhi

> Core types and traits for Non-Human Identity (NHI) management.

## Purpose

Provides a unified abstraction for non-human identities including service accounts and AI agents. Both share common governance needs: ownership, lifecycle management, risk scoring, and certification campaigns. This crate defines the common trait and types that enable unified NHI governance.

## Layer

foundation

## Status

🟢 **stable**

Production-ready with comprehensive documentation and test coverage. 37+ unit tests, 21+ doc tests, all public API items documented with runnable examples.

## Dependencies

### Internal (xavyo)
None (standalone foundation crate)

### External (key)
- `serde` - Serialization (snake_case JSON format)
- `uuid` - Identity identifiers
- `chrono` - Timestamps for lifecycle tracking
- `async-trait` - Async trait support

## Public API

### Types

```rust
/// Type of non-human identity
pub enum NhiType {
    ServiceAccount, // Machine-to-machine credentials
    AiAgent,        // AI/ML agents with tool permissions
}

/// Lifecycle status of an NHI
pub enum NhiStatus {
    Active,              // Can be used
    Inactive,            // Not recently used
    Suspended,           // Blocked, requires admin review
    PendingCertification, // Awaiting owner re-certification
    Expired,             // Past expiration date
    Revoked,             // Permanently disabled
}

/// Risk level classification (implements Ord)
pub enum NhiRiskLevel {
    Low,      // Score 0-25, no action needed
    Medium,   // Score 26-50, monitor
    High,     // Score 51-75, action recommended, alerts
    Critical, // Score 76-100, immediate action, alerts
}

/// Factors contributing to risk score
pub struct RiskFactors {
    pub staleness_days: Option<i64>,      // Days since last activity (0-40 pts)
    pub credential_age_days: Option<i64>, // Days since rotation (0-30 pts)
    pub scope_count: Option<u32>,         // Number of entitlements (0-30 pts)
}

/// Parse errors
pub struct NhiTypeParseError(pub String);
pub struct NhiStatusParseError(pub String);
```

### Traits

```rust
/// Common interface for all non-human identities
pub trait NonHumanIdentity: Send + Sync {
    // Required methods (14 total)
    fn id(&self) -> Uuid;
    fn tenant_id(&self) -> Uuid;  // CRITICAL: Multi-tenant isolation
    fn name(&self) -> &str;
    fn description(&self) -> Option<&str>;
    fn nhi_type(&self) -> NhiType;
    fn owner_id(&self) -> Uuid;
    fn backup_owner_id(&self) -> Option<Uuid>;
    fn status(&self) -> NhiStatus;
    fn created_at(&self) -> DateTime<Utc>;
    fn expires_at(&self) -> Option<DateTime<Utc>>;
    fn last_activity_at(&self) -> Option<DateTime<Utc>>;
    fn risk_score(&self) -> u32;
    fn next_certification_at(&self) -> Option<DateTime<Utc>>;
    fn last_certified_at(&self) -> Option<DateTime<Utc>>;

    // Derived methods (5 total)
    fn is_active(&self) -> bool;
    fn is_expired(&self) -> bool;
    fn is_stale(&self, threshold_days: i64) -> bool;
    fn needs_certification(&self) -> bool;
    fn risk_level(&self) -> NhiRiskLevel;
}
```

### Functions

```rust
/// Calculate risk score (0-100) from factors
pub fn calculate_risk_score(factors: &RiskFactors) -> u32;

/// Convert score to risk level
pub fn calculate_risk_level(score: u32) -> NhiRiskLevel;

/// Convert risk level name to representative score
pub fn risk_level_to_score(risk_level: &str) -> u32;

/// Clamp score to 0-100 range
pub fn normalize_score(score: i32) -> u32;
```

### Constants (risk::weights module)

```rust
pub const STALENESS_MAX: u32 = 40;
pub const CREDENTIAL_AGE_MAX: u32 = 30;
pub const SCOPE_MAX: u32 = 30;
pub const STALENESS_CRITICAL_DAYS: i64 = 90;
pub const STALENESS_MEDIUM_DAYS: i64 = 30;
pub const CREDENTIAL_CRITICAL_DAYS: i64 = 90;
pub const CREDENTIAL_MEDIUM_DAYS: i64 = 30;
pub const SCOPE_CRITICAL_COUNT: u32 = 50;
pub const SCOPE_MEDIUM_COUNT: u32 = 20;
```

## Usage Example

```rust
use xavyo_nhi::{
    NonHumanIdentity, NhiType, NhiStatus, NhiRiskLevel,
    RiskFactors, calculate_risk_score, calculate_risk_level
};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Implement NonHumanIdentity for your type
struct MyServiceAccount {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    owner_id: Uuid,
    status: NhiStatus,
    created_at: DateTime<Utc>,
    risk_score: u32,
}

impl NonHumanIdentity for MyServiceAccount {
    fn id(&self) -> Uuid { self.id }
    fn tenant_id(&self) -> Uuid { self.tenant_id }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> Option<&str> { None }
    fn nhi_type(&self) -> NhiType { NhiType::ServiceAccount }
    fn owner_id(&self) -> Uuid { self.owner_id }
    fn backup_owner_id(&self) -> Option<Uuid> { None }
    fn status(&self) -> NhiStatus { self.status }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn expires_at(&self) -> Option<DateTime<Utc>> { None }
    fn last_activity_at(&self) -> Option<DateTime<Utc>> { None }
    fn risk_score(&self) -> u32 { self.risk_score }
    fn next_certification_at(&self) -> Option<DateTime<Utc>> { None }
    fn last_certified_at(&self) -> Option<DateTime<Utc>> { None }
}

// Use derived methods
fn audit_nhi(nhi: &impl NonHumanIdentity) {
    if nhi.is_stale(30) {
        println!("NHI {} inactive for 30+ days", nhi.name());
    }
    if nhi.risk_level().should_alert() {
        println!("NHI {} has high risk level", nhi.name());
    }
}

// Calculate risk from factors
let factors = RiskFactors {
    staleness_days: Some(45),       // 20 pts
    credential_age_days: Some(100), // 30 pts
    scope_count: Some(30),          // 15 pts
};
let score = calculate_risk_score(&factors);
let level = calculate_risk_level(score);
assert_eq!(score, 65);
assert_eq!(level, NhiRiskLevel::High);
```

## Multi-Tenant Isolation

**CRITICAL**: Every NHI has a `tenant_id()`. All queries and operations MUST be scoped by tenant to prevent cross-tenant data leakage.

```rust
// CORRECT: Filter by tenant
fn get_nhis(tenant_id: Uuid, all_nhis: &[impl NonHumanIdentity]) -> Vec<&impl NonHumanIdentity> {
    all_nhis.iter().filter(|n| n.tenant_id() == tenant_id).collect()
}

// WRONG: No tenant filter - security violation!
fn get_all_nhis(nhis: &[impl NonHumanIdentity]) -> Vec<&impl NonHumanIdentity> {
    nhis.iter().collect() // DO NOT DO THIS
}
```

## Integration Points

- **Consumed by**: `xavyo-db` (models), `xavyo-api-agents`, `xavyo-api-nhi`, `xavyo-governance`
- **Provides**: Unified interface for NHI governance operations

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `sqlx` | Enable SQLx derives for database types | sqlx |

## Anti-Patterns

- **Never** query NHIs without filtering by `tenant_id` - causes cross-tenant data leakage
- **Never** create NHIs without assigning an owner - orphaned accounts are security risks
- **Never** skip credential rotation for active NHIs - stale credentials increase risk
- **Never** ignore high-risk NHIs in certification campaigns - they require immediate attention
- **Never** use `Uuid::nil()` as a placeholder tenant_id - violates multi-tenant isolation

## Related Crates

- `xavyo-api-agents` - AI agent management API
- `xavyo-api-nhi` - Unified NHI management API
- `xavyo-governance` - NHI certification campaigns
- `xavyo-db` - Persistent NHI models
