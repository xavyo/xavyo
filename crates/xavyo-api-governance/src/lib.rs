//! Governance API endpoints for xavyo.
//!
//! This crate provides REST API endpoints for entitlement management,
//! part of the Identity Governance and Administration (IGA) feature set.
//!
//! # Endpoints
//!
//! ## Entitlement Management (F033)
//! - `GET/POST /governance/applications` - Application registry
//! - `GET/POST /governance/entitlements` - Entitlement definitions
//! - `GET/POST /governance/assignments` - User/group assignments
//! - `GET/POST /governance/role-entitlements` - Role mappings
//! - `GET /governance/users/{id}/effective-access` - Effective access queries
//!
//! ## Separation of Duties (F034)
//! - `GET/POST /governance/sod-rules` - `SoD` rule management
//! - `GET/PUT/DELETE /governance/sod-rules/{id}` - Individual rule operations
//! - `POST /governance/sod-rules/{id}/enable` - Enable a rule
//! - `POST /governance/sod-rules/{id}/disable` - Disable a rule

pub mod consumers;
pub mod error;
pub mod handlers;
pub mod jobs;
pub mod models;
pub mod router;
pub mod services;

#[cfg(feature = "kafka")]
pub use consumers::{AssignmentCreatedConsumer, ManagerChangeConsumer, SodViolationConsumer};
pub use error::{ApiGovernanceError, ApiResult, ErrorResponse};
pub use jobs::{
    BulkActionJob, BulkActionJobError, BulkActionJobStats, EscalationJob, EscalationJobError,
    EscalationStats, FailedOperationRetryJob, GracePeriodExpirationJob, MicroCertExpirationJob,
    MicroCertExpirationJobError, MicroCertExpirationStats, ScheduledTransitionJob,
};
pub use router::governance_router;
