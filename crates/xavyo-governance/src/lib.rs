//! Identity Governance and Administration (IGA) domain logic.
//!
//! This crate provides the core domain logic for entitlement management,
//! including applications, entitlements, assignments, and effective access queries.
//!
//! # Features
//!
//! - Application registry management
//! - Granular entitlement definitions with risk levels
//! - User and group entitlement assignments
//! - Role-to-entitlement mappings
//! - Effective access consolidation
//! - Audit logging for all governance changes
//! - Separation of Duties (SoD) rule management
//! - SoD violation detection (preventive and detective)
//! - SoD exemption handling with time-bound approvals
//!
//! # Services
//!
//! The [`services`] module provides business logic for:
//! - [`services::EntitlementService`] - CRUD operations for entitlements
//! - [`services::AssignmentService`] - Assign/revoke entitlements for users
//! - [`services::ValidationService`] - Validate assignments against business rules
//! - [`services::SodService`] - Manage SoD rules (exclusive, cardinality, inclusive)
//! - [`services::SodValidationService`] - Validate assignments against SoD rules
//! - [`services::SodExemptionService`] - Manage SoD exemptions for approved violations
//!
//! # Audit
//!
//! The [`audit`] module provides audit logging following the F-003 pattern:
//! - [`audit::AuditStore`] trait for pluggable storage backends
//! - [`audit::InMemoryAuditStore`] for testing
//! - [`audit::EntitlementAuditEvent`] for tracking changes

pub mod audit;
pub mod error;
pub mod services;
pub mod types;

// Re-export commonly used types
pub use error::{GovernanceError, Result};
pub use types::{
    AppStatus,
    AppType,
    ApplicationId,
    AssignmentId,
    AssignmentSource,
    AssignmentStatus,
    AssignmentTargetType,
    EntitlementId,
    EntitlementStatus,
    RiskLevel,
    // SoD types
    SodConflictType,
    SodExemptionId,
    SodRuleId,
    SodRuleStatus,
    SodSeverity,
    SodViolationId,
    SodViolationStatus,
};

// Re-export service types
pub use services::{
    AssignEntitlementInput,
    AssignmentService,
    CreateEntitlementInput,
    // SoD service types
    CreateSodExemptionInput,
    CreateSodRuleInput,
    DetectiveScanResult,
    Entitlement,
    EntitlementFilter,
    EntitlementService,
    InMemorySodExemptionStore,
    InMemorySodRuleStore,
    InMemorySodViolationStore,
    ListOptions,
    PreventiveValidationResult,
    RuleScanResult,
    SodExemption,
    SodExemptionService,
    SodExemptionStatus,
    SodExemptionStore,
    SodRule,
    SodRuleStore,
    SodService,
    SodValidationService,
    SodViolation,
    SodViolationInfo,
    SodViolationStore,
    UpdateEntitlementInput,
    UpdateSodRuleInput,
    UserViolationReport,
};

// Re-export audit types
pub use audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEvent, InMemoryAuditStore};
