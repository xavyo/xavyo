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
//!
//! # Services
//!
//! The [`services`] module provides business logic for:
//! - [`services::EntitlementService`] - CRUD operations for entitlements
//! - [`services::AssignmentService`] - Assign/revoke entitlements for users
//! - [`services::ValidationService`] - Validate assignments against business rules
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
    AppStatus, AppType, ApplicationId, AssignmentId, AssignmentSource, AssignmentStatus,
    AssignmentTargetType, EntitlementId, EntitlementStatus, RiskLevel,
};

// Re-export service types
pub use services::{
    AssignEntitlementInput, AssignmentService, CreateEntitlementInput, Entitlement,
    EntitlementFilter, EntitlementService, ListOptions, UpdateEntitlementInput,
};

// Re-export audit types
pub use audit::{AuditStore, EntitlementAuditAction, EntitlementAuditEvent, InMemoryAuditStore};
