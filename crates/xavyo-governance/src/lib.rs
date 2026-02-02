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

pub mod error;
pub mod types;

// Re-export commonly used types
pub use error::{GovernanceError, Result};
pub use types::{
    AppStatus, AppType, ApplicationId, AssignmentId, AssignmentSource, AssignmentStatus,
    AssignmentTargetType, EntitlementId, EntitlementStatus, RiskLevel,
};
