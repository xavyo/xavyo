//! Service layer for identity governance.
//!
//! This module provides business logic services for managing entitlements,
//! assignments, and validation rules.

pub mod assignment;
pub mod entitlement;
pub mod validation;

// Re-export commonly used types
pub use assignment::{
    AssignEntitlementInput, AssignmentService, AssignmentStore, EntitlementAssignment,
    InMemoryAssignmentStore,
};
pub use entitlement::{
    CreateEntitlementInput, Entitlement, EntitlementFilter, EntitlementService, EntitlementStore,
    InMemoryEntitlementStore, ListOptions, UpdateEntitlementInput,
};
pub use validation::{
    ValidationError, ValidationResult, ValidationRule, ValidationRuleType, ValidationService,
    Validator,
};
