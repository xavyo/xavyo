//! Service layer for identity governance.
//!
//! This module provides business logic services for managing entitlements,
//! assignments, validation rules, and Separation of Duties (SoD).

pub mod assignment;
pub mod entitlement;
pub mod sod;
pub mod sod_exemption;
pub mod sod_validation;
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

// Re-export SoD types
pub use sod::{
    CreateSodRuleInput, InMemorySodRuleStore, SodRule, SodRuleStore, SodService, UpdateSodRuleInput,
};
pub use sod_exemption::{
    CreateSodExemptionInput, InMemorySodExemptionStore, SodExemption, SodExemptionService,
    SodExemptionStatus, SodExemptionStore,
};
pub use sod_validation::{
    DetectiveScanResult, InMemorySodViolationStore, PreventiveValidationResult, RuleScanResult,
    SodValidationService, SodViolation, SodViolationInfo, SodViolationStore, UserViolationReport,
};
