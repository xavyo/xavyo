//! Validation service for entitlement assignments.
//!
//! This module provides pluggable validators for checking assignment rules.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::services::assignment::AssignEntitlementInput;

// ============================================================================
// Types
// ============================================================================

/// Type of validation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationRuleType {
    /// Requires a prerequisite entitlement to be assigned first.
    RequiresPrerequisite,
    /// Maximum number of assignments per user.
    MaxAssignmentsPerUser,
    /// Requires a justification to be provided.
    RequiresJustification,
}

/// A validation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Unique identifier.
    pub id: Uuid,
    /// The entitlement this rule applies to.
    pub entitlement_id: Uuid,
    /// Type of rule.
    pub rule_type: ValidationRuleType,
    /// Rule parameters (JSON).
    pub parameters: serde_json::Value,
}

/// Result of a validation check.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Whether the validation passed.
    pub is_valid: bool,
    /// Validation errors (if any).
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    /// Create a successful validation result.
    pub fn success() -> Self {
        Self {
            is_valid: true,
            errors: vec![],
        }
    }

    /// Create a failed validation result with a single error.
    pub fn failure(error: ValidationError) -> Self {
        Self {
            is_valid: false,
            errors: vec![error],
        }
    }

    /// Create a failed validation result with multiple errors.
    pub fn failures(errors: Vec<ValidationError>) -> Self {
        Self {
            is_valid: errors.is_empty(),
            errors,
        }
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        if !other.is_valid {
            self.is_valid = false;
        }
        self.errors.extend(other.errors);
    }
}

/// A validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Field that caused the error (optional).
    pub field: Option<String>,
}

impl ValidationError {
    /// Create a new validation error.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            field: None,
        }
    }

    /// Create a new validation error with a field.
    pub fn with_field(
        code: impl Into<String>,
        message: impl Into<String>,
        field: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            field: Some(field.into()),
        }
    }
}

// ============================================================================
// Validator Trait
// ============================================================================

/// Trait for pluggable validators.
pub trait Validator: Send + Sync {
    /// Validate an assignment request.
    fn validate(
        &self,
        input: &AssignEntitlementInput,
        user_entitlements: &[Uuid],
    ) -> ValidationResult;
}

// ============================================================================
// Built-in Validators
// ============================================================================

/// Validates that expiry date is in the future.
#[derive(Debug, Default)]
pub struct ExpiryDateValidator;

impl Validator for ExpiryDateValidator {
    fn validate(
        &self,
        input: &AssignEntitlementInput,
        _user_entitlements: &[Uuid],
    ) -> ValidationResult {
        if let Some(expires_at) = input.expires_at {
            if expires_at <= Utc::now() {
                return ValidationResult::failure(ValidationError::with_field(
                    "INVALID_EXPIRY_DATE",
                    "Expiry date must be in the future",
                    "expires_at",
                ));
            }
        }
        ValidationResult::success()
    }
}

/// Validates that the assignment doesn't already exist.
#[derive(Debug, Default)]
pub struct DuplicateAssignmentValidator;

impl DuplicateAssignmentValidator {
    /// Create a new duplicate assignment validator.
    pub fn new() -> Self {
        Self
    }
}

impl Validator for DuplicateAssignmentValidator {
    fn validate(
        &self,
        input: &AssignEntitlementInput,
        user_entitlements: &[Uuid],
    ) -> ValidationResult {
        if user_entitlements.contains(&input.entitlement_id) {
            return ValidationResult::failure(ValidationError::new(
                "DUPLICATE_ASSIGNMENT",
                format!(
                    "User already has entitlement {} assigned",
                    input.entitlement_id
                ),
            ));
        }
        ValidationResult::success()
    }
}

/// Validates that a prerequisite entitlement is assigned.
#[derive(Debug)]
pub struct PrerequisiteValidator {
    prerequisite_entitlement_id: Uuid,
}

impl PrerequisiteValidator {
    /// Create a new prerequisite validator.
    pub fn new(prerequisite_entitlement_id: Uuid) -> Self {
        Self {
            prerequisite_entitlement_id,
        }
    }
}

impl Validator for PrerequisiteValidator {
    fn validate(
        &self,
        _input: &AssignEntitlementInput,
        user_entitlements: &[Uuid],
    ) -> ValidationResult {
        if !user_entitlements.contains(&self.prerequisite_entitlement_id) {
            return ValidationResult::failure(ValidationError::new(
                "PREREQUISITE_NOT_MET",
                format!(
                    "Prerequisite entitlement {} must be assigned first",
                    self.prerequisite_entitlement_id
                ),
            ));
        }
        ValidationResult::success()
    }
}

/// Validates that a justification is provided.
#[derive(Debug, Default)]
pub struct JustificationRequiredValidator;

impl Validator for JustificationRequiredValidator {
    fn validate(
        &self,
        input: &AssignEntitlementInput,
        _user_entitlements: &[Uuid],
    ) -> ValidationResult {
        match &input.justification {
            Some(j) if !j.trim().is_empty() => ValidationResult::success(),
            _ => ValidationResult::failure(ValidationError::with_field(
                "JUSTIFICATION_REQUIRED",
                "A justification is required for this assignment",
                "justification",
            )),
        }
    }
}

// ============================================================================
// Validation Service
// ============================================================================

/// Service for validating entitlement assignments.
pub struct ValidationService {
    validators: Vec<Box<dyn Validator>>,
}

impl Default for ValidationService {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationService {
    /// Create a new validation service.
    pub fn new() -> Self {
        Self { validators: vec![] }
    }

    /// Add a validator.
    pub fn add_validator(&mut self, validator: Box<dyn Validator>) {
        self.validators.push(validator);
    }

    /// Create with default validators (expiry date only).
    pub fn with_defaults() -> Self {
        let mut service = Self::new();
        service.add_validator(Box::new(ExpiryDateValidator));
        service
    }

    /// Validate an assignment request.
    pub async fn validate_assignment(
        &self,
        _tenant_id: Uuid,
        input: &AssignEntitlementInput,
        user_entitlements: &[Uuid],
    ) -> ValidationResult {
        let mut result = ValidationResult::success();

        for validator in &self.validators {
            let validator_result = validator.validate(input, user_entitlements);
            result.merge(validator_result);
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_input() -> AssignEntitlementInput {
        AssignEntitlementInput {
            entitlement_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            assigned_by: Uuid::new_v4(),
            expires_at: None,
            justification: None,
        }
    }

    #[test]
    fn test_expiry_date_validation() {
        let validator = ExpiryDateValidator;

        // No expiry - should pass
        let input = create_input();
        let result = validator.validate(&input, &[]);
        assert!(result.is_valid);

        // Future expiry - should pass
        let mut input = create_input();
        input.expires_at = Some(Utc::now() + Duration::days(30));
        let result = validator.validate(&input, &[]);
        assert!(result.is_valid);

        // Past expiry - should fail
        let mut input = create_input();
        input.expires_at = Some(Utc::now() - Duration::days(1));
        let result = validator.validate(&input, &[]);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].code, "INVALID_EXPIRY_DATE");
    }

    #[test]
    fn test_prerequisite_validation() {
        let prereq_id = Uuid::new_v4();
        let validator = PrerequisiteValidator::new(prereq_id);
        let input = create_input();

        // Without prerequisite - should fail
        let result = validator.validate(&input, &[]);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].code, "PREREQUISITE_NOT_MET");

        // With prerequisite - should pass
        let result = validator.validate(&input, &[prereq_id]);
        assert!(result.is_valid);
    }

    #[test]
    fn test_duplicate_validation() {
        let entitlement_id = Uuid::new_v4();
        let validator = DuplicateAssignmentValidator::new();

        let mut input = create_input();
        input.entitlement_id = entitlement_id;

        // Not already assigned - should pass
        let result = validator.validate(&input, &[]);
        assert!(result.is_valid);

        // Already assigned - should fail
        let result = validator.validate(&input, &[entitlement_id]);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].code, "DUPLICATE_ASSIGNMENT");
    }

    #[tokio::test]
    async fn test_validation_success() {
        let mut service = ValidationService::new();
        service.add_validator(Box::new(ExpiryDateValidator));

        let input = create_input();
        let result = service
            .validate_assignment(Uuid::new_v4(), &input, &[])
            .await;
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_multiple_validation_errors() {
        let prereq_id = Uuid::new_v4();
        let mut service = ValidationService::new();
        service.add_validator(Box::new(ExpiryDateValidator));
        service.add_validator(Box::new(PrerequisiteValidator::new(prereq_id)));
        service.add_validator(Box::new(JustificationRequiredValidator));

        let mut input = create_input();
        input.expires_at = Some(Utc::now() - Duration::days(1)); // Invalid

        let result = service
            .validate_assignment(Uuid::new_v4(), &input, &[])
            .await;

        assert!(!result.is_valid);
        // Should have 3 errors: expiry, prerequisite, justification
        assert_eq!(result.errors.len(), 3);
    }

    #[test]
    fn test_validation_result_structure() {
        let result = ValidationResult::success();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());

        let error = ValidationError::new("TEST_ERROR", "Test message");
        let result = ValidationResult::failure(error);
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].code, "TEST_ERROR");
    }

    #[test]
    fn test_validation_result_merge() {
        let mut result1 = ValidationResult::success();
        let result2 = ValidationResult::failure(ValidationError::new("ERROR1", "Error 1"));
        let result3 = ValidationResult::failure(ValidationError::new("ERROR2", "Error 2"));

        result1.merge(result2);
        assert!(!result1.is_valid);
        assert_eq!(result1.errors.len(), 1);

        result1.merge(result3);
        assert_eq!(result1.errors.len(), 2);
    }

    #[test]
    fn test_justification_required_validation() {
        let validator = JustificationRequiredValidator;

        // No justification - should fail
        let input = create_input();
        let result = validator.validate(&input, &[]);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].code, "JUSTIFICATION_REQUIRED");

        // Empty justification - should fail
        let mut input = create_input();
        input.justification = Some("".to_string());
        let result = validator.validate(&input, &[]);
        assert!(!result.is_valid);

        // Whitespace only - should fail
        let mut input = create_input();
        input.justification = Some("   ".to_string());
        let result = validator.validate(&input, &[]);
        assert!(!result.is_valid);

        // Valid justification - should pass
        let mut input = create_input();
        input.justification = Some("Required for project".to_string());
        let result = validator.validate(&input, &[]);
        assert!(result.is_valid);
    }
}
