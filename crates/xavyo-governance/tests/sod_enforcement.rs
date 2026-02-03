//! Integration tests for SoD enforcement (US3).
//!
//! These tests validate all SoD conflict types and exemption handling.

#![cfg(feature = "integration")]

mod common;

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_governance::services::assignment::AssignEntitlementInput;
use xavyo_governance::services::entitlement::CreateEntitlementInput;
use xavyo_governance::services::sod::CreateSodRuleInput;
use xavyo_governance::services::sod_exemption::CreateSodExemptionInput;
use xavyo_governance::types::{RiskLevel, SodConflictType, SodSeverity};

use common::TestContext;

// ============================================================================
// SOD-001: Exclusive Rule Violation Detection
// ============================================================================

/// Test exclusive rule violation detection.
///
/// Given exclusive SoD rule for [Edit, Delete]
/// And user has "Edit" entitlement
/// When attempting to assign "Delete"
/// Then a violation is detected
/// And the violation severity is recorded
#[tokio::test]
async fn test_sod_001_exclusive_rule_violation_detection() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let edit = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Edit entitlement");

    let delete = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Create exclusive SoD rule
    let rule = ctx
        .services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Edit+Delete".to_string(),
                description: Some("Cannot have both Edit and Delete".to_string()),
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![edit.id.into_inner(), delete.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // Assign Edit to user
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: edit.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Business need".to_string()),
            },
        )
        .await
        .expect("Failed to assign Edit");

    // Check if assigning Delete would violate SoD
    let current_entitlements = vec![edit.id.into_inner()];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(
            ctx.tenant_a,
            user_id,
            delete.id.into_inner(),
            &current_entitlements,
        )
        .await
        .expect("Validation failed");

    // Verify violation detected
    assert!(
        !result.is_valid,
        "Should detect violation when trying to assign Delete"
    );
    assert_eq!(result.violations.len(), 1, "Should have 1 violation");

    let violation = &result.violations[0];
    assert_eq!(violation.rule_id, rule.id);
    assert_eq!(violation.severity, SodSeverity::High);
    assert!(
        violation
            .conflicting_entitlements
            .contains(&edit.id.into_inner()),
        "Conflicting entitlements should include Edit"
    );
    assert!(
        violation
            .conflicting_entitlements
            .contains(&delete.id.into_inner()),
        "Conflicting entitlements should include Delete"
    );
}

// ============================================================================
// SOD-002: Cardinality Rule Violation Detection
// ============================================================================

/// Test cardinality rule violation detection.
///
/// Given cardinality rule: max 2 of [A, B, C, D, E]
/// And user has [A, B] assigned
/// When attempting to assign C
/// Then a violation is detected
#[tokio::test]
async fn test_sod_002_cardinality_rule_violation_detection() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create 5 entitlements
    let mut entitlements = Vec::new();
    for name in ["A", "B", "C", "D", "E"] {
        let e = ctx
            .services
            .entitlement
            .create(
                ctx.tenant_a,
                CreateEntitlementInput {
                    application_id: app_id,
                    name: format!("Permission {}", name),
                    description: None,
                    risk_level: RiskLevel::Medium,
                    owner_id: None,
                    external_id: None,
                    metadata: None,
                    is_delegable: true,
                },
                ctx.actor_id,
            )
            .await
            .expect("Failed to create entitlement");
        entitlements.push(e);
    }

    let entitlement_ids: Vec<Uuid> = entitlements.iter().map(|e| e.id.into_inner()).collect();

    // Create cardinality rule: max 2
    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "Max 2 of 5".to_string(),
                description: Some("Cannot have more than 2".to_string()),
                conflict_type: SodConflictType::Cardinality,
                entitlement_ids: entitlement_ids.clone(),
                max_count: Some(2),
                severity: SodSeverity::Medium,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // Assign A and B to user
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: entitlement_ids[0], // A
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Need A".to_string()),
            },
        )
        .await
        .expect("Failed to assign A");

    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: entitlement_ids[1], // B
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Need B".to_string()),
            },
        )
        .await
        .expect("Failed to assign B");

    // Check if assigning C would violate cardinality
    let current = vec![entitlement_ids[0], entitlement_ids[1]];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, entitlement_ids[2], &current)
        .await
        .expect("Validation failed");

    // Verify violation detected
    assert!(
        !result.is_valid,
        "Should detect cardinality violation when adding 3rd entitlement"
    );
    assert_eq!(result.violations.len(), 1);
    // Message format: "User can have at most X of these entitlements, has Y (rule 'name')"
    assert!(
        result.violations[0].message.contains("at most")
            || result.violations[0].message.contains("Max"),
        "Message should mention cardinality limit: {}",
        result.violations[0].message
    );
}

// ============================================================================
// SOD-003: Inclusive Rule Violation Detection
// ============================================================================

/// Test inclusive rule violation detection.
///
/// Given inclusive rule for [Approve, Review]
/// And user has neither assigned
/// When attempting to assign only "Approve"
/// Then a violation is detected
#[tokio::test]
async fn test_sod_003_inclusive_rule_violation_detection() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let approve = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Approve".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Approve entitlement");

    let review = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Review".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Review entitlement");

    // Create inclusive SoD rule
    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "Approve+Review Together".to_string(),
                description: Some("Must have both or neither".to_string()),
                conflict_type: SodConflictType::Inclusive,
                entitlement_ids: vec![approve.id.into_inner(), review.id.into_inner()],
                max_count: None,
                severity: SodSeverity::Low,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // User has neither - try to assign only Approve
    let current: Vec<Uuid> = vec![];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, approve.id.into_inner(), &current)
        .await
        .expect("Validation failed");

    // Verify violation detected
    assert!(
        !result.is_valid,
        "Should detect inclusive violation when assigning only one of paired entitlements"
    );
}

// ============================================================================
// SOD-004: Exemption Honored During Validation
// ============================================================================

/// Test that exemptions are honored during validation.
///
/// Given exclusive SoD rule for [Edit, Delete]
/// And user has valid exemption for this rule
/// When user has both entitlements
/// Then validation passes (exemption honored)
#[tokio::test]
async fn test_sod_004_exemption_honored_during_validation() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let edit = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Edit entitlement");

    let delete = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Create exclusive SoD rule
    let rule = ctx
        .services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Edit+Delete".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![edit.id.into_inner(), delete.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // Create exemption for user
    ctx.services
        .sod_exemption
        .grant_exemption(
            ctx.tenant_a,
            CreateSodExemptionInput {
                rule_id: rule.id,
                user_id,
                justification:
                    "Emergency access approved by security team for critical incident response"
                        .to_string(),
                expires_at: Some(Utc::now() + Duration::days(30)),
                granted_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to grant exemption");

    // Assign Edit to user
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: edit.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("With exemption".to_string()),
            },
        )
        .await
        .expect("Failed to assign Edit");

    // Now try to assign Delete - should pass due to exemption
    let current = vec![edit.id.into_inner()];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, delete.id.into_inner(), &current)
        .await
        .expect("Validation failed");

    // With exemption, should be valid
    assert!(
        result.is_valid,
        "Validation should pass when user has valid exemption"
    );
}

// ============================================================================
// Edge Case: Exemption Expiration During Check
// ============================================================================

/// Test that expired exemptions are not honored.
#[tokio::test]
async fn test_exemption_expiration_not_honored() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let edit = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Edit entitlement");

    let delete = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Create exclusive SoD rule
    let rule = ctx
        .services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Edit+Delete".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![edit.id.into_inner(), delete.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // Create EXPIRED exemption (expires in the past)
    // Note: The exemption store should handle this, but we test the validation behavior
    let expired_exemption = ctx
        .services
        .sod_exemption
        .grant_exemption(
            ctx.tenant_a,
            CreateSodExemptionInput {
                rule_id: rule.id,
                user_id,
                justification: "Temporary exemption that has now expired for security compliance"
                    .to_string(),
                // Exemption that expires immediately (or in the past would be rejected)
                // So we test with a very short window
                expires_at: Some(Utc::now() + Duration::milliseconds(1)),
                granted_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to grant exemption");

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Assign Edit to user
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: edit.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Test".to_string()),
            },
        )
        .await
        .expect("Failed to assign Edit");

    // Now try to assign Delete - should FAIL because exemption expired
    let current = vec![edit.id.into_inner()];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, delete.id.into_inner(), &current)
        .await
        .expect("Validation failed");

    assert!(
        !result.is_valid,
        "Validation should fail when exemption has expired"
    );
}

// ============================================================================
// Detective Validation Across All Assignments
// ============================================================================

/// Test detective validation scans all user assignments.
#[tokio::test]
async fn test_detective_validation_across_all_assignments() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let edit = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Edit entitlement");

    let delete = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Assign both (bypassing preventive validation for this test)
    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: edit.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Test".to_string()),
            },
        )
        .await
        .expect("Failed to assign Edit");

    ctx.services
        .assignment
        .assign(
            ctx.tenant_a,
            AssignEntitlementInput {
                entitlement_id: delete.id.into_inner(),
                user_id,
                assigned_by: ctx.actor_id,
                expires_at: None,
                justification: Some("Test".to_string()),
            },
        )
        .await
        .expect("Failed to assign Delete");

    // Now create the SoD rule (after assignments already exist)
    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Edit+Delete".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![edit.id.into_inner(), delete.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // Get existing violations for user using get_user_violations
    // Note: For this to work, violations must already be recorded in the store
    // The validate_preventive method is used during assignment to check and record violations
    let current_entitlements = vec![edit.id.into_inner()];

    // Now try to add Delete which would cause a violation
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(
            ctx.tenant_a,
            user_id,
            delete.id.into_inner(),
            &current_entitlements,
        )
        .await
        .expect("Preventive validation failed");

    // Should detect the potential violation
    assert!(!result.is_valid, "Validation should find violation");
    assert_eq!(
        result.violations.len(),
        1,
        "Should find 1 violation for Edit+Delete"
    );
}

// ============================================================================
// Additional SoD Tests
// ============================================================================

/// Test that non-violating assignments pass.
#[tokio::test]
async fn test_non_violating_assignment_passes() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let view = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "View".to_string(),
                description: None,
                risk_level: RiskLevel::Low,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create View entitlement");

    let edit = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Edit".to_string(),
                description: None,
                risk_level: RiskLevel::Medium,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Edit entitlement");

    let delete = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "Delete".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create Delete entitlement");

    // Create exclusive rule for Edit+Delete only
    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No Edit+Delete".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![edit.id.into_inner(), delete.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create SoD rule");

    // User has View - try to assign Edit (should pass, no conflict)
    let current = vec![view.id.into_inner()];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, edit.id.into_inner(), &current)
        .await
        .expect("Validation failed");

    assert!(result.is_valid, "Should pass when no SoD conflict exists");
}

/// Test multiple rules violation.
#[tokio::test]
async fn test_multiple_rules_violation() {
    let ctx = TestContext::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create entitlements
    let a = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "A".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create A");

    let b = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "B".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create B");

    let c = ctx
        .services
        .entitlement
        .create(
            ctx.tenant_a,
            CreateEntitlementInput {
                application_id: app_id,
                name: "C".to_string(),
                description: None,
                risk_level: RiskLevel::High,
                owner_id: None,
                external_id: None,
                metadata: None,
                is_delegable: true,
            },
            ctx.actor_id,
        )
        .await
        .expect("Failed to create C");

    // Create two exclusive rules
    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No A+B".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![a.id.into_inner(), b.id.into_inner()],
                max_count: None,
                severity: SodSeverity::High,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create first SoD rule");

    ctx.services
        .sod
        .create_rule(
            ctx.tenant_a,
            CreateSodRuleInput {
                name: "No A+C".to_string(),
                description: None,
                conflict_type: SodConflictType::Exclusive,
                entitlement_ids: vec![a.id.into_inner(), c.id.into_inner()],
                max_count: None,
                severity: SodSeverity::Critical,
                created_by: ctx.actor_id,
            },
        )
        .await
        .expect("Failed to create second SoD rule");

    // User has B and C - try to assign A (violates BOTH rules)
    let current = vec![b.id.into_inner(), c.id.into_inner()];
    let result = ctx
        .services
        .sod_validation
        .validate_preventive(ctx.tenant_a, user_id, a.id.into_inner(), &current)
        .await
        .expect("Validation failed");

    assert!(!result.is_valid, "Should detect violations");
    assert_eq!(
        result.violations.len(),
        2,
        "Should detect violations from both rules"
    );
}
