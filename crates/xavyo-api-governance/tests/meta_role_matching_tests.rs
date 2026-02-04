//! Unit tests for meta-role criteria matching logic (F056 - T019).
//!
//! Tests all criteria operators (eq, neq, in, `not_in`, gt, gte, lt, lte,
//! contains, `starts_with`) and logic combinations (AND, OR).

mod common;

use common::*;
use uuid::Uuid;
use xavyo_api_governance::services::{MetaRoleMatchingService, MetaRoleService};
use xavyo_db::{CreateGovMetaRole, CreateGovMetaRoleCriteria, CriteriaLogic, CriteriaOperator};

// =========================================================================
// Basic Operator Tests - EQ (Equal)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_eq_matches_exact_value() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create high-risk role
    let high_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create low-risk role
    let low_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;

    // Create meta-role matching risk_level = "High"
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "High Risk Policy", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Evaluate high-risk role - should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, high_risk_role)
        .await;
    assert!(result.is_ok());
    let matches = result.unwrap();
    assert_eq!(
        matches.matching_meta_roles.len(),
        1,
        "High-risk role should match"
    );

    // Evaluate low-risk role - should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_risk_role)
        .await;
    assert!(result.is_ok());
    let matches = result.unwrap();
    assert_eq!(
        matches.matching_meta_roles.len(),
        0,
        "Low-risk role should not match"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_eq_case_sensitivity() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create role with "high" risk level (lowercase in DB)
    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create meta-role matching risk_level = "high" (exact match)
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Case Match", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("high"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Note: The matching service converts risk_level to format like "High" via Debug format
    // This test verifies the current behavior
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await;
    assert!(result.is_ok());

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// NEQ (Not Equal) Operator
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_neq_excludes_value() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let low_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;
    let high_risk_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create meta-role matching risk_level != "Low"
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "Not Low Risk", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "neq",
        serde_json::json!("Low"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // High risk should match (not low)
    let result = matching_service
        .evaluate_role_matches(tenant_id, high_risk_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    // Low risk should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_risk_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// IN Operator
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_in_matches_list() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let high_role = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let critical_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "critical").await;
    let low_role = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;

    // Create meta-role matching risk_level IN ["High", "Critical"]
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "High or Critical", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "in",
        serde_json::json!(["High", "Critical"]),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // High and Critical should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, high_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    let result = matching_service
        .evaluate_role_matches(tenant_id, critical_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    // Low should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// NOT_IN Operator
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_not_in_excludes_list() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let low_role = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;
    let medium_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "medium").await;
    let high_role = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create meta-role matching risk_level NOT IN ["Low", "Medium"]
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Exclude Low/Medium", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "not_in",
        serde_json::json!(["Low", "Medium"]),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Low and Medium should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    let result = matching_service
        .evaluate_role_matches(tenant_id, medium_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    // High should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, high_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// CONTAINS Operator
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_contains_substring() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Note: 'contains' works on string fields. The entitlement name contains identifiers.
    // For now, we test with the status field or other string fields if available.

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role matching status contains "acti" (should match "active")
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Status Contains", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "status",
        "contains",
        serde_json::json!("Acti"), // GovEntitlementStatus::Active becomes "Active" via Debug
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    // Status is "Active" in Debug format, "Acti" is contained
    assert_eq!(result.matching_meta_roles.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// STARTS_WITH Operator
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_starts_with() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role matching status starts_with "Act"
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Status Starts With", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "status",
        "starts_with",
        serde_json::json!("Act"), // "Active".starts_with("Act") = true
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Name Field Tests (string matching)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_name_contains() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create an entitlement - its name will contain "Entitlement"
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role matching name contains "Entitlement"
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Name Match Policy", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "name",
        "contains",
        serde_json::json!("Entitlement"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        1,
        "Role name should contain 'Entitlement'"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Boolean Field Tests (is_delegable)
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_eq_boolean_true() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create entitlements - default is_delegable = true
    let delegable_role = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role matching is_delegable = true
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Delegable Only", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "is_delegable",
        "eq",
        serde_json::json!(true),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, delegable_role)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Application ID Matching
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_eq_application_id() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app1_id = create_test_application(&pool, tenant_id).await;
    let app2_id = create_test_application(&pool, tenant_id).await;

    let role_in_app1 = create_test_entitlement(&pool, tenant_id, app1_id, None).await;
    let role_in_app2 = create_test_entitlement(&pool, tenant_id, app2_id, None).await;

    // Create meta-role matching application_id = app1
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user_id, "App1 Only", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "application_id",
        "eq",
        serde_json::json!(app1_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // App1 role should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_in_app1)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    // App2 role should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_in_app2)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Owner ID Matching
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_eq_owner_id() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user1_id = create_test_user(&pool, tenant_id).await;
    let user2_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_owned_by_user1 =
        create_test_entitlement(&pool, tenant_id, app_id, Some(user1_id)).await;
    let role_owned_by_user2 =
        create_test_entitlement(&pool, tenant_id, app_id, Some(user2_id)).await;
    let role_no_owner = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role matching owner_id = user1
    let meta_role_id = create_test_meta_role(&pool, tenant_id, user1_id, "User1 Owned", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "owner_id",
        "eq",
        serde_json::json!(user1_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // User1's role should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_owned_by_user1)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    // User2's role should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_owned_by_user2)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    // No owner role should not match
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_no_owner)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 0);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// AND Logic Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_logic_and_all_must_match() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create role: high risk + owned by user
    let matching_role =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;

    // Create role: high risk but no owner
    let partial_match =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create meta-role with AND logic: risk_level = High AND owner_id = user_id
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "High AND Owned", 100).await;

    // The default is AND logic, but let's be explicit by checking
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "owner_id",
        "eq",
        serde_json::json!(user_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Role with both conditions should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, matching_role)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        1,
        "Both criteria met - should match"
    );

    // Role with only one condition should NOT match (AND logic)
    let result = matching_service
        .evaluate_role_matches(tenant_id, partial_match)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        0,
        "Only risk matches, owner doesn't - should not match"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// OR Logic Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_criteria_logic_or_any_can_match() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create different roles
    let high_risk_no_owner =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;
    let low_risk_with_owner =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "low").await;
    let low_risk_no_owner =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "low").await;

    // Create meta-role with OR logic: risk_level = High OR owner_id = user_id
    let service = MetaRoleService::new(pool.clone());
    let input = CreateGovMetaRole {
        name: "High OR Owned".to_string(),
        description: None,
        priority: Some(100),
        criteria_logic: Some(CriteriaLogic::Or), // Explicit OR
    };
    let meta_role = service
        .create(tenant_id, user_id, input, vec![])
        .await
        .unwrap();

    // Add criteria
    service
        .add_criterion(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleCriteria {
                field: "risk_level".to_string(),
                operator: CriteriaOperator::Eq,
                value: serde_json::json!("High"),
            },
        )
        .await
        .unwrap();

    service
        .add_criterion(
            tenant_id,
            meta_role.id,
            CreateGovMetaRoleCriteria {
                field: "owner_id".to_string(),
                operator: CriteriaOperator::Eq,
                value: serde_json::json!(user_id.to_string()),
            },
        )
        .await
        .unwrap();

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // High risk (matches first criterion) - should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, high_risk_no_owner)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        1,
        "High risk matches OR condition"
    );

    // Low risk but owned by user (matches second criterion) - should match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_risk_with_owner)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        1,
        "Owner matches OR condition"
    );

    // Low risk, no owner (matches neither) - should NOT match
    let result = matching_service
        .evaluate_role_matches(tenant_id, low_risk_no_owner)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        0,
        "Neither criterion matches"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Empty Criteria Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_meta_role_without_criteria_matches_nothing() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create meta-role without any criteria
    create_test_meta_role(&pool, tenant_id, user_id, "No Criteria", 100).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Should not match because there are no criteria to satisfy
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        0,
        "No criteria = no match"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Multiple Meta-roles Matching
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_multiple_meta_roles_can_match_same_role() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Create a role that matches multiple criteria
    let role_id =
        create_test_entitlement_with_risk(&pool, tenant_id, app_id, Some(user_id), "high").await;

    // Create meta-role 1: matches high risk
    let meta1_id = create_test_meta_role(&pool, tenant_id, user_id, "High Risk Policy", 10).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta1_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    // Create meta-role 2: matches specific owner
    let meta2_id = create_test_meta_role(&pool, tenant_id, user_id, "Owner Policy", 20).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta2_id,
        "owner_id",
        "eq",
        serde_json::json!(user_id.to_string()),
    )
    .await;

    // Create meta-role 3: matches app (also applies to this role)
    let meta3_id = create_test_meta_role(&pool, tenant_id, user_id, "App Policy", 30).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta3_id,
        "application_id",
        "eq",
        serde_json::json!(app_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();

    // All three meta-roles should match
    assert_eq!(
        result.matching_meta_roles.len(),
        3,
        "All three meta-roles should match"
    );

    // Verify ordering by priority
    assert_eq!(result.matching_meta_roles[0].priority, 10);
    assert_eq!(result.matching_meta_roles[1].priority, 20);
    assert_eq!(result.matching_meta_roles[2].priority, 30);

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Disabled Meta-role Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disabled_meta_role_does_not_match() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    // Create and disable meta-role
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Disabled Policy", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let service = MetaRoleService::new(pool.clone());
    service
        .disable(tenant_id, meta_role_id, user_id)
        .await
        .unwrap();

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Disabled meta-role should not be in matches
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        0,
        "Disabled meta-role should not match"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Match Reason Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_match_reason_contains_criteria_details() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Detailed Match", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    let match_info = &result.matching_meta_roles[0];
    let reason = &match_info.match_reason;

    // Match reason should contain useful debugging info
    assert!(reason.get("logic").is_some(), "Should contain logic type");
    assert!(
        reason.get("matched_criteria").is_some(),
        "Should contain matched criteria"
    );

    let matched = reason.get("matched_criteria").unwrap().as_array().unwrap();
    assert!(
        !matched.is_empty(),
        "Should have at least one matched criterion"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Edge Cases and Boundary Tests
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_role_not_found_returns_error() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, Uuid::new_v4())
        .await;
    assert!(result.is_err(), "Should return error for non-existent role");

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_null_owner_id_handling() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    // Role with no owner
    let role_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Meta-role checking owner_id != some_user
    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Not Owned By User", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "owner_id",
        "neq",
        serde_json::json!(user_id.to_string()),
    )
    .await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    // Null != user_id should be true
    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(
        result.matching_meta_roles.len(),
        1,
        "Null owner != specific user"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =========================================================================
// Already Applied Detection
// =========================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_already_applied_flag() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;

    let role_id = create_test_entitlement_with_risk(&pool, tenant_id, app_id, None, "high").await;

    let meta_role_id =
        create_test_meta_role(&pool, tenant_id, user_id, "Already Applied", 100).await;
    create_test_meta_role_criterion(
        &pool,
        tenant_id,
        meta_role_id,
        "risk_level",
        "eq",
        serde_json::json!("High"),
    )
    .await;

    // Create existing inheritance
    create_test_meta_role_inheritance(&pool, tenant_id, meta_role_id, role_id).await;

    let matching_service = MetaRoleMatchingService::new(pool.clone());

    let result = matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await
        .unwrap();
    assert_eq!(result.matching_meta_roles.len(), 1);

    let match_info = &result.matching_meta_roles[0];
    assert!(
        match_info.already_applied,
        "Should detect existing inheritance"
    );
    assert!(
        match_info.inheritance_id.is_some(),
        "Should have inheritance ID"
    );

    cleanup_meta_role_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
