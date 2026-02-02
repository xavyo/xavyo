//! Integration tests for Identity Merge workflow (F062).
//!
//! Tests for User Story 1: Review and Merge Duplicate Identities (P1 - MVP)
//!
//! These tests require a running PostgreSQL database.
//! Run with: cargo test --package xavyo-api-governance --test identity_merge_integration_tests --features integration

#![cfg(feature = "integration")]

use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovCorrelationRule, CreateGovDuplicateCandidate, CreateGovMergeOperation,
    GovArchivedIdentity, GovCorrelationRule, GovDuplicateCandidate, GovDuplicateStatus,
    GovEntitlementStrategy, GovFuzzyAlgorithm, GovMatchType, GovMergeAudit, GovMergeOperation,
    GovMergeOperationStatus, RuleMatch, RuleMatches,
};

mod common;
use common::setup_test_db;

// ============================================================================
// Helper functions
// ============================================================================

async fn create_test_correlation_rule(pool: &PgPool, tenant_id: Uuid) -> GovCorrelationRule {
    let input = CreateGovCorrelationRule {
        name: format!("Test Rule {}", Uuid::new_v4()),
        attribute: "email".to_string(),
        match_type: GovMatchType::Exact,
        algorithm: None,
        threshold: None,
        weight: Some(50.0),
        priority: Some(100),
    };

    GovCorrelationRule::create(pool, tenant_id, input)
        .await
        .expect("Failed to create correlation rule")
}

async fn create_test_duplicate_candidate(
    pool: &PgPool,
    tenant_id: Uuid,
    identity_a_id: Uuid,
    identity_b_id: Uuid,
    confidence: f64,
) -> GovDuplicateCandidate {
    // Ensure canonical ordering (a < b)
    let (id_a, id_b) = if identity_a_id < identity_b_id {
        (identity_a_id, identity_b_id)
    } else {
        (identity_b_id, identity_a_id)
    };

    let rule_matches = RuleMatches {
        matches: vec![RuleMatch {
            rule_id: Uuid::new_v4(),
            rule_name: "Email exact match".to_string(),
            attribute: "email".to_string(),
            value_a: Some(serde_json::Value::String("test@example.com".to_string())),
            value_b: Some(serde_json::Value::String("test@example.com".to_string())),
            similarity: 1.0,
            weighted_score: confidence,
        }],
        total_confidence: confidence,
    };

    let input = CreateGovDuplicateCandidate {
        identity_a_id: id_a,
        identity_b_id: id_b,
        confidence_score: confidence,
        rule_matches,
    };

    GovDuplicateCandidate::create(pool, tenant_id, input)
        .await
        .expect("Failed to create duplicate candidate")
}

// ============================================================================
// Duplicate Candidate CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_create_duplicate_candidate() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();

    let candidate =
        create_test_duplicate_candidate(&pool, tenant_id, identity_a, identity_b, 85.0).await;

    assert_eq!(candidate.tenant_id, tenant_id);
    assert_eq!(candidate.confidence_score, 85.0);
    assert_eq!(candidate.status, GovDuplicateStatus::Pending);
}

#[tokio::test]
async fn test_canonical_ordering_enforced() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();

    // Create with larger ID first
    let large_id = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();
    let small_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let candidate =
        create_test_duplicate_candidate(&pool, tenant_id, large_id, small_id, 90.0).await;

    // Should be stored with smaller ID as identity_a
    assert_eq!(candidate.identity_a_id, small_id);
    assert_eq!(candidate.identity_b_id, large_id);
}

#[tokio::test]
async fn test_find_duplicate_by_id() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();

    let created =
        create_test_duplicate_candidate(&pool, tenant_id, identity_a, identity_b, 75.0).await;

    let found = GovDuplicateCandidate::find_by_id(&pool, tenant_id, created.id)
        .await
        .expect("Query failed")
        .expect("Candidate not found");

    assert_eq!(found.id, created.id);
    assert_eq!(found.confidence_score, 75.0);
}

#[tokio::test]
async fn test_list_duplicates_by_status() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();

    // Create pending duplicates
    for i in 0..3 {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        create_test_duplicate_candidate(&pool, tenant_id, a, b, 80.0 + i as f64).await;
    }

    let pending =
        GovDuplicateCandidate::list_by_status(&pool, tenant_id, GovDuplicateStatus::Pending, 50, 0)
            .await
            .expect("Query failed");

    assert!(pending.len() >= 3);
    assert!(pending
        .iter()
        .all(|c| c.status == GovDuplicateStatus::Pending));
}

#[tokio::test]
async fn test_dismiss_duplicate_candidate() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();
    let dismissed_by = Uuid::new_v4();

    let candidate =
        create_test_duplicate_candidate(&pool, tenant_id, identity_a, identity_b, 70.0).await;

    let dismissed = GovDuplicateCandidate::dismiss(
        &pool,
        tenant_id,
        candidate.id,
        dismissed_by,
        "False positive - different people with same name".to_string(),
    )
    .await
    .expect("Dismiss failed")
    .expect("Candidate not found");

    assert_eq!(dismissed.status, GovDuplicateStatus::Dismissed);
    assert_eq!(dismissed.dismissed_by, Some(dismissed_by));
    assert!(dismissed.dismissed_reason.is_some());
    assert!(dismissed.dismissed_at.is_some());
}

// ============================================================================
// Merge Operation Tests
// ============================================================================

#[tokio::test]
async fn test_create_merge_operation() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let operator_id = Uuid::new_v4();

    let input = CreateGovMergeOperation {
        candidate_id: None,
        source_identity_id: source_id,
        target_identity_id: target_id,
        entitlement_strategy: GovEntitlementStrategy::Union,
        attribute_selections: json!({
            "email": { "source": "target" },
            "display_name": { "source": "source" }
        }),
        entitlement_selections: None,
        operator_id,
    };

    let operation = GovMergeOperation::create(&pool, tenant_id, input)
        .await
        .expect("Failed to create merge operation");

    assert_eq!(operation.tenant_id, tenant_id);
    assert_eq!(operation.source_identity_id, source_id);
    assert_eq!(operation.target_identity_id, target_id);
    assert_eq!(operation.status, GovMergeOperationStatus::InProgress);
    assert_eq!(
        operation.entitlement_strategy,
        GovEntitlementStrategy::Union
    );
}

#[tokio::test]
async fn test_complete_merge_operation() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let operator_id = Uuid::new_v4();

    let input = CreateGovMergeOperation {
        candidate_id: None,
        source_identity_id: source_id,
        target_identity_id: target_id,
        entitlement_strategy: GovEntitlementStrategy::Union,
        attribute_selections: json!({}),
        entitlement_selections: None,
        operator_id,
    };

    let operation = GovMergeOperation::create(&pool, tenant_id, input)
        .await
        .expect("Failed to create merge operation");

    let completed = GovMergeOperation::complete(&pool, tenant_id, operation.id)
        .await
        .expect("Complete failed")
        .expect("Operation not found");

    assert_eq!(completed.status, GovMergeOperationStatus::Completed);
    assert!(completed.completed_at.is_some());
}

#[tokio::test]
async fn test_fail_merge_operation() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let operator_id = Uuid::new_v4();

    let input = CreateGovMergeOperation {
        candidate_id: None,
        source_identity_id: source_id,
        target_identity_id: target_id,
        entitlement_strategy: GovEntitlementStrategy::Union,
        attribute_selections: json!({}),
        entitlement_selections: None,
        operator_id,
    };

    let operation = GovMergeOperation::create(&pool, tenant_id, input)
        .await
        .expect("Failed to create merge operation");

    let failed = GovMergeOperation::fail(
        &pool,
        tenant_id,
        operation.id,
        "SoD violation could not be resolved".to_string(),
    )
    .await
    .expect("Fail failed")
    .expect("Operation not found");

    assert_eq!(failed.status, GovMergeOperationStatus::Failed);
    assert!(failed.error_message.is_some());
    assert!(failed.completed_at.is_some());
}

#[tokio::test]
async fn test_circular_merge_detection() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let identity_a = Uuid::new_v4();
    let identity_b = Uuid::new_v4();
    let operator_id = Uuid::new_v4();

    // Create operation A -> B
    let input = CreateGovMergeOperation {
        candidate_id: None,
        source_identity_id: identity_a,
        target_identity_id: identity_b,
        entitlement_strategy: GovEntitlementStrategy::Union,
        attribute_selections: json!({}),
        entitlement_selections: None,
        operator_id,
    };

    GovMergeOperation::create(&pool, tenant_id, input)
        .await
        .expect("Failed to create merge operation");

    // Check for circular merge B -> A
    let has_circular =
        GovMergeOperation::has_pending_merge_involving(&pool, tenant_id, identity_b, identity_a)
            .await
            .expect("Query failed");

    assert!(has_circular);
}

// ============================================================================
// Correlation Rule Tests
// ============================================================================

#[tokio::test]
async fn test_create_exact_match_rule() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();

    let rule = create_test_correlation_rule(&pool, tenant_id).await;

    assert_eq!(rule.tenant_id, tenant_id);
    assert_eq!(rule.match_type, GovMatchType::Exact);
    assert!(rule.is_active);
}

#[tokio::test]
async fn test_create_fuzzy_match_rule() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();

    let input = CreateGovCorrelationRule {
        name: "Name fuzzy match".to_string(),
        attribute: "display_name".to_string(),
        match_type: GovMatchType::Fuzzy,
        algorithm: Some(GovFuzzyAlgorithm::JaroWinkler),
        threshold: Some(0.85),
        weight: Some(30.0),
        priority: Some(50),
    };

    let rule = GovCorrelationRule::create(&pool, tenant_id, input)
        .await
        .expect("Failed to create fuzzy rule");

    assert_eq!(rule.match_type, GovMatchType::Fuzzy);
    assert_eq!(rule.algorithm, Some(GovFuzzyAlgorithm::JaroWinkler));
    assert_eq!(rule.threshold, Some(0.85));
}

#[tokio::test]
async fn test_list_active_correlation_rules() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();

    // Create multiple rules
    for _ in 0..3 {
        create_test_correlation_rule(&pool, tenant_id).await;
    }

    let active_rules = GovCorrelationRule::list_active(&pool, tenant_id)
        .await
        .expect("Query failed");

    assert!(active_rules.len() >= 3);
    assert!(active_rules.iter().all(|r| r.is_active));
}

// ============================================================================
// Merge Audit Tests
// ============================================================================

#[tokio::test]
async fn test_create_merge_audit() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let operation_id = Uuid::new_v4();

    let source_snapshot = json!({
        "id": Uuid::new_v4(),
        "email": "source@example.com",
        "display_name": "Source User"
    });

    let target_snapshot = json!({
        "id": Uuid::new_v4(),
        "email": "target@example.com",
        "display_name": "Target User"
    });

    let merged_snapshot = json!({
        "id": Uuid::new_v4(),
        "email": "target@example.com",
        "display_name": "Source User"
    });

    let audit = GovMergeAudit::create(
        &pool,
        tenant_id,
        operation_id,
        source_snapshot.clone(),
        target_snapshot.clone(),
        merged_snapshot.clone(),
        json!({ "email": { "source": "target" }, "display_name": { "source": "source" } }),
        json!({ "strategy": "union" }),
        None,
    )
    .await
    .expect("Failed to create audit record");

    assert_eq!(audit.tenant_id, tenant_id);
    assert_eq!(audit.operation_id, operation_id);
    assert_eq!(audit.source_snapshot, source_snapshot);
}

#[tokio::test]
async fn test_audit_record_is_immutable() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let operation_id = Uuid::new_v4();

    let audit = GovMergeAudit::create(
        &pool,
        tenant_id,
        operation_id,
        json!({}),
        json!({}),
        json!({}),
        json!({}),
        json!({}),
        None,
    )
    .await
    .expect("Failed to create audit record");

    // Attempt to update should fail (trigger blocks updates)
    let result = sqlx::query(
        r#"
        UPDATE gov_merge_audits
        SET source_snapshot = '{"modified": true}'::jsonb
        WHERE id = $1
        "#,
    )
    .bind(audit.id)
    .execute(&pool)
    .await;

    // The trigger should raise an error
    assert!(result.is_err());
}

// ============================================================================
// Archived Identity Tests
// ============================================================================

#[tokio::test]
async fn test_create_archived_identity() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let original_user_id = Uuid::new_v4();
    let merge_operation_id = Uuid::new_v4();

    let snapshot = json!({
        "id": original_user_id,
        "email": "archived@example.com",
        "display_name": "Archived User",
        "entitlements": []
    });

    let external_refs = json!({
        "scim_id": "scim-uuid",
        "ldap_dn": "cn=user,dc=example"
    });

    let archived = GovArchivedIdentity::create(
        &pool,
        tenant_id,
        original_user_id,
        merge_operation_id,
        snapshot.clone(),
        external_refs.clone(),
    )
    .await
    .expect("Failed to create archived identity");

    assert_eq!(archived.tenant_id, tenant_id);
    assert_eq!(archived.original_user_id, original_user_id);
    assert_eq!(archived.merge_operation_id, merge_operation_id);
    assert_eq!(archived.snapshot, snapshot);
    assert_eq!(archived.external_references, external_refs);
}

#[tokio::test]
async fn test_find_archived_by_original_user() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let original_user_id = Uuid::new_v4();
    let merge_operation_id = Uuid::new_v4();

    GovArchivedIdentity::create(
        &pool,
        tenant_id,
        original_user_id,
        merge_operation_id,
        json!({}),
        json!({}),
    )
    .await
    .expect("Failed to create archived identity");

    let found = GovArchivedIdentity::find_by_original_user(&pool, tenant_id, original_user_id)
        .await
        .expect("Query failed")
        .expect("Archived identity not found");

    assert_eq!(found.original_user_id, original_user_id);
}

// ============================================================================
// Full Merge Workflow Integration Test
// ============================================================================

#[tokio::test]
async fn test_complete_merge_workflow() {
    let pool = setup_test_db().await;
    let tenant_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let operator_id = Uuid::new_v4();

    // 1. Create duplicate candidate
    let candidate =
        create_test_duplicate_candidate(&pool, tenant_id, source_id, target_id, 95.0).await;
    assert_eq!(candidate.status, GovDuplicateStatus::Pending);

    // 2. Create merge operation
    let merge_input = CreateGovMergeOperation {
        candidate_id: Some(candidate.id),
        source_identity_id: source_id,
        target_identity_id: target_id,
        entitlement_strategy: GovEntitlementStrategy::Union,
        attribute_selections: json!({
            "email": { "source": "target", "value": "target@example.com" },
            "display_name": { "source": "source", "value": "Better Name" }
        }),
        entitlement_selections: None,
        operator_id,
    };

    let operation = GovMergeOperation::create(&pool, tenant_id, merge_input)
        .await
        .expect("Failed to create merge operation");
    assert_eq!(operation.status, GovMergeOperationStatus::InProgress);

    // 3. Create audit record
    let _audit = GovMergeAudit::create(
        &pool,
        tenant_id,
        operation.id,
        json!({ "id": source_id, "email": "source@example.com" }),
        json!({ "id": target_id, "email": "target@example.com" }),
        json!({ "id": target_id, "email": "target@example.com", "display_name": "Better Name" }),
        json!({ "email": "target", "display_name": "source" }),
        json!({ "strategy": "union" }),
        None,
    )
    .await
    .expect("Failed to create audit record");

    // 4. Archive source identity
    let _archived = GovArchivedIdentity::create(
        &pool,
        tenant_id,
        source_id,
        operation.id,
        json!({ "id": source_id, "email": "source@example.com" }),
        json!({ "scim_id": "scim-source" }),
    )
    .await
    .expect("Failed to archive identity");

    // 5. Complete merge operation
    let completed = GovMergeOperation::complete(&pool, tenant_id, operation.id)
        .await
        .expect("Complete failed")
        .expect("Operation not found");
    assert_eq!(completed.status, GovMergeOperationStatus::Completed);

    // 6. Mark duplicate as merged
    let merged_candidate = GovDuplicateCandidate::mark_merged(&pool, tenant_id, candidate.id)
        .await
        .expect("Mark merged failed")
        .expect("Candidate not found");
    assert_eq!(merged_candidate.status, GovDuplicateStatus::Merged);

    // 7. Verify archived identity exists
    let archived = GovArchivedIdentity::find_by_original_user(&pool, tenant_id, source_id)
        .await
        .expect("Query failed");
    assert!(archived.is_some());

    // 8. Verify audit trail exists
    let audits = GovMergeAudit::list_by_operation(&pool, operation.id)
        .await
        .expect("Query failed");
    assert!(!audits.is_empty());
}
