//! Integration tests for Identity Merge (F062) using current service and DB APIs.
//!
//! Run with:
//! `DATABASE_URL=postgres://... TEST_DATABASE_URL=... SQLX_OFFLINE=true \
//!  cargo test -p xavyo-api-governance --features integration \
//!  --test identity_merge_integration_tests -- --test-threads=1`

#![cfg(feature = "integration")]

mod common;

use common::{
    cleanup_test_tenant, create_test_pool, create_test_tenant, create_test_user,
};
use chrono::Utc;
use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;
use xavyo_api_governance::{
    models::{MergeExecuteRequest, MergePreviewRequest},
    services::IdentityMergeService,
};
use xavyo_db::models::{
    CreateGovArchivedIdentity, CreateGovCorrelationRule, CreateGovDuplicateCandidate,
    CreateGovMergeAudit, CreateGovMergeOperation, DuplicateCandidateFilter,
    EntitlementDecision, ExternalReferences, GovArchivedIdentity, GovCorrelationRule,
    GovDuplicateCandidate, GovDuplicateStatus, GovEntitlementStrategy, GovMatchType,
    GovMergeAudit, GovMergeOperation, IdentitySnapshot, RuleMatch, RuleMatches,
};

async fn cleanup_identity_merge_data(pool: &sqlx::PgPool, tenant_id: Uuid) {
    let _ = sqlx::query("DELETE FROM gov_merge_audits WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM gov_archived_identities WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM gov_merge_operations WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM gov_duplicate_candidates WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM gov_correlation_rules WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

fn correlation_rule_input(name: &str) -> CreateGovCorrelationRule {
    CreateGovCorrelationRule {
        name: name.to_string(),
        attribute: "email".to_string(),
        match_type: GovMatchType::Exact,
        algorithm: None,
        threshold: None,
        weight: Some(Decimal::new(50, 0)),
        priority: Some(100),
        connector_id: None,
        source_attribute: None,
        target_attribute: None,
        expression: None,
        tier: None,
        is_definitive: None,
        normalize: None,
    }
}

async fn create_duplicate_candidate(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    identity_a_id: Uuid,
    identity_b_id: Uuid,
    confidence: Decimal,
) -> GovDuplicateCandidate {
    let rule_matches = RuleMatches {
        matches: vec![RuleMatch {
            rule_id: Uuid::new_v4(),
            rule_name: "Email exact match".to_string(),
            attribute: "email".to_string(),
            value_a: Some("test@example.com".to_string()),
            value_b: Some("test@example.com".to_string()),
            similarity: 1.0,
            weighted_score: confidence.to_string().parse().unwrap_or(85.0),
        }],
        total_confidence: confidence.to_string().parse().unwrap_or(85.0),
    };

    GovDuplicateCandidate::upsert(
        pool,
        tenant_id,
        CreateGovDuplicateCandidate {
            identity_a_id,
            identity_b_id,
            confidence_score: confidence,
            rule_matches,
        },
    )
    .await
    .expect("Failed to create duplicate candidate")
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_service_lists_and_dismisses_duplicates() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let service = IdentityMergeService::new(pool.clone());

    let identity_a = create_test_user(&pool, tenant_id).await;
    let identity_b = create_test_user(&pool, tenant_id).await;
    let dismissed_by = create_test_user(&pool, tenant_id).await;

    let candidate = create_duplicate_candidate(
        &pool,
        tenant_id,
        identity_a,
        identity_b,
        Decimal::new(8500, 2),
    )
    .await;

    let filter = DuplicateCandidateFilter {
        status: Some(GovDuplicateStatus::Pending),
        ..Default::default()
    };
    let (pending, total) = service
        .list_duplicates(tenant_id, &filter, 50, 0)
        .await
        .expect("list_duplicates failed");
    assert!(total >= 1);
    assert!(pending.iter().any(|c| c.id == candidate.id));

    let dismissed = service
        .dismiss_duplicate(
            tenant_id,
            candidate.id,
            dismissed_by,
            "False positive",
        )
        .await
        .expect("dismiss_duplicate failed");
    assert_eq!(dismissed.status, GovDuplicateStatus::Dismissed);

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_service_get_duplicate_detail() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let service = IdentityMergeService::new(pool.clone());

    let identity_a = create_test_user(&pool, tenant_id).await;
    let identity_b = create_test_user(&pool, tenant_id).await;

    let candidate = create_duplicate_candidate(
        &pool,
        tenant_id,
        identity_a,
        identity_b,
        Decimal::new(9000, 2),
    )
    .await;

    let detail = service
        .get_duplicate_detail(tenant_id, candidate.id)
        .await
        .expect("get_duplicate_detail failed");

    assert_eq!(detail.id, candidate.id);
    assert_eq!(detail.identity_a_id, candidate.identity_a_id);
    assert_eq!(detail.identity_b_id, candidate.identity_b_id);
    assert!(!detail.rule_matches.is_empty());

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_service_merge_preview() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let service = IdentityMergeService::new(pool.clone());

    let source_id = create_test_user(&pool, tenant_id).await;
    let target_id = create_test_user(&pool, tenant_id).await;

    let preview = service
        .preview(
            tenant_id,
            &MergePreviewRequest {
                source_identity_id: source_id,
                target_identity_id: target_id,
                entitlement_strategy: GovEntitlementStrategy::Union,
                attribute_selections: Some(json!({
                    "email": { "source": "target" }
                })),
            },
        )
        .await
        .expect("preview failed");

    assert_eq!(preview.source_identity.id, source_id);
    assert_eq!(preview.target_identity.id, target_id);
    assert_eq!(preview.merged_preview.id, target_id);

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_correlation_rule_create_and_list_active() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let rule = GovCorrelationRule::create(
        &pool,
        tenant_id,
        correlation_rule_input("Email exact match"),
    )
    .await
    .expect("Failed to create correlation rule");

    assert_eq!(rule.match_type, GovMatchType::Exact);
    assert!(rule.is_active);

    let active = GovCorrelationRule::list_active(&pool, tenant_id)
        .await
        .expect("list_active failed");
    assert!(active.iter().any(|r| r.id == rule.id));

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_merge_audit_and_archived_identity_models() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let original_user_id = create_test_user(&pool, tenant_id).await;
    let target_user_id = create_test_user(&pool, tenant_id).await;
    let operator_id = create_test_user(&pool, tenant_id).await;

    let operation = GovMergeOperation::create(
        &pool,
        tenant_id,
        CreateGovMergeOperation {
            candidate_id: None,
            source_identity_id: original_user_id,
            target_identity_id: target_user_id,
            entitlement_strategy: GovEntitlementStrategy::Union,
            attribute_selections: json!({}),
            entitlement_selections: None,
            operator_id,
        },
    )
    .await
    .expect("Failed to create merge operation");

    let now = Utc::now();
    let source_snapshot = IdentitySnapshot {
        id: original_user_id,
        email: Some("source@example.com".to_string()),
        display_name: Some("Source User".to_string()),
        attributes: json!({}),
        entitlements: vec![],
        external_references: json!({}),
        created_at: now,
        updated_at: now,
    };
    let target_snapshot = IdentitySnapshot {
        id: Uuid::new_v4(),
        email: Some("target@example.com".to_string()),
        display_name: Some("Target User".to_string()),
        attributes: json!({}),
        entitlements: vec![],
        external_references: json!({}),
        created_at: now,
        updated_at: now,
    };
    let merged_snapshot = target_snapshot.clone();

    let audit = GovMergeAudit::create(
        &pool,
        tenant_id,
        CreateGovMergeAudit {
            operation_id: operation.id,
            source_snapshot: source_snapshot.clone(),
            target_snapshot: target_snapshot.clone(),
            merged_snapshot: merged_snapshot.clone(),
            attribute_decisions: vec![],
            entitlement_decisions: EntitlementDecision {
                strategy: "union".to_string(),
                source_entitlements: vec![],
                target_entitlements: vec![],
                merged_entitlements: vec![],
                excluded_entitlements: vec![],
            },
            sod_violations: None,
        },
    )
    .await
    .expect("Failed to create merge audit");

    assert_eq!(audit.operation_id, operation.id);

    let archived = GovArchivedIdentity::create(
        &pool,
        tenant_id,
        CreateGovArchivedIdentity {
            original_user_id,
            merge_operation_id: operation.id,
            snapshot: json!({ "id": original_user_id, "email": "source@example.com" }),
            external_references: ExternalReferences {
                scim_id: Some("scim-uuid".to_string()),
                ..Default::default()
            },
        },
    )
    .await
    .expect("Failed to create archived identity");

    let found = GovArchivedIdentity::find_by_original_user(&pool, tenant_id, original_user_id)
        .await
        .expect("find_by_original_user failed")
        .expect("Archived identity not found");
    assert_eq!(found.id, archived.id);

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_service_execute_merge() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let service = IdentityMergeService::new(pool.clone());

    let source_id = create_test_user(&pool, tenant_id).await;
    let target_id = create_test_user(&pool, tenant_id).await;
    let operator_id = create_test_user(&pool, tenant_id).await;

    let _candidate = create_duplicate_candidate(
        &pool,
        tenant_id,
        source_id,
        target_id,
        Decimal::new(9500, 2),
    )
    .await;

    let result = service
        .execute(
            tenant_id,
            operator_id,
            &MergeExecuteRequest {
                source_identity_id: source_id,
                target_identity_id: target_id,
                entitlement_strategy: GovEntitlementStrategy::Union,
                attribute_selections: Some(json!({})),
                entitlement_selections: None,
                sod_override_reason: None,
            },
        )
        .await
        .expect("execute merge failed");

    assert_eq!(result.target_identity_id, target_id);
    assert!(GovArchivedIdentity::find_by_original_user(&pool, tenant_id, source_id)
        .await
        .expect("lookup failed")
        .is_some());

    cleanup_identity_merge_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
