//! Integration tests for outlier detection analysis (F059 - T021, T022).
//!
//! Tests the analysis execution workflow and dashboard results listing.

mod common;

use common::{
    cleanup_outlier_data, cleanup_test_tenant, create_test_application, create_test_assignment,
    create_test_entitlement, create_test_outlier_analysis, create_test_outlier_config,
    create_test_outlier_result, create_test_peer_group, create_test_pool, create_test_tenant,
    create_test_user,
};
use xavyo_api_governance::services::OutlierScoringService;
use xavyo_db::OutlierTriggerType;

/// T021: Integration test for analysis execution
/// Tests that an analysis can be triggered and runs to completion.
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_analysis_execution_workflow() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create config
    let _config_id = create_test_outlier_config(&pool, tenant_id).await;

    // Setup: Create users with entitlements
    let user1 = create_test_user(&pool, tenant_id).await;
    let user2 = create_test_user(&pool, tenant_id).await;
    let user3 = create_test_user(&pool, tenant_id).await;

    let app = create_test_application(&pool, tenant_id).await;
    let ent1 = create_test_entitlement(&pool, tenant_id, app, Some(user1)).await;
    let ent2 = create_test_entitlement(&pool, tenant_id, app, Some(user1)).await;
    let ent3 = create_test_entitlement(&pool, tenant_id, app, Some(user1)).await;

    // User1 has 3 entitlements (potential outlier)
    create_test_assignment(&pool, tenant_id, user1, ent1).await;
    create_test_assignment(&pool, tenant_id, user1, ent2).await;
    create_test_assignment(&pool, tenant_id, user1, ent3).await;

    // User2 and User3 have 1 entitlement each (normal)
    create_test_assignment(&pool, tenant_id, user2, ent1).await;
    create_test_assignment(&pool, tenant_id, user3, ent1).await;

    // Setup: Create a peer group
    let _peer_group = create_test_peer_group(
        &pool,
        tenant_id,
        "Engineering",
        "department",
        "department",
        "Engineering",
    )
    .await;

    // Execute: Trigger analysis
    let scoring_service = OutlierScoringService::new(pool.clone());
    let result = scoring_service
        .trigger_analysis(tenant_id, OutlierTriggerType::Manual)
        .await;

    // Verify: Analysis was created
    assert!(result.is_ok(), "Analysis should be triggered successfully");
    let analysis = result.unwrap();
    assert_eq!(analysis.tenant_id, tenant_id);
    assert!(matches!(
        analysis.status,
        xavyo_db::OutlierAnalysisStatus::Pending | xavyo_db::OutlierAnalysisStatus::Running
    ));

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T021: Test that concurrent analysis triggers are prevented
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_analysis_prevents_concurrent_execution() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create config
    create_test_outlier_config(&pool, tenant_id).await;

    // Setup: Create a running analysis
    let _analysis_id = create_test_outlier_analysis(&pool, tenant_id, "running").await;

    // Execute: Try to trigger another analysis
    let scoring_service = OutlierScoringService::new(pool.clone());
    let result = scoring_service
        .trigger_analysis(tenant_id, OutlierTriggerType::Manual)
        .await;

    // Verify: Should fail with conflict error
    assert!(
        result.is_err(),
        "Should not allow concurrent analysis execution"
    );
    let err = result.unwrap_err();
    assert!(err.is_conflict(), "Error should be a conflict: {err:?}");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T022: Integration test for dashboard results listing
/// Tests that outlier results are properly returned and paginated.
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_dashboard_results_listing() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create completed analysis with results
    let analysis_id = create_test_outlier_analysis(&pool, tenant_id, "completed").await;

    // Create test users
    let user1 = create_test_user(&pool, tenant_id).await;
    let user2 = create_test_user(&pool, tenant_id).await;
    let user3 = create_test_user(&pool, tenant_id).await;

    // Create results with different scores and classifications
    let _result1 =
        create_test_outlier_result(&pool, tenant_id, analysis_id, user1, 85.0, "outlier").await;
    let _result2 =
        create_test_outlier_result(&pool, tenant_id, analysis_id, user2, 45.0, "normal").await;
    let _result3 =
        create_test_outlier_result(&pool, tenant_id, analysis_id, user3, 72.0, "outlier").await;

    // Execute: List results
    let scoring_service = OutlierScoringService::new(pool.clone());
    let (results, total) = scoring_service
        .list_results(
            tenant_id,
            Some(analysis_id), // Filter by analysis
            None,              // No user filter
            None,              // No classification filter
            None,              // No min score
            None,              // No max score
            50,                // Limit
            0,                 // Offset
        )
        .await
        .expect("Should list results");

    // Verify: All results returned
    assert_eq!(total, 3, "Should have 3 total results");
    assert_eq!(results.len(), 3, "Should return all 3 results");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T022: Test filtering by classification
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_dashboard_filter_by_classification() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create completed analysis with mixed results
    let analysis_id = create_test_outlier_analysis(&pool, tenant_id, "completed").await;

    let user1 = create_test_user(&pool, tenant_id).await;
    let user2 = create_test_user(&pool, tenant_id).await;
    let user3 = create_test_user(&pool, tenant_id).await;

    create_test_outlier_result(&pool, tenant_id, analysis_id, user1, 85.0, "outlier").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user2, 45.0, "normal").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user3, 72.0, "outlier").await;

    // Execute: List only outliers
    let scoring_service = OutlierScoringService::new(pool.clone());
    let (results, total) = scoring_service
        .list_results(
            tenant_id,
            Some(analysis_id),
            None,
            Some(xavyo_db::OutlierClassification::Outlier), // Only outliers
            None,
            None,
            50,
            0,
        )
        .await
        .expect("Should list filtered results");

    // Verify: Only outliers returned
    assert_eq!(total, 2, "Should have 2 outlier results");
    assert_eq!(results.len(), 2, "Should return 2 outlier results");
    for result in &results {
        assert!(
            matches!(
                result.classification,
                xavyo_db::OutlierClassification::Outlier
            ),
            "All results should be outliers"
        );
    }

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T022: Test filtering by score range
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_dashboard_filter_by_score_range() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup
    let analysis_id = create_test_outlier_analysis(&pool, tenant_id, "completed").await;

    let user1 = create_test_user(&pool, tenant_id).await;
    let user2 = create_test_user(&pool, tenant_id).await;
    let user3 = create_test_user(&pool, tenant_id).await;
    let user4 = create_test_user(&pool, tenant_id).await;

    create_test_outlier_result(&pool, tenant_id, analysis_id, user1, 25.0, "normal").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user2, 55.0, "normal").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user3, 75.0, "outlier").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user4, 92.0, "outlier").await;

    // Execute: Filter by score range 50-80
    let scoring_service = OutlierScoringService::new(pool.clone());
    let (results, total) = scoring_service
        .list_results(
            tenant_id,
            Some(analysis_id),
            None,
            None,
            Some(50.0), // Min score
            Some(80.0), // Max score
            50,
            0,
        )
        .await
        .expect("Should list score-filtered results");

    // Verify: Only scores in range returned
    assert_eq!(total, 2, "Should have 2 results in score range");
    assert_eq!(results.len(), 2, "Should return 2 results");
    for result in &results {
        assert!(
            result.overall_score >= 50.0 && result.overall_score <= 80.0,
            "Score {} should be in range 50-80",
            result.overall_score
        );
    }

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T022: Test pagination
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_dashboard_pagination() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create analysis with many results
    let analysis_id = create_test_outlier_analysis(&pool, tenant_id, "completed").await;

    // Create 5 users with results
    for i in 0..5 {
        let user = create_test_user(&pool, tenant_id).await;
        let score = 50.0 + (f64::from(i) * 10.0);
        create_test_outlier_result(
            &pool,
            tenant_id,
            analysis_id,
            user,
            score,
            if i < 2 { "normal" } else { "outlier" },
        )
        .await;
    }

    let scoring_service = OutlierScoringService::new(pool.clone());

    // Execute: Get first page (2 items)
    let (page1, total) = scoring_service
        .list_results(tenant_id, Some(analysis_id), None, None, None, None, 2, 0)
        .await
        .expect("Should get page 1");

    // Verify page 1
    assert_eq!(total, 5, "Total should be 5");
    assert_eq!(page1.len(), 2, "Page 1 should have 2 items");

    // Execute: Get second page
    let (page2, _) = scoring_service
        .list_results(tenant_id, Some(analysis_id), None, None, None, None, 2, 2)
        .await
        .expect("Should get page 2");

    // Verify page 2
    assert_eq!(page2.len(), 2, "Page 2 should have 2 items");

    // Execute: Get third page
    let (page3, _) = scoring_service
        .list_results(tenant_id, Some(analysis_id), None, None, None, None, 2, 4)
        .await
        .expect("Should get page 3");

    // Verify page 3
    assert_eq!(page3.len(), 1, "Page 3 should have 1 item");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T022: Test summary statistics
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_dashboard_summary_statistics() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create completed analysis with results
    let analysis_id = create_test_outlier_analysis(&pool, tenant_id, "completed").await;

    // Mark analysis as completed with proper timestamp
    sqlx::query(
        r"
        UPDATE gov_outlier_analyses
        SET status = 'completed'::gov_outlier_analysis_status,
            completed_at = NOW(),
            total_users = 4,
            outlier_count = 2
        WHERE id = $1
        ",
    )
    .bind(analysis_id)
    .execute(&pool)
    .await
    .expect("Should update analysis");

    let user1 = create_test_user(&pool, tenant_id).await;
    let user2 = create_test_user(&pool, tenant_id).await;
    let user3 = create_test_user(&pool, tenant_id).await;
    let user4 = create_test_user(&pool, tenant_id).await;

    create_test_outlier_result(&pool, tenant_id, analysis_id, user1, 80.0, "outlier").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user2, 45.0, "normal").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user3, 70.0, "outlier").await;
    create_test_outlier_result(&pool, tenant_id, analysis_id, user4, 30.0, "normal").await;

    // Execute: Get summary
    let scoring_service = OutlierScoringService::new(pool.clone());
    let summary = scoring_service
        .get_summary(tenant_id)
        .await
        .expect("Should get summary");

    // Verify summary
    assert_eq!(summary.total_users, 4, "Should have 4 total users");
    assert_eq!(summary.outlier_count, 2, "Should have 2 outliers");
    assert_eq!(summary.normal_count, 2, "Should have 2 normal");
    assert!(summary.avg_score > 0.0, "Should have positive avg score");
    assert_eq!(summary.max_score, 80.0, "Max score should be 80");
    assert!(summary.analysis_id.is_some(), "Should have analysis ID");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
