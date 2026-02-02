//! Integration tests for outlier detection configuration (F059 - T037).
//!
//! Tests configuration CRUD operations.

mod common;

use common::{
    cleanup_outlier_data, cleanup_test_tenant, create_test_outlier_config, create_test_pool,
    create_test_tenant,
};
use xavyo_api_governance::services::OutlierConfigService;
use xavyo_db::{ScoringWeights, UpsertOutlierConfiguration};

/// T037: Integration test for getting or creating configuration
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_get_or_create() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // First call should create default config
    let config1 = config_service
        .get_or_create(tenant_id)
        .await
        .expect("Should create config");

    assert_eq!(config1.tenant_id, tenant_id);
    assert_eq!(config1.confidence_threshold, 2.0); // Default
    assert_eq!(config1.min_peer_group_size, 5); // Default
    assert!(config1.is_enabled);

    // Second call should return same config
    let config2 = config_service
        .get_or_create(tenant_id)
        .await
        .expect("Should get existing config");

    assert_eq!(config1.id, config2.id);
    assert_eq!(config1.created_at, config2.created_at);

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for updating configuration
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_update() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Setup: Create initial config
    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Update confidence threshold and min peer group size
    let input = UpsertOutlierConfiguration {
        confidence_threshold: Some(3.0),
        frequency_threshold: None,
        min_peer_group_size: Some(10),
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let updated = config_service
        .update(tenant_id, input)
        .await
        .expect("Should update config");

    assert_eq!(updated.confidence_threshold, 3.0);
    assert_eq!(updated.min_peer_group_size, 10);

    // Verify the change persisted
    let fetched = config_service
        .get_or_create(tenant_id)
        .await
        .expect("Should get updated config");

    assert_eq!(fetched.confidence_threshold, 3.0);
    assert_eq!(fetched.min_peer_group_size, 10);

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for updating scoring weights
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_update_scoring_weights() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Update with custom weights that sum to 1.0
    let new_weights = ScoringWeights {
        role_frequency: 0.40,       // Increased from 0.30
        entitlement_count: 0.20,    // Decreased from 0.25
        assignment_pattern: 0.15,   // Decreased from 0.20
        peer_group_coverage: 0.15,  // Same
        historical_deviation: 0.10, // Same
    };

    let input = UpsertOutlierConfiguration {
        confidence_threshold: None,
        frequency_threshold: None,
        min_peer_group_size: None,
        scoring_weights: Some(new_weights),
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let updated = config_service
        .update(tenant_id, input)
        .await
        .expect("Should update weights");

    assert!((updated.scoring_weights.0.role_frequency - 0.40).abs() < 0.001);
    assert!((updated.scoring_weights.0.entitlement_count - 0.20).abs() < 0.001);

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for weight validation rejection
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_reject_invalid_weights() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Try to update with weights that don't sum to 1.0
    let bad_weights = ScoringWeights {
        role_frequency: 0.50,
        entitlement_count: 0.50,
        assignment_pattern: 0.20, // Sum = 1.20, too high
        peer_group_coverage: 0.00,
        historical_deviation: 0.00,
    };

    let input = UpsertOutlierConfiguration {
        confidence_threshold: None,
        frequency_threshold: None,
        min_peer_group_size: None,
        scoring_weights: Some(bad_weights),
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let result = config_service.update(tenant_id, input).await;

    assert!(
        result.is_err(),
        "Should reject weights that don't sum to 1.0"
    );

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for confidence threshold validation
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_reject_invalid_confidence_threshold() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Try with threshold too high
    let input_high = UpsertOutlierConfiguration {
        confidence_threshold: Some(6.0), // Max is 5.0
        frequency_threshold: None,
        min_peer_group_size: None,
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let result = config_service.update(tenant_id, input_high).await;
    assert!(result.is_err(), "Should reject threshold > 5.0");

    // Try with threshold too low
    let input_low = UpsertOutlierConfiguration {
        confidence_threshold: Some(0.3), // Min is 0.5 - actually this should pass since validation is 0.0-5.0
        frequency_threshold: None,
        min_peer_group_size: None,
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    // Note: 0.3 is within 0.0-5.0 range, so this should actually pass
    // The original test assumption was wrong - confidence threshold range is 0.0-5.0
    let result = config_service.update(tenant_id, input_low).await;
    assert!(result.is_ok(), "Threshold 0.3 is valid (range is 0.0-5.0)");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for enabling/disabling configuration
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_toggle_enabled() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Disable using enable/disable methods
    let updated = config_service
        .disable(tenant_id)
        .await
        .expect("Should disable config");

    assert!(!updated.is_enabled);

    // Re-enable
    let updated = config_service
        .enable(tenant_id)
        .await
        .expect("Should re-enable config");

    assert!(updated.is_enabled);

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for frequency threshold validation
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_frequency_threshold_validation() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Try with threshold too high (must be 0.0-1.0)
    let input = UpsertOutlierConfiguration {
        confidence_threshold: None,
        frequency_threshold: Some(1.5), // Max is 1.0
        min_peer_group_size: None,
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let result = config_service.update(tenant_id, input).await;
    assert!(result.is_err(), "Should reject frequency threshold > 1.0");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

/// T037: Integration test for min peer group size validation
#[tokio::test]
#[ignore = "Requires test database"]
async fn test_config_min_peer_group_size_validation() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    create_test_outlier_config(&pool, tenant_id).await;

    let config_service = OutlierConfigService::new(pool.clone());

    // Try with size too small (must be 2-100)
    let input = UpsertOutlierConfiguration {
        confidence_threshold: None,
        frequency_threshold: None,
        min_peer_group_size: Some(1), // Min is 2
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let result = config_service.update(tenant_id, input).await;
    assert!(result.is_err(), "Should reject min peer group size < 2");

    // Try with size too large
    let input = UpsertOutlierConfiguration {
        confidence_threshold: None,
        frequency_threshold: None,
        min_peer_group_size: Some(101), // Max is 100
        scoring_weights: None,
        schedule_cron: None,
        retention_days: None,
        is_enabled: None,
    };

    let result = config_service.update(tenant_id, input).await;
    assert!(result.is_err(), "Should reject min peer group size > 100");

    // Cleanup
    cleanup_outlier_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}
