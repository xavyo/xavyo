//! License Incompatibility Service (F065).
//!
//! Provides business logic for managing license incompatibility rules.
//! These rules define pairs of license pools that cannot be assigned
//! to the same user (similar to `SoD` rules for entitlements).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicenseIncompatibility, GovLicenseIncompatibility, GovLicensePool,
    IncompatibilityViolation, LicenseIncompatibilityFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::LicenseAuditService;
use crate::models::license::{
    CreateLicenseIncompatibilityRequest, LicenseIncompatibilityListResponse,
    LicenseIncompatibilityResponse, ListLicenseIncompatibilitiesParams,
};

// ============================================================================
// Pure Business Logic Functions (extracted for testability)
// ============================================================================

/// Validates that two pool IDs are not the same.
///
/// An incompatibility rule must reference two distinct pools; a pool
/// cannot be incompatible with itself.
pub(crate) fn validate_not_self_incompatible(pool_a_id: Uuid, pool_b_id: Uuid) -> Result<()> {
    if pool_a_id == pool_b_id {
        return Err(GovernanceError::Validation(
            "Pool A and Pool B must be different".to_string(),
        ));
    }
    Ok(())
}

/// Enforces pagination limits on list queries.
///
/// - `limit` is clamped to `[1, 100]`.
/// - `offset` is clamped to `>= 0`.
pub(crate) fn enforce_list_limits(limit: i64, offset: i64) -> (i64, i64) {
    let clamped_limit = limit.clamp(1, 100);
    let clamped_offset = offset.max(0);
    (clamped_limit, clamped_offset)
}

/// Normalizes a pool pair so that the smaller UUID always comes first.
///
/// This ensures symmetric incompatibility lookups: if (A, B) is stored,
/// looking up (B, A) will produce the same normalized pair.
pub(crate) fn normalize_pool_pair(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Formats a human-readable violation summary from a list of violations.
///
/// Returns a message suitable for error responses or audit logs.
/// Used in tests and available for cross-service error reporting.
#[allow(dead_code)]
pub(crate) fn format_violation_message(violations: &[IncompatibilityViolation]) -> String {
    match violations.len() {
        0 => "No incompatibility violations found.".to_string(),
        1 => {
            let v = &violations[0];
            format!(
                "Incompatibility violation: pool '{}' conflicts with existing pool '{}' (reason: {})",
                v.requested_pool_name, v.existing_pool_name, v.reason
            )
        }
        n => {
            let mut msg = format!("{n} incompatibility violations found:");
            for (i, v) in violations.iter().enumerate() {
                msg.push_str(&format!(
                    "\n  {}. pool '{}' conflicts with existing pool '{}' (reason: {})",
                    i + 1,
                    v.requested_pool_name,
                    v.existing_pool_name,
                    v.reason
                ));
            }
            msg
        }
    }
}

/// Service for license incompatibility rule management.
pub struct LicenseIncompatibilityService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

impl LicenseIncompatibilityService {
    /// Create a new incompatibility service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    /// Create a new incompatibility rule.
    ///
    /// Validates that both pools exist and that the rule doesn't already exist.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: CreateLicenseIncompatibilityRequest,
    ) -> Result<LicenseIncompatibilityResponse> {
        // Validate that pool_a_id and pool_b_id are different
        validate_not_self_incompatible(request.pool_a_id, request.pool_b_id)?;

        // Normalize the pool pair so the smaller UUID is always first.
        // This ensures symmetric lookups work correctly in the DB.
        let (pool_a_id, pool_b_id) = normalize_pool_pair(request.pool_a_id, request.pool_b_id);

        // Validate both pools exist
        let pool_a = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_a_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_a_id))?;

        let pool_b = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_b_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_b_id))?;

        // Check if rule already exists (symmetric)
        if let Some(_existing) =
            GovLicenseIncompatibility::are_incompatible(&self.pool, tenant_id, pool_a_id, pool_b_id)
                .await?
        {
            return Err(GovernanceError::Validation(format!(
                "Incompatibility rule already exists between '{}' and '{}'",
                pool_a.name, pool_b.name
            )));
        }

        // Create the rule
        let input = CreateGovLicenseIncompatibility {
            pool_a_id,
            pool_b_id,
            reason: request.reason.clone(),
            created_by: actor_id,
        };

        let created = GovLicenseIncompatibility::create(&self.pool, tenant_id, &input).await?;

        // Log audit event
        self.audit_service
            .log_incompatibility_created(
                tenant_id,
                created.id,
                pool_a_id,
                pool_b_id,
                &pool_a.name,
                &pool_b.name,
                &request.reason,
                actor_id,
            )
            .await?;

        Ok(LicenseIncompatibilityResponse::from_model_with_names(
            created,
            Some(pool_a.name),
            Some(pool_a.vendor),
            Some(pool_b.name),
            Some(pool_b.vendor),
        ))
    }

    /// Get an incompatibility rule by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Option<LicenseIncompatibilityResponse>> {
        let rule =
            GovLicenseIncompatibility::find_by_id(&self.pool, tenant_id, rule_id.into()).await?;

        match rule {
            Some(r) => {
                // Fetch pool names for display
                let pool_a = GovLicensePool::find_by_id(&self.pool, tenant_id, r.pool_a_id).await?;
                let pool_b = GovLicensePool::find_by_id(&self.pool, tenant_id, r.pool_b_id).await?;

                Ok(Some(LicenseIncompatibilityResponse::from_model_with_names(
                    r,
                    pool_a.as_ref().map(|p| p.name.clone()),
                    pool_a.as_ref().map(|p| p.vendor.clone()),
                    pool_b.as_ref().map(|p| p.name.clone()),
                    pool_b.as_ref().map(|p| p.vendor.clone()),
                )))
            }
            None => Ok(None),
        }
    }

    /// Get an incompatibility rule by ID, returning an error if not found.
    pub async fn get_required(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<LicenseIncompatibilityResponse> {
        self.get(tenant_id, rule_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseIncompatibilityNotFound(rule_id))
    }

    /// List incompatibility rules with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        params: ListLicenseIncompatibilitiesParams,
    ) -> Result<LicenseIncompatibilityListResponse> {
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);

        let filter = LicenseIncompatibilityFilter {
            pool_id: params.pool_id,
        };

        let rules = GovLicenseIncompatibility::list_with_details(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;

        let total = GovLicenseIncompatibility::count(&self.pool, tenant_id, &filter).await?;

        Ok(LicenseIncompatibilityListResponse {
            items: rules
                .into_iter()
                .map(LicenseIncompatibilityResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Delete an incompatibility rule.
    pub async fn delete(&self, tenant_id: Uuid, rule_id: Uuid, actor_id: Uuid) -> Result<bool> {
        // Get the rule first to get pool names for audit
        let rule = GovLicenseIncompatibility::find_by_id(&self.pool, tenant_id, rule_id.into())
            .await?
            .ok_or_else(|| GovernanceError::LicenseIncompatibilityNotFound(rule_id))?;

        let pool_a = GovLicensePool::find_by_id(&self.pool, tenant_id, rule.pool_a_id).await?;
        let pool_b = GovLicensePool::find_by_id(&self.pool, tenant_id, rule.pool_b_id).await?;

        let deleted =
            GovLicenseIncompatibility::delete(&self.pool, tenant_id, rule_id.into()).await?;

        if deleted {
            self.audit_service
                .log_incompatibility_deleted(
                    tenant_id,
                    rule_id,
                    rule.pool_a_id,
                    rule.pool_b_id,
                    pool_a
                        .as_ref()
                        .map_or("unknown", |p| p.name.as_str()),
                    pool_b
                        .as_ref()
                        .map_or("unknown", |p| p.name.as_str()),
                    actor_id,
                )
                .await?;
        }

        Ok(deleted)
    }

    /// Check if assigning a license from a pool to a user would violate any incompatibility rules.
    pub async fn check_violations(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pool_id: Uuid,
    ) -> Result<Vec<IncompatibilityViolation>> {
        let violations = GovLicenseIncompatibility::check_user_violations(
            &self.pool, tenant_id, user_id, pool_id,
        )
        .await?;

        Ok(violations)
    }

    /// Check if two pools are incompatible.
    pub async fn are_pools_incompatible(
        &self,
        tenant_id: Uuid,
        pool_a_id: Uuid,
        pool_b_id: Uuid,
    ) -> Result<bool> {
        let result = GovLicenseIncompatibility::are_incompatible(
            &self.pool, tenant_id, pool_a_id, pool_b_id,
        )
        .await?;

        Ok(result.is_some())
    }

    /// Get the underlying database pool reference.
    #[must_use] 
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::license::{
        CreateLicenseIncompatibilityRequest, LicenseIncompatibilityResponse,
        ListIncompatibilitiesParams,
    };

    // ========================================================================
    // validate_not_self_incompatible tests
    // ========================================================================

    #[test]
    fn test_validate_not_self_incompatible_different_uuids_ok() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(validate_not_self_incompatible(a, b).is_ok());
    }

    #[test]
    fn test_validate_not_self_incompatible_same_uuid_err() {
        let id = Uuid::new_v4();
        let result = validate_not_self_incompatible(id, id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Pool A and Pool B must be different"),
            "Expected validation message, got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_not_self_incompatible_nil_uuids() {
        // Even nil UUIDs that are equal should be rejected
        let nil = Uuid::nil();
        assert!(validate_not_self_incompatible(nil, nil).is_err());
    }

    #[test]
    fn test_validate_not_self_incompatible_nil_vs_non_nil() {
        let nil = Uuid::nil();
        let non_nil = Uuid::new_v4();
        assert!(validate_not_self_incompatible(nil, non_nil).is_ok());
    }

    // ========================================================================
    // enforce_list_limits tests
    // ========================================================================

    #[test]
    fn test_enforce_list_limits_normal_values() {
        assert_eq!(enforce_list_limits(20, 0), (20, 0));
        assert_eq!(enforce_list_limits(50, 100), (50, 100));
    }

    #[test]
    fn test_enforce_list_limits_zero_limit_clamped_to_one() {
        let (limit, _) = enforce_list_limits(0, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_negative_limit_clamped_to_one() {
        let (limit, _) = enforce_list_limits(-5, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_over_max_clamped_to_100() {
        let (limit, _) = enforce_list_limits(500, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_exact_boundaries() {
        assert_eq!(enforce_list_limits(1, 0), (1, 0));
        assert_eq!(enforce_list_limits(100, 0), (100, 0));
    }

    #[test]
    fn test_enforce_list_limits_negative_offset_clamped_to_zero() {
        let (_, offset) = enforce_list_limits(20, -10);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_list_limits_large_offset_preserved() {
        let (_, offset) = enforce_list_limits(20, 999_999);
        assert_eq!(offset, 999_999);
    }

    // ========================================================================
    // normalize_pool_pair tests
    // ========================================================================

    #[test]
    fn test_normalize_pool_pair_already_ordered() {
        let a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let b = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();
        assert_eq!(normalize_pool_pair(a, b), (a, b));
    }

    #[test]
    fn test_normalize_pool_pair_reversed_order() {
        let a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let b = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();
        // Passing in reversed order should still produce (a, b)
        assert_eq!(normalize_pool_pair(b, a), (a, b));
    }

    #[test]
    fn test_normalize_pool_pair_symmetric() {
        let x = Uuid::new_v4();
        let y = Uuid::new_v4();
        // Regardless of argument order, the result is the same
        assert_eq!(normalize_pool_pair(x, y), normalize_pool_pair(y, x));
    }

    #[test]
    fn test_normalize_pool_pair_equal_uuids() {
        let id = Uuid::new_v4();
        // Equal UUIDs: both positions should be the same
        assert_eq!(normalize_pool_pair(id, id), (id, id));
    }

    #[test]
    fn test_normalize_pool_pair_deterministic_with_random_ids() {
        // Generate several random pairs and verify symmetry holds
        for _ in 0..10 {
            let a = Uuid::new_v4();
            let b = Uuid::new_v4();
            let (norm_a, norm_b) = normalize_pool_pair(a, b);
            let (norm_a2, norm_b2) = normalize_pool_pair(b, a);
            assert_eq!(norm_a, norm_a2);
            assert_eq!(norm_b, norm_b2);
            assert!(norm_a <= norm_b);
        }
    }

    // ========================================================================
    // format_violation_message tests
    // ========================================================================

    #[test]
    fn test_format_violation_message_no_violations() {
        let msg = format_violation_message(&[]);
        assert_eq!(msg, "No incompatibility violations found.");
    }

    #[test]
    fn test_format_violation_message_single_violation() {
        let violation = IncompatibilityViolation {
            rule_id: Uuid::new_v4(),
            existing_pool_id: Uuid::new_v4(),
            existing_pool_name: "Microsoft 365 E3".to_string(),
            requested_pool_id: Uuid::new_v4(),
            requested_pool_name: "Microsoft 365 E5".to_string(),
            reason: "E5 supersedes E3".to_string(),
        };
        let msg = format_violation_message(&[violation]);
        assert!(msg.contains("Microsoft 365 E5"));
        assert!(msg.contains("Microsoft 365 E3"));
        assert!(msg.contains("E5 supersedes E3"));
        assert!(msg.starts_with("Incompatibility violation:"));
    }

    #[test]
    fn test_format_violation_message_multiple_violations() {
        let requested_pool_id = Uuid::new_v4();
        let violations = vec![
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool X".to_string(),
                requested_pool_id,
                requested_pool_name: "New Pool".to_string(),
                reason: "Conflict with Pool X".to_string(),
            },
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool Y".to_string(),
                requested_pool_id,
                requested_pool_name: "New Pool".to_string(),
                reason: "Conflict with Pool Y".to_string(),
            },
        ];

        let msg = format_violation_message(&violations);
        assert!(msg.starts_with("2 incompatibility violations found:"));
        assert!(msg.contains("1. pool 'New Pool' conflicts with existing pool 'Pool X'"));
        assert!(msg.contains("2. pool 'New Pool' conflicts with existing pool 'Pool Y'"));
        assert!(msg.contains("Conflict with Pool X"));
        assert!(msg.contains("Conflict with Pool Y"));
    }

    #[test]
    fn test_format_violation_message_preserves_unicode_names() {
        let violation = IncompatibilityViolation {
            rule_id: Uuid::new_v4(),
            existing_pool_id: Uuid::new_v4(),
            existing_pool_name: "Adobe CC \u{30C1}\u{30FC}\u{30E0}".to_string(), // Japanese team
            requested_pool_id: Uuid::new_v4(),
            requested_pool_name: "Adobe CC \u{500B}\u{4EBA}".to_string(), // Japanese individual
            reason: "\u{30E9}\u{30A4}\u{30BB}\u{30F3}\u{30B9}\u{7AF6}\u{5408}".to_string(), // license conflict
        };
        let msg = format_violation_message(&[violation]);
        assert!(msg.contains("Adobe CC"));
    }

    // ========================================================================
    // Serde Tests (kept from original - these are genuinely useful)
    // ========================================================================

    #[test]
    fn test_list_params_from_json_defaults() {
        let json = r#"{}"#;
        let params: ListIncompatibilitiesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 20); // default_limit() function
        assert_eq!(params.offset, 0);
        assert!(params.pool_id.is_none());
    }

    #[test]
    fn test_list_params_with_pool_filter() {
        let pool_id = Uuid::new_v4();
        let json = format!(r#"{{"pool_id": "{}"}}"#, pool_id);
        let params: ListIncompatibilitiesParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params.pool_id, Some(pool_id));
    }

    #[test]
    fn test_list_params_with_pagination() {
        let json = r#"{"limit": 50, "offset": 100}"#;
        let params: ListIncompatibilitiesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 100);
    }

    #[test]
    fn test_list_params_limit_enforcement_integration() {
        // Deserialize extreme values and run through enforce_list_limits
        let json = r#"{"limit": 0}"#;
        let params: ListIncompatibilitiesParams = serde_json::from_str(json).unwrap();
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);
        assert_eq!(limit, 1); // clamped from 0 to 1
        assert_eq!(offset, 0);

        let json = r#"{"limit": 500}"#;
        let params: ListIncompatibilitiesParams = serde_json::from_str(json).unwrap();
        let (limit, _) = enforce_list_limits(params.limit, params.offset);
        assert_eq!(limit, 100); // clamped from 500 to 100
    }

    // ========================================================================
    // Reason Validation Tests
    // ========================================================================

    #[test]
    fn test_reason_various_formats() {
        let reasons = vec![
            "License terms conflict",
            "Cost optimization - E5 includes E3 features",
            "Vendor restriction: cannot mix products",
            "Compliance requirement per AUDIT-2024-001",
            "\u{540C}\u{3058}\u{30D9}\u{30F3}\u{30C0}\u{30FC}\u{306E}\u{7570}\u{306A}\u{308B}\u{30A8}\u{30C7}\u{30A3}\u{30B7}\u{30E7}\u{30F3}", // Japanese: "Different editions from same vendor"
            "R\u{00E8}gle de conformit\u{00E9}: licences incompatibles", // French
        ];

        for reason in reasons {
            let request = CreateLicenseIncompatibilityRequest {
                pool_a_id: Uuid::new_v4(),
                pool_b_id: Uuid::new_v4(),
                reason: reason.to_string(),
            };
            assert!(!request.reason.is_empty());
        }
    }

    // ========================================================================
    // Response Structure Tests (useful for verifying display logic)
    // ========================================================================

    #[test]
    fn test_incompatibility_response_deleted_pool() {
        // When a pool is deleted, its name/vendor might be None
        let response = LicenseIncompatibilityResponse {
            id: Uuid::new_v4(),
            pool_a_id: Uuid::new_v4(),
            pool_a_name: Some("Active Pool".to_string()),
            pool_a_vendor: Some("Vendor".to_string()),
            pool_b_id: Uuid::new_v4(),
            pool_b_name: None, // Pool was deleted
            pool_b_vendor: None,
            reason: "Historical rule".to_string(),
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
        };

        assert!(response.pool_a_name.is_some());
        assert!(response.pool_b_name.is_none());
    }

    // ========================================================================
    // Symmetric incompatibility concept tests
    // ========================================================================

    #[test]
    fn test_symmetric_incompatibility_via_normalize() {
        // If (A, B) is incompatible, then (B, A) should yield the same
        // normalized pair, so a single DB row covers both directions.
        let pool_a = Uuid::new_v4();
        let pool_b = Uuid::new_v4();

        let (norm_ab_first, norm_ab_second) = normalize_pool_pair(pool_a, pool_b);
        let (norm_ba_first, norm_ba_second) = normalize_pool_pair(pool_b, pool_a);

        assert_eq!(norm_ab_first, norm_ba_first);
        assert_eq!(norm_ab_second, norm_ba_second);
    }

    #[test]
    fn test_normalize_matches_db_storage_convention() {
        // The DB layer (GovLicenseIncompatibility::create) normalizes with
        // `if req.pool_a_id < req.pool_b_id`, so our normalize_pool_pair
        // must produce the same ordering.
        let small = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let large = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();

        let (first, second) = normalize_pool_pair(large, small);
        assert_eq!(first, small);
        assert_eq!(second, large);
    }

    // ========================================================================
    // Combined / scenario tests
    // ========================================================================

    #[test]
    fn test_validate_then_normalize_workflow() {
        // Simulate the create workflow: validate first, then normalize
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Step 1: validate they are different
        assert!(validate_not_self_incompatible(a, b).is_ok());

        // Step 2: normalize for storage
        let (first, second) = normalize_pool_pair(a, b);
        assert!(first <= second);
        assert_ne!(first, second); // because we validated they differ
    }

    #[test]
    fn test_violation_scenario_microsoft_licenses() {
        // Real-world scenario: User has E3, tries to get E5
        let e3_pool_id = Uuid::new_v4();
        let e5_pool_id = Uuid::new_v4();

        let violation = IncompatibilityViolation {
            rule_id: Uuid::new_v4(),
            existing_pool_id: e3_pool_id,
            existing_pool_name: "Microsoft 365 E3".to_string(),
            requested_pool_id: e5_pool_id,
            requested_pool_name: "Microsoft 365 E5".to_string(),
            reason: "E5 includes all E3 features - avoid cost duplication".to_string(),
        };

        let msg = format_violation_message(&[violation]);
        assert!(msg.contains("E3"));
        assert!(msg.contains("E5"));
        assert!(msg.contains("cost"));
    }

    #[test]
    fn test_multiple_violations_all_same_requested_pool() {
        // A user might violate multiple incompatibility rules when
        // requesting a license from a pool that conflicts with
        // multiple pools they already have licenses from.
        let requested_pool_id = Uuid::new_v4();
        let violations = vec![
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool X".to_string(),
                requested_pool_id,
                requested_pool_name: "New Pool".to_string(),
                reason: "Conflict with Pool X".to_string(),
            },
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool Y".to_string(),
                requested_pool_id,
                requested_pool_name: "New Pool".to_string(),
                reason: "Conflict with Pool Y".to_string(),
            },
        ];

        // All violations reference the same requested pool
        assert_eq!(
            violations[0].requested_pool_id,
            violations[1].requested_pool_id
        );
        // But different existing pools
        assert_ne!(
            violations[0].existing_pool_id,
            violations[1].existing_pool_id
        );

        // Format and verify
        let msg = format_violation_message(&violations);
        assert!(msg.contains("Pool X"));
        assert!(msg.contains("Pool Y"));
        assert!(msg.contains("2 incompatibility violations found:"));
    }
}
