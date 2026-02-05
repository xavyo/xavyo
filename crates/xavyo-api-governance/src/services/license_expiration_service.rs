//! License Expiration Service (F065 - US7).
//!
//! Provides business logic for managing license pool expiration, renewal alerts,
//! and expiration policy enforcement. Supports:
//! - Finding pools expiring within a configurable window
//! - Automatically expiring pools past their expiration date
//! - Enforcing expiration policies (`BlockNew`, `RevokeAll`, `WarnOnly`)
//! - Generating renewal alert information for pools approaching expiration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::models::{
    GovLicenseAssignment, GovLicensePool, LicenseAuditAction, LicenseExpirationPolicy,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::{LicenseAuditService, RecordPoolEventParams};
use crate::models::license::{ExpiringLicensesResponse, ExpiringPoolInfo};

// ============================================================================
// Result Types
// ============================================================================

/// Result of checking and expiring pools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationCheckResult {
    /// Total number of active pools checked.
    pub pools_checked: usize,
    /// Number of pools newly expired.
    pub pools_expired: usize,
    /// Summary of policies applied to each expired pool.
    pub policies_applied: Vec<PolicyApplicationSummary>,
}

/// Summary of a policy applied to a single expired pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApplicationSummary {
    /// The pool that was expired.
    pub pool_id: Uuid,
    /// The pool display name.
    pub pool_name: String,
    /// The policy that was enforced.
    pub policy: LicenseExpirationPolicy,
    /// Number of assignments revoked (only non-zero for `RevokeAll`).
    pub assignments_revoked: i64,
}

/// Result of applying an expiration policy to a single pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApplicationResult {
    /// The pool that the policy was applied to.
    pub pool_id: Uuid,
    /// The policy that was enforced.
    pub policy: LicenseExpirationPolicy,
    /// Number of assignments revoked (only non-zero for `RevokeAll`).
    pub assignments_revoked: i64,
}

/// Result of identifying pools needing renewal alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalAlertResult {
    /// Pools within their warning window that need renewal alerts.
    pub pools_needing_alerts: Vec<RenewalAlertInfo>,
}

/// Information about a pool that needs a renewal alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalAlertInfo {
    /// The pool ID.
    pub pool_id: Uuid,
    /// The pool display name.
    pub pool_name: String,
    /// The vendor name.
    pub vendor: String,
    /// When the pool expires.
    pub expiration_date: DateTime<Utc>,
    /// Days remaining until expiration.
    pub days_until_expiration: i64,
    /// Number of currently allocated licenses.
    pub allocated_count: i32,
    /// Total license capacity.
    pub total_capacity: i32,
}

/// Description of the action determined by an expiration policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpirationAction {
    /// Block new assignments but keep existing ones active.
    BlockNewAssignments,
    /// Revoke all active assignments immediately.
    RevokeAllAssignments,
    /// Warn only; no enforcement action taken.
    WarnOnly,
}

// ============================================================================
// Pure Business Logic Functions
// ============================================================================

/// Check if a pool has expired based on its expiration date.
///
/// Returns `true` if the pool has a set expiration date that is in the past
/// relative to the given `now` timestamp. Returns `false` if there is no
/// expiration date set (the pool never expires).
///
/// Note: The async service method `check_and_expire_pools` uses
/// `GovLicensePool::find_newly_expired()` which performs the expiration check
/// in SQL. This pure function is available for non-DB filtering scenarios
/// and is exercised by unit tests.
#[allow(dead_code)]
pub(crate) fn is_pool_expired(expiration_date: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match expiration_date {
        Some(exp) => exp <= now,
        None => false,
    }
}

/// Check if a pool is within its warning window (approaching expiration but not yet expired).
///
/// Returns `true` when `now` is within the `warning_days` window before expiration
/// but the pool has not yet expired. Returns `false` for pools with no expiration date,
/// pools that are already expired, or pools outside the warning window.
pub(crate) fn should_send_warning(
    expiration_date: Option<DateTime<Utc>>,
    warning_days: i64,
    now: DateTime<Utc>,
) -> bool {
    match expiration_date {
        Some(exp) => {
            let warning_threshold = exp - chrono::Duration::days(warning_days);
            now >= warning_threshold && now < exp
        }
        None => false,
    }
}

/// Determine what enforcement action to take based on the expiration policy.
///
/// Maps each `LicenseExpirationPolicy` variant to the concrete action:
/// - `BlockNew` → block new assignments (existing remain active)
/// - `RevokeAll` → revoke all active assignments immediately
/// - `WarnOnly` → no enforcement action, only advisory
pub(crate) fn determine_expiration_action(policy: LicenseExpirationPolicy) -> ExpirationAction {
    match policy {
        LicenseExpirationPolicy::BlockNew => ExpirationAction::BlockNewAssignments,
        LicenseExpirationPolicy::RevokeAll => ExpirationAction::RevokeAllAssignments,
        LicenseExpirationPolicy::WarnOnly => ExpirationAction::WarnOnly,
    }
}

/// Build an `ExpiringPoolInfo` from a `GovLicensePool` and a reference timestamp.
///
/// Computes `days_until_expiration` as the difference between the pool's
/// `expiration_date` and `now`, clamped to a minimum of 0. Returns `None` if
/// the pool has no expiration date set.
pub(crate) fn build_expiring_pool_info(
    pool: &GovLicensePool,
    now: DateTime<Utc>,
) -> Option<ExpiringPoolInfo> {
    pool.expiration_date.map(|exp_date| {
        let days_until = compute_days_until_expiration(exp_date, now);
        ExpiringPoolInfo {
            id: pool.id,
            name: pool.name.clone(),
            vendor: pool.vendor.clone(),
            expiration_date: exp_date,
            days_until_expiration: days_until,
            allocated_count: pool.allocated_count,
            total_capacity: pool.total_capacity,
            expiration_policy: pool.expiration_policy,
        }
    })
}

/// Compute the number of days until expiration, clamped to a minimum of 0.
///
/// If `expiration_date` is in the past relative to `now`, returns 0 instead
/// of a negative number.
pub(crate) fn compute_days_until_expiration(
    expiration_date: DateTime<Utc>,
    now: DateTime<Utc>,
) -> i64 {
    (expiration_date - now).num_days().max(0)
}

// ============================================================================
// Service
// ============================================================================

/// Service for license expiration management and renewal alerts.
pub struct LicenseExpirationService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

impl LicenseExpirationService {
    /// Create a new license expiration service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    /// Find active pools expiring within a given number of days.
    ///
    /// Queries for active pools whose `expiration_date` falls within
    /// `within_days` days from now, excluding pools that are already expired
    /// or have no expiration date set.
    ///
    /// Results are ordered by expiration date ascending (soonest first).
    pub async fn get_expiring_pools(
        &self,
        tenant_id: Uuid,
        within_days: i64,
    ) -> Result<ExpiringLicensesResponse> {
        let expiring_pools =
            GovLicensePool::find_expiring(&self.pool, tenant_id, within_days as i32).await?;

        let now = Utc::now();
        let pools: Vec<ExpiringPoolInfo> = expiring_pools
            .iter()
            .filter_map(|p| build_expiring_pool_info(p, now))
            .collect();

        let total_expiring = pools.len() as i64;

        Ok(ExpiringLicensesResponse {
            pools,
            total_expiring,
        })
    }

    /// Check all active pools and expire those past their expiration date.
    ///
    /// For each pool that has passed its `expiration_date`:
    /// 1. Updates the pool status to `Expired`
    /// 2. Applies the pool's `expiration_policy`
    /// 3. Logs audit events
    ///
    /// Returns statistics about the operation including how many pools were
    /// expired and what policies were applied.
    pub async fn check_and_expire_pools(&self, tenant_id: Uuid) -> Result<ExpirationCheckResult> {
        // Find active pools that have passed their expiration date
        let newly_expired = GovLicensePool::find_newly_expired(&self.pool, tenant_id).await?;
        let pools_checked = newly_expired.len();
        let mut pools_expired: usize = 0;
        let mut policies_applied: Vec<PolicyApplicationSummary> = Vec::new();

        for pool_record in &newly_expired {
            // Set the pool status to expired
            let expired_result =
                GovLicensePool::set_expired(&self.pool, tenant_id, pool_record.id).await?;

            if expired_result.is_some() {
                pools_expired += 1;

                info!(
                    pool_id = %pool_record.id,
                    pool_name = %pool_record.name,
                    "License pool expired"
                );

                // Log audit event for pool expiration
                let _ = self
                    .audit_service
                    .record_pool_event(
                        tenant_id,
                        RecordPoolEventParams {
                            pool_id: pool_record.id,
                            action: LicenseAuditAction::PoolExpired,
                            actor_id: Uuid::nil(), // System actor
                            details: Some(serde_json::json!({
                                "pool_name": pool_record.name,
                                "expiration_date": pool_record.expiration_date,
                                "expiration_policy": pool_record.expiration_policy,
                            })),
                        },
                    )
                    .await;

                // Apply the expiration policy
                let policy_result = self
                    .apply_expiration_policy(tenant_id, pool_record.id)
                    .await?;

                policies_applied.push(PolicyApplicationSummary {
                    pool_id: pool_record.id,
                    pool_name: pool_record.name.clone(),
                    policy: policy_result.policy,
                    assignments_revoked: policy_result.assignments_revoked,
                });
            }
        }

        Ok(ExpirationCheckResult {
            pools_checked,
            pools_expired,
            policies_applied,
        })
    }

    /// Apply the expiration policy for a pool.
    ///
    /// Loads the pool, checks its `expiration_policy`, and takes action:
    ///
    /// - **`BlockNew`**: No additional action needed. The pool's expired status
    ///   already blocks new assignments via `is_allocation_blocked()`.
    /// - **`RevokeAll`**: Revokes all active assignments for this pool and
    ///   resets the `allocated_count` to 0.
    /// - **`WarnOnly`**: No action needed beyond the status change. Existing
    ///   assignments remain active.
    pub async fn apply_expiration_policy(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<PolicyApplicationResult> {
        let pool_record = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        let policy = pool_record.expiration_policy;
        let mut assignments_revoked: i64 = 0;
        let action = determine_expiration_action(policy);

        match action {
            ExpirationAction::BlockNewAssignments => {
                // No additional action needed - pool status=expired already blocks
                // new assignments in is_allocation_blocked().
                info!(
                    pool_id = %pool_id,
                    "BlockNew policy applied: new assignments blocked"
                );
            }
            ExpirationAction::RevokeAllAssignments => {
                // Revoke all active assignments for this pool
                let revoked_count =
                    GovLicenseAssignment::expire_all_for_pool(&self.pool, tenant_id, pool_id)
                        .await?;
                assignments_revoked = revoked_count as i64;

                // Reset allocated count to 0 since all assignments are revoked.
                // We do this by setting status to expired which already happened,
                // but we also need to zero out allocated_count.
                sqlx::query(
                    r"
                    UPDATE gov_license_pools
                    SET allocated_count = 0, updated_at = NOW()
                    WHERE id = $1 AND tenant_id = $2
                    ",
                )
                .bind(pool_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;

                info!(
                    pool_id = %pool_id,
                    revoked = assignments_revoked,
                    "RevokeAll policy applied: all assignments revoked"
                );

                // Log audit event for bulk revocation
                if assignments_revoked > 0 {
                    let _ = self
                        .audit_service
                        .record_pool_event(
                            tenant_id,
                            RecordPoolEventParams {
                                pool_id,
                                action: LicenseAuditAction::LicenseExpired,
                                actor_id: Uuid::nil(), // System actor
                                details: Some(serde_json::json!({
                                    "policy": "revoke_all",
                                    "assignments_revoked": assignments_revoked,
                                })),
                            },
                        )
                        .await;
                }
            }
            ExpirationAction::WarnOnly => {
                // No action needed beyond status change. Existing assignments
                // remain active and functional.
                info!(
                    pool_id = %pool_id,
                    "WarnOnly policy applied: no enforcement action taken"
                );
            }
        }

        Ok(PolicyApplicationResult {
            pool_id,
            policy,
            assignments_revoked,
        })
    }

    /// Identify pools that need renewal alerts.
    ///
    /// Finds active pools whose expiration date is within their `warning_days`
    /// window but have not yet expired. These pools should trigger renewal
    /// notifications to administrators.
    ///
    /// The actual notification dispatch is out of scope for this service --
    /// callers should use the returned list to send notifications via their
    /// preferred channel (email, Slack, etc.).
    pub async fn send_renewal_alerts(&self, tenant_id: Uuid) -> Result<RenewalAlertResult> {
        // Get all active pools for the tenant
        let active_pools = GovLicensePool::list_active(&self.pool, tenant_id).await?;

        let now = Utc::now();
        let mut pools_needing_alerts: Vec<RenewalAlertInfo> = Vec::new();

        for pool_record in &active_pools {
            // Use the extracted pure function for warning check
            if should_send_warning(
                pool_record.expiration_date,
                i64::from(pool_record.warning_days),
                now,
            ) {
                if let Some(exp_date) = pool_record.expiration_date {
                    let days_until = compute_days_until_expiration(exp_date, now);

                    pools_needing_alerts.push(RenewalAlertInfo {
                        pool_id: pool_record.id,
                        pool_name: pool_record.name.clone(),
                        vendor: pool_record.vendor.clone(),
                        expiration_date: exp_date,
                        days_until_expiration: days_until,
                        allocated_count: pool_record.allocated_count,
                        total_capacity: pool_record.total_capacity,
                    });

                    warn!(
                        pool_id = %pool_record.id,
                        pool_name = %pool_record.name,
                        days_until = days_until,
                        "License pool approaching expiration"
                    );
                }
            }
        }

        // Sort by days until expiration (soonest first)
        pools_needing_alerts.sort_by_key(|p| p.days_until_expiration);

        Ok(RenewalAlertResult {
            pools_needing_alerts,
        })
    }

    /// Get the underlying database pool reference.
    #[must_use]
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the audit service reference.
    #[must_use]
    pub fn audit_service(&self) -> &LicenseAuditService {
        &self.audit_service
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use rust_decimal::Decimal;
    use xavyo_db::models::{
        LicenseBillingPeriod, LicenseExpirationPolicy, LicensePoolStatus, LicenseType,
    };

    // ========================================================================
    // Helper: build a GovLicensePool for testing pure functions
    // ========================================================================

    fn make_pool(overrides: PoolOverrides) -> GovLicensePool {
        GovLicensePool {
            id: overrides.id.unwrap_or_else(Uuid::new_v4),
            tenant_id: Uuid::new_v4(),
            name: overrides.name.unwrap_or_else(|| "Test Pool".to_string()),
            vendor: overrides
                .vendor
                .unwrap_or_else(|| "Test Vendor".to_string()),
            description: None,
            total_capacity: overrides.total_capacity.unwrap_or(100),
            allocated_count: overrides.allocated_count.unwrap_or(50),
            cost_per_license: Some(Decimal::from(10)),
            currency: "USD".to_string(),
            billing_period: LicenseBillingPeriod::Monthly,
            license_type: LicenseType::Named,
            expiration_date: overrides.expiration_date,
            expiration_policy: overrides
                .expiration_policy
                .unwrap_or(LicenseExpirationPolicy::BlockNew),
            warning_days: overrides.warning_days.unwrap_or(60),
            status: overrides.status.unwrap_or(LicensePoolStatus::Active),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Uuid::new_v4(),
        }
    }

    #[derive(Default)]
    struct PoolOverrides {
        id: Option<Uuid>,
        name: Option<String>,
        vendor: Option<String>,
        total_capacity: Option<i32>,
        allocated_count: Option<i32>,
        expiration_date: Option<DateTime<Utc>>,
        expiration_policy: Option<LicenseExpirationPolicy>,
        warning_days: Option<i32>,
        status: Option<LicensePoolStatus>,
    }

    // ========================================================================
    // is_pool_expired Tests
    // ========================================================================

    #[test]
    fn test_is_pool_expired_none_returns_false() {
        let now = Utc::now();
        assert!(!is_pool_expired(None, now));
    }

    #[test]
    fn test_is_pool_expired_future_date_returns_false() {
        let now = Utc::now();
        let future = now + Duration::days(30);
        assert!(!is_pool_expired(Some(future), now));
    }

    #[test]
    fn test_is_pool_expired_past_date_returns_true() {
        let now = Utc::now();
        let past = now - Duration::days(5);
        assert!(is_pool_expired(Some(past), now));
    }

    #[test]
    fn test_is_pool_expired_exact_now_returns_true() {
        // expiration_date <= now means exactly-now is expired
        let now = Utc::now();
        assert!(is_pool_expired(Some(now), now));
    }

    #[test]
    fn test_is_pool_expired_one_second_ago() {
        let now = Utc::now();
        let just_past = now - Duration::seconds(1);
        assert!(is_pool_expired(Some(just_past), now));
    }

    #[test]
    fn test_is_pool_expired_one_second_ahead() {
        let now = Utc::now();
        let just_future = now + Duration::seconds(1);
        assert!(!is_pool_expired(Some(just_future), now));
    }

    // ========================================================================
    // should_send_warning Tests
    // ========================================================================

    #[test]
    fn test_should_send_warning_within_window_returns_true() {
        let now = Utc::now();
        let expiration = now + Duration::days(10);
        let warning_days = 30;
        // now is 10 days before expiration, window starts at 30 days before
        assert!(should_send_warning(Some(expiration), warning_days, now));
    }

    #[test]
    fn test_should_send_warning_outside_window_returns_false() {
        let now = Utc::now();
        let expiration = now + Duration::days(90);
        let warning_days = 30;
        // now is 90 days before expiration, window starts at 30 days before
        assert!(!should_send_warning(Some(expiration), warning_days, now));
    }

    #[test]
    fn test_should_send_warning_already_expired_returns_false() {
        let now = Utc::now();
        let expiration = now - Duration::days(5);
        let warning_days = 30;
        // Pool already expired; now >= exp so now < exp is false
        assert!(!should_send_warning(Some(expiration), warning_days, now));
    }

    #[test]
    fn test_should_send_warning_no_expiration_returns_false() {
        let now = Utc::now();
        assert!(!should_send_warning(None, 30, now));
    }

    #[test]
    fn test_should_send_warning_exactly_at_window_boundary() {
        let now = Utc::now();
        let warning_days = 30;
        let expiration = now + Duration::days(warning_days);
        // warning_threshold = expiration - 30 days = now
        // now >= now && now < expiration → true
        assert!(should_send_warning(Some(expiration), warning_days, now));
    }

    #[test]
    fn test_should_send_warning_one_second_before_window() {
        let now = Utc::now();
        let warning_days: i64 = 30;
        // Expiration is 30 days + 1 second from now, so warning_threshold = now + 1s
        let expiration = now + Duration::days(warning_days) + Duration::seconds(1);
        // warning_threshold = expiration - 30 days = now + 1s
        // now < now + 1s → now < warning_threshold → false
        assert!(!should_send_warning(Some(expiration), warning_days, now));
    }

    #[test]
    fn test_should_send_warning_exactly_at_expiration_returns_false() {
        let now = Utc::now();
        // expiration == now, so now < exp is false
        assert!(!should_send_warning(Some(now), 30, now));
    }

    #[test]
    fn test_should_send_warning_one_day_before_expiration() {
        let now = Utc::now();
        let expiration = now + Duration::days(1);
        // 1 day before expiration, warning window is 60 days
        assert!(should_send_warning(Some(expiration), 60, now));
    }

    #[test]
    fn test_should_send_warning_zero_warning_days() {
        let now = Utc::now();
        let expiration = now + Duration::days(10);
        // warning_threshold = expiration - 0 = expiration
        // now >= expiration is false (now is 10 days before)
        assert!(!should_send_warning(Some(expiration), 0, now));
    }

    // ========================================================================
    // determine_expiration_action Tests
    // ========================================================================

    #[test]
    fn test_determine_action_block_new() {
        let action = determine_expiration_action(LicenseExpirationPolicy::BlockNew);
        assert_eq!(action, ExpirationAction::BlockNewAssignments);
    }

    #[test]
    fn test_determine_action_revoke_all() {
        let action = determine_expiration_action(LicenseExpirationPolicy::RevokeAll);
        assert_eq!(action, ExpirationAction::RevokeAllAssignments);
    }

    #[test]
    fn test_determine_action_warn_only() {
        let action = determine_expiration_action(LicenseExpirationPolicy::WarnOnly);
        assert_eq!(action, ExpirationAction::WarnOnly);
    }

    #[test]
    fn test_determine_action_all_policies_exhaustive() {
        // Verify all policies map to distinct actions
        let actions: Vec<ExpirationAction> = vec![
            determine_expiration_action(LicenseExpirationPolicy::BlockNew),
            determine_expiration_action(LicenseExpirationPolicy::RevokeAll),
            determine_expiration_action(LicenseExpirationPolicy::WarnOnly),
        ];
        assert_eq!(actions[0], ExpirationAction::BlockNewAssignments);
        assert_eq!(actions[1], ExpirationAction::RevokeAllAssignments);
        assert_eq!(actions[2], ExpirationAction::WarnOnly);
        // Each action is different
        assert_ne!(actions[0], actions[1]);
        assert_ne!(actions[1], actions[2]);
        assert_ne!(actions[0], actions[2]);
    }

    // ========================================================================
    // compute_days_until_expiration Tests
    // ========================================================================

    #[test]
    fn test_compute_days_30_days_away() {
        let now = Utc::now();
        let exp = now + Duration::days(30);
        assert_eq!(compute_days_until_expiration(exp, now), 30);
    }

    #[test]
    fn test_compute_days_same_instant() {
        let now = Utc::now();
        assert_eq!(compute_days_until_expiration(now, now), 0);
    }

    #[test]
    fn test_compute_days_past_date_clamped_to_zero() {
        let now = Utc::now();
        let past = now - Duration::days(10);
        assert_eq!(compute_days_until_expiration(past, now), 0);
    }

    #[test]
    fn test_compute_days_one_year_ahead() {
        let now = Utc::now();
        let exp = now + Duration::days(365);
        assert_eq!(compute_days_until_expiration(exp, now), 365);
    }

    #[test]
    fn test_compute_days_hours_within_same_day() {
        let now = Utc::now();
        let exp = now + Duration::hours(12);
        // 12 hours = 0 full days
        assert_eq!(compute_days_until_expiration(exp, now), 0);
    }

    #[test]
    fn test_compute_days_just_over_one_day() {
        let now = Utc::now();
        let exp = now + Duration::hours(25);
        assert_eq!(compute_days_until_expiration(exp, now), 1);
    }

    #[test]
    fn test_compute_days_large_negative_clamped() {
        let now = Utc::now();
        let far_past = now - Duration::days(1000);
        assert_eq!(compute_days_until_expiration(far_past, now), 0);
    }

    // ========================================================================
    // build_expiring_pool_info Tests
    // ========================================================================

    #[test]
    fn test_build_expiring_pool_info_with_expiration_date() {
        let now = Utc::now();
        let exp = now + Duration::days(15);
        let pool_id = Uuid::new_v4();
        let pool = make_pool(PoolOverrides {
            id: Some(pool_id),
            name: Some("Microsoft 365 E3".to_string()),
            vendor: Some("Microsoft".to_string()),
            total_capacity: Some(200),
            allocated_count: Some(150),
            expiration_date: Some(exp),
            expiration_policy: Some(LicenseExpirationPolicy::RevokeAll),
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.id, pool_id);
        assert_eq!(info.name, "Microsoft 365 E3");
        assert_eq!(info.vendor, "Microsoft");
        assert_eq!(info.days_until_expiration, 15);
        assert_eq!(info.allocated_count, 150);
        assert_eq!(info.total_capacity, 200);
        assert_eq!(info.expiration_policy, LicenseExpirationPolicy::RevokeAll);
        assert_eq!(info.expiration_date, exp);
    }

    #[test]
    fn test_build_expiring_pool_info_no_expiration_returns_none() {
        let now = Utc::now();
        let pool = make_pool(PoolOverrides {
            expiration_date: None,
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now);
        assert!(info.is_none());
    }

    #[test]
    fn test_build_expiring_pool_info_past_expiration_clamps_days() {
        let now = Utc::now();
        let past = now - Duration::days(5);
        let pool = make_pool(PoolOverrides {
            expiration_date: Some(past),
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now).unwrap();
        assert_eq!(info.days_until_expiration, 0);
    }

    #[test]
    fn test_build_expiring_pool_info_preserves_all_fields() {
        let now = Utc::now();
        let exp = now + Duration::days(7);
        let pool = make_pool(PoolOverrides {
            name: Some("Adobe CC".to_string()),
            vendor: Some("Adobe".to_string()),
            total_capacity: Some(50),
            allocated_count: Some(25),
            expiration_date: Some(exp),
            expiration_policy: Some(LicenseExpirationPolicy::WarnOnly),
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now).unwrap();
        assert_eq!(info.name, "Adobe CC");
        assert_eq!(info.vendor, "Adobe");
        assert_eq!(info.total_capacity, 50);
        assert_eq!(info.allocated_count, 25);
        assert_eq!(info.expiration_policy, LicenseExpirationPolicy::WarnOnly);
    }

    #[test]
    fn test_build_expiring_pool_info_exact_now_gives_zero_days() {
        let now = Utc::now();
        let pool = make_pool(PoolOverrides {
            expiration_date: Some(now),
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now).unwrap();
        assert_eq!(info.days_until_expiration, 0);
    }

    // ========================================================================
    // Integration of pure functions: combined scenarios
    // ========================================================================

    #[test]
    fn test_expired_pool_should_not_warn() {
        // If a pool is expired, should_send_warning must return false
        let now = Utc::now();
        let exp = now - Duration::days(10);
        assert!(is_pool_expired(Some(exp), now));
        assert!(!should_send_warning(Some(exp), 60, now));
    }

    #[test]
    fn test_pool_in_warning_window_not_yet_expired() {
        let now = Utc::now();
        let exp = now + Duration::days(5);
        let warning_days = 30;
        assert!(!is_pool_expired(Some(exp), now));
        assert!(should_send_warning(Some(exp), warning_days, now));
    }

    #[test]
    fn test_pool_well_before_warning_window() {
        let now = Utc::now();
        let exp = now + Duration::days(100);
        let warning_days = 30;
        assert!(!is_pool_expired(Some(exp), now));
        assert!(!should_send_warning(Some(exp), warning_days, now));
    }

    #[test]
    fn test_build_info_then_check_expired() {
        // Build info for a pool that expires in 0 days, verify it rounds to 0
        let now = Utc::now();
        let exp = now - Duration::hours(1);
        let pool = make_pool(PoolOverrides {
            expiration_date: Some(exp),
            ..Default::default()
        });

        let info = build_expiring_pool_info(&pool, now).unwrap();
        assert_eq!(info.days_until_expiration, 0);
        assert!(is_pool_expired(Some(exp), now));
    }

    #[test]
    fn test_action_and_warning_for_each_policy() {
        let now = Utc::now();
        let exp = now + Duration::days(10);
        let warning_days = 30;

        // Pool is in warning window for all policies
        for policy in [
            LicenseExpirationPolicy::BlockNew,
            LicenseExpirationPolicy::RevokeAll,
            LicenseExpirationPolicy::WarnOnly,
        ] {
            assert!(should_send_warning(Some(exp), warning_days, now));
            let _action = determine_expiration_action(policy);
            // Warning is independent of the policy action
        }
    }

    // ========================================================================
    // ExpirationAction Debug/Eq Tests
    // ========================================================================

    #[test]
    fn test_expiration_action_debug() {
        let action = ExpirationAction::BlockNewAssignments;
        let debug = format!("{:?}", action);
        assert!(debug.contains("BlockNewAssignments"));
    }

    #[test]
    fn test_expiration_action_clone_eq() {
        let a = ExpirationAction::RevokeAllAssignments;
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ========================================================================
    // Serialization roundtrip tests (retained for result types)
    // ========================================================================

    #[test]
    fn test_expiration_check_result_serialization_roundtrip() {
        let result = ExpirationCheckResult {
            pools_checked: 10,
            pools_expired: 1,
            policies_applied: vec![PolicyApplicationSummary {
                pool_id: Uuid::new_v4(),
                pool_name: "Test Pool".to_string(),
                policy: LicenseExpirationPolicy::WarnOnly,
                assignments_revoked: 0,
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ExpirationCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pools_checked, 10);
        assert_eq!(deserialized.pools_expired, 1);
        assert_eq!(deserialized.policies_applied.len(), 1);
        assert_eq!(
            deserialized.policies_applied[0].policy,
            LicenseExpirationPolicy::WarnOnly
        );
    }

    #[test]
    fn test_policy_application_result_serialization_roundtrip() {
        let pool_id = Uuid::new_v4();
        let result = PolicyApplicationResult {
            pool_id,
            policy: LicenseExpirationPolicy::RevokeAll,
            assignments_revoked: 75,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: PolicyApplicationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pool_id, pool_id);
        assert_eq!(deserialized.policy, LicenseExpirationPolicy::RevokeAll);
        assert_eq!(deserialized.assignments_revoked, 75);
    }

    #[test]
    fn test_renewal_alert_info_serialization_roundtrip() {
        let pool_id = Uuid::new_v4();
        let exp_date = Utc::now() + Duration::days(7);
        let info = RenewalAlertInfo {
            pool_id,
            pool_name: "Roundtrip Pool".to_string(),
            vendor: "Roundtrip Vendor".to_string(),
            expiration_date: exp_date,
            days_until_expiration: 7,
            allocated_count: 10,
            total_capacity: 25,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: RenewalAlertInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pool_id, pool_id);
        assert_eq!(deserialized.pool_name, "Roundtrip Pool");
        assert_eq!(deserialized.days_until_expiration, 7);
    }
}
