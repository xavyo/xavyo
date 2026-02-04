//! Delegation Lifecycle Service for governance API (F053).
//!
//! Handles automatic delegation lifecycle management:
//! - Activating pending delegations when `start_at` is reached
//! - Expiring delegations when `ends_at` is reached
//! - Sending expiration warnings before delegation ends

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::GovApprovalDelegation;
use xavyo_governance::error::Result;

/// Service for delegation lifecycle operations.
pub struct DelegationLifecycleService {
    pool: PgPool,
}

/// Result of lifecycle processing.
#[derive(Debug, Clone, Default)]
pub struct LifecycleProcessingResult {
    /// Number of delegations activated.
    pub activated_count: usize,
    /// Number of delegations expired.
    pub expired_count: usize,
    /// Number of expiration warnings sent.
    pub warnings_sent: usize,
    /// IDs of activated delegations.
    pub activated_ids: Vec<Uuid>,
    /// IDs of expired delegations.
    pub expired_ids: Vec<Uuid>,
    /// IDs of delegations with warnings sent.
    pub warned_ids: Vec<Uuid>,
}

impl DelegationLifecycleService {
    /// Create a new delegation lifecycle service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Activate pending delegations whose `start_at` has been reached.
    ///
    /// Finds all delegations with status = pending and `starts_at` <= now,
    /// then updates their status to active.
    pub async fn activate_pending_delegations(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<GovApprovalDelegation>> {
        let now = Utc::now();

        // Find pending delegations that should be activated
        let pending_delegations: Vec<GovApprovalDelegation> = sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
                AND status = 'pending'
                AND starts_at <= $2
                AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        let mut activated = Vec::new();

        for delegation in pending_delegations {
            // Activate the delegation using existing method
            let result =
                GovApprovalDelegation::activate(&self.pool, tenant_id, delegation.id).await?;

            if let Some(updated) = result {
                activated.push(updated);
            }
        }

        Ok(activated)
    }

    /// Expire delegations whose `ends_at` has been reached.
    ///
    /// Finds all delegations with status = active and `ends_at` <= now,
    /// then updates their status to expired.
    pub async fn expire_delegations(&self, tenant_id: Uuid) -> Result<Vec<GovApprovalDelegation>> {
        let now = Utc::now();

        // Find active delegations that should be expired
        let active_delegations: Vec<GovApprovalDelegation> = sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
                AND status = 'active'
                AND ends_at <= $2
                AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        let mut expired = Vec::new();

        for delegation in active_delegations {
            // Mark as expired using existing method
            let result =
                GovApprovalDelegation::expire(&self.pool, tenant_id, delegation.id).await?;

            if let Some(updated) = result {
                expired.push(updated);
            }
        }

        Ok(expired)
    }

    /// Send expiration warnings for delegations expiring soon.
    ///
    /// Finds all delegations with status = active, `ends_at` <= now + 24h,
    /// and `expiry_warning_sent` = false, then marks them as warned.
    /// The actual notification sending is handled by notification service.
    pub async fn send_expiration_warnings(
        &self,
        tenant_id: Uuid,
        warning_hours: i64,
    ) -> Result<Vec<GovApprovalDelegation>> {
        let now = Utc::now();
        let warning_threshold = now + Duration::hours(warning_hours);

        // Find delegations expiring soon that haven't been warned
        let expiring_delegations: Vec<GovApprovalDelegation> = sqlx::query_as(
            r"
            SELECT * FROM gov_approval_delegations
            WHERE tenant_id = $1
                AND status = 'active'
                AND ends_at <= $2
                AND ends_at > $3
                AND is_active = true
                AND expiry_warning_sent = false
            ",
        )
        .bind(tenant_id)
        .bind(warning_threshold)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        let mut warned = Vec::new();

        for delegation in expiring_delegations {
            // Mark as warned using existing method
            let result = GovApprovalDelegation::mark_expiry_warning_sent(
                &self.pool,
                tenant_id,
                delegation.id,
            )
            .await?;

            if let Some(updated) = result {
                warned.push(updated);
                // Note: Actual notification sending would be done here by calling
                // notification service. For now we just mark the warning as sent.
            }
        }

        Ok(warned)
    }

    /// Process all delegation lifecycle operations for a tenant.
    ///
    /// Combines activation, expiration, and warning operations.
    pub async fn process_delegation_lifecycle(
        &self,
        tenant_id: Uuid,
    ) -> Result<LifecycleProcessingResult> {
        let activated = self.activate_pending_delegations(tenant_id).await?;
        let expired = self.expire_delegations(tenant_id).await?;
        let warned = self.send_expiration_warnings(tenant_id, 24).await?;

        Ok(LifecycleProcessingResult {
            activated_count: activated.len(),
            expired_count: expired.len(),
            warnings_sent: warned.len(),
            activated_ids: activated.iter().map(|d| d.id).collect(),
            expired_ids: expired.iter().map(|d| d.id).collect(),
            warned_ids: warned.iter().map(|d| d.id).collect(),
        })
    }

    /// Process lifecycle for all tenants.
    ///
    /// This is for batch processing across all tenants.
    pub async fn process_all_tenants_lifecycle(
        &self,
    ) -> Result<Vec<(Uuid, LifecycleProcessingResult)>> {
        // Get all distinct tenant IDs with active delegations
        let tenant_ids: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT tenant_id FROM gov_approval_delegations
            WHERE is_active = true OR status IN ('pending', 'active')
            ",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();

        for tenant_id in tenant_ids {
            let result = self.process_delegation_lifecycle(tenant_id).await?;
            results.push((tenant_id, result));
        }

        Ok(results)
    }

    /// Get database pool reference.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_processing_result_default() {
        let result = LifecycleProcessingResult::default();

        assert_eq!(result.activated_count, 0);
        assert_eq!(result.expired_count, 0);
        assert_eq!(result.warnings_sent, 0);
        assert!(result.activated_ids.is_empty());
        assert!(result.expired_ids.is_empty());
        assert!(result.warned_ids.is_empty());
    }

    #[test]
    fn test_lifecycle_processing_result_with_data() {
        let result = LifecycleProcessingResult {
            activated_count: 2,
            expired_count: 3,
            warnings_sent: 1,
            activated_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            expired_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            warned_ids: vec![Uuid::new_v4()],
        };

        assert_eq!(result.activated_count, 2);
        assert_eq!(result.expired_count, 3);
        assert_eq!(result.warnings_sent, 1);
        assert_eq!(result.activated_ids.len(), 2);
        assert_eq!(result.expired_ids.len(), 3);
        assert_eq!(result.warned_ids.len(), 1);
    }

    #[test]
    fn test_warning_threshold_calculation() {
        let now = Utc::now();
        let warning_hours = 24i64;
        let warning_threshold = now + Duration::hours(warning_hours);

        assert!(warning_threshold > now);
        let diff = warning_threshold - now;
        assert_eq!(diff.num_hours(), 24);
    }
}
