//! Metrics service for role effectiveness analytics.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateRoleMetrics, EntitlementUsage, GovRoleMetrics, MetricsTrendDirection, RoleMetricsFilter,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for role metrics operations.
pub struct MetricsService {
    pool: PgPool,
}

impl MetricsService {
    /// Create a new metrics service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the latest metrics for a role.
    pub async fn get_latest_by_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<GovRoleMetrics> {
        GovRoleMetrics::find_latest_by_role(&self.pool, tenant_id, role_id)
            .await?
            .ok_or(GovernanceError::RoleMetricsNotFound(role_id))
    }

    /// Get metrics by ID.
    pub async fn get(&self, tenant_id: Uuid, metrics_id: Uuid) -> Result<GovRoleMetrics> {
        GovRoleMetrics::find_by_id(&self.pool, tenant_id, metrics_id)
            .await?
            .ok_or(GovernanceError::RoleMetricsNotFound(metrics_id))
    }

    /// List metrics history for a role.
    pub async fn list_by_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovRoleMetrics>> {
        let metrics =
            GovRoleMetrics::list_by_role(&self.pool, tenant_id, role_id, limit, offset).await?;
        Ok(metrics)
    }

    /// List latest metrics for all roles with filtering and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_latest(
        &self,
        tenant_id: Uuid,
        role_id: Option<Uuid>,
        trend_direction: Option<MetricsTrendDirection>,
        min_utilization: Option<f64>,
        max_utilization: Option<f64>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRoleMetrics>, i64)> {
        let filter = RoleMetricsFilter {
            role_id,
            trend_direction,
            min_utilization,
            max_utilization,
        };

        let metrics =
            GovRoleMetrics::list_latest_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovRoleMetrics::count_roles_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((metrics, total))
    }

    /// Calculate utilization rate for a role.
    ///
    /// Utilization = active_users / total_users
    pub fn calculate_utilization_rate(total_users: i32, active_users: i32) -> f64 {
        if total_users == 0 {
            return 0.0;
        }
        (active_users as f64 / total_users as f64).min(1.0)
    }

    /// Calculate coverage rate for a role.
    ///
    /// Coverage = used_entitlements / total_entitlements
    pub fn calculate_coverage_rate(entitlement_usage: &[EntitlementUsage]) -> f64 {
        if entitlement_usage.is_empty() {
            return 0.0;
        }

        let used_count = entitlement_usage
            .iter()
            .filter(|e| e.used_by_count > 0)
            .count();

        used_count as f64 / entitlement_usage.len() as f64
    }

    /// Calculate trend direction by comparing current to previous metrics.
    pub fn calculate_trend(
        current_utilization: f64,
        previous_utilization: Option<f64>,
    ) -> MetricsTrendDirection {
        let Some(prev) = previous_utilization else {
            return MetricsTrendDirection::Stable;
        };

        let diff = current_utilization - prev;
        if diff > 0.05 {
            MetricsTrendDirection::Up
        } else if diff < -0.05 {
            MetricsTrendDirection::Down
        } else {
            MetricsTrendDirection::Stable
        }
    }

    /// Maximum number of roles that can be processed in a single batch.
    const MAX_BATCH_SIZE: usize = 100;

    /// Calculate metrics for a set of roles.
    ///
    /// This is the main entry point for calculating metrics for multiple roles.
    /// Note: Role metrics are calculated based on group assignments and entitlement usage.
    /// The role_id should correspond to a group ID in the system.
    ///
    /// The input is limited to MAX_BATCH_SIZE (100) roles to prevent memory issues.
    /// For larger sets, call this method multiple times with different batches.
    pub async fn calculate_metrics_for_roles(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<Vec<GovRoleMetrics>> {
        // Limit batch size to prevent OOM
        let limited_ids = if role_ids.len() > Self::MAX_BATCH_SIZE {
            tracing::warn!(
                tenant_id = %tenant_id,
                requested = role_ids.len(),
                max = Self::MAX_BATCH_SIZE,
                "Role IDs truncated to max batch size"
            );
            &role_ids[..Self::MAX_BATCH_SIZE]
        } else {
            role_ids
        };

        let mut results = Vec::with_capacity(limited_ids.len());

        for role_id in limited_ids {
            let metrics = self.calculate_for_role(tenant_id, *role_id).await?;
            results.push(metrics);
        }

        tracing::info!(
            tenant_id = %tenant_id,
            role_count = results.len(),
            "Calculated metrics for roles"
        );

        Ok(results)
    }

    /// Calculate metrics for a single role.
    async fn calculate_for_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<GovRoleMetrics> {
        // Get previous metrics for trend calculation
        let previous = GovRoleMetrics::find_latest_by_role(&self.pool, tenant_id, role_id).await?;

        // Query user count for this role (group membership via user_groups table)
        // role_id corresponds to a group_id
        let user_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(DISTINCT user_id)
            FROM user_groups
            WHERE tenant_id = $1 AND group_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        // For active users, count users who have logged in recently
        // Fall back to users with recent group membership activity
        let active_user_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(DISTINCT ug.user_id)
            FROM user_groups ug
            LEFT JOIN login_history lh ON lh.user_id = ug.user_id AND lh.tenant_id = ug.tenant_id
            WHERE ug.tenant_id = $1 AND ug.group_id = $2
              AND (lh.created_at > NOW() - INTERVAL '30 days' OR ug.created_at > NOW() - INTERVAL '30 days')
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        // Get entitlements assigned to this role (via group assignment)
        // Note: role_id is treated as a group_id, and entitlements are assigned to groups
        let entitlement_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT entitlement_id
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'group' AND target_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Calculate entitlement usage
        let mut entitlement_usage = Vec::with_capacity(entitlement_ids.len());
        for ent_id in &entitlement_ids {
            // Count how many users have this specific entitlement assigned
            let used_by: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM gov_entitlement_assignments
                WHERE tenant_id = $1 AND entitlement_id = $2 AND status = 'active'
                "#,
            )
            .bind(tenant_id)
            .bind(ent_id)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

            let usage_rate = if user_count > 0 {
                used_by as f64 / user_count as f64
            } else {
                0.0
            };

            entitlement_usage.push(EntitlementUsage {
                entitlement_id: *ent_id,
                used_by_count: used_by as i32,
                total_users: user_count as i32,
                usage_rate,
            });
        }

        // Calculate rates
        let utilization_rate =
            Self::calculate_utilization_rate(user_count as i32, active_user_count as i32);
        let coverage_rate = Self::calculate_coverage_rate(&entitlement_usage);
        let trend_direction = Self::calculate_trend(
            utilization_rate,
            previous.as_ref().map(|p| p.utilization_rate),
        );

        let input = CreateRoleMetrics {
            role_id,
            utilization_rate,
            coverage_rate,
            user_count: user_count as i32,
            active_user_count: active_user_count as i32,
            entitlement_usage,
            trend_direction,
        };

        let metrics = GovRoleMetrics::create(&self.pool, tenant_id, input).await?;
        Ok(metrics)
    }

    /// Cleanup old metrics, keeping the last N records per role.
    pub async fn cleanup_old_metrics(&self, tenant_id: Uuid, keep_count: i64) -> Result<u64> {
        let deleted =
            GovRoleMetrics::cleanup_old_metrics(&self.pool, tenant_id, keep_count).await?;

        if deleted > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                deleted = deleted,
                "Cleaned up old metrics records"
            );
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_utilization_rate() {
        assert!((MetricsService::calculate_utilization_rate(100, 80) - 0.8).abs() < f64::EPSILON);
        assert!((MetricsService::calculate_utilization_rate(0, 0) - 0.0).abs() < f64::EPSILON);
        assert!((MetricsService::calculate_utilization_rate(50, 50) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_coverage_rate() {
        let usage = vec![
            EntitlementUsage {
                entitlement_id: Uuid::new_v4(),
                used_by_count: 10,
                total_users: 20,
                usage_rate: 0.5,
            },
            EntitlementUsage {
                entitlement_id: Uuid::new_v4(),
                used_by_count: 0, // Unused
                total_users: 20,
                usage_rate: 0.0,
            },
        ];

        let coverage = MetricsService::calculate_coverage_rate(&usage);
        assert!((coverage - 0.5).abs() < f64::EPSILON); // 1 of 2 used
    }

    #[test]
    fn test_calculate_trend() {
        assert_eq!(
            MetricsService::calculate_trend(0.8, Some(0.7)),
            MetricsTrendDirection::Up
        );
        assert_eq!(
            MetricsService::calculate_trend(0.5, Some(0.7)),
            MetricsTrendDirection::Down
        );
        assert_eq!(
            MetricsService::calculate_trend(0.7, Some(0.72)),
            MetricsTrendDirection::Stable
        );
        assert_eq!(
            MetricsService::calculate_trend(0.7, None),
            MetricsTrendDirection::Stable
        );
    }
}
