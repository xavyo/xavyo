//! Governance Role Metrics model.
//!
//! Represents role effectiveness metrics snapshots.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Trend direction for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = MetricsTrendDirection))]
#[sqlx(type_name = "trend_direction", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// Metrics trending upward.
    Up,
    /// Metrics stable.
    Stable,
    /// Metrics trending downward.
    Down,
}

/// Entitlement usage details within a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EntitlementUsage {
    /// Entitlement ID.
    pub entitlement_id: Uuid,
    /// Users who actually use this entitlement.
    pub used_by_count: i32,
    /// Total users with the role.
    pub total_users: i32,
    /// Usage rate (`used_by_count` / `total_users`).
    pub usage_rate: f64,
}

/// Role effectiveness metrics snapshot.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleMetrics {
    /// Unique identifier for this metrics record.
    pub id: Uuid,

    /// The tenant this metrics belongs to.
    pub tenant_id: Uuid,

    /// The role being measured.
    pub role_id: Uuid,

    /// When these metrics were calculated.
    pub calculated_at: DateTime<Utc>,

    /// Utilization rate (active users / total users with role).
    pub utilization_rate: f64,

    /// Coverage rate (used entitlements / total entitlements in role).
    pub coverage_rate: f64,

    /// Total users with this role.
    pub user_count: i32,

    /// Active users (users who have logged in recently).
    pub active_user_count: i32,

    /// Per-entitlement usage statistics.
    pub entitlement_usage: serde_json::Value,

    /// Trend compared to previous period.
    pub trend_direction: TrendDirection,

    /// When this record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create role metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleMetrics {
    pub role_id: Uuid,
    pub utilization_rate: f64,
    pub coverage_rate: f64,
    pub user_count: i32,
    pub active_user_count: i32,
    pub entitlement_usage: Vec<EntitlementUsage>,
    pub trend_direction: TrendDirection,
}

/// Filter options for listing metrics.
#[derive(Debug, Clone, Default)]
pub struct RoleMetricsFilter {
    pub role_id: Option<Uuid>,
    pub trend_direction: Option<TrendDirection>,
    pub min_utilization: Option<f64>,
    pub max_utilization: Option<f64>,
}

impl GovRoleMetrics {
    /// Find the latest metrics for a role.
    pub async fn find_latest_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT id, tenant_id, role_id, calculated_at,
                utilization_rate::float8 as utilization_rate,
                coverage_rate::float8 as coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction, created_at
            FROM gov_role_metrics
            WHERE tenant_id = $1 AND role_id = $2
            ORDER BY calculated_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_optional(pool)
        .await
    }

    /// Find metrics by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT id, tenant_id, role_id, calculated_at,
                utilization_rate::float8 as utilization_rate,
                coverage_rate::float8 as coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction, created_at
            FROM gov_role_metrics
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List metrics history for a role.
    pub async fn list_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT id, tenant_id, role_id, calculated_at,
                utilization_rate::float8 as utilization_rate,
                coverage_rate::float8 as coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction, created_at
            FROM gov_role_metrics
            WHERE tenant_id = $1 AND role_id = $2
            ORDER BY calculated_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List latest metrics for all roles with filtering and pagination.
    pub async fn list_latest_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleMetricsFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Use DISTINCT ON to get latest metrics per role
        let mut query = String::from(
            r"
            SELECT DISTINCT ON (role_id) id, tenant_id, role_id, calculated_at,
                utilization_rate::float8 as utilization_rate,
                coverage_rate::float8 as coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction, created_at
            FROM gov_role_metrics
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND role_id = ${param_count}"));
        }
        if filter.trend_direction.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trend_direction = ${param_count}"));
        }
        if filter.min_utilization.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND utilization_rate >= ${param_count}"));
        }
        if filter.max_utilization.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND utilization_rate <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY role_id, calculated_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRoleMetrics>(&query).bind(tenant_id);

        if let Some(role_id) = filter.role_id {
            q = q.bind(role_id);
        }
        if let Some(trend) = filter.trend_direction {
            q = q.bind(trend);
        }
        if let Some(min_util) = filter.min_utilization {
            q = q.bind(min_util);
        }
        if let Some(max_util) = filter.max_utilization {
            q = q.bind(max_util);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count unique roles with metrics.
    pub async fn count_roles_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RoleMetricsFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(DISTINCT role_id) FROM gov_role_metrics
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND role_id = ${param_count}"));
        }
        if filter.trend_direction.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trend_direction = ${param_count}"));
        }
        if filter.min_utilization.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND utilization_rate >= ${param_count}"));
        }
        if filter.max_utilization.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND utilization_rate <= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(role_id) = filter.role_id {
            q = q.bind(role_id);
        }
        if let Some(trend) = filter.trend_direction {
            q = q.bind(trend);
        }
        if let Some(min_util) = filter.min_utilization {
            q = q.bind(min_util);
        }
        if let Some(max_util) = filter.max_utilization {
            q = q.bind(max_util);
        }

        q.fetch_one(pool).await
    }

    /// Create a new metrics record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateRoleMetrics,
    ) -> Result<Self, sqlx::Error> {
        let entitlement_usage = serde_json::to_value(&input.entitlement_usage)
            .unwrap_or_else(|_| serde_json::json!([]));

        sqlx::query_as(
            r"
            INSERT INTO gov_role_metrics (
                tenant_id, role_id, calculated_at, utilization_rate, coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction
            )
            VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8)
            RETURNING id, tenant_id, role_id, calculated_at,
                utilization_rate::float8 as utilization_rate,
                coverage_rate::float8 as coverage_rate,
                user_count, active_user_count, entitlement_usage, trend_direction, created_at
            ",
        )
        .bind(tenant_id)
        .bind(input.role_id)
        .bind(input.utilization_rate)
        .bind(input.coverage_rate)
        .bind(input.user_count)
        .bind(input.active_user_count)
        .bind(&entitlement_usage)
        .bind(input.trend_direction)
        .fetch_one(pool)
        .await
    }

    /// Create metrics for multiple roles in batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        inputs: Vec<CreateRoleMetrics>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let metrics = Self::create(pool, tenant_id, input).await?;
            results.push(metrics);
        }
        Ok(results)
    }

    /// Delete old metrics (keep last N records per role).
    pub async fn cleanup_old_metrics(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        keep_count: i64,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_role_metrics
            WHERE tenant_id = $1
            AND id NOT IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY role_id ORDER BY calculated_at DESC) as rn
                    FROM gov_role_metrics
                    WHERE tenant_id = $1
                ) ranked
                WHERE rn <= $2
            )
            ",
        )
        .bind(tenant_id)
        .bind(keep_count)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Parse entitlement usage from JSON.
    #[must_use]
    pub fn parse_entitlement_usage(&self) -> Vec<EntitlementUsage> {
        serde_json::from_value(self.entitlement_usage.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trend_direction_serialization() {
        let up = TrendDirection::Up;
        let json = serde_json::to_string(&up).unwrap();
        assert_eq!(json, "\"up\"");

        let stable = TrendDirection::Stable;
        let json = serde_json::to_string(&stable).unwrap();
        assert_eq!(json, "\"stable\"");

        let down = TrendDirection::Down;
        let json = serde_json::to_string(&down).unwrap();
        assert_eq!(json, "\"down\"");
    }

    #[test]
    fn test_entitlement_usage_parsing() {
        let json = serde_json::json!([
            {
                "entitlement_id": "00000000-0000-0000-0000-000000000001",
                "used_by_count": 45,
                "total_users": 50,
                "usage_rate": 0.9
            }
        ]);

        let usage: Vec<EntitlementUsage> = serde_json::from_value(json).unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].used_by_count, 45);
        assert_eq!(usage[0].total_users, 50);
        assert!((usage[0].usage_rate - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_role_metrics_filter_defaults() {
        let filter = RoleMetricsFilter::default();
        assert!(filter.role_id.is_none());
        assert!(filter.trend_direction.is_none());
        assert!(filter.min_utilization.is_none());
        assert!(filter.max_utilization.is_none());
    }
}
