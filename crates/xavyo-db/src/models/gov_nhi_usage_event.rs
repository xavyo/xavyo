//! NHI Usage Event model.
//!
//! High-volume table tracking NHI authentication events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

// Note: IP addresses are stored as String in PostgreSQL INET columns
// because sqlx maps INET to String. Use source_ip_addr() helper for parsing.

/// Outcome of an NHI usage event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_nhi_usage_outcome", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NhiUsageOutcome {
    /// Authentication/operation succeeded.
    Success,
    /// Authentication/operation failed.
    Failure,
    /// Access was denied (authorization failure).
    Denied,
}

/// An NHI usage event record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovNhiUsageEvent {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The NHI that authenticated.
    pub nhi_id: Uuid,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// The resource/service accessed.
    pub target_resource: String,

    /// The action performed (read, write, admin, etc.).
    pub action: String,

    /// Outcome of the event.
    pub outcome: NhiUsageOutcome,

    /// Source IP address (stored as String, INET in DB).
    pub source_ip: Option<String>,

    /// User agent string.
    pub user_agent: Option<String>,

    /// Request duration in milliseconds.
    pub duration_ms: Option<i32>,

    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Request to create a new usage event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovNhiUsageEvent {
    pub nhi_id: Uuid,
    pub target_resource: String,
    pub action: String,
    pub outcome: NhiUsageOutcome,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub duration_ms: Option<i32>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter options for listing usage events.
#[derive(Debug, Clone, Default)]
pub struct NhiUsageEventFilter {
    pub nhi_id: Option<Uuid>,
    pub target_resource: Option<String>,
    pub outcome: Option<NhiUsageOutcome>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Summary of usage for an NHI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiUsageSummary {
    pub nhi_id: Uuid,
    pub period_days: i32,
    pub total_events: i64,
    pub successful_events: i64,
    pub failed_events: i64,
    pub denied_events: i64,
    pub unique_resources: i64,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Resource access count.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResourceAccessCount {
    pub target_resource: String,
    pub access_count: i64,
    pub last_access: DateTime<Utc>,
}

impl GovNhiUsageEvent {
    /// Get the source IP as parsed IpAddr (if present and valid).
    #[must_use]
    pub fn source_ip_addr(&self) -> Option<IpAddr> {
        self.source_ip.as_ref().and_then(|s| s.parse().ok())
    }

    /// Record a new usage event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovNhiUsageEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_nhi_usage_events (
                tenant_id, nhi_id, target_resource, action, outcome,
                source_ip, user_agent, duration_ms, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(data.nhi_id)
        .bind(&data.target_resource)
        .bind(&data.action)
        .bind(data.outcome)
        .bind(data.source_ip)
        .bind(&data.user_agent)
        .bind(data.duration_ms)
        .bind(&data.metadata)
        .fetch_one(pool)
        .await
    }

    /// List usage events for an NHI with filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiUsageEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_nhi_usage_events
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.nhi_id.is_some() {
            query.push_str(&format!(" AND nhi_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.target_resource.is_some() {
            query.push_str(&format!(" AND target_resource ILIKE ${}", param_idx));
            param_idx += 1;
        }

        if filter.outcome.is_some() {
            query.push_str(&format!(" AND outcome = ${}", param_idx));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            query.push_str(&format!(" AND timestamp >= ${}", param_idx));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            query.push_str(&format!(" AND timestamp <= ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(nhi_id) = filter.nhi_id {
            q = q.bind(nhi_id);
        }

        if let Some(ref resource) = filter.target_resource {
            q = q.bind(format!("%{}%", resource));
        }

        if let Some(outcome) = filter.outcome {
            q = q.bind(outcome);
        }

        if let Some(start) = filter.start_date {
            q = q.bind(start);
        }

        if let Some(end) = filter.end_date {
            q = q.bind(end);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count usage events with filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiUsageEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_nhi_usage_events
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.nhi_id.is_some() {
            query.push_str(&format!(" AND nhi_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.target_resource.is_some() {
            query.push_str(&format!(" AND target_resource ILIKE ${}", param_idx));
            param_idx += 1;
        }

        if filter.outcome.is_some() {
            query.push_str(&format!(" AND outcome = ${}", param_idx));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            query.push_str(&format!(" AND timestamp >= ${}", param_idx));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            query.push_str(&format!(" AND timestamp <= ${}", param_idx));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(nhi_id) = filter.nhi_id {
            q = q.bind(nhi_id);
        }

        if let Some(ref resource) = filter.target_resource {
            q = q.bind(format!("%{}%", resource));
        }

        if let Some(outcome) = filter.outcome {
            q = q.bind(outcome);
        }

        if let Some(start) = filter.start_date {
            q = q.bind(start);
        }

        if let Some(end) = filter.end_date {
            q = q.bind(end);
        }

        q.fetch_one(pool).await
    }

    /// Get usage summary for an NHI.
    pub async fn get_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        period_days: i32,
    ) -> Result<NhiUsageSummary, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE outcome = 'success') as success,
                COUNT(*) FILTER (WHERE outcome = 'failure') as failure,
                COUNT(*) FILTER (WHERE outcome = 'denied') as denied,
                COUNT(DISTINCT target_resource) as unique_resources,
                MAX(timestamp) as last_used
            FROM gov_nhi_usage_events
            WHERE tenant_id = $1
                AND nhi_id = $2
                AND timestamp >= NOW() - ($3 || ' days')::interval
            "#,
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(period_days)
        .fetch_one(pool)
        .await?;

        Ok(NhiUsageSummary {
            nhi_id,
            period_days,
            total_events: row.0,
            successful_events: row.1,
            failed_events: row.2,
            denied_events: row.3,
            unique_resources: row.4,
            last_used_at: row.5,
        })
    }

    /// Get top accessed resources for an NHI.
    pub async fn get_top_resources(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        period_days: i32,
        limit: i64,
    ) -> Result<Vec<ResourceAccessCount>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                target_resource,
                COUNT(*) as access_count,
                MAX(timestamp) as last_access
            FROM gov_nhi_usage_events
            WHERE tenant_id = $1
                AND nhi_id = $2
                AND timestamp >= NOW() - ($3 || ' days')::interval
            GROUP BY target_resource
            ORDER BY access_count DESC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(period_days)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get the last usage timestamp for an NHI.
    pub async fn get_last_used(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT MAX(timestamp) FROM gov_nhi_usage_events
            WHERE tenant_id = $1 AND nhi_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_outcome_serialization() {
        let success = NhiUsageOutcome::Success;
        let json = serde_json::to_string(&success).unwrap();
        assert_eq!(json, "\"success\"");

        let failure = NhiUsageOutcome::Failure;
        let json = serde_json::to_string(&failure).unwrap();
        assert_eq!(json, "\"failure\"");

        let denied = NhiUsageOutcome::Denied;
        let json = serde_json::to_string(&denied).unwrap();
        assert_eq!(json, "\"denied\"");
    }

    #[test]
    fn test_usage_summary_default() {
        let summary = NhiUsageSummary {
            nhi_id: Uuid::new_v4(),
            period_days: 30,
            total_events: 100,
            successful_events: 95,
            failed_events: 3,
            denied_events: 2,
            unique_resources: 5,
            last_used_at: Some(Utc::now()),
        };

        assert_eq!(
            summary.total_events,
            summary.successful_events + summary.failed_events + summary.denied_events
        );
    }
}
