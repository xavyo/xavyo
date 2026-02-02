//! Governance Risk Event model.
//!
//! Represents individual events contributing to user risk scores.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A governance risk event.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The user this event is for.
    pub user_id: Uuid,

    /// Associated risk factor (optional).
    pub factor_id: Option<Uuid>,

    /// Event type identifier.
    pub event_type: String,

    /// Event magnitude/value.
    pub value: f64,

    /// Reference to source (e.g., login_id, violation_id).
    pub source_ref: Option<String>,

    /// When the event was created.
    pub created_at: DateTime<Utc>,

    /// When the event expires (stops contributing to score).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to create a new risk event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRiskEvent {
    pub user_id: Uuid,
    pub factor_id: Option<Uuid>,
    pub event_type: String,
    pub value: Option<f64>,
    pub source_ref: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter options for listing risk events.
#[derive(Debug, Clone, Default)]
pub struct RiskEventFilter {
    pub user_id: Option<Uuid>,
    pub factor_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub include_expired: bool,
}

impl GovRiskEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List active (non-expired) events for a user.
    pub async fn list_active_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_events
            WHERE tenant_id = $1 AND user_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// List all events for a user with pagination.
    pub async fn list_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        include_expired: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if include_expired {
            sqlx::query_as(
                r#"
                SELECT * FROM gov_risk_events
                WHERE tenant_id = $1 AND user_id = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM gov_risk_events
                WHERE tenant_id = $1 AND user_id = $2
                AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// Count events for a user.
    pub async fn count_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        include_expired: bool,
    ) -> Result<i64, sqlx::Error> {
        if include_expired {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*) FROM gov_risk_events
                WHERE tenant_id = $1 AND user_id = $2
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*) FROM gov_risk_events
                WHERE tenant_id = $1 AND user_id = $2
                AND (expires_at IS NULL OR expires_at > NOW())
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_one(pool)
            .await
        }
    }

    /// List events by type for a user.
    pub async fn list_by_type_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_events
            WHERE tenant_id = $1 AND user_id = $2 AND event_type = $3
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(event_type)
        .fetch_all(pool)
        .await
    }

    /// Create a new risk event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRiskEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_risk_events (
                tenant_id, user_id, factor_id, event_type, value, source_ref, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.factor_id)
        .bind(&input.event_type)
        .bind(input.value.unwrap_or(1.0))
        .bind(&input.source_ref)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Delete an event.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all expired events for a tenant.
    pub async fn cleanup_expired(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_events
            WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= NOW()
            "#,
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete events older than a specific date.
    pub async fn cleanup_older_than(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_events
            WHERE tenant_id = $1 AND created_at < $2
            "#,
        )
        .bind(tenant_id)
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Sum event values by type for a user (for score calculation).
    pub async fn sum_by_type_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        event_type: &str,
    ) -> Result<f64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(value), 0) FROM gov_risk_events
            WHERE tenant_id = $1 AND user_id = $2 AND event_type = $3
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(event_type)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_risk_event_defaults() {
        let input = CreateGovRiskEvent {
            user_id: Uuid::new_v4(),
            factor_id: None,
            event_type: "failed_login".to_string(),
            value: None,
            source_ref: None,
            expires_at: None,
        };

        assert!(input.value.is_none());
        assert!(input.factor_id.is_none());
    }
}
