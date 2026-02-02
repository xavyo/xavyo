//! Governance Correlation Threshold model (F067).
//!
//! Per-connector confidence threshold configuration for the correlation engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Per-connector correlation threshold configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCorrelationThreshold {
    /// Unique identifier for the threshold record.
    pub id: Uuid,

    /// The tenant this threshold belongs to.
    pub tenant_id: Uuid,

    /// The connector these thresholds apply to.
    pub connector_id: Uuid,

    /// Confidence score at or above which matches are auto-confirmed.
    pub auto_confirm_threshold: rust_decimal::Decimal,

    /// Confidence score at or above which matches require manual review.
    pub manual_review_threshold: rust_decimal::Decimal,

    /// Whether tuning mode is enabled (logs decisions without acting).
    pub tuning_mode: bool,

    /// Whether to include deactivated accounts in correlation.
    pub include_deactivated: bool,

    /// Number of accounts to process per correlation batch.
    pub batch_size: i32,

    /// When the threshold was created.
    pub created_at: DateTime<Utc>,

    /// When the threshold was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update correlation thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertGovCorrelationThreshold {
    pub auto_confirm_threshold: Option<rust_decimal::Decimal>,
    pub manual_review_threshold: Option<rust_decimal::Decimal>,
    pub tuning_mode: Option<bool>,
    pub include_deactivated: Option<bool>,
    pub batch_size: Option<i32>,
}

impl GovCorrelationThreshold {
    /// Find threshold configuration for a specific connector within a tenant.
    pub async fn find_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_correlation_thresholds
            WHERE tenant_id = $1 AND connector_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(pool)
        .await
    }

    /// Upsert threshold configuration for a connector.
    ///
    /// Inserts a new row or updates the existing one on conflict of
    /// `(tenant_id, connector_id)`. Uses COALESCE to fall back to sensible
    /// defaults when optional fields are not provided.
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: UpsertGovCorrelationThreshold,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_correlation_thresholds (
                tenant_id, connector_id,
                auto_confirm_threshold, manual_review_threshold,
                tuning_mode, include_deactivated, batch_size
            )
            VALUES (
                $1, $2,
                COALESCE($3, 0.8500),
                COALESCE($4, 0.5000),
                COALESCE($5, false),
                COALESCE($6, true),
                COALESCE($7, 500)
            )
            ON CONFLICT (tenant_id, connector_id) DO UPDATE SET
                auto_confirm_threshold = COALESCE($3, gov_correlation_thresholds.auto_confirm_threshold),
                manual_review_threshold = COALESCE($4, gov_correlation_thresholds.manual_review_threshold),
                tuning_mode = COALESCE($5, gov_correlation_thresholds.tuning_mode),
                include_deactivated = COALESCE($6, gov_correlation_thresholds.include_deactivated),
                batch_size = COALESCE($7, gov_correlation_thresholds.batch_size),
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(input.auto_confirm_threshold)
        .bind(input.manual_review_threshold)
        .bind(input.tuning_mode)
        .bind(input.include_deactivated)
        .bind(input.batch_size)
        .fetch_one(pool)
        .await
    }

    /// Delete threshold configuration for a connector.
    ///
    /// Returns `true` if a row was deleted, `false` if no matching row existed.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_correlation_thresholds
            WHERE tenant_id = $1 AND connector_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Returns a default threshold instance for when no row exists in the database.
    ///
    /// This is a pure in-memory helper that does not perform any database call.
    /// Uses `Uuid::nil()` for the `id` field to indicate it is not persisted.
    pub fn find_or_default(tenant_id: Uuid, connector_id: Uuid) -> Self {
        Self {
            id: Uuid::nil(),
            tenant_id,
            connector_id,
            auto_confirm_threshold: rust_decimal::Decimal::new(85, 2), // 0.85
            manual_review_threshold: rust_decimal::Decimal::new(50, 2), // 0.50
            tuning_mode: false,
            include_deactivated: true,
            batch_size: 500,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_thresholds() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let defaults = GovCorrelationThreshold::find_or_default(tenant_id, connector_id);

        assert_eq!(defaults.id, Uuid::nil());
        assert_eq!(defaults.tenant_id, tenant_id);
        assert_eq!(defaults.connector_id, connector_id);
        assert_eq!(
            defaults.auto_confirm_threshold,
            rust_decimal::Decimal::new(85, 2)
        );
        assert_eq!(
            defaults.manual_review_threshold,
            rust_decimal::Decimal::new(50, 2)
        );
        assert!(!defaults.tuning_mode);
        assert!(defaults.include_deactivated);
        assert_eq!(defaults.batch_size, 500);
    }

    #[test]
    fn test_threshold_validation() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let defaults = GovCorrelationThreshold::find_or_default(tenant_id, connector_id);

        // Auto-confirm threshold should be greater than manual review threshold.
        assert!(defaults.auto_confirm_threshold > defaults.manual_review_threshold);
    }

    #[test]
    fn test_upsert_request_serialization() {
        let request = UpsertGovCorrelationThreshold {
            auto_confirm_threshold: Some(rust_decimal::Decimal::new(90, 2)), // 0.90
            manual_review_threshold: Some(rust_decimal::Decimal::new(60, 2)), // 0.60
            tuning_mode: Some(true),
            include_deactivated: None,
            batch_size: Some(1000),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: UpsertGovCorrelationThreshold = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.auto_confirm_threshold,
            Some(rust_decimal::Decimal::new(90, 2))
        );
        assert_eq!(
            deserialized.manual_review_threshold,
            Some(rust_decimal::Decimal::new(60, 2))
        );
        assert_eq!(deserialized.tuning_mode, Some(true));
        assert!(deserialized.include_deactivated.is_none());
        assert_eq!(deserialized.batch_size, Some(1000));
    }
}
