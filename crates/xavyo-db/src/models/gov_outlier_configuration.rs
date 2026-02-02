//! Outlier detection configuration model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_outlier_types::ScoringWeights;

/// Tenant-level configuration for outlier detection.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovOutlierConfiguration {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this configuration belongs to.
    pub tenant_id: Uuid,

    /// Z-score threshold for outlier classification (default 2.0).
    pub confidence_threshold: f64,

    /// Minimum frequency for a role to be considered "normal" (default 0.1 = 10%).
    pub frequency_threshold: f64,

    /// Minimum users in peer group for statistical validity (default 5).
    pub min_peer_group_size: i32,

    /// Weights for each scoring factor (JSON).
    pub scoring_weights: sqlx::types::Json<ScoringWeights>,

    /// Cron expression for scheduled analysis (null = disabled).
    pub schedule_cron: Option<String>,

    /// Days to retain analysis results (default 365).
    pub retention_days: i32,

    /// Whether outlier detection is enabled.
    pub is_enabled: bool,

    /// When created.
    pub created_at: DateTime<Utc>,

    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update outlier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertOutlierConfiguration {
    pub confidence_threshold: Option<f64>,
    pub frequency_threshold: Option<f64>,
    pub min_peer_group_size: Option<i32>,
    pub scoring_weights: Option<ScoringWeights>,
    pub schedule_cron: Option<String>,
    pub retention_days: Option<i32>,
    pub is_enabled: Option<bool>,
}

impl GovOutlierConfiguration {
    /// Find configuration by tenant ID.
    pub async fn find_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_outlier_configurations
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Create default configuration for a tenant.
    pub async fn create_default(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<Self, sqlx::Error> {
        let weights = ScoringWeights::default();
        sqlx::query_as(
            r#"
            INSERT INTO gov_outlier_configurations (
                tenant_id, confidence_threshold, frequency_threshold,
                min_peer_group_size, scoring_weights, retention_days, is_enabled
            )
            VALUES ($1, 2.0, 0.1, 5, $2, 365, true)
            ON CONFLICT (tenant_id) DO UPDATE SET updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(sqlx::types::Json(&weights))
        .fetch_one(pool)
        .await
    }

    /// Get or create configuration for a tenant.
    pub async fn get_or_create(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<Self, sqlx::Error> {
        if let Some(config) = Self::find_by_tenant(pool, tenant_id).await? {
            return Ok(config);
        }
        Self::create_default(pool, tenant_id).await
    }

    /// Update configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: UpsertOutlierConfiguration,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 2; // $1 is tenant_id

        if input.confidence_threshold.is_some() {
            set_clauses.push(format!("confidence_threshold = ${}", param_idx));
            param_idx += 1;
        }
        if input.frequency_threshold.is_some() {
            set_clauses.push(format!("frequency_threshold = ${}", param_idx));
            param_idx += 1;
        }
        if input.min_peer_group_size.is_some() {
            set_clauses.push(format!("min_peer_group_size = ${}", param_idx));
            param_idx += 1;
        }
        if input.scoring_weights.is_some() {
            set_clauses.push(format!("scoring_weights = ${}", param_idx));
            param_idx += 1;
        }
        if input.schedule_cron.is_some() {
            set_clauses.push(format!("schedule_cron = ${}", param_idx));
            param_idx += 1;
        }
        if input.retention_days.is_some() {
            set_clauses.push(format!("retention_days = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_enabled.is_some() {
            set_clauses.push(format!("is_enabled = ${}", param_idx));
        }

        let query = format!(
            "UPDATE gov_outlier_configurations SET {} WHERE tenant_id = $1 RETURNING *",
            set_clauses.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(v) = input.confidence_threshold {
            q = q.bind(v);
        }
        if let Some(v) = input.frequency_threshold {
            q = q.bind(v);
        }
        if let Some(v) = input.min_peer_group_size {
            q = q.bind(v);
        }
        if let Some(v) = input.scoring_weights {
            q = q.bind(sqlx::types::Json(v));
        }
        if let Some(v) = input.schedule_cron {
            q = q.bind(v);
        }
        if let Some(v) = input.retention_days {
            q = q.bind(v);
        }
        if let Some(v) = input.is_enabled {
            q = q.bind(v);
        }

        q.fetch_optional(pool).await
    }

    /// Clear schedule (disable scheduled runs).
    pub async fn clear_schedule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_outlier_configurations
            SET schedule_cron = NULL, updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Enable or disable outlier detection.
    pub async fn set_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        is_enabled: bool,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_outlier_configurations
            SET is_enabled = $2, updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(is_enabled)
        .fetch_optional(pool)
        .await
    }

    /// Get the scoring weights as a struct.
    pub fn get_weights(&self) -> &ScoringWeights {
        &self.scoring_weights.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_weights_in_config() {
        let weights = ScoringWeights::default();
        assert!(weights.validate().is_ok());
        assert!((weights.role_frequency - 0.30).abs() < 0.001);
        assert!((weights.entitlement_count - 0.25).abs() < 0.001);
    }
}
