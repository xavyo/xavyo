//! Governance Risk Threshold model.
//!
//! Represents configurable thresholds for alerting and enforcement.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "alert_severity", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Informational alert.
    Info,
    /// Warning alert.
    Warning,
    /// Critical alert.
    Critical,
}

impl AlertSeverity {
    /// Check if this is a critical severity.
    #[must_use] 
    pub fn is_critical(&self) -> bool {
        matches!(self, Self::Critical)
    }

    /// Check if this severity requires immediate attention.
    #[must_use] 
    pub fn requires_attention(&self) -> bool {
        matches!(self, Self::Warning | Self::Critical)
    }
}

/// Threshold actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "threshold_action", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ThresholdAction {
    /// Generate alert only.
    Alert,
    /// Require MFA on next login.
    RequireMfa,
    /// Block access.
    Block,
}

impl ThresholdAction {
    /// Check if this action blocks access.
    #[must_use] 
    pub fn blocks_access(&self) -> bool {
        matches!(self, Self::Block)
    }

    /// Check if this action requires MFA.
    #[must_use] 
    pub fn requires_mfa(&self) -> bool {
        matches!(self, Self::RequireMfa | Self::Block)
    }
}

/// A governance risk threshold.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskThreshold {
    /// Unique identifier for the threshold.
    pub id: Uuid,

    /// The tenant this threshold belongs to.
    pub tenant_id: Uuid,

    /// Threshold display name.
    pub name: String,

    /// Score value that triggers this threshold.
    pub score_value: i32,

    /// Alert severity when triggered.
    pub severity: AlertSeverity,

    /// Action to take when triggered.
    pub action: ThresholdAction,

    /// Hours between re-alerts for same user.
    pub cooldown_hours: i32,

    /// Whether the threshold is enabled.
    pub is_enabled: bool,

    /// When the threshold was created.
    pub created_at: DateTime<Utc>,

    /// When the threshold was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new risk threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRiskThreshold {
    pub name: String,
    pub score_value: i32,
    pub severity: AlertSeverity,
    pub action: Option<ThresholdAction>,
    pub cooldown_hours: Option<i32>,
    pub is_enabled: Option<bool>,
}

/// Request to update a risk threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovRiskThreshold {
    pub name: Option<String>,
    pub score_value: Option<i32>,
    pub severity: Option<AlertSeverity>,
    pub action: Option<ThresholdAction>,
    pub cooldown_hours: Option<i32>,
    pub is_enabled: Option<bool>,
}

/// Filter options for listing risk thresholds.
#[derive(Debug, Clone, Default)]
pub struct RiskThresholdFilter {
    pub severity: Option<AlertSeverity>,
    pub action: Option<ThresholdAction>,
    pub is_enabled: Option<bool>,
}

impl GovRiskThreshold {
    /// Find a threshold by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a threshold by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List enabled thresholds for a tenant, ordered by score.
    pub async fn list_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE tenant_id = $1 AND is_enabled = true
            ORDER BY score_value ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Find thresholds exceeded by a score.
    pub async fn find_exceeded(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        score: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE tenant_id = $1 AND is_enabled = true AND score_value <= $2
            ORDER BY score_value DESC
            ",
        )
        .bind(tenant_id)
        .bind(score)
        .fetch_all(pool)
        .await
    }

    /// Get the highest exceeded threshold (most severe action).
    pub async fn find_highest_exceeded(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        score: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE tenant_id = $1 AND is_enabled = true AND score_value <= $2
            ORDER BY score_value DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(score)
        .fetch_optional(pool)
        .await
    }

    /// List thresholds for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskThresholdFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_risk_thresholds
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.action.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action = ${param_count}"));
        }
        if filter.is_enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_enabled = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY score_value ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRiskThreshold>(&query).bind(tenant_id);

        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(action) = filter.action {
            q = q.bind(action);
        }
        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count thresholds in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskThresholdFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_risk_thresholds
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.action.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action = ${param_count}"));
        }
        if filter.is_enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_enabled = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(action) = filter.action {
            q = q.bind(action);
        }
        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }

        q.fetch_one(pool).await
    }

    /// Create a new risk threshold.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRiskThreshold,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_risk_thresholds (
                tenant_id, name, score_value, severity, action, cooldown_hours, is_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.score_value)
        .bind(input.severity)
        .bind(input.action.unwrap_or(ThresholdAction::Alert))
        .bind(input.cooldown_hours.unwrap_or(24))
        .bind(input.is_enabled.unwrap_or(true))
        .fetch_one(pool)
        .await
    }

    /// Update a risk threshold.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovRiskThreshold,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.score_value.is_some() {
            updates.push(format!("score_value = ${param_idx}"));
            param_idx += 1;
        }
        if input.severity.is_some() {
            updates.push(format!("severity = ${param_idx}"));
            param_idx += 1;
        }
        if input.action.is_some() {
            updates.push(format!("action = ${param_idx}"));
            param_idx += 1;
        }
        if input.cooldown_hours.is_some() {
            updates.push(format!("cooldown_hours = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_enabled.is_some() {
            updates.push(format!("is_enabled = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_risk_thresholds SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovRiskThreshold>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(score_value) = input.score_value {
            q = q.bind(score_value);
        }
        if let Some(severity) = input.severity {
            q = q.bind(severity);
        }
        if let Some(action) = input.action {
            q = q.bind(action);
        }
        if let Some(cooldown_hours) = input.cooldown_hours {
            q = q.bind(cooldown_hours);
        }
        if let Some(is_enabled) = input.is_enabled {
            q = q.bind(is_enabled);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a risk threshold.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_risk_thresholds
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable a risk threshold.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_risk_thresholds
            SET is_enabled = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_enabled = false
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a risk threshold.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_risk_thresholds
            SET is_enabled = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_enabled = true
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_severity() {
        assert!(!AlertSeverity::Info.is_critical());
        assert!(!AlertSeverity::Warning.is_critical());
        assert!(AlertSeverity::Critical.is_critical());

        assert!(!AlertSeverity::Info.requires_attention());
        assert!(AlertSeverity::Warning.requires_attention());
        assert!(AlertSeverity::Critical.requires_attention());
    }

    #[test]
    fn test_threshold_action() {
        assert!(!ThresholdAction::Alert.blocks_access());
        assert!(!ThresholdAction::RequireMfa.blocks_access());
        assert!(ThresholdAction::Block.blocks_access());

        assert!(!ThresholdAction::Alert.requires_mfa());
        assert!(ThresholdAction::RequireMfa.requires_mfa());
        assert!(ThresholdAction::Block.requires_mfa());
    }

    #[test]
    fn test_severity_serialization() {
        let info = AlertSeverity::Info;
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(json, "\"info\"");

        let critical = AlertSeverity::Critical;
        let json = serde_json::to_string(&critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn test_action_serialization() {
        let alert = ThresholdAction::Alert;
        let json = serde_json::to_string(&alert).unwrap();
        assert_eq!(json, "\"alert\"");

        let block = ThresholdAction::Block;
        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(json, "\"block\"");

        let mfa = ThresholdAction::RequireMfa;
        let json = serde_json::to_string(&mfa).unwrap();
        assert_eq!(json, "\"require_mfa\"");
    }
}
