//! Risk alert service for governance API.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovRiskAlert, GovRiskAlert, GovRiskThreshold, RiskAlertFilter, RiskAlertSortBy,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AcknowledgeAlertResponse, AlertSummary, BulkAcknowledgeResponse, ListRiskAlertsQuery,
    RiskAlertListResponse, RiskAlertResponse, RiskAlertSortOption, SeverityCount,
};

/// Service for managing risk alerts.
pub struct RiskAlertService {
    pool: PgPool,
}

impl RiskAlertService {
    /// Create a new risk alert service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get an alert by ID.
    pub async fn get(&self, tenant_id: Uuid, alert_id: Uuid) -> ApiResult<RiskAlertResponse> {
        let alert = GovRiskAlert::find_by_id(&self.pool, tenant_id, alert_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk alert not found: {}",
                alert_id
            )))?;

        Ok(RiskAlertResponse::from(alert))
    }

    /// List alerts with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListRiskAlertsQuery,
    ) -> ApiResult<RiskAlertListResponse> {
        let filter = RiskAlertFilter {
            user_id: query.user_id,
            threshold_id: query.threshold_id,
            severity: query.severity,
            acknowledged: query.acknowledged,
        };

        let sort_by = match query.sort_by.unwrap_or_default() {
            RiskAlertSortOption::CreatedAtDesc => RiskAlertSortBy::CreatedAtDesc,
            RiskAlertSortOption::CreatedAtAsc => RiskAlertSortBy::CreatedAtAsc,
            RiskAlertSortOption::SeverityDesc => RiskAlertSortBy::SeverityDesc,
            RiskAlertSortOption::ScoreDesc => RiskAlertSortBy::ScoreDesc,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let alerts =
            GovRiskAlert::list_by_tenant(&self.pool, tenant_id, &filter, sort_by, limit, offset)
                .await?;
        let total = GovRiskAlert::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(RiskAlertListResponse {
            items: alerts.into_iter().map(RiskAlertResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Acknowledge a single alert.
    pub async fn acknowledge(
        &self,
        tenant_id: Uuid,
        alert_id: Uuid,
        acknowledged_by: Uuid,
    ) -> ApiResult<AcknowledgeAlertResponse> {
        let alert = GovRiskAlert::acknowledge(&self.pool, tenant_id, alert_id, acknowledged_by)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk alert not found or already acknowledged: {}",
                alert_id
            )))?;

        Ok(AcknowledgeAlertResponse {
            alert: RiskAlertResponse::from(alert),
        })
    }

    /// Acknowledge all alerts for a user.
    pub async fn acknowledge_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        acknowledged_by: Uuid,
    ) -> ApiResult<BulkAcknowledgeResponse> {
        let count =
            GovRiskAlert::acknowledge_for_user(&self.pool, tenant_id, user_id, acknowledged_by)
                .await?;

        Ok(BulkAcknowledgeResponse {
            acknowledged_count: count,
        })
    }

    /// Get alert summary (unacknowledged counts by severity).
    pub async fn get_summary(&self, tenant_id: Uuid) -> ApiResult<AlertSummary> {
        let counts = GovRiskAlert::count_unacknowledged_by_severity(&self.pool, tenant_id).await?;

        let unacknowledged: Vec<SeverityCount> = counts
            .into_iter()
            .map(|(severity, count)| SeverityCount { severity, count })
            .collect();

        let total_unacknowledged: i64 = unacknowledged.iter().map(|c| c.count).sum();

        Ok(AlertSummary {
            unacknowledged,
            total_unacknowledged,
        })
    }

    /// Check if an alert should be generated (respects cooldown period).
    /// Returns true if alert should be generated.
    pub async fn should_generate_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        threshold: &GovRiskThreshold,
    ) -> ApiResult<bool> {
        let exists = GovRiskAlert::exists_within_cooldown(
            &self.pool,
            tenant_id,
            user_id,
            threshold.id,
            threshold.cooldown_hours,
        )
        .await?;

        Ok(!exists)
    }

    /// Generate an alert for a user exceeding a threshold.
    /// Respects cooldown deduplication - returns None if within cooldown.
    pub async fn generate_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        threshold: &GovRiskThreshold,
        score: i32,
    ) -> ApiResult<Option<RiskAlertResponse>> {
        // Check cooldown
        if !self
            .should_generate_alert(tenant_id, user_id, threshold)
            .await?
        {
            return Ok(None);
        }

        let input = CreateGovRiskAlert {
            user_id,
            threshold_id: threshold.id,
            score_at_alert: score,
            severity: threshold.severity,
        };

        let alert = GovRiskAlert::create(&self.pool, tenant_id, input).await?;

        Ok(Some(RiskAlertResponse::from(alert)))
    }

    /// Check user's score against all enabled thresholds and generate alerts.
    /// Returns list of newly generated alerts.
    pub async fn check_and_generate_alerts(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        score: i32,
    ) -> ApiResult<Vec<RiskAlertResponse>> {
        let thresholds = GovRiskThreshold::find_exceeded(&self.pool, tenant_id, score).await?;

        let mut generated = Vec::new();

        for threshold in thresholds {
            if let Some(alert) = self
                .generate_alert(tenant_id, user_id, &threshold, score)
                .await?
            {
                generated.push(alert);
            }
        }

        Ok(generated)
    }

    /// Delete an alert.
    pub async fn delete(&self, tenant_id: Uuid, alert_id: Uuid) -> ApiResult<()> {
        let deleted = GovRiskAlert::delete(&self.pool, tenant_id, alert_id).await?;

        if !deleted {
            return Err(ApiGovernanceError::NotFound(format!(
                "Risk alert not found: {}",
                alert_id
            )));
        }

        Ok(())
    }

    /// Get most recent alert for a user.
    pub async fn get_most_recent_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> ApiResult<Option<RiskAlertResponse>> {
        let alert = GovRiskAlert::get_most_recent_for_user(&self.pool, tenant_id, user_id).await?;
        Ok(alert.map(RiskAlertResponse::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::AlertSeverity;

    #[test]
    fn test_alert_summary_total() {
        let summary = AlertSummary {
            unacknowledged: vec![
                SeverityCount {
                    severity: AlertSeverity::Critical,
                    count: 5,
                },
                SeverityCount {
                    severity: AlertSeverity::Warning,
                    count: 10,
                },
            ],
            total_unacknowledged: 15,
        };

        assert_eq!(summary.total_unacknowledged, 15);
        assert_eq!(summary.unacknowledged.len(), 2);
    }

    #[test]
    fn test_bulk_acknowledge_response() {
        let response = BulkAcknowledgeResponse {
            acknowledged_count: 5,
        };
        assert_eq!(response.acknowledged_count, 5);
    }

    #[test]
    fn test_sort_option_mapping() {
        let sort = RiskAlertSortOption::SeverityDesc;
        let db_sort = match sort {
            RiskAlertSortOption::CreatedAtDesc => RiskAlertSortBy::CreatedAtDesc,
            RiskAlertSortOption::CreatedAtAsc => RiskAlertSortBy::CreatedAtAsc,
            RiskAlertSortOption::SeverityDesc => RiskAlertSortBy::SeverityDesc,
            RiskAlertSortOption::ScoreDesc => RiskAlertSortBy::ScoreDesc,
        };
        assert!(matches!(db_sort, RiskAlertSortBy::SeverityDesc));
    }
}
