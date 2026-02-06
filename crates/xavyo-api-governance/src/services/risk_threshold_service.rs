//! Risk threshold service for governance API.

use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

use xavyo_db::{
    CreateGovRiskThreshold, GovRiskThreshold, RiskThresholdFilter, UpdateGovRiskThreshold,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRiskThresholdRequest, ListRiskThresholdsQuery, RiskThresholdListResponse,
    RiskThresholdResponse, UpdateRiskThresholdRequest,
};

/// Service for managing risk thresholds.
pub struct RiskThresholdService {
    pool: PgPool,
}

impl RiskThresholdService {
    /// Create a new risk threshold service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new risk threshold.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateRiskThresholdRequest,
    ) -> ApiResult<RiskThresholdResponse> {
        request.validate()?;

        // Check for duplicate name
        if let Some(_existing) =
            GovRiskThreshold::find_by_name(&self.pool, tenant_id, &request.name).await?
        {
            return Err(ApiGovernanceError::Validation(format!(
                "Threshold with name '{}' already exists",
                request.name
            )));
        }

        let input = CreateGovRiskThreshold {
            name: request.name,
            score_value: request.score_value,
            severity: request.severity,
            action: request.action,
            cooldown_hours: request.cooldown_hours,
            is_enabled: request.is_enabled,
        };

        let threshold = GovRiskThreshold::create(&self.pool, tenant_id, input).await?;

        Ok(RiskThresholdResponse::from(threshold))
    }

    /// Get a risk threshold by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        threshold_id: Uuid,
    ) -> ApiResult<RiskThresholdResponse> {
        let threshold = GovRiskThreshold::find_by_id(&self.pool, tenant_id, threshold_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found: {threshold_id}"
            )))?;

        Ok(RiskThresholdResponse::from(threshold))
    }

    /// List risk thresholds with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListRiskThresholdsQuery,
    ) -> ApiResult<RiskThresholdListResponse> {
        let filter = RiskThresholdFilter {
            severity: query.severity,
            action: query.action,
            is_enabled: query.is_enabled,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let thresholds =
            GovRiskThreshold::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovRiskThreshold::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(RiskThresholdListResponse {
            items: thresholds
                .into_iter()
                .map(RiskThresholdResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Update a risk threshold.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        threshold_id: Uuid,
        request: UpdateRiskThresholdRequest,
    ) -> ApiResult<RiskThresholdResponse> {
        request.validate()?;

        // Check threshold exists
        GovRiskThreshold::find_by_id(&self.pool, tenant_id, threshold_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found: {threshold_id}"
            )))?;

        // Check for duplicate name if changing
        if let Some(ref name) = request.name {
            if let Some(existing) =
                GovRiskThreshold::find_by_name(&self.pool, tenant_id, name).await?
            {
                if existing.id != threshold_id {
                    return Err(ApiGovernanceError::Validation(format!(
                        "Threshold with name '{name}' already exists"
                    )));
                }
            }
        }

        let input = UpdateGovRiskThreshold {
            name: request.name,
            score_value: request.score_value,
            severity: request.severity,
            action: request.action,
            cooldown_hours: request.cooldown_hours,
            is_enabled: request.is_enabled,
        };

        let threshold = GovRiskThreshold::update(&self.pool, tenant_id, threshold_id, input)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found: {threshold_id}"
            )))?;

        Ok(RiskThresholdResponse::from(threshold))
    }

    /// Delete a risk threshold.
    pub async fn delete(&self, tenant_id: Uuid, threshold_id: Uuid) -> ApiResult<()> {
        let deleted = GovRiskThreshold::delete(&self.pool, tenant_id, threshold_id).await?;

        if !deleted {
            return Err(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found: {threshold_id}"
            )));
        }

        Ok(())
    }

    /// Enable a risk threshold.
    pub async fn enable(
        &self,
        tenant_id: Uuid,
        threshold_id: Uuid,
    ) -> ApiResult<RiskThresholdResponse> {
        let threshold = GovRiskThreshold::enable(&self.pool, tenant_id, threshold_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found or already enabled: {threshold_id}"
            )))?;

        Ok(RiskThresholdResponse::from(threshold))
    }

    /// Disable a risk threshold.
    pub async fn disable(
        &self,
        tenant_id: Uuid,
        threshold_id: Uuid,
    ) -> ApiResult<RiskThresholdResponse> {
        let threshold = GovRiskThreshold::disable(&self.pool, tenant_id, threshold_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk threshold not found or already disabled: {threshold_id}"
            )))?;

        Ok(RiskThresholdResponse::from(threshold))
    }

    /// Get enabled thresholds ordered by score.
    pub async fn list_enabled(&self, tenant_id: Uuid) -> ApiResult<Vec<RiskThresholdResponse>> {
        let thresholds = GovRiskThreshold::list_enabled(&self.pool, tenant_id).await?;
        Ok(thresholds
            .into_iter()
            .map(RiskThresholdResponse::from)
            .collect())
    }

    /// Find all thresholds exceeded by a score.
    pub async fn find_exceeded(
        &self,
        tenant_id: Uuid,
        score: i32,
    ) -> ApiResult<Vec<RiskThresholdResponse>> {
        let thresholds = GovRiskThreshold::find_exceeded(&self.pool, tenant_id, score).await?;
        Ok(thresholds
            .into_iter()
            .map(RiskThresholdResponse::from)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::AlertSeverity;

    #[test]
    fn test_cooldown_hours_validation() {
        // Test valid cooldown
        let request = CreateRiskThresholdRequest {
            name: "Test".to_string(),
            score_value: 50,
            severity: AlertSeverity::Warning,
            action: None,
            cooldown_hours: Some(24),
            is_enabled: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_cooldown_hours_invalid() {
        // Test invalid cooldown (too high)
        let request = CreateRiskThresholdRequest {
            name: "Test".to_string(),
            score_value: 50,
            severity: AlertSeverity::Warning,
            action: None,
            cooldown_hours: Some(1000), // > 720 max
            is_enabled: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_score_value_validation() {
        // Test valid score
        let request = CreateRiskThresholdRequest {
            name: "Test".to_string(),
            score_value: 75,
            severity: AlertSeverity::Critical,
            action: None,
            cooldown_hours: None,
            is_enabled: None,
        };
        assert!(request.validate().is_ok());

        // Test invalid score (too high)
        let request2 = CreateRiskThresholdRequest {
            name: "Test".to_string(),
            score_value: 150,
            severity: AlertSeverity::Critical,
            action: None,
            cooldown_hours: None,
            is_enabled: None,
        };
        assert!(request2.validate().is_err());
    }

    #[test]
    fn test_name_validation() {
        // Test empty name
        let request = CreateRiskThresholdRequest {
            name: "".to_string(),
            score_value: 50,
            severity: AlertSeverity::Info,
            action: None,
            cooldown_hours: None,
            is_enabled: None,
        };
        assert!(request.validate().is_err());
    }
}
