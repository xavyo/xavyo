//! Correlation Threshold Service for the Correlation Engine (F067).
//!
//! Manages per-connector correlation threshold configuration, controlling
//! auto-confirm and manual-review confidence boundaries.

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::{GovCorrelationThreshold, UpsertGovCorrelationThreshold};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::correlation::{CorrelationThresholdResponse, UpsertCorrelationThresholdRequest};

/// Service for managing per-connector correlation thresholds.
pub struct CorrelationThresholdService {
    pool: PgPool,
}

impl CorrelationThresholdService {
    /// Create a new correlation threshold service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get threshold configuration for a specific connector.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<CorrelationThresholdResponse> {
        let threshold =
            GovCorrelationThreshold::find_by_connector(&self.pool, tenant_id, connector_id)
                .await?
                .ok_or(GovernanceError::CorrelationThresholdNotFound(connector_id))?;

        Ok(threshold_to_response(threshold))
    }

    /// Create or update correlation thresholds for a connector.
    ///
    /// Validates:
    /// - Thresholds are between 0.0 and 1.0
    /// - `auto_confirm_threshold` > `manual_review_threshold` (when both provided)
    /// - `batch_size` is between 50 and 5000
    pub async fn upsert(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        request: UpsertCorrelationThresholdRequest,
    ) -> Result<CorrelationThresholdResponse> {
        // Validate threshold ranges (0.0 to 1.0).
        if let Some(auto_confirm) = request.auto_confirm_threshold {
            if !(0.0..=1.0).contains(&auto_confirm) {
                return Err(GovernanceError::InvalidCorrelationThreshold(auto_confirm));
            }
        }
        if let Some(manual_review) = request.manual_review_threshold {
            if !(0.0..=1.0).contains(&manual_review) {
                return Err(GovernanceError::InvalidCorrelationThreshold(manual_review));
            }
        }

        // Validate threshold ordering: auto_confirm must be strictly greater than manual_review.
        if let (Some(auto_confirm), Some(manual_review)) = (
            request.auto_confirm_threshold,
            request.manual_review_threshold,
        ) {
            if auto_confirm <= manual_review {
                return Err(GovernanceError::InvalidThresholdOrdering {
                    auto_confirm,
                    manual_review,
                });
            }
        }

        // Validate batch_size range (50 to 5000).
        if let Some(batch_size) = request.batch_size {
            if !(50..=5000).contains(&batch_size) {
                return Err(GovernanceError::InvalidCorrelationBatchSize(batch_size));
            }
        }

        let input = UpsertGovCorrelationThreshold {
            auto_confirm_threshold: request
                .auto_confirm_threshold
                .map(|v| Decimal::try_from(v).unwrap_or_default()),
            manual_review_threshold: request
                .manual_review_threshold
                .map(|v| Decimal::try_from(v).unwrap_or_default()),
            tuning_mode: request.tuning_mode,
            include_deactivated: request.include_deactivated,
            batch_size: request.batch_size,
        };

        let threshold =
            GovCorrelationThreshold::upsert(&self.pool, tenant_id, connector_id, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            threshold_id = %threshold.id,
            "Correlation threshold upserted"
        );

        Ok(threshold_to_response(threshold))
    }
}

/// Map a database threshold model to an API response.
fn threshold_to_response(t: GovCorrelationThreshold) -> CorrelationThresholdResponse {
    CorrelationThresholdResponse {
        id: t.id,
        connector_id: t.connector_id,
        auto_confirm_threshold: t
            .auto_confirm_threshold
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.85),
        manual_review_threshold: t
            .manual_review_threshold
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.50),
        tuning_mode: t.tuning_mode,
        include_deactivated: t.include_deactivated,
        batch_size: t.batch_size,
        created_at: t.created_at,
        updated_at: t.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_threshold_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests require a database connection.
    }

    #[test]
    fn test_threshold_to_response_mapping() {
        let threshold = GovCorrelationThreshold::find_or_default(Uuid::new_v4(), Uuid::new_v4());
        let response = threshold_to_response(threshold.clone());

        assert_eq!(response.id, threshold.id);
        assert_eq!(response.connector_id, threshold.connector_id);
        assert!((response.auto_confirm_threshold - 0.85).abs() < f64::EPSILON);
        assert!((response.manual_review_threshold - 0.50).abs() < f64::EPSILON);
        assert!(!response.tuning_mode);
        assert!(response.include_deactivated);
        assert_eq!(response.batch_size, 500);
    }
}
