//! Outlier configuration service for F059.
//!
//! Handles CRUD operations for tenant-level outlier detection configuration.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{GovOutlierConfiguration, ScoringWeights, UpsertOutlierConfiguration};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for managing outlier detection configuration.
pub struct OutlierConfigService {
    pool: PgPool,
}

impl OutlierConfigService {
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get configuration for a tenant, creating default if it doesn't exist.
    pub async fn get_or_create(&self, tenant_id: Uuid) -> Result<GovOutlierConfiguration> {
        GovOutlierConfiguration::get_or_create(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get configuration for a tenant (returns None if not configured).
    pub async fn get(&self, tenant_id: Uuid) -> Result<Option<GovOutlierConfiguration>> {
        GovOutlierConfiguration::find_by_tenant(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update configuration for a tenant.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        input: UpsertOutlierConfiguration,
    ) -> Result<GovOutlierConfiguration> {
        // Validate weights if provided
        if let Some(ref weights) = input.scoring_weights {
            self.validate_scoring_weights(weights)?;
        }

        // Validate confidence threshold if provided
        if let Some(threshold) = input.confidence_threshold {
            if !(0.0..=5.0).contains(&threshold) {
                return Err(GovernanceError::Validation(
                    "Confidence threshold must be between 0.0 and 5.0".to_string(),
                ));
            }
        }

        // Validate frequency threshold if provided
        if let Some(threshold) = input.frequency_threshold {
            if !(0.0..=1.0).contains(&threshold) {
                return Err(GovernanceError::Validation(
                    "Frequency threshold must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        // Validate min peer group size if provided
        if let Some(size) = input.min_peer_group_size {
            if !(2..=100).contains(&size) {
                return Err(GovernanceError::Validation(
                    "Min peer group size must be between 2 and 100".to_string(),
                ));
            }
        }

        // Validate retention days if provided
        if let Some(days) = input.retention_days {
            if !(30..=3650).contains(&days) {
                return Err(GovernanceError::Validation(
                    "Retention days must be between 30 and 3650".to_string(),
                ));
            }
        }

        // Validate cron expression if provided
        if let Some(ref cron) = input.schedule_cron {
            self.validate_cron_expression(cron)?;
        }

        // Ensure config exists first
        let _ = self.get_or_create(tenant_id).await?;

        // Update the config
        GovOutlierConfiguration::update(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierConfigNotFound(tenant_id))
    }

    /// Enable outlier detection for a tenant.
    pub async fn enable(&self, tenant_id: Uuid) -> Result<GovOutlierConfiguration> {
        GovOutlierConfiguration::set_enabled(&self.pool, tenant_id, true)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierConfigNotFound(tenant_id))
    }

    /// Disable outlier detection for a tenant.
    pub async fn disable(&self, tenant_id: Uuid) -> Result<GovOutlierConfiguration> {
        GovOutlierConfiguration::set_enabled(&self.pool, tenant_id, false)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierConfigNotFound(tenant_id))
    }

    /// Clear the schedule (disable scheduled runs).
    pub async fn clear_schedule(&self, tenant_id: Uuid) -> Result<GovOutlierConfiguration> {
        GovOutlierConfiguration::clear_schedule(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierConfigNotFound(tenant_id))
    }

    /// Validate scoring weights.
    fn validate_scoring_weights(&self, weights: &ScoringWeights) -> Result<()> {
        weights.validate().map_err(GovernanceError::Validation)
    }

    /// Validate cron expression.
    fn validate_cron_expression(&self, cron: &str) -> Result<()> {
        // Basic cron validation: should have 5 or 6 parts
        let parts: Vec<&str> = cron.split_whitespace().collect();
        if parts.len() < 5 || parts.len() > 6 {
            return Err(GovernanceError::Validation(
                "Invalid cron expression: must have 5 or 6 parts".to_string(),
            ));
        }

        // TODO: More comprehensive cron validation could be added here
        // For now, we just check basic structure

        Ok(())
    }

    /// Get default scoring weights.
    #[must_use] 
    pub fn default_weights() -> ScoringWeights {
        ScoringWeights::default()
    }

    /// Check if outlier detection is enabled for a tenant.
    pub async fn is_enabled(&self, tenant_id: Uuid) -> Result<bool> {
        match self.get(tenant_id).await? {
            Some(config) => Ok(config.is_enabled),
            None => Ok(false), // Default to disabled if not configured
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_weights() {
        let weights = OutlierConfigService::default_weights();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn test_validate_scoring_weights_valid() {
        // We can't easily test the service method without a pool,
        // but we can test the ScoringWeights validation directly
        let weights = ScoringWeights::default();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn test_validate_scoring_weights_invalid_sum() {
        let weights = ScoringWeights {
            role_frequency: 0.5,
            entitlement_count: 0.5,
            assignment_pattern: 0.5,
            peer_group_coverage: 0.5,
            historical_deviation: 0.5,
        };
        assert!(weights.validate().is_err());
    }

    #[test]
    fn test_validate_scoring_weights_negative() {
        let weights = ScoringWeights {
            role_frequency: -0.1,
            entitlement_count: 0.5,
            assignment_pattern: 0.3,
            peer_group_coverage: 0.2,
            historical_deviation: 0.1,
        };
        assert!(weights.validate().is_err());
    }
}
