//! Risk factor service for governance API.

use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

use xavyo_db::{
    CreateGovRiskFactor, GovRiskFactor, RiskFactorCategory, RiskFactorFilter, UpdateGovRiskFactor,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRiskFactorRequest, ListRiskFactorsQuery, RiskFactorListResponse, RiskFactorResponse,
    UpdateRiskFactorRequest,
};

/// Service for managing risk factor definitions.
pub struct RiskFactorService {
    pool: PgPool,
}

impl RiskFactorService {
    /// Create a new risk factor service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new risk factor.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateRiskFactorRequest,
    ) -> ApiResult<RiskFactorResponse> {
        // Validate request
        request.validate()?;

        // Validate weight range (0.0-10.0)
        self.validate_weight(request.weight)?;

        // Validate category and factor type combination
        self.validate_factor_type(&request.category, &request.factor_type)?;

        // Check for duplicate factor type within tenant
        if let Some(existing) =
            GovRiskFactor::find_by_factor_type(&self.pool, tenant_id, &request.factor_type).await?
        {
            return Err(ApiGovernanceError::Conflict(format!(
                "Risk factor with type '{}' already exists: {}",
                request.factor_type, existing.id
            )));
        }

        let input = CreateGovRiskFactor {
            name: request.name,
            category: request.category,
            factor_type: request.factor_type,
            weight: request.weight,
            description: request.description,
            is_enabled: request.is_enabled,
        };

        let factor = GovRiskFactor::create(&self.pool, tenant_id, input).await?;

        Ok(RiskFactorResponse::from(factor))
    }

    /// Get a risk factor by ID.
    pub async fn get(&self, tenant_id: Uuid, factor_id: Uuid) -> ApiResult<RiskFactorResponse> {
        let factor = GovRiskFactor::find_by_id(&self.pool, tenant_id, factor_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        Ok(RiskFactorResponse::from(factor))
    }

    /// Update a risk factor.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        factor_id: Uuid,
        request: UpdateRiskFactorRequest,
    ) -> ApiResult<RiskFactorResponse> {
        // Validate request
        request.validate()?;

        // Validate weight if provided
        if let Some(weight) = request.weight {
            self.validate_weight(weight)?;
        }

        // Verify factor exists
        let existing = GovRiskFactor::find_by_id(&self.pool, tenant_id, factor_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        // Validate category and factor type combination if either is being updated
        let category = request.category.unwrap_or(existing.category);
        let factor_type = request
            .factor_type
            .clone()
            .unwrap_or(existing.factor_type.clone());
        self.validate_factor_type(&category, &factor_type)?;

        // Check for duplicate factor type if being changed
        if let Some(ref new_type) = request.factor_type {
            if new_type != &existing.factor_type {
                if let Some(other) =
                    GovRiskFactor::find_by_factor_type(&self.pool, tenant_id, new_type).await?
                {
                    if other.id != factor_id {
                        return Err(ApiGovernanceError::Conflict(format!(
                            "Risk factor with type '{}' already exists: {}",
                            new_type, other.id
                        )));
                    }
                }
            }
        }

        let input = UpdateGovRiskFactor {
            name: request.name,
            category: request.category,
            factor_type: request.factor_type,
            weight: request.weight,
            description: request.description,
            is_enabled: request.is_enabled,
        };

        let factor = GovRiskFactor::update(&self.pool, tenant_id, factor_id, input)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        Ok(RiskFactorResponse::from(factor))
    }

    /// Delete a risk factor.
    pub async fn delete(&self, tenant_id: Uuid, factor_id: Uuid) -> ApiResult<()> {
        // Verify factor exists
        GovRiskFactor::find_by_id(&self.pool, tenant_id, factor_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        GovRiskFactor::delete(&self.pool, tenant_id, factor_id).await?;

        Ok(())
    }

    /// List risk factors with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListRiskFactorsQuery,
    ) -> ApiResult<RiskFactorListResponse> {
        let filter = RiskFactorFilter {
            category: query.category,
            is_enabled: query.is_enabled,
            factor_type: query.factor_type,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let factors =
            GovRiskFactor::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovRiskFactor::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(RiskFactorListResponse {
            items: factors.into_iter().map(RiskFactorResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Enable a risk factor.
    pub async fn enable(&self, tenant_id: Uuid, factor_id: Uuid) -> ApiResult<RiskFactorResponse> {
        let factor = GovRiskFactor::enable(&self.pool, tenant_id, factor_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        Ok(RiskFactorResponse::from(factor))
    }

    /// Disable a risk factor.
    pub async fn disable(&self, tenant_id: Uuid, factor_id: Uuid) -> ApiResult<RiskFactorResponse> {
        let factor = GovRiskFactor::disable(&self.pool, tenant_id, factor_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk factor not found: {factor_id}"
            )))?;

        Ok(RiskFactorResponse::from(factor))
    }

    /// Validate weight is within allowed range (0.0-10.0).
    fn validate_weight(&self, weight: f64) -> ApiResult<()> {
        if !(0.0..=10.0).contains(&weight) {
            return Err(ApiGovernanceError::Validation(format!(
                "Weight must be between 0.0 and 10.0, got: {weight}"
            )));
        }
        Ok(())
    }

    /// Validate factor type is appropriate for its category.
    fn validate_factor_type(
        &self,
        category: &RiskFactorCategory,
        factor_type: &str,
    ) -> ApiResult<()> {
        // Static factors
        let static_types = [
            "sensitive_entitlement_count",
            "sod_violation_count",
            "total_entitlement_count",
            "high_risk_app_access",
            "orphan_account",
            "excessive_privilege",
        ];

        // Dynamic factors
        let dynamic_types = [
            "failed_login_count",
            "unusual_login_time",
            "new_location_login",
            "excessive_access_attempts",
            "dormant_account_activity",
        ];

        match category {
            RiskFactorCategory::Static => {
                if !static_types.contains(&factor_type)
                    && !factor_type.starts_with("custom_static_")
                {
                    return Err(ApiGovernanceError::Validation(format!(
                        "Invalid static factor type '{factor_type}'. Valid types: {static_types:?} or custom_static_* prefix"
                    )));
                }
            }
            RiskFactorCategory::Dynamic => {
                if !dynamic_types.contains(&factor_type)
                    && !factor_type.starts_with("custom_dynamic_")
                {
                    return Err(ApiGovernanceError::Validation(format!(
                        "Invalid dynamic factor type '{factor_type}'. Valid types: {dynamic_types:?} or custom_dynamic_* prefix"
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ApiGovernanceError;
    use xavyo_db::RiskFactorCategory;

    /// Standalone weight validation function for testing (mirrors service logic).
    fn validate_weight_test(weight: f64) -> Result<(), ApiGovernanceError> {
        if !(0.0..=10.0).contains(&weight) {
            return Err(ApiGovernanceError::Validation(format!(
                "Weight must be between 0.0 and 10.0, got: {}",
                weight
            )));
        }
        Ok(())
    }

    /// Standalone factor type validation function for testing (mirrors service logic).
    fn validate_factor_type_test(
        category: &RiskFactorCategory,
        factor_type: &str,
    ) -> Result<(), ApiGovernanceError> {
        let static_types = [
            "sensitive_entitlement_count",
            "sod_violation_count",
            "total_entitlement_count",
            "high_risk_app_access",
            "orphan_account",
            "excessive_privilege",
        ];

        let dynamic_types = [
            "failed_login_count",
            "unusual_login_time",
            "new_location_login",
            "excessive_access_attempts",
            "dormant_account_activity",
        ];

        match category {
            RiskFactorCategory::Static => {
                if !static_types.contains(&factor_type)
                    && !factor_type.starts_with("custom_static_")
                {
                    return Err(ApiGovernanceError::Validation(format!(
                        "Invalid static factor type '{}'",
                        factor_type
                    )));
                }
            }
            RiskFactorCategory::Dynamic => {
                if !dynamic_types.contains(&factor_type)
                    && !factor_type.starts_with("custom_dynamic_")
                {
                    return Err(ApiGovernanceError::Validation(format!(
                        "Invalid dynamic factor type '{}'",
                        factor_type
                    )));
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_weight_validation_valid() {
        assert!(validate_weight_test(0.0).is_ok());
        assert!(validate_weight_test(5.0).is_ok());
        assert!(validate_weight_test(10.0).is_ok());
    }

    #[test]
    fn test_weight_validation_invalid() {
        assert!(validate_weight_test(-0.1).is_err());
        assert!(validate_weight_test(10.1).is_err());
        assert!(validate_weight_test(100.0).is_err());
    }

    #[test]
    fn test_factor_type_validation_static() {
        // Valid static types
        assert!(validate_factor_type_test(
            &RiskFactorCategory::Static,
            "sensitive_entitlement_count"
        )
        .is_ok());
        assert!(
            validate_factor_type_test(&RiskFactorCategory::Static, "sod_violation_count").is_ok()
        );
        assert!(
            validate_factor_type_test(&RiskFactorCategory::Static, "custom_static_my_factor")
                .is_ok()
        );

        // Invalid static types
        assert!(
            validate_factor_type_test(&RiskFactorCategory::Static, "failed_login_count").is_err()
        );
        assert!(validate_factor_type_test(&RiskFactorCategory::Static, "unknown_type").is_err());
    }

    #[test]
    fn test_factor_type_validation_dynamic() {
        // Valid dynamic types
        assert!(
            validate_factor_type_test(&RiskFactorCategory::Dynamic, "failed_login_count").is_ok()
        );
        assert!(
            validate_factor_type_test(&RiskFactorCategory::Dynamic, "unusual_login_time").is_ok()
        );
        assert!(validate_factor_type_test(
            &RiskFactorCategory::Dynamic,
            "custom_dynamic_my_factor"
        )
        .is_ok());

        // Invalid dynamic types
        assert!(validate_factor_type_test(
            &RiskFactorCategory::Dynamic,
            "sensitive_entitlement_count"
        )
        .is_err());
        assert!(validate_factor_type_test(&RiskFactorCategory::Dynamic, "unknown_type").is_err());
    }
}
