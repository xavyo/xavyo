//! Governance Risk Factor model.
//!
//! Represents configurable risk indicators with weights for identity risk scoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Category for risk factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "risk_factor_category", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorCategory {
    /// Based on current access state (entitlements, SoD violations).
    Static,
    /// Based on behavioral events (login anomalies, patterns).
    Dynamic,
}

impl RiskFactorCategory {
    /// Check if this is a static factor.
    pub fn is_static(&self) -> bool {
        matches!(self, Self::Static)
    }

    /// Check if this is a dynamic factor.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic)
    }
}

/// A governance risk factor definition.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRiskFactor {
    /// Unique identifier for the factor.
    pub id: Uuid,

    /// The tenant this factor belongs to.
    pub tenant_id: Uuid,

    /// Factor display name.
    pub name: String,

    /// Factor category (static or dynamic).
    pub category: RiskFactorCategory,

    /// Specific factor type identifier.
    pub factor_type: String,

    /// Weight in score calculation (0.0-10.0).
    pub weight: f64,

    /// Human-readable description.
    pub description: Option<String>,

    /// Whether the factor is enabled.
    pub is_enabled: bool,

    /// When the factor was created.
    pub created_at: DateTime<Utc>,

    /// When the factor was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new risk factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovRiskFactor {
    pub name: String,
    pub category: RiskFactorCategory,
    pub factor_type: String,
    pub weight: f64,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
}

/// Request to update a risk factor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovRiskFactor {
    pub name: Option<String>,
    pub category: Option<RiskFactorCategory>,
    pub factor_type: Option<String>,
    pub weight: Option<f64>,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
}

/// Filter options for listing risk factors.
#[derive(Debug, Clone, Default)]
pub struct RiskFactorFilter {
    pub category: Option<RiskFactorCategory>,
    pub is_enabled: Option<bool>,
    pub factor_type: Option<String>,
}

impl GovRiskFactor {
    /// Find a factor by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a factor by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find a factor by type within a tenant.
    pub async fn find_by_factor_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        factor_type: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE tenant_id = $1 AND factor_type = $2
            "#,
        )
        .bind(tenant_id)
        .bind(factor_type)
        .fetch_optional(pool)
        .await
    }

    /// List enabled factors for a tenant.
    pub async fn list_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE tenant_id = $1 AND is_enabled = true
            ORDER BY category, name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List enabled factors by category for a tenant.
    pub async fn list_by_category(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        category: RiskFactorCategory,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE tenant_id = $1 AND category = $2 AND is_enabled = true
            ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(category)
        .fetch_all(pool)
        .await
    }

    /// List factors for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskFactorFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_risk_factors
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.category.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND category = ${}", param_count));
        }
        if filter.is_enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_enabled = ${}", param_count));
        }
        if filter.factor_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND factor_type = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY category, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRiskFactor>(&query).bind(tenant_id);

        if let Some(category) = filter.category {
            q = q.bind(category);
        }
        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }
        if let Some(ref factor_type) = filter.factor_type {
            q = q.bind(factor_type);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count factors in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &RiskFactorFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_risk_factors
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.category.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND category = ${}", param_count));
        }
        if filter.is_enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_enabled = ${}", param_count));
        }
        if filter.factor_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND factor_type = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(category) = filter.category {
            q = q.bind(category);
        }
        if let Some(is_enabled) = filter.is_enabled {
            q = q.bind(is_enabled);
        }
        if let Some(ref factor_type) = filter.factor_type {
            q = q.bind(factor_type);
        }

        q.fetch_one(pool).await
    }

    /// Create a new risk factor.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovRiskFactor,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_risk_factors (
                tenant_id, name, category, factor_type, weight, description, is_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.category)
        .bind(&input.factor_type)
        .bind(input.weight)
        .bind(&input.description)
        .bind(input.is_enabled.unwrap_or(true))
        .fetch_one(pool)
        .await
    }

    /// Update a risk factor.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovRiskFactor,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.category.is_some() {
            updates.push(format!("category = ${}", param_idx));
            param_idx += 1;
        }
        if input.factor_type.is_some() {
            updates.push(format!("factor_type = ${}", param_idx));
            param_idx += 1;
        }
        if input.weight.is_some() {
            updates.push(format!("weight = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_enabled.is_some() {
            updates.push(format!("is_enabled = ${}", param_idx));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_risk_factors SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovRiskFactor>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(category) = input.category {
            q = q.bind(category);
        }
        if let Some(ref factor_type) = input.factor_type {
            q = q.bind(factor_type);
        }
        if let Some(weight) = input.weight {
            q = q.bind(weight);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(is_enabled) = input.is_enabled {
            q = q.bind(is_enabled);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a risk factor.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_risk_factors
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable a risk factor.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_risk_factors
            SET is_enabled = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_enabled = false
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a risk factor.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_risk_factors
            SET is_enabled = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_enabled = true
            RETURNING *
            "#,
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
    fn test_risk_factor_category() {
        assert!(RiskFactorCategory::Static.is_static());
        assert!(!RiskFactorCategory::Static.is_dynamic());
        assert!(RiskFactorCategory::Dynamic.is_dynamic());
        assert!(!RiskFactorCategory::Dynamic.is_static());
    }

    #[test]
    fn test_category_serialization() {
        let static_cat = RiskFactorCategory::Static;
        let json = serde_json::to_string(&static_cat).unwrap();
        assert_eq!(json, "\"static\"");

        let dynamic_cat = RiskFactorCategory::Dynamic;
        let json = serde_json::to_string(&dynamic_cat).unwrap();
        assert_eq!(json, "\"dynamic\"");
    }
}
