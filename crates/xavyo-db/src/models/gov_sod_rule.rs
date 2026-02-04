//! Governance `SoD` Rule model.
//!
//! Represents Separation of Duties rules that define conflicting entitlement pairs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Severity levels for `SoD` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_sod_severity", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovSodSeverity {
    /// Low severity - informational.
    Low,
    /// Medium severity - should be addressed.
    Medium,
    /// High severity - priority remediation.
    High,
    /// Critical severity - immediate action required.
    Critical,
}

/// Status for `SoD` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_sod_rule_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovSodRuleStatus {
    /// Rule is actively enforced.
    Active,
    /// Rule is disabled (not deleted for audit).
    Inactive,
}

/// A governance `SoD` rule defining a conflicting entitlement pair.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovSodRule {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// Rule display name.
    pub name: String,

    /// Rule description.
    pub description: Option<String>,

    /// First conflicting entitlement.
    pub first_entitlement_id: Uuid,

    /// Second conflicting entitlement.
    pub second_entitlement_id: Uuid,

    /// Severity level.
    pub severity: GovSodSeverity,

    /// Rule status.
    pub status: GovSodRuleStatus,

    /// Business rationale for the rule.
    pub business_rationale: Option<String>,

    /// Who created this rule.
    pub created_by: Uuid,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new `SoD` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovSodRule {
    pub name: String,
    pub description: Option<String>,
    pub first_entitlement_id: Uuid,
    pub second_entitlement_id: Uuid,
    pub severity: GovSodSeverity,
    pub business_rationale: Option<String>,
    pub created_by: Uuid,
}

/// Request to update an `SoD` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovSodRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<GovSodSeverity>,
    pub business_rationale: Option<String>,
}

/// Filter options for listing `SoD` rules.
#[derive(Debug, Clone, Default)]
pub struct SodRuleFilter {
    pub status: Option<GovSodRuleStatus>,
    pub severity: Option<GovSodSeverity>,
    pub entitlement_id: Option<Uuid>,
}

impl GovSodRule {
    /// Find a rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a rule by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_rules
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find a rule by entitlement pair (order-independent).
    pub async fn find_by_entitlement_pair(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_a: Uuid,
        entitlement_b: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_rules
            WHERE tenant_id = $1
              AND LEAST(first_entitlement_id, second_entitlement_id) = LEAST($2, $3)
              AND GREATEST(first_entitlement_id, second_entitlement_id) = GREATEST($2, $3)
            ",
        )
        .bind(tenant_id)
        .bind(entitlement_a)
        .bind(entitlement_b)
        .fetch_optional(pool)
        .await
    }

    /// List rules for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_sod_rules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (first_entitlement_id = ${param_count} OR second_entitlement_id = ${param_count})"
            ));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovSodRule>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count rules in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodRuleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_sod_rules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (first_entitlement_id = ${param_count} OR second_entitlement_id = ${param_count})"
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(severity) = filter.severity {
            q = q.bind(severity);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new `SoD` rule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovSodRule,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sod_rules (
                tenant_id, name, description, first_entitlement_id, second_entitlement_id,
                severity, business_rationale, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.first_entitlement_id)
        .bind(input.second_entitlement_id)
        .bind(input.severity)
        .bind(&input.business_rationale)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update an `SoD` rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovSodRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.severity.is_some() {
            updates.push(format!("severity = ${param_idx}"));
            param_idx += 1;
        }
        if input.business_rationale.is_some() {
            updates.push(format!("business_rationale = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_sod_rules SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovSodRule>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(severity) = input.severity {
            q = q.bind(severity);
        }
        if let Some(ref business_rationale) = input.business_rationale {
            q = q.bind(business_rationale);
        }

        q.fetch_optional(pool).await
    }

    /// Enable a rule.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_rules
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a rule.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_rules
            SET status = 'inactive', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sod_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find all active rules involving a specific entitlement.
    pub async fn find_active_by_entitlement(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_rules
            WHERE tenant_id = $1
              AND status = 'active'
              AND (first_entitlement_id = $2 OR second_entitlement_id = $2)
            ORDER BY severity DESC, created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_all(pool)
        .await
    }

    /// Get all active rules for a tenant.
    pub async fn list_active(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_rules
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY severity DESC, created_at ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Check if rule is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovSodRuleStatus::Active)
    }

    /// Get the other entitlement ID given one of the pair.
    #[must_use] 
    pub fn get_conflicting_entitlement(&self, entitlement_id: Uuid) -> Option<Uuid> {
        if self.first_entitlement_id == entitlement_id {
            Some(self.second_entitlement_id)
        } else if self.second_entitlement_id == entitlement_id {
            Some(self.first_entitlement_id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rule_request() {
        let request = CreateGovSodRule {
            name: "AP-Vendor Segregation".to_string(),
            description: Some("Prevents AP and Vendor Management access".to_string()),
            first_entitlement_id: Uuid::new_v4(),
            second_entitlement_id: Uuid::new_v4(),
            severity: GovSodSeverity::High,
            business_rationale: Some("Fraud prevention".to_string()),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(request.name, "AP-Vendor Segregation");
        assert_eq!(request.severity, GovSodSeverity::High);
    }

    #[test]
    fn test_severity_serialization() {
        let critical = GovSodSeverity::Critical;
        let json = serde_json::to_string(&critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn test_status_serialization() {
        let active = GovSodRuleStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");
    }

    #[test]
    fn test_get_conflicting_entitlement() {
        let rule = GovSodRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            description: None,
            first_entitlement_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            second_entitlement_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            severity: GovSodSeverity::Medium,
            status: GovSodRuleStatus::Active,
            business_rationale: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(
            rule.get_conflicting_entitlement(rule.first_entitlement_id),
            Some(rule.second_entitlement_id)
        );
        assert_eq!(
            rule.get_conflicting_entitlement(rule.second_entitlement_id),
            Some(rule.first_entitlement_id)
        );
        assert_eq!(rule.get_conflicting_entitlement(Uuid::new_v4()), None);
    }
}
