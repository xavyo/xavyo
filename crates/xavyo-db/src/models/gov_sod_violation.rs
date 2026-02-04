//! Governance `SoD` Violation model.
//!
//! Represents detected instances where users have conflicting entitlements.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for `SoD` violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_violation_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovViolationStatus {
    /// Violation is active and needs attention.
    Active,
    /// Violation exists but is exempted.
    Exempted,
    /// Violation was resolved (entitlement removed).
    Remediated,
}

/// A detected `SoD` violation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovSodViolation {
    /// Unique identifier for the violation.
    pub id: Uuid,

    /// The tenant this violation belongs to.
    pub tenant_id: Uuid,

    /// The violated rule.
    pub rule_id: Uuid,

    /// The user with the conflict.
    pub user_id: Uuid,

    /// Assignment for first entitlement (nullable if deleted).
    pub first_assignment_id: Option<Uuid>,

    /// Assignment for second entitlement (nullable if deleted).
    pub second_assignment_id: Option<Uuid>,

    /// Violation status.
    pub status: GovViolationStatus,

    /// When the violation was detected.
    pub detected_at: DateTime<Utc>,

    /// When the violation was remediated.
    pub remediated_at: Option<DateTime<Utc>>,

    /// Who remediated the violation.
    pub remediated_by: Option<Uuid>,

    /// Notes about remediation.
    pub remediation_notes: Option<String>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new `SoD` violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovSodViolation {
    pub rule_id: Uuid,
    pub user_id: Uuid,
    pub first_assignment_id: Option<Uuid>,
    pub second_assignment_id: Option<Uuid>,
}

/// Filter options for listing `SoD` violations.
#[derive(Debug, Clone, Default)]
pub struct SodViolationFilter {
    pub rule_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<GovViolationStatus>,
    pub detected_after: Option<DateTime<Utc>>,
    pub detected_before: Option<DateTime<Utc>>,
}

impl GovSodViolation {
    /// Find a violation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_violations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an active or exempted violation for a rule/user combination.
    pub async fn find_active_for_rule_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_violations
            WHERE tenant_id = $1 AND rule_id = $2 AND user_id = $3
              AND status IN ('active', 'exempted')
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List violations for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodViolationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_sod_violations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.rule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND rule_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.detected_after.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND detected_at >= ${param_count}"));
        }
        if filter.detected_before.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND detected_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY detected_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovSodViolation>(&query).bind(tenant_id);

        if let Some(rule_id) = filter.rule_id {
            q = q.bind(rule_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(detected_after) = filter.detected_after {
            q = q.bind(detected_after);
        }
        if let Some(detected_before) = filter.detected_before {
            q = q.bind(detected_before);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count violations in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodViolationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_sod_violations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.rule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND rule_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.detected_after.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND detected_at >= ${param_count}"));
        }
        if filter.detected_before.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND detected_at <= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(rule_id) = filter.rule_id {
            q = q.bind(rule_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(detected_after) = filter.detected_after {
            q = q.bind(detected_after);
        }
        if let Some(detected_before) = filter.detected_before {
            q = q.bind(detected_before);
        }

        q.fetch_one(pool).await
    }

    /// Count active violations for a rule.
    pub async fn count_active_for_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_sod_violations
            WHERE tenant_id = $1 AND rule_id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new `SoD` violation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovSodViolation,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sod_violations (
                tenant_id, rule_id, user_id, first_assignment_id, second_assignment_id
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.rule_id)
        .bind(input.user_id)
        .bind(input.first_assignment_id)
        .bind(input.second_assignment_id)
        .fetch_one(pool)
        .await
    }

    /// Create or get existing violation (upsert logic at app level).
    pub async fn create_if_not_exists(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovSodViolation,
    ) -> Result<Self, sqlx::Error> {
        // First check if active/exempted violation exists
        if let Some(existing) =
            Self::find_active_for_rule_user(pool, tenant_id, input.rule_id, input.user_id).await?
        {
            return Ok(existing);
        }

        // Create new violation
        Self::create(pool, tenant_id, input).await
    }

    /// Mark violation as remediated.
    pub async fn remediate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        remediated_by: Uuid,
        notes: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_violations
            SET status = 'remediated',
                remediated_at = NOW(),
                remediated_by = $3,
                remediation_notes = $4,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('active', 'exempted')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(remediated_by)
        .bind(notes)
        .fetch_optional(pool)
        .await
    }

    /// Mark violation as exempted.
    pub async fn mark_exempted(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_violations
            SET status = 'exempted', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reactivate violation (when exemption expires/revoked).
    pub async fn reactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_violations
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'exempted'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete violations for a rule.
    pub async fn delete_for_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sod_violations
            WHERE tenant_id = $1 AND rule_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find all users violating a specific rule.
    pub async fn find_users_violating_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        first_entitlement_id: Uuid,
        second_entitlement_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT DISTINCT ea1.target_id as user_id
            FROM gov_entitlement_assignments ea1
            JOIN gov_entitlement_assignments ea2
                ON ea1.tenant_id = ea2.tenant_id
                AND ea1.target_type = ea2.target_type
                AND ea1.target_id = ea2.target_id
            WHERE ea1.tenant_id = $1
              AND ea1.target_type = 'user'
              AND ea1.status = 'active'
              AND ea2.status = 'active'
              AND ea1.entitlement_id = $2
              AND ea2.entitlement_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(first_entitlement_id)
        .bind(second_entitlement_id)
        .fetch_all(pool)
        .await
    }

    /// Check if a violation is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovViolationStatus::Active)
    }

    /// Check if a violation is exempted.
    #[must_use] 
    pub fn is_exempted(&self) -> bool {
        matches!(self.status, GovViolationStatus::Exempted)
    }

    /// Check if a violation is remediated.
    #[must_use] 
    pub fn is_remediated(&self) -> bool {
        matches!(self.status, GovViolationStatus::Remediated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_violation_request() {
        let request = CreateGovSodViolation {
            rule_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            first_assignment_id: Some(Uuid::new_v4()),
            second_assignment_id: Some(Uuid::new_v4()),
        };

        assert!(request.first_assignment_id.is_some());
    }

    #[test]
    fn test_violation_status_serialization() {
        let active = GovViolationStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let exempted = GovViolationStatus::Exempted;
        let json = serde_json::to_string(&exempted).unwrap();
        assert_eq!(json, "\"exempted\"");
    }
}
