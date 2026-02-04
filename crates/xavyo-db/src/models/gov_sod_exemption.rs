//! Governance `SoD` Exemption model.
//!
//! Represents approved exceptions allowing users to hold conflicting entitlements.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status for `SoD` exemptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_exemption_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovExemptionStatus {
    /// Exemption is in effect.
    Active,
    /// Exemption has expired.
    Expired,
    /// Exemption was manually revoked.
    Revoked,
}

/// An `SoD` exemption allowing a user to bypass a rule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovSodExemption {
    /// Unique identifier for the exemption.
    pub id: Uuid,

    /// The tenant this exemption belongs to.
    pub tenant_id: Uuid,

    /// The exempted rule.
    pub rule_id: Uuid,

    /// The exempted user.
    pub user_id: Uuid,

    /// Who approved the exemption.
    pub approver_id: Uuid,

    /// Business justification (required).
    pub justification: String,

    /// Exemption status.
    pub status: GovExemptionStatus,

    /// When the exemption was created.
    pub created_at: DateTime<Utc>,

    /// When the exemption expires.
    pub expires_at: DateTime<Utc>,

    /// When the exemption was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Who revoked the exemption (if applicable).
    pub revoked_by: Option<Uuid>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new `SoD` exemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovSodExemption {
    pub rule_id: Uuid,
    pub user_id: Uuid,
    pub approver_id: Uuid,
    pub justification: String,
    pub expires_at: DateTime<Utc>,
}

/// Filter options for listing `SoD` exemptions.
#[derive(Debug, Clone, Default)]
pub struct SodExemptionFilter {
    pub rule_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<GovExemptionStatus>,
}

impl GovSodExemption {
    /// Find an exemption by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_exemptions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an active exemption for a rule/user combination.
    pub async fn find_active_for_rule_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_exemptions
            WHERE tenant_id = $1 AND rule_id = $2 AND user_id = $3
              AND status = 'active'
              AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if user has active exemption for a rule.
    pub async fn has_active_exemption(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_sod_exemptions
            WHERE tenant_id = $1 AND rule_id = $2 AND user_id = $3
              AND status = 'active'
              AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List exemptions for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodExemptionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_sod_exemptions
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

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovSodExemption>(&query).bind(tenant_id);

        if let Some(rule_id) = filter.rule_id {
            q = q.bind(rule_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count exemptions in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SodExemptionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_sod_exemptions
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

        q.fetch_one(pool).await
    }

    /// Create a new `SoD` exemption.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovSodExemption,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_sod_exemptions (
                tenant_id, rule_id, user_id, approver_id, justification, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.rule_id)
        .bind(input.user_id)
        .bind(input.approver_id)
        .bind(&input.justification)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Revoke an exemption.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        revoked_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_sod_exemptions
            SET status = 'revoked',
                revoked_at = NOW(),
                revoked_by = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(revoked_by)
        .fetch_optional(pool)
        .await
    }

    /// Expire exemptions past their expiration date.
    pub async fn expire_past_due(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_sod_exemptions
            SET status = 'expired', updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active' AND expires_at <= NOW()
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find exemptions expiring within a time window (for notifications).
    pub async fn find_expiring_soon(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        within_hours: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_sod_exemptions
            WHERE tenant_id = $1
              AND status = 'active'
              AND expires_at > NOW()
              AND expires_at <= NOW() + ($2 || ' hours')::interval
            ORDER BY expires_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(within_hours)
        .fetch_all(pool)
        .await
    }

    /// Delete exemptions for a rule.
    pub async fn delete_for_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_sod_exemptions
            WHERE tenant_id = $1 AND rule_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if exemption is active (status and not expired).
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovExemptionStatus::Active) && self.expires_at > Utc::now()
    }

    /// Check if exemption is expired (by time, not status).
    #[must_use] 
    pub fn is_expired_by_time(&self) -> bool {
        self.expires_at <= Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_exemption_request() {
        let request = CreateGovSodExemption {
            rule_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            approver_id: Uuid::new_v4(),
            justification: "Emergency access for year-end close".to_string(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };

        assert!(!request.justification.is_empty());
        assert!(request.expires_at > Utc::now());
    }

    #[test]
    fn test_exemption_status_serialization() {
        let active = GovExemptionStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let revoked = GovExemptionStatus::Revoked;
        let json = serde_json::to_string(&revoked).unwrap();
        assert_eq!(json, "\"revoked\"");
    }
}
