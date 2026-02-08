//! NHI Service Account extension model (201-tool-nhi-promotion).
//!
//! Type-specific fields for service accounts. 1:1 relationship with `nhi_identities`
//! where `nhi_type = 'service_account'`. Always queried via JOIN with `nhi_identities`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use xavyo_nhi::NhiLifecycleState;

/// Service account extension row (the `nhi_service_accounts` table only).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiServiceAccount {
    pub nhi_id: Uuid,
    pub purpose: String,
    pub environment: Option<String>,
}

/// Combined NHI identity + service account extension fields.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiServiceAccountWithIdentity {
    // Base identity fields
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub lifecycle_state: NhiLifecycleState,
    pub suspension_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
    pub risk_score: Option<i32>,
    pub last_certified_at: Option<DateTime<Utc>>,
    pub next_certification_at: Option<DateTime<Utc>>,
    pub last_certified_by: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    // Service account-specific fields
    pub purpose: String,
    pub environment: Option<String>,
}

/// Request to create a service account extension row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiServiceAccount {
    pub nhi_id: Uuid,
    pub purpose: String,
    pub environment: Option<String>,
}

/// Request to update a service account extension row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNhiServiceAccount {
    pub purpose: Option<String>,
    pub environment: Option<String>,
}

/// Filter options for listing NHI service accounts.
#[derive(Debug, Clone, Default)]
pub struct NhiServiceAccountFilter {
    pub environment: Option<String>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
}

const SA_JOIN_SELECT: &str = r"
    SELECT i.id, i.tenant_id, i.name, i.description, i.owner_id, i.backup_owner_id,
           i.lifecycle_state, i.suspension_reason, i.expires_at, i.last_activity_at,
           i.inactivity_threshold_days, i.grace_period_ends_at, i.risk_score,
           i.last_certified_at, i.next_certification_at, i.last_certified_by,
           i.rotation_interval_days, i.last_rotation_at, i.created_at, i.updated_at, i.created_by,
           s.purpose, s.environment
    FROM nhi_identities i
    INNER JOIN nhi_service_accounts s ON s.nhi_id = i.id
";

impl NhiServiceAccount {
    /// Insert a service account extension row. The base `nhi_identities` row must exist already.
    pub async fn create(
        pool: &PgPool,
        input: CreateNhiServiceAccount,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_service_accounts (nhi_id, purpose, environment)
            VALUES ($1, $2, $3)
            RETURNING *
            ",
        )
        .bind(input.nhi_id)
        .bind(&input.purpose)
        .bind(&input.environment)
        .fetch_one(pool)
        .await
    }

    /// Find a service account by NHI ID (returns joined identity + service account data).
    pub async fn find_by_nhi_id(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Option<NhiServiceAccountWithIdentity>, sqlx::Error> {
        let query = format!("{SA_JOIN_SELECT} WHERE i.tenant_id = $1 AND i.id = $2");
        sqlx::query_as::<_, NhiServiceAccountWithIdentity>(&query)
            .bind(tenant_id)
            .bind(nhi_id)
            .fetch_optional(pool)
            .await
    }

    /// Update a service account extension row.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        input: UpdateNhiServiceAccount,
    ) -> Result<Option<NhiServiceAccount>, sqlx::Error> {
        sqlx::query_as::<_, NhiServiceAccount>(
            r"
            UPDATE nhi_service_accounts
            SET purpose = COALESCE($3, purpose),
                environment = COALESCE($4, environment)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(&input.purpose)
        .bind(&input.environment)
        .fetch_optional(pool)
        .await
    }

    /// Delete a service account extension row (tenant-scoped).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, nhi_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM nhi_service_accounts WHERE nhi_id = $1 AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(nhi_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List service accounts for a tenant with optional filtering and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &NhiServiceAccountFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiServiceAccountWithIdentity>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        let mut query = format!("{SA_JOIN_SELECT} WHERE i.tenant_id = $1");
        let mut param_idx = 2;

        if filter.environment.is_some() {
            query.push_str(&format!(" AND s.environment = ${param_idx}"));
            param_idx += 1;
        }
        if filter.lifecycle_state.is_some() {
            query.push_str(&format!(" AND i.lifecycle_state = ${param_idx}"));
            param_idx += 1;
        }
        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND i.owner_id = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY i.name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, NhiServiceAccountWithIdentity>(&query).bind(tenant_id);

        if let Some(ref environment) = filter.environment {
            q = q.bind(environment);
        }
        if let Some(lifecycle_state) = filter.lifecycle_state {
            q = q.bind(lifecycle_state);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_service_account_serialization() {
        let sa = NhiServiceAccount {
            nhi_id: Uuid::new_v4(),
            purpose: "CI/CD pipeline".to_string(),
            environment: Some("production".to_string()),
        };

        let json = serde_json::to_string(&sa).unwrap();
        let deserialized: NhiServiceAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(sa.purpose, deserialized.purpose);
        assert_eq!(sa.environment, deserialized.environment);
    }

    #[test]
    fn test_create_nhi_service_account() {
        let input = CreateNhiServiceAccount {
            nhi_id: Uuid::new_v4(),
            purpose: "Database access".to_string(),
            environment: Some("staging".to_string()),
        };

        assert_eq!(input.purpose, "Database access");
    }

    #[test]
    fn test_update_nhi_service_account_default() {
        let update = UpdateNhiServiceAccount::default();
        assert!(update.purpose.is_none());
        assert!(update.environment.is_none());
    }

    #[test]
    fn test_nhi_service_account_filter_default() {
        let filter = NhiServiceAccountFilter::default();
        assert!(filter.environment.is_none());
        assert!(filter.lifecycle_state.is_none());
        assert!(filter.owner_id.is_none());
    }
}
