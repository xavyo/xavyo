//! Governance Service Account model.
//!
//! Represents non-human identities (NHIs) registered in the service account registry.
//! Extended with NHI lifecycle management capabilities (F061).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_nhi_audit_event::NhiSuspensionReason;

/// Status of a service account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_service_account_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountStatus {
    /// Account is active and operational.
    Active,
    /// Account has expired (past expiration date).
    Expired,
    /// Account is suspended (manually or due to policy).
    Suspended,
}

impl ServiceAccountStatus {
    /// Check if this status allows normal operations.
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A governance service account record (NHI).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovServiceAccount {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this account belongs to.
    pub tenant_id: Uuid,

    /// The user ID this service account is linked to.
    pub user_id: Uuid,

    /// Display name for the service account.
    pub name: String,

    /// Purpose/justification for the service account.
    pub purpose: String,

    /// Owner responsible for this service account.
    pub owner_id: Uuid,

    /// Current status.
    pub status: ServiceAccountStatus,

    /// When this account expires (if applicable).
    pub expires_at: Option<DateTime<Utc>>,

    /// When ownership was last certified.
    pub last_certified_at: Option<DateTime<Utc>>,

    /// Who performed the last certification.
    pub certified_by: Option<Uuid>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,

    // ---- NHI Lifecycle Fields (F061) ----
    /// Backup owner for ownership transfer on primary owner departure.
    pub backup_owner_id: Option<Uuid>,

    /// Days between credential rotations (1-365, default 90).
    pub rotation_interval_days: Option<i32>,

    /// Timestamp of last credential rotation.
    pub last_rotation_at: Option<DateTime<Utc>>,

    /// Timestamp of last authentication event.
    pub last_used_at: Option<DateTime<Utc>>,

    /// Days of inactivity before suspension warning (min 30, default 90).
    pub inactivity_threshold_days: Option<i32>,

    /// When grace period after suspension warning ends.
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Why NHI was suspended (if applicable).
    pub suspension_reason: Option<NhiSuspensionReason>,

    // ---- F108: Anomaly Detection Fields ----
    /// Z-score threshold for anomaly detection (default 2.5 = ~99% confidence).
    pub anomaly_threshold: Option<rust_decimal::Decimal>,

    /// Timestamp of last anomaly detection run.
    pub last_anomaly_check_at: Option<DateTime<Utc>>,

    /// JSON baseline metrics for behavioral comparison.
    pub anomaly_baseline: Option<serde_json::Value>,
}

/// Request to register a new service account (NHI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovServiceAccount {
    pub user_id: Uuid,
    pub name: String,
    pub purpose: String,
    pub owner_id: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    // NHI lifecycle fields
    pub backup_owner_id: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub inactivity_threshold_days: Option<i32>,
}

/// Request to update a service account (NHI).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovServiceAccount {
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub owner_id: Option<Uuid>,
    pub status: Option<ServiceAccountStatus>,
    pub expires_at: Option<DateTime<Utc>>,
    // NHI lifecycle fields
    pub backup_owner_id: Option<Uuid>,
    pub rotation_interval_days: Option<i32>,
    pub inactivity_threshold_days: Option<i32>,
    pub last_rotation_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub suspension_reason: Option<NhiSuspensionReason>,
    // F108: Anomaly detection fields
    pub anomaly_threshold: Option<rust_decimal::Decimal>,
    pub anomaly_baseline: Option<serde_json::Value>,
}

/// Filter options for listing service accounts (NHIs).
#[derive(Debug, Clone, Default)]
pub struct ServiceAccountFilter {
    pub status: Option<ServiceAccountStatus>,
    pub owner_id: Option<Uuid>,
    pub expiring_within_days: Option<i32>,
    pub needs_certification: Option<bool>,
    // NHI lifecycle filters
    pub backup_owner_id: Option<Uuid>,
    pub inactive_days: Option<i32>,
    pub needs_rotation: Option<bool>,
}

impl GovServiceAccount {
    /// Check if this account is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Get days until expiration (negative if expired).
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|exp| {
            let duration = exp.signed_duration_since(Utc::now());
            duration.num_days()
        })
    }

    /// Check if certification is due (more than 365 days since last cert).
    pub fn needs_certification(&self) -> bool {
        match self.last_certified_at {
            Some(certified_at) => {
                let days_since = Utc::now().signed_duration_since(certified_at).num_days();
                days_since > 365
            }
            None => true,
        }
    }

    /// Check if credential rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        let interval = self.rotation_interval_days.unwrap_or(90);
        match self.last_rotation_at {
            Some(last_rotation) => {
                let days_since = Utc::now().signed_duration_since(last_rotation).num_days();
                days_since >= interval as i64
            }
            None => true, // Never rotated, needs rotation
        }
    }

    /// Get days since last use.
    pub fn days_since_last_use(&self) -> Option<i64> {
        self.last_used_at
            .map(|used| Utc::now().signed_duration_since(used).num_days())
    }

    /// Check if NHI is inactive (not used within threshold).
    pub fn is_inactive(&self) -> bool {
        let threshold = self.inactivity_threshold_days.unwrap_or(90);
        match self.days_since_last_use() {
            Some(days) => days >= threshold as i64,
            None => true, // Never used, considered inactive
        }
    }

    /// Check if NHI is in grace period before suspension.
    pub fn is_in_grace_period(&self) -> bool {
        match self.grace_period_ends_at {
            Some(ends_at) => ends_at > Utc::now(),
            None => false,
        }
    }

    /// Find a service account by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a service account by user ID within a tenant.
    pub async fn find_by_user_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a user is registered as a service account.
    pub async fn is_service_account(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_service_accounts
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if a name already exists for service accounts in a tenant.
    pub async fn name_exists(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_service_accounts
            WHERE tenant_id = $1 AND LOWER(name) = LOWER($2)
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List service accounts by owner.
    pub async fn list_by_owner(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        owner_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1 AND owner_id = $2
            ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(owner_id)
        .fetch_all(pool)
        .await
    }

    /// List service accounts expiring within specified days.
    pub async fn list_expiring(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
                AND status = 'active'
                AND expires_at IS NOT NULL
                AND expires_at <= NOW() + ($2 || ' days')::interval
                AND expires_at > NOW()
            ORDER BY expires_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(days)
        .fetch_all(pool)
        .await
    }

    /// List service accounts needing certification.
    pub async fn list_needing_certification(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
                AND status = 'active'
                AND (
                    last_certified_at IS NULL
                    OR last_certified_at < NOW() - INTERVAL '365 days'
                )
            ORDER BY last_certified_at ASC NULLS FIRST
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List all service accounts for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ServiceAccountFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_idx));
            param_idx += 1;
        }

        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND owner_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.expiring_within_days.is_some() {
            query.push_str(&format!(
                " AND expires_at IS NOT NULL AND expires_at <= NOW() + (${} || ' days')::interval AND expires_at > NOW()",
                param_idx
            ));
            param_idx += 1;
        }

        if filter.needs_certification == Some(true) {
            query.push_str(
                " AND (last_certified_at IS NULL OR last_certified_at < NOW() - INTERVAL '365 days')",
            );
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        if let Some(days) = filter.expiring_within_days {
            q = q.bind(days);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count service accounts for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ServiceAccountFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_service_accounts
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_idx));
            param_idx += 1;
        }

        if filter.owner_id.is_some() {
            query.push_str(&format!(" AND owner_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.expiring_within_days.is_some() {
            query.push_str(&format!(
                " AND expires_at IS NOT NULL AND expires_at <= NOW() + (${} || ' days')::interval AND expires_at > NOW()",
                param_idx
            ));
        }

        if filter.needs_certification == Some(true) {
            query.push_str(
                " AND (last_certified_at IS NULL OR last_certified_at < NOW() - INTERVAL '365 days')",
            );
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }

        if let Some(days) = filter.expiring_within_days {
            q = q.bind(days);
        }

        q.fetch_one(pool).await
    }

    /// Register a new service account.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovServiceAccount,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_service_accounts (
                tenant_id, user_id, name, purpose, owner_id, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(data.user_id)
        .bind(&data.name)
        .bind(&data.purpose)
        .bind(data.owner_id)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Update a service account.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: UpdateGovServiceAccount,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET
                name = COALESCE($3, name),
                purpose = COALESCE($4, purpose),
                owner_id = COALESCE($5, owner_id),
                status = COALESCE($6, status),
                expires_at = COALESCE($7, expires_at)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(data.name)
        .bind(data.purpose)
        .bind(data.owner_id)
        .bind(data.status)
        .bind(data.expires_at)
        .fetch_optional(pool)
        .await
    }

    /// Certify a service account.
    pub async fn certify(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        certified_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET
                last_certified_at = NOW(),
                certified_by = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(certified_by)
        .fetch_optional(pool)
        .await
    }

    /// Suspend a service account.
    pub async fn suspend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET status = 'suspended'
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reactivate a suspended service account.
    pub async fn reactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET status = 'active'
            WHERE id = $1 AND tenant_id = $2 AND status = 'suspended'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark expired accounts.
    pub async fn mark_expired(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_service_accounts
            SET status = 'expired'
            WHERE tenant_id = $1
                AND status = 'active'
                AND expires_at IS NOT NULL
                AND expires_at < NOW()
            "#,
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Unregister (delete) a service account.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_service_accounts
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all registered service account user IDs for exclusion.
    pub async fn get_all_user_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT user_id FROM gov_service_accounts
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update the last_rotation_at timestamp for an NHI.
    pub async fn update_last_rotation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET last_rotation_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update the last_used_at timestamp for an NHI (for activity tracking).
    /// This is called during credential validation to track NHI usage.
    pub async fn update_last_used(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_service_accounts
            SET last_used_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find NHIs that need credential rotation.
    ///
    /// Returns NHIs where:
    /// - rotation_interval_days is set
    /// - last_rotation_at is older than rotation_interval_days
    /// - OR last_rotation_at is NULL and created_at is older than rotation_interval_days
    pub async fn find_needing_rotation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
                AND status = 'active'
                AND rotation_interval_days IS NOT NULL
                AND (
                    (last_rotation_at IS NOT NULL AND last_rotation_at < NOW() - (rotation_interval_days || ' days')::INTERVAL)
                    OR
                    (last_rotation_at IS NULL AND created_at < NOW() - (rotation_interval_days || ' days')::INTERVAL)
                )
            ORDER BY COALESCE(last_rotation_at, created_at) ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_account_status_is_operational() {
        assert!(ServiceAccountStatus::Active.is_operational());
        assert!(!ServiceAccountStatus::Expired.is_operational());
        assert!(!ServiceAccountStatus::Suspended.is_operational());
    }

    #[test]
    fn test_status_serialization() {
        let active = ServiceAccountStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let expired = ServiceAccountStatus::Expired;
        let json = serde_json::to_string(&expired).unwrap();
        assert_eq!(json, "\"expired\"");
    }
}
