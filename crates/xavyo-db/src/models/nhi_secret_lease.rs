//! Database model for NHI secret leases.
//!
//! Leases are time-bounded grants for accessing vaulted secrets.
//! They are automatically revoked when the NHI is suspended/deactivated/archived.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Column list for RETURNING / SELECT — casts source_ip INET → text for sqlx.
const LEASE_RETURNING: &str = r"
    id, tenant_id, secret_id, lessee_nhi_id, lessee_type,
    issued_at, expires_at, renewed_at, revoked_at,
    status, revocation_reason, issued_by, source_ip::text AS source_ip
";

/// A time-bounded lease for accessing a vaulted secret.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiSecretLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub secret_id: Uuid,
    pub lessee_nhi_id: Uuid,
    pub lessee_type: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub renewed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub issued_by: Option<Uuid>,
    pub source_ip: Option<String>,
}

impl NhiSecretLease {
    /// List active leases for an NHI identity's secrets.
    pub async fn list_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let sql = format!(
            r"
            SELECT {LEASE_RETURNING}
            FROM nhi_secret_leases
            WHERE tenant_id = $1
              AND secret_id IN (
                  SELECT id FROM nhi_vaulted_secrets WHERE tenant_id = $1 AND nhi_id = $2
              )
              AND status = 'active'
              AND expires_at > NOW()
            ORDER BY issued_at DESC
            "
        );
        sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(nhi_id)
            .fetch_all(pool)
            .await
    }

    /// Get a lease by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        lease_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let sql = format!(
            "SELECT {LEASE_RETURNING} FROM nhi_secret_leases WHERE tenant_id = $1 AND id = $2"
        );
        sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(lease_id)
            .fetch_optional(pool)
            .await
    }

    /// Renew a lease by extending its expiry.
    pub async fn renew(
        pool: &PgPool,
        tenant_id: Uuid,
        lease_id: Uuid,
        extend_secs: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        let sql = format!(
            r"
            UPDATE nhi_secret_leases
            SET expires_at = NOW() + ($3 || ' seconds')::interval,
                renewed_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND status = 'active'
            RETURNING {LEASE_RETURNING}
            "
        );
        sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(lease_id)
            .bind(extend_secs.to_string())
            .fetch_optional(pool)
            .await
    }

    /// Revoke a specific lease.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        lease_id: Uuid,
        reason: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_secret_leases
            SET status = 'revoked', revoked_at = NOW(), revocation_reason = $3
            WHERE tenant_id = $1 AND id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(lease_id)
        .bind(reason)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke ALL active leases for secrets owned by the given NHI.
    /// Called automatically on lifecycle transitions (suspend/deactivate/archive).
    pub async fn revoke_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        reason: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_secret_leases l
            SET status = 'revoked', revoked_at = NOW(), revocation_reason = $3
            FROM nhi_vaulted_secrets s
            WHERE l.secret_id = s.id
              AND s.tenant_id = $1
              AND s.nhi_id = $2
              AND l.status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(reason)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Expire all leases past their expiry time.
    pub async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_secret_leases
            SET status = 'expired'
            WHERE status = 'active' AND expires_at <= NOW()
            ",
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}
