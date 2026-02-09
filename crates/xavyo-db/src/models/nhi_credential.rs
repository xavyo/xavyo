//! NHI Credential model (201-tool-nhi-promotion).
//!
//! Unified credential storage for all NHI types. Replaces `gov_nhi_credentials`
//! with a simple FK to `nhi_identities` instead of a polymorphic reference.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An NHI credential record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiCredential {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub nhi_id: Uuid,
    pub credential_type: String,
    #[serde(skip_serializing)]
    pub credential_hash: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub is_active: bool,
    pub rotated_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new NHI credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiCredential {
    pub nhi_id: Uuid,
    pub credential_type: String,
    pub credential_hash: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub rotated_by: Option<Uuid>,
}

impl NhiCredential {
    /// Check if this credential is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        self.is_active && self.valid_from <= now && self.valid_until > now
    }

    /// Create a new credential.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        data: CreateNhiCredential,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_credentials (
                tenant_id, nhi_id, credential_type, credential_hash,
                valid_from, valid_until, rotated_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.nhi_id)
        .bind(&data.credential_type)
        .bind(&data.credential_hash)
        .bind(data.valid_from)
        .bind(data.valid_until)
        .bind(data.rotated_by)
        .fetch_one(pool)
        .await
    }

    /// Find a credential by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_credentials
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a credential by hash (for authentication).
    pub async fn find_by_hash(pool: &PgPool, hash: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_credentials
            WHERE credential_hash = $1
              AND is_active = true
              AND valid_from <= NOW()
              AND valid_until > NOW()
            ",
        )
        .bind(hash)
        .fetch_optional(pool)
        .await
    }

    /// List credentials for an NHI with pagination.
    pub async fn list_by_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        sqlx::query_as(
            r"
            SELECT * FROM nhi_credentials
            WHERE tenant_id = $1 AND nhi_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List active credentials for an NHI.
    pub async fn list_active_by_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_credentials
            WHERE tenant_id = $1 AND nhi_id = $2
              AND is_active = true
              AND valid_from <= NOW()
              AND valid_until > NOW()
            ORDER BY valid_from DESC
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_all(pool)
        .await
    }

    /// Deactivate a single credential.
    pub async fn deactivate(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_credentials
            SET is_active = false
            WHERE tenant_id = $1 AND id = $2 AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Deactivate all credentials for an NHI.
    pub async fn deactivate_all_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE nhi_credentials
            SET is_active = false
            WHERE tenant_id = $1 AND nhi_id = $2 AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_credential_is_valid() {
        use chrono::Duration;

        let valid = NhiCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            credential_type: "api_key".to_string(),
            credential_hash: "hash123".to_string(),
            valid_from: Utc::now() - Duration::hours(1),
            valid_until: Utc::now() + Duration::hours(1),
            is_active: true,
            rotated_by: None,
            created_at: Utc::now(),
        };
        assert!(valid.is_valid());

        let expired = NhiCredential {
            valid_until: Utc::now() - Duration::hours(1),
            ..valid.clone()
        };
        assert!(!expired.is_valid());

        let inactive = NhiCredential {
            is_active: false,
            ..valid
        };
        assert!(!inactive.is_valid());
    }

    #[test]
    fn test_nhi_credential_serialization_hides_hash() {
        let cred = NhiCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            credential_type: "secret".to_string(),
            credential_hash: "supersecret".to_string(),
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(30),
            is_active: true,
            rotated_by: None,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&cred).unwrap();
        assert!(!json.contains("supersecret"));
        assert!(json.contains("\"secret\""));
    }

    #[test]
    fn test_create_nhi_credential() {
        let input = CreateNhiCredential {
            nhi_id: Uuid::new_v4(),
            credential_type: "api_key".to_string(),
            credential_hash: "argon2hash".to_string(),
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::days(90),
            rotated_by: Some(Uuid::new_v4()),
        };

        assert_eq!(input.credential_type, "api_key");
        assert!(input.rotated_by.is_some());
    }
}
