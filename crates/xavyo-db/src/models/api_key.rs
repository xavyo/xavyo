//! API Key model for tenant admin access.
//!
//! API keys are used for programmatic access to the xavyo API.
//! Keys are stored as SHA-256 hashes, never in plaintext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::DbError;

/// An API key for programmatic access to the xavyo API.
///
/// API keys are scoped to a tenant and user, with optional scope restrictions.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier for the API key.
    pub id: Uuid,

    /// The tenant this API key belongs to.
    pub tenant_id: Uuid,

    /// The user this API key belongs to.
    pub user_id: Uuid,

    /// Human-readable name for the API key.
    pub name: String,

    /// First characters of the key for identification (e.g., "`xavyo_sk`").
    pub key_prefix: String,

    /// SHA-256 hash of the full API key.
    #[serde(skip_serializing)]
    pub key_hash: String,

    /// Allowed API scopes (empty = all scopes).
    pub scopes: Vec<String>,

    /// Whether the API key is active.
    pub is_active: bool,

    /// When the API key was last used.
    pub last_used_at: Option<DateTime<Utc>>,

    /// When the API key expires (None = never).
    pub expires_at: Option<DateTime<Utc>>,

    /// When the API key was created.
    pub created_at: DateTime<Utc>,

    /// Optional per-key rate limit (requests per hour).
    /// NULL or 0 = no per-key rate limit.
    pub rate_limit_per_hour: Option<i32>,
}

/// Data required to create a new API key.
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// Check if the API key is valid (active and not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.is_active {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }

        true
    }

    /// Create a new API key in the database.
    ///
    /// The `key_hash` should be a SHA-256 hash of the full API key.
    pub async fn create(pool: &PgPool, data: CreateApiKey) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO api_keys (tenant_id, user_id, name, key_prefix, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.user_id)
        .bind(&data.name)
        .bind(&data.key_prefix)
        .bind(&data.key_hash)
        .bind(&data.scopes)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Create a new API key within a transaction.
    pub async fn create_in_tx<'e>(
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        data: CreateApiKey,
    ) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO api_keys (tenant_id, user_id, name, key_prefix, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.user_id)
        .bind(&data.name)
        .bind(&data.key_prefix)
        .bind(&data.key_hash)
        .bind(&data.scopes)
        .bind(data.expires_at)
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Find an API key by its hash.
    ///
    /// This is the primary lookup method for authentication.
    pub async fn find_by_hash(pool: &PgPool, key_hash: &str) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM api_keys WHERE key_hash = $1
            ",
        )
        .bind(key_hash)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Find an API key by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM api_keys WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// List all API keys for a user within a tenant.
    pub async fn list_by_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM api_keys
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Update the `last_used_at` timestamp.
    pub async fn update_last_used(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<(), DbError> {
        sqlx::query(
            r"
            UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(())
    }

    /// Deactivate an API key.
    pub async fn deactivate(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE api_keys SET is_active = false
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Delete an API key.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query(
            r"
            DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result.rows_affected() > 0)
    }

    /// Rotate an API key by creating a new one and optionally deactivating the old.
    ///
    /// F-KEY-ROTATE: This method creates a new API key to replace an existing one.
    /// The old key can be kept active for a grace period before being deactivated.
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `tenant_id` - Tenant ID for authorization
    /// * `old_key_id` - ID of the key to rotate
    /// * `new_data` - Data for the new API key
    /// * `deactivate_old` - If true, deactivates the old key immediately
    ///
    /// # Returns
    ///
    /// Returns the newly created API key on success.
    pub async fn rotate(
        pool: &PgPool,
        tenant_id: Uuid,
        old_key_id: Uuid,
        new_data: CreateApiKey,
        deactivate_old: bool,
    ) -> Result<Self, DbError> {
        // Verify old key exists and belongs to tenant
        let old_key = Self::find_by_id(pool, tenant_id, old_key_id)
            .await?
            .ok_or_else(|| DbError::NotFound("API key not found".to_string()))?;

        // Verify old key is still active
        if !old_key.is_active {
            return Err(DbError::ValidationFailed(
                "Cannot rotate an inactive API key".to_string(),
            ));
        }

        // Create the new key
        let new_key = Self::create(pool, new_data).await?;

        // Optionally deactivate the old key
        if deactivate_old {
            Self::deactivate(pool, tenant_id, old_key_id).await?;
        }

        Ok(new_key)
    }

    /// List all API keys for a tenant (admin view).
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM api_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_is_valid_active() {
        let key = ApiKey {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Key".to_string(),
            key_prefix: "xavyo_sk".to_string(),
            key_hash: "abc123".to_string(),
            scopes: vec![],
            is_active: true,
            last_used_at: None,
            expires_at: None,
            created_at: Utc::now(),
            rate_limit_per_hour: None,
        };

        assert!(key.is_valid());
    }

    #[test]
    fn test_api_key_is_valid_inactive() {
        let key = ApiKey {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Key".to_string(),
            key_prefix: "xavyo_sk".to_string(),
            key_hash: "abc123".to_string(),
            scopes: vec![],
            is_active: false,
            last_used_at: None,
            expires_at: None,
            created_at: Utc::now(),
            rate_limit_per_hour: None,
        };

        assert!(!key.is_valid());
    }

    #[test]
    fn test_api_key_is_valid_expired() {
        let key = ApiKey {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Key".to_string(),
            key_prefix: "xavyo_sk".to_string(),
            key_hash: "abc123".to_string(),
            scopes: vec![],
            is_active: true,
            last_used_at: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            created_at: Utc::now(),
            rate_limit_per_hour: None,
        };

        assert!(!key.is_valid());
    }
}
