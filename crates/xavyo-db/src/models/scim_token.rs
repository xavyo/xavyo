//! SCIM Token entity model.
//!
//! Bearer tokens for SCIM API authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A SCIM Bearer token for API authentication.
///
/// Tokens are scoped to a tenant and used by IdPs to authenticate
/// SCIM provisioning requests.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScimToken {
    /// Unique identifier for the token.
    pub id: Uuid,

    /// The tenant this token belongs to.
    pub tenant_id: Uuid,

    /// Human-readable name (e.g., "Azure AD Sync").
    pub name: String,

    /// SHA-256 hash of the Bearer token.
    pub token_hash: String,

    /// Display prefix (e.g., "xscim_...XXXX").
    pub token_prefix: String,

    /// When the token was created.
    pub created_at: DateTime<Utc>,

    /// When the token was last used successfully.
    pub last_used_at: Option<DateTime<Utc>>,

    /// When the token was revoked (None = active).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Admin who created the token.
    pub created_by: Uuid,
}

/// Request to create a new SCIM token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimToken {
    pub name: String,
}

/// Response when a new token is created (includes the raw token once).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimTokenCreated {
    pub id: Uuid,
    pub name: String,
    /// The raw token - only shown once!
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub warning: String,
}

/// Token info for listing (without hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimTokenInfo {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
}

impl From<ScimToken> for ScimTokenInfo {
    fn from(token: ScimToken) -> Self {
        Self {
            id: token.id,
            name: token.name,
            token_prefix: token.token_prefix,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
            revoked_at: token.revoked_at,
            created_by: token.created_by,
        }
    }
}

impl ScimToken {
    /// Check if the token is active (not revoked).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Find a token by its hash.
    pub async fn find_by_hash(
        pool: &sqlx::PgPool,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_tokens
            WHERE token_hash = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
    }

    /// Find a token by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_tokens
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all tokens for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_tokens
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new token.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
        token_hash: &str,
        token_prefix: &str,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO scim_tokens (tenant_id, name, token_hash, token_prefix, created_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(token_hash)
        .bind(token_prefix)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update last_used_at timestamp.
    pub async fn update_last_used(pool: &sqlx::PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE scim_tokens SET last_used_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Revoke a token.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_tokens SET revoked_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
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
    fn test_token_is_active() {
        let token = ScimToken {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Token".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "xscim_...XXXX".to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
            created_by: Uuid::new_v4(),
        };
        assert!(token.is_active());
    }

    #[test]
    fn test_token_info_conversion() {
        let token = ScimToken {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Token".to_string(),
            token_hash: "secret_hash".to_string(),
            token_prefix: "xscim_...XXXX".to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
            created_by: Uuid::new_v4(),
        };

        let info: ScimTokenInfo = token.into();
        assert_eq!(info.token_prefix, "xscim_...XXXX");
        // Note: token_hash is not included in ScimTokenInfo
    }
}
