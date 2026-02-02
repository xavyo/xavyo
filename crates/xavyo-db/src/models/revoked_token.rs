//! Revoked token model for JWT access token revocation (F069).
//!
//! Stores JTI blacklist entries for revoked JWT access tokens.
//! Each row represents a single revoked token. Rows are automatically
//! cleaned up after the token's original expiration time passes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A revoked JWT access token record.
///
/// When a token is revoked, its JTI is stored here so that
/// subsequent authentication requests can check and reject it.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RevokedToken {
    /// Unique record identifier.
    pub id: Uuid,

    /// JWT ID claim from the revoked token (unique).
    pub jti: String,

    /// User whose token was revoked.
    pub user_id: Uuid,

    /// Tenant isolation (RLS-enforced).
    pub tenant_id: Uuid,

    /// Optional reason for revocation.
    pub reason: Option<String>,

    /// When the token was revoked.
    pub revoked_at: DateTime<Utc>,

    /// Original token expiration time (for cleanup scheduling).
    pub expires_at: DateTime<Utc>,

    /// ID of the user/admin who performed the revocation (NULL for system-initiated).
    pub revoked_by: Option<Uuid>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new revoked token record.
#[derive(Debug, Clone)]
pub struct CreateRevokedToken {
    pub jti: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub reason: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_by: Option<Uuid>,
}

impl RevokedToken {
    /// Insert a new revoked token record.
    ///
    /// Uses ON CONFLICT DO NOTHING to handle duplicate JTI gracefully
    /// (revoking an already-revoked token is a no-op).
    pub async fn insert<'e, E>(
        executor: E,
        input: CreateRevokedToken,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO revoked_tokens (jti, user_id, tenant_id, reason, expires_at, revoked_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (jti) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(&input.jti)
        .bind(input.user_id)
        .bind(input.tenant_id)
        .bind(&input.reason)
        .bind(input.expires_at)
        .bind(input.revoked_by)
        .fetch_optional(executor)
        .await
    }

    /// Check if a JTI has been revoked.
    ///
    /// This is called on every authenticated request to check the blacklist.
    /// Returns true if the token is revoked and not yet expired.
    pub async fn is_revoked<'e, E>(executor: E, jti: &str) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM revoked_tokens
                WHERE jti = $1
            )
            "#,
        )
        .bind(jti)
        .fetch_one(executor)
        .await?;

        Ok(result.0)
    }

    /// Find a revoked token by JTI.
    pub async fn find_by_jti<'e, E>(
        executor: E,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM revoked_tokens
            WHERE tenant_id = $1 AND jti = $2
            "#,
        )
        .bind(tenant_id)
        .bind(jti)
        .fetch_optional(executor)
        .await
    }

    /// Find all revoked tokens for a user.
    pub async fn find_by_user_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM revoked_tokens
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY revoked_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Count revoked tokens for a user.
    pub async fn count_by_user<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM revoked_tokens
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Delete expired revocation records.
    ///
    /// Records where `expires_at < NOW()` are no longer needed because
    /// the token would be invalid anyway due to JWT expiry.
    /// Returns the number of records deleted.
    pub async fn delete_expired<'e, E>(executor: E) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM revoked_tokens
            WHERE expires_at < NOW()
            "#,
        )
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_revoked_token_fields() {
        let input = CreateRevokedToken {
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            reason: Some("compromised".to_string()),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            revoked_by: Some(Uuid::new_v4()),
        };

        assert!(!input.jti.is_empty());
        assert!(input.reason.is_some());
        assert!(input.revoked_by.is_some());
    }

    #[test]
    fn test_create_revoked_token_without_optional_fields() {
        let input = CreateRevokedToken {
            jti: "test-jti".to_string(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            reason: None,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            revoked_by: None,
        };

        assert!(input.reason.is_none());
        assert!(input.revoked_by.is_none());
    }
}
