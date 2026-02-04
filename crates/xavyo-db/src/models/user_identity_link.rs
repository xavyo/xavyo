//! User Identity Link model for OIDC federation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// User Identity Link entity - links local user to external `IdP` identity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserIdentityLink {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub identity_provider_id: Uuid,
    pub subject: String,
    pub issuer: String,
    pub raw_claims: Option<serde_json::Value>,
    pub last_login_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new user identity link.
#[derive(Debug, Clone)]
pub struct CreateUserIdentityLink {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub identity_provider_id: Uuid,
    pub subject: String,
    pub issuer: String,
    pub raw_claims: Option<serde_json::Value>,
}

/// Input for updating a user identity link.
#[derive(Debug, Clone, Default)]
pub struct UpdateUserIdentityLink {
    pub raw_claims: Option<serde_json::Value>,
}

impl UserIdentityLink {
    /// Create a new user identity link.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateUserIdentityLink,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO user_identity_links (
                tenant_id, user_id, identity_provider_id, subject, issuer, raw_claims
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(input.user_id)
        .bind(input.identity_provider_id)
        .bind(&input.subject)
        .bind(&input.issuer)
        .bind(&input.raw_claims)
        .fetch_one(pool)
        .await
    }

    /// Find by ID.
    ///
    /// **SECURITY WARNING**: This method does NOT filter by `tenant_id`.
    /// Use `find_by_id_and_tenant()` for tenant-isolated queries.
    #[deprecated(
        since = "0.1.0",
        note = "Use find_by_id_and_tenant() for tenant-isolated queries"
    )]
    pub async fn find_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM user_identity_links WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Find by ID with tenant isolation.
    ///
    /// SECURITY: This method ensures tenant isolation by requiring `tenant_id`.
    pub async fn find_by_id_and_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM user_identity_links WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// Find by user ID.
    pub async fn find_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_identity_links
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Find by `IdP` subject claim.
    pub async fn find_by_subject(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_provider_id: Uuid,
        subject: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_identity_links
            WHERE tenant_id = $1 AND identity_provider_id = $2 AND subject = $3
            ",
        )
        .bind(tenant_id)
        .bind(identity_provider_id)
        .bind(subject)
        .fetch_optional(pool)
        .await
    }

    /// Find by user and `IdP`.
    pub async fn find_by_user_and_idp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_identity_links
            WHERE tenant_id = $1 AND user_id = $2 AND identity_provider_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(identity_provider_id)
        .fetch_optional(pool)
        .await
    }

    /// Count links for an `IdP` (to prevent deletion when users are linked).
    pub async fn count_by_idp(
        pool: &sqlx::PgPool,
        identity_provider_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_identity_links WHERE identity_provider_id = $1",
        )
        .bind(identity_provider_id)
        .fetch_one(pool)
        .await?;
        Ok(result.0)
    }

    /// Update link (claims and last login).
    pub async fn update(
        pool: &sqlx::PgPool,
        id: Uuid,
        input: UpdateUserIdentityLink,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_identity_links
            SET
                raw_claims = COALESCE($2, raw_claims),
                last_login_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            ",
        )
        .bind(id)
        .bind(&input.raw_claims)
        .fetch_one(pool)
        .await
    }

    /// List all links for a user.
    pub async fn list_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_identity_links
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Update last login timestamp.
    pub async fn touch_last_login(pool: &sqlx::PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE user_identity_links SET last_login_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Delete a link.
    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM user_identity_links WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all links for an `IdP`.
    pub async fn delete_by_idp(
        pool: &sqlx::PgPool,
        identity_provider_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM user_identity_links WHERE identity_provider_id = $1")
            .bind(identity_provider_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}
