//! Social connection model for storing user-provider links.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Social connection entity representing a link between a user and a social provider.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SocialConnection {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub access_token_encrypted: Option<Vec<u8>>,
    pub refresh_token_encrypted: Option<Vec<u8>>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub is_private_email: bool,
    pub raw_claims: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new social connection.
#[derive(Debug, Clone)]
pub struct CreateSocialConnection {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub access_token_encrypted: Option<Vec<u8>>,
    pub refresh_token_encrypted: Option<Vec<u8>>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub is_private_email: bool,
    pub raw_claims: Option<serde_json::Value>,
}

/// Input for updating a social connection.
#[derive(Debug, Clone, Default)]
pub struct UpdateSocialConnection {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub access_token_encrypted: Option<Vec<u8>>,
    pub refresh_token_encrypted: Option<Vec<u8>>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub raw_claims: Option<serde_json::Value>,
}

impl SocialConnection {
    /// Create a new social connection in the database.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateSocialConnection,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO social_connections (
                tenant_id, user_id, provider, provider_user_id, email, display_name,
                access_token_encrypted, refresh_token_encrypted, token_expires_at,
                is_private_email, raw_claims
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(input.user_id)
        .bind(&input.provider)
        .bind(&input.provider_user_id)
        .bind(&input.email)
        .bind(&input.display_name)
        .bind(&input.access_token_encrypted)
        .bind(&input.refresh_token_encrypted)
        .bind(input.token_expires_at)
        .bind(input.is_private_email)
        .bind(&input.raw_claims)
        .fetch_one(pool)
        .await
    }

    /// Find a social connection by provider and provider user ID.
    pub async fn find_by_provider_user_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM social_connections
            WHERE tenant_id = $1 AND provider = $2 AND provider_user_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a social connection by provider and email.
    pub async fn find_by_provider_email(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider: &str,
        email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM social_connections
            WHERE tenant_id = $1 AND provider = $2 AND email = $3
            "#,
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// Find all social connections for a user.
    pub async fn find_by_user_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM social_connections
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Find a specific connection for a user and provider.
    pub async fn find_by_user_and_provider(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM social_connections
            WHERE tenant_id = $1 AND user_id = $2 AND provider = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider)
        .fetch_optional(pool)
        .await
    }

    /// Update a social connection.
    pub async fn update(
        pool: &sqlx::PgPool,
        id: Uuid,
        input: UpdateSocialConnection,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE social_connections
            SET
                email = COALESCE($2, email),
                display_name = COALESCE($3, display_name),
                access_token_encrypted = COALESCE($4, access_token_encrypted),
                refresh_token_encrypted = COALESCE($5, refresh_token_encrypted),
                token_expires_at = COALESCE($6, token_expires_at),
                raw_claims = COALESCE($7, raw_claims),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&input.email)
        .bind(&input.display_name)
        .bind(&input.access_token_encrypted)
        .bind(&input.refresh_token_encrypted)
        .bind(input.token_expires_at)
        .bind(&input.raw_claims)
        .fetch_one(pool)
        .await
    }

    /// Delete a social connection.
    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM social_connections WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count connections for a user (for unlink validation).
    pub async fn count_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM social_connections
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }
}
