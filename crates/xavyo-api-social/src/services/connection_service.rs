//! Connection service for managing social connections.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ProviderType, SocialError, SocialResult};
use crate::providers::SocialUserInfo;
use crate::services::encryption::EncryptionService;

/// Connection service for managing social identity links.
#[derive(Clone)]
pub struct ConnectionService {
    pool: PgPool,
    encryption: EncryptionService,
}

/// Result of attempting to find or create a connection.
pub enum ConnectionResult {
    /// Existing connection found - user can be logged in.
    Existing { connection_id: Uuid, user_id: Uuid },
    /// No connection found, but email matches existing user - needs linking.
    EmailCollision {
        existing_user_id: Uuid,
        email: String,
    },
    /// New user - connection can be created with new user.
    NewUser,
}

impl ConnectionService {
    /// Create a new connection service.
    #[must_use] 
    pub fn new(pool: PgPool, encryption: EncryptionService) -> Self {
        Self { pool, encryption }
    }

    /// Find a connection by provider user ID.
    pub async fn find_by_provider_user_id(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
        provider_user_id: &str,
    ) -> SocialResult<Option<ConnectionInfo>> {
        let row: Option<ConnectionRow> = sqlx::query_as(
            r"
            SELECT id, user_id, provider, email, display_name, is_private_email, created_at
            FROM social_connections
            WHERE tenant_id = $1 AND provider = $2 AND provider_user_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(provider.to_string())
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| ConnectionInfo {
            id: r.id,
            user_id: r.user_id,
            provider: r.provider,
            email: r.email,
            display_name: r.display_name,
            is_private_email: r.is_private_email,
            created_at: r.created_at,
        }))
    }

    /// Check if a connection exists and determine the appropriate action.
    pub async fn check_connection(
        &self,
        tenant_id: Uuid,
        provider: ProviderType,
        user_info: &SocialUserInfo,
    ) -> SocialResult<ConnectionResult> {
        // First, check if connection already exists
        if let Some(connection) = self
            .find_by_provider_user_id(tenant_id, provider, &user_info.provider_user_id)
            .await?
        {
            return Ok(ConnectionResult::Existing {
                connection_id: connection.id,
                user_id: connection.user_id,
            });
        }

        // No existing connection - check for email collision
        if let Some(email) = &user_info.email {
            let existing_user: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM users WHERE tenant_id = $1 AND email = $2")
                    .bind(tenant_id)
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await?;

            if let Some((existing_user_id,)) = existing_user {
                return Ok(ConnectionResult::EmailCollision {
                    existing_user_id,
                    email: email.clone(),
                });
            }
        }

        Ok(ConnectionResult::NewUser)
    }

    /// Create a new social connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_connection(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: ProviderType,
        user_info: &SocialUserInfo,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_in: Option<i64>,
    ) -> SocialResult<Uuid> {
        let access_token_encrypted = if let Some(token) = access_token {
            Some(self.encryption.encrypt_string(tenant_id, token)?)
        } else {
            None
        };

        let refresh_token_encrypted = if let Some(token) = refresh_token {
            Some(self.encryption.encrypt_string(tenant_id, token)?)
        } else {
            None
        };

        let token_expires_at = expires_in.map(|secs| Utc::now() + Duration::seconds(secs));

        let raw_claims = serde_json::to_value(&user_info.raw_claims).ok();

        let (id,): (Uuid,) = sqlx::query_as(
            r"
            INSERT INTO social_connections (
                tenant_id, user_id, provider, provider_user_id, email, display_name,
                access_token_encrypted, refresh_token_encrypted, token_expires_at,
                is_private_email, raw_claims
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.to_string())
        .bind(&user_info.provider_user_id)
        .bind(&user_info.email)
        .bind(user_info.name.as_ref().or(user_info.given_name.as_ref()))
        .bind(&access_token_encrypted)
        .bind(&refresh_token_encrypted)
        .bind(token_expires_at)
        .bind(user_info.is_private_email)
        .bind(&raw_claims)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Update an existing connection with new tokens.
    pub async fn update_connection(
        &self,
        tenant_id: Uuid,
        connection_id: Uuid,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_in: Option<i64>,
    ) -> SocialResult<()> {
        let access_token_encrypted = if let Some(token) = access_token {
            Some(self.encryption.encrypt_string(tenant_id, token)?)
        } else {
            None
        };

        let refresh_token_encrypted = if let Some(token) = refresh_token {
            Some(self.encryption.encrypt_string(tenant_id, token)?)
        } else {
            None
        };

        let token_expires_at = expires_in.map(|secs| Utc::now() + Duration::seconds(secs));

        sqlx::query(
            r"
            UPDATE social_connections
            SET
                access_token_encrypted = COALESCE($3, access_token_encrypted),
                refresh_token_encrypted = COALESCE($4, refresh_token_encrypted),
                token_expires_at = COALESCE($5, token_expires_at),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(connection_id)
        .bind(tenant_id)
        .bind(&access_token_encrypted)
        .bind(&refresh_token_encrypted)
        .bind(token_expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Link a social account to an existing user.
    #[allow(clippy::too_many_arguments)]
    pub async fn link_to_existing_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: ProviderType,
        user_info: &SocialUserInfo,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_in: Option<i64>,
    ) -> SocialResult<Uuid> {
        // Check if this provider account is already linked to another user
        if let Some(existing) = self
            .find_by_provider_user_id(tenant_id, provider, &user_info.provider_user_id)
            .await?
        {
            if existing.user_id != user_id {
                return Err(SocialError::AlreadyLinkedToOther);
            }
            // Already linked to this user - just update tokens
            self.update_connection(
                tenant_id,
                existing.id,
                access_token,
                refresh_token,
                expires_in,
            )
            .await?;
            return Ok(existing.id);
        }

        // Create new connection
        self.create_connection(
            tenant_id,
            user_id,
            provider,
            user_info,
            access_token,
            refresh_token,
            expires_in,
        )
        .await
    }

    /// Get all connections for a user.
    pub async fn get_user_connections(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> SocialResult<Vec<ConnectionInfo>> {
        let rows: Vec<ConnectionRow> = sqlx::query_as(
            r"
            SELECT id, user_id, provider, email, display_name, is_private_email, created_at
            FROM social_connections
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ConnectionInfo {
                id: r.id,
                user_id: r.user_id,
                provider: r.provider,
                email: r.email,
                display_name: r.display_name,
                is_private_email: r.is_private_email,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Check if a user can unlink a provider (has other auth methods).
    pub async fn can_unlink(&self, tenant_id: Uuid, user_id: Uuid) -> SocialResult<bool> {
        // Count social connections
        let (connection_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM social_connections WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Check if user has a password
        let (has_password,): (bool,) = sqlx::query_as(
            "SELECT password_hash IS NOT NULL FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        // Can unlink if: has password OR has more than one social connection
        Ok(has_password || connection_count > 1)
    }

    /// Delete a social connection.
    pub async fn delete_connection(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: ProviderType,
    ) -> SocialResult<bool> {
        // First check if can unlink
        if !self.can_unlink(tenant_id, user_id).await? {
            return Err(SocialError::UnlinkForbidden {
                reason:
                    "Cannot unlink your only authentication method. Please set a password first."
                        .to_string(),
            });
        }

        let result = sqlx::query(
            "DELETE FROM social_connections WHERE tenant_id = $1 AND user_id = $2 AND provider = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.to_string())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(SocialError::ConnectionNotFound);
        }

        Ok(true)
    }
}

/// Connection information (without encrypted tokens).
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_private_email: bool,
    pub created_at: DateTime<Utc>,
}

/// Internal row type for queries.
#[derive(Debug, sqlx::FromRow)]
struct ConnectionRow {
    id: Uuid,
    user_id: Uuid,
    provider: String,
    email: Option<String>,
    display_name: Option<String>,
    is_private_email: bool,
    created_at: DateTime<Utc>,
}
