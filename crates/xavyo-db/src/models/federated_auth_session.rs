//! Federated Auth Session model for OAuth state management.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Session expiry time in minutes.
pub const SESSION_EXPIRY_MINUTES: i64 = 10;

/// Federated Auth Session entity - temporary storage for auth flow state.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FederatedAuthSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_provider_id: Uuid,
    pub state: String,
    pub nonce: String,
    /// PKCE verifier stored as plain text (session is short-lived, 10 min).
    pub pkce_verifier: String,
    pub redirect_uri: String,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Input for creating a new session.
#[derive(Debug, Clone)]
pub struct CreateFederatedAuthSession {
    pub tenant_id: Uuid,
    pub identity_provider_id: Uuid,
    pub state: String,
    pub nonce: String,
    /// PKCE verifier - stored as plain text since session is short-lived
    pub pkce_verifier: String,
    pub redirect_uri: String,
}

impl FederatedAuthSession {
    /// Create a new auth session.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateFederatedAuthSession,
    ) -> Result<Self, sqlx::Error> {
        let expires_at = Utc::now() + Duration::minutes(SESSION_EXPIRY_MINUTES);

        sqlx::query_as(
            r"
            INSERT INTO federated_auth_sessions (
                tenant_id, identity_provider_id, state, nonce,
                pkce_verifier, redirect_uri, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(input.identity_provider_id)
        .bind(&input.state)
        .bind(&input.nonce)
        .bind(&input.pkce_verifier)
        .bind(&input.redirect_uri)
        .bind(expires_at)
        .fetch_one(pool)
        .await
    }

    /// Find session by state parameter (and verify not expired).
    pub async fn find_by_state(
        pool: &sqlx::PgPool,
        state: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM federated_auth_sessions
            WHERE state = $1 AND expires_at > NOW()
            ",
        )
        .bind(state)
        .fetch_optional(pool)
        .await
    }

    /// Find session by ID.
    pub async fn find_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM federated_auth_sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Delete session by state (used after successful callback).
    pub async fn delete_by_state(pool: &sqlx::PgPool, state: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM federated_auth_sessions WHERE state = $1")
            .bind(state)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete session by ID.
    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM federated_auth_sessions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Clean up expired sessions.
    pub async fn cleanup_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM federated_auth_sessions WHERE expires_at < NOW()")
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Delete expired sessions (alias for `cleanup_expired`).
    pub async fn delete_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        Self::cleanup_expired(pool).await
    }

    /// Mark session as used after successful callback.
    pub async fn mark_used(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("UPDATE federated_auth_sessions SET is_used = true WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Check if session is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session has been used.
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.is_used
    }
}
