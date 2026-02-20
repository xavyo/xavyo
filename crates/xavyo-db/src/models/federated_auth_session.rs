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
    /// Nonce, encrypted at rest (AES-256-GCM, per-tenant key).
    pub nonce: Vec<u8>,
    /// PKCE verifier, encrypted at rest (AES-256-GCM, per-tenant key).
    pub pkce_verifier: Vec<u8>,
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
    /// Nonce, encrypted (AES-256-GCM, per-tenant key).
    pub nonce: Vec<u8>,
    /// PKCE verifier, encrypted (AES-256-GCM, per-tenant key).
    pub pkce_verifier: Vec<u8>,
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

    /// Find session by state parameter (not expired, not already used).
    ///
    /// # Security Note
    /// This method does not filter by tenant_id because the state parameter serves as the
    /// tenant isolation mechanism. The state is a CSPRNG-generated unique value that inherently
    /// prevents cross-tenant contamination - it's cryptographically infeasible for one tenant
    /// to guess another tenant's state. The session record itself contains the tenant_id, which
    /// is validated after retrieval. Adding a tenant_id parameter here would require encoding
    /// the tenant_id in the state (since the caller doesn't know which tenant initiated the flow
    /// until after the state lookup), which adds complexity without security benefit.
    pub async fn find_by_state(
        pool: &sqlx::PgPool,
        state: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM federated_auth_sessions
            WHERE state = $1 AND expires_at > NOW() AND is_used = false
            ",
        )
        .bind(state)
        .fetch_optional(pool)
        .await
    }

    /// Atomically consume a session by state (prevents TOCTOU race conditions).
    ///
    /// This method combines find_by_state and mark_used into a single atomic operation,
    /// preventing replay attacks where an attacker tries to use the same state twice
    /// in parallel requests. Returns the session if successfully marked as used, or None
    /// if the session doesn't exist, is already used, or is expired.
    pub async fn consume_by_state(
        pool: &sqlx::PgPool,
        state: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE federated_auth_sessions
            SET is_used = true
            WHERE state = $1 AND is_used = false AND expires_at > NOW()
            RETURNING *
            ",
        )
        .bind(state)
        .fetch_optional(pool)
        .await
    }

    /// Find session by ID with tenant isolation.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM federated_auth_sessions WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// Delete session by state (used after successful callback).
    pub async fn delete_by_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        state: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM federated_auth_sessions WHERE state = $1 AND tenant_id = $2")
                .bind(state)
                .bind(tenant_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete session by ID with tenant isolation.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM federated_auth_sessions WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all sessions for a specific identity provider within a tenant.
    pub async fn delete_by_idp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        idp_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM federated_auth_sessions WHERE tenant_id = $1 AND identity_provider_id = $2",
        )
        .bind(tenant_id)
        .bind(idp_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Clean up expired sessions (all tenants — use for system maintenance only).
    pub async fn cleanup_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM federated_auth_sessions WHERE expires_at < NOW()")
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Clean up expired sessions for a specific tenant.
    /// R9: Tenant-scoped cleanup to respect data sovereignty.
    pub async fn cleanup_expired_for_tenant(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM federated_auth_sessions WHERE tenant_id = $1 AND expires_at < NOW()",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete expired sessions (alias for `cleanup_expired`).
    pub async fn delete_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        Self::cleanup_expired(pool).await
    }

    /// Mark session as used after successful callback.
    pub async fn mark_used(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE federated_auth_sessions SET is_used = true WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
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
