//! Governance Persona Session model (F063).
//!
//! Tracks which persona is currently active for a user session.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A persona session - tracks active persona context.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPersonaSession {
    /// Unique identifier for the session.
    pub id: Uuid,

    /// The tenant this session belongs to.
    pub tenant_id: Uuid,

    /// Physical user who owns this session.
    pub user_id: Uuid,

    /// Currently active persona (NULL = operating as physical user).
    pub active_persona_id: Option<Uuid>,

    /// Previous persona before last switch (for audit trail).
    pub previous_persona_id: Option<Uuid>,

    /// User-provided reason for the context switch.
    pub switch_reason: Option<String>,

    /// When context was switched.
    pub switched_at: DateTime<Utc>,

    /// Session expiration time.
    pub expires_at: DateTime<Utc>,

    /// When the session was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create or update a persona session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertPersonaSession {
    pub active_persona_id: Option<Uuid>,
    pub switch_reason: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl GovPersonaSession {
    /// Find a session by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_persona_sessions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the active session for a user (not expired).
    pub async fn find_active_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_persona_sessions
            WHERE tenant_id = $1 AND user_id = $2 AND expires_at > NOW()
            ORDER BY switched_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List session history for a user with pagination.
    pub async fn find_history_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_persona_sessions
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY switched_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List sessions for a persona (for audit).
    pub async fn find_by_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_persona_sessions
            WHERE tenant_id = $1 AND active_persona_id = $2
            ORDER BY switched_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(persona_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Create or update a persona session (switch context).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        input: UpsertPersonaSession,
    ) -> Result<Self, sqlx::Error> {
        // Get current active session to capture previous_persona_id
        let current = Self::find_active_for_user(pool, tenant_id, user_id).await?;
        let previous_persona_id = current.and_then(|s| s.active_persona_id);

        sqlx::query_as(
            r"
            INSERT INTO gov_persona_sessions (
                tenant_id, user_id, active_persona_id, previous_persona_id,
                switch_reason, switched_at, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(input.active_persona_id)
        .bind(previous_persona_id)
        .bind(&input.switch_reason)
        .bind(input.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Invalidate all active sessions for a persona (on persona deactivation).
    pub async fn invalidate_by_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_persona_sessions
            SET expires_at = NOW()
            WHERE tenant_id = $1 AND active_persona_id = $2 AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(persona_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Invalidate all sessions for a user.
    pub async fn invalidate_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_persona_sessions
            SET expires_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clean up expired sessions (for maintenance job).
    pub async fn cleanup_expired(
        pool: &sqlx::PgPool,
        older_than_days: i32,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_persona_sessions
            WHERE expires_at < NOW() - $1::interval
            ",
        )
        .bind(format!("{older_than_days} days"))
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if session is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Check if user is operating as a persona.
    #[must_use]
    pub fn is_persona_active(&self) -> bool {
        self.active_persona_id.is_some() && self.is_valid()
    }

    /// Get remaining time until expiration.
    #[must_use]
    pub fn time_until_expiration(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }

    /// Invalidate all sessions for a specific persona (when persona expires).
    pub async fn invalidate_for_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_persona_sessions
            SET active_persona_id = NULL,
                switch_reason = CONCAT(switch_reason, ' [Invalidated: persona expired]'),
                updated_at = NOW()
            WHERE tenant_id = $1 AND active_persona_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(persona_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_persona_session_request() {
        let input = UpsertPersonaSession {
            active_persona_id: Some(Uuid::new_v4()),
            switch_reason: Some("Administrative task".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(8),
        };

        assert!(input.active_persona_id.is_some());
        assert!(input.switch_reason.is_some());
    }

    #[test]
    fn test_session_validity() {
        let session = GovPersonaSession {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            active_persona_id: Some(Uuid::new_v4()),
            previous_persona_id: None,
            switch_reason: None,
            switched_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
        };

        assert!(session.is_valid());
        assert!(session.is_persona_active());
    }

    #[test]
    fn test_expired_session() {
        let session = GovPersonaSession {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            active_persona_id: Some(Uuid::new_v4()),
            previous_persona_id: None,
            switch_reason: None,
            switched_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            created_at: Utc::now() - chrono::Duration::hours(2),
        };

        assert!(!session.is_valid());
        assert!(!session.is_persona_active());
    }

    #[test]
    fn test_session_without_persona() {
        let session = GovPersonaSession {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            active_persona_id: None, // Operating as physical user
            previous_persona_id: Some(Uuid::new_v4()),
            switch_reason: Some("Task completed".to_string()),
            switched_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
        };

        assert!(session.is_valid());
        assert!(!session.is_persona_active());
    }
}
