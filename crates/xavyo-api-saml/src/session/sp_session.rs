//! SAML SP session tracking for Single Logout
//!
//! Tracks which Service Providers have active sessions for each user,
//! enabling the IdP to send LogoutRequests to all relevant SPs during SLO.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Represents an active session between a user and a Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub sp_id: Uuid,
    pub session_index: String,
    pub name_id: String,
    pub name_id_format: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// SP session store error
#[derive(Debug, thiserror::Error)]
pub enum SpSessionError {
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Trait for SP session storage
#[async_trait]
pub trait SpSessionStore: Send + Sync {
    /// Record a new SP session after assertion issuance
    async fn record(&self, session: SpSession) -> Result<(), SpSessionError>;

    /// Get all active (non-revoked, non-expired) sessions for a user
    async fn get_active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SpSession>, SpSessionError>;

    /// Revoke all sessions for a user (returns count of revoked sessions)
    async fn revoke_all_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, SpSessionError>;

    /// Clean up expired/revoked sessions for a specific tenant (returns count of deleted sessions)
    async fn cleanup_expired(&self, tenant_id: Uuid) -> Result<u64, SpSessionError>;
}

/// PostgreSQL-backed SP session store for production
pub struct PostgresSpSessionStore {
    pool: PgPool,
}

impl PostgresSpSessionStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SpSessionStore for PostgresSpSessionStore {
    async fn record(&self, session: SpSession) -> Result<(), SpSessionError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            SpSessionError::StorageError(format!("Failed to acquire connection: {e}"))
        })?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(session.tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                SpSessionError::StorageError(format!("Failed to set tenant context: {e}"))
            })?;

        sqlx::query(
            r"
            INSERT INTO saml_sp_sessions (
                id, tenant_id, user_id, sp_id, session_index,
                name_id, name_id_format, created_at, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (tenant_id, user_id, sp_id, session_index) DO UPDATE
            SET name_id = EXCLUDED.name_id,
                name_id_format = EXCLUDED.name_id_format,
                expires_at = EXCLUDED.expires_at,
                revoked_at = NULL
            ",
        )
        .bind(session.id)
        .bind(session.tenant_id)
        .bind(session.user_id)
        .bind(session.sp_id)
        .bind(&session.session_index)
        .bind(&session.name_id)
        .bind(&session.name_id_format)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(|e| SpSessionError::StorageError(format!("Failed to record SP session: {e}")))?;

        Ok(())
    }

    async fn get_active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SpSession>, SpSessionError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            SpSessionError::StorageError(format!("Failed to acquire connection: {e}"))
        })?;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                SpSessionError::StorageError(format!("Failed to set tenant context: {e}"))
            })?;

        let rows = sqlx::query_as::<_, SpSessionRow>(
            r"
            SELECT id, tenant_id, user_id, sp_id, session_index,
                   name_id, name_id_format, created_at, expires_at, revoked_at
            FROM saml_sp_sessions
            WHERE tenant_id = $1 AND user_id = $2
              AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| SpSessionError::StorageError(format!("Failed to get active sessions: {e}")))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_all_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, SpSessionError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            SpSessionError::StorageError(format!("Failed to acquire connection: {e}"))
        })?;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                SpSessionError::StorageError(format!("Failed to set tenant context: {e}"))
            })?;

        let result = sqlx::query(
            r"
            UPDATE saml_sp_sessions
            SET revoked_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| SpSessionError::StorageError(format!("Failed to revoke sessions: {e}")))?;

        Ok(result.rows_affected())
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> Result<u64, SpSessionError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            SpSessionError::StorageError(format!("Failed to acquire connection: {e}"))
        })?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                SpSessionError::StorageError(format!("Failed to set tenant context: {e}"))
            })?;

        let result = sqlx::query(
            r"DELETE FROM saml_sp_sessions WHERE tenant_id = $1 AND (expires_at < NOW() OR revoked_at IS NOT NULL)",
        )
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            SpSessionError::StorageError(format!("Failed to cleanup expired sessions: {e}"))
        })?;

        Ok(result.rows_affected())
    }
}

/// SQLx row type for SP sessions
#[derive(sqlx::FromRow)]
struct SpSessionRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    sp_id: Uuid,
    session_index: String,
    name_id: String,
    name_id_format: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SpSessionRow> for SpSession {
    fn from(row: SpSessionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            sp_id: row.sp_id,
            session_index: row.session_index,
            name_id: row.name_id,
            name_id_format: row.name_id_format,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

/// In-memory SP session store for testing
#[derive(Debug, Default)]
pub struct InMemorySpSessionStore {
    sessions: Arc<RwLock<HashMap<Uuid, SpSession>>>,
}

impl InMemorySpSessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SpSessionStore for InMemorySpSessionStore {
    async fn record(&self, session: SpSession) -> Result<(), SpSessionError> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id, session);
        Ok(())
    }

    async fn get_active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<SpSession>, SpSessionError> {
        let sessions = self.sessions.read().await;
        let now = Utc::now();
        Ok(sessions
            .values()
            .filter(|s| {
                s.tenant_id == tenant_id
                    && s.user_id == user_id
                    && s.revoked_at.is_none()
                    && s.expires_at > now
            })
            .cloned()
            .collect())
    }

    async fn revoke_all_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, SpSessionError> {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let mut count = 0u64;
        for session in sessions.values_mut() {
            if session.tenant_id == tenant_id
                && session.user_id == user_id
                && session.revoked_at.is_none()
            {
                session.revoked_at = Some(now);
                count += 1;
            }
        }
        Ok(count)
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> Result<u64, SpSessionError> {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let before = sessions.len();
        sessions.retain(|_, s| {
            // Only clean up sessions for the specified tenant
            !(s.tenant_id == tenant_id && (s.expires_at <= now || s.revoked_at.is_some()))
        });
        Ok((before - sessions.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(tenant_id: Uuid, user_id: Uuid, sp_id: Uuid) -> SpSession {
        SpSession {
            id: Uuid::new_v4(),
            tenant_id,
            user_id,
            sp_id,
            session_index: format!("_session_{}", Uuid::new_v4()),
            name_id: "user@example.com".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn test_in_memory_record_and_get() {
        let store = InMemorySpSessionStore::new();
        let tid = Uuid::new_v4();
        let uid = Uuid::new_v4();
        let sp_id = Uuid::new_v4();

        let session = make_session(tid, uid, sp_id);
        store.record(session).await.unwrap();

        let active = store.get_active_for_user(tid, uid).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].sp_id, sp_id);
    }

    #[tokio::test]
    async fn test_in_memory_revoke_all() {
        let store = InMemorySpSessionStore::new();
        let tid = Uuid::new_v4();
        let uid = Uuid::new_v4();

        store
            .record(make_session(tid, uid, Uuid::new_v4()))
            .await
            .unwrap();
        store
            .record(make_session(tid, uid, Uuid::new_v4()))
            .await
            .unwrap();

        let revoked = store.revoke_all_for_user(tid, uid).await.unwrap();
        assert_eq!(revoked, 2);

        let active = store.get_active_for_user(tid, uid).await.unwrap();
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_tenant_isolation() {
        let store = InMemorySpSessionStore::new();
        let tid1 = Uuid::new_v4();
        let tid2 = Uuid::new_v4();
        let uid = Uuid::new_v4();

        store
            .record(make_session(tid1, uid, Uuid::new_v4()))
            .await
            .unwrap();
        store
            .record(make_session(tid2, uid, Uuid::new_v4()))
            .await
            .unwrap();

        let active_t1 = store.get_active_for_user(tid1, uid).await.unwrap();
        assert_eq!(active_t1.len(), 1);

        let active_t2 = store.get_active_for_user(tid2, uid).await.unwrap();
        assert_eq!(active_t2.len(), 1);
    }
}
