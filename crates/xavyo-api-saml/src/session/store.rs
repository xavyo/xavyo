//! Session storage for SAML `AuthnRequest` tracking
//!
//! Provides both in-memory (for testing) and PostgreSQL-backed
//! session stores for production use.

use super::types::{AuthnRequestSession, SessionError};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Session store trait for `AuthnRequest` tracking
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a new `AuthnRequest` session
    async fn store(&self, session: AuthnRequestSession) -> Result<(), SessionError>;

    /// Look up a session by tenant and request ID
    async fn get(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<Option<AuthnRequestSession>, SessionError>;

    /// Look up a session by its unique ID (UUID)
    async fn get_by_id(&self, id: Uuid) -> Result<Option<AuthnRequestSession>, SessionError>;

    /// Validate and consume a session atomically
    ///
    /// This method looks up the session, validates it, marks it as consumed,
    /// and returns the session. If the session is invalid, an error is returned.
    async fn validate_and_consume(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<AuthnRequestSession, SessionError>;

    /// Validate and consume a session by its unique ID (UUID) atomically.
    /// Requires `tenant_id` for tenant isolation — prevents cross-tenant session consumption.
    async fn consume_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<AuthnRequestSession, SessionError>;

    /// Clean up expired sessions
    ///
    /// Returns the number of sessions deleted
    async fn cleanup_expired(&self) -> Result<u64, SessionError>;
}

/// In-memory session store for testing
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    sessions: Arc<RwLock<HashMap<(Uuid, String), AuthnRequestSession>>>,
}

impl InMemorySessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn store(&self, session: AuthnRequestSession) -> Result<(), SessionError> {
        let key = (session.tenant_id, session.request_id.clone());
        let mut sessions = self.sessions.write().await;

        if sessions.contains_key(&key) {
            return Err(SessionError::DuplicateRequestId(session.request_id));
        }

        sessions.insert(key, session);
        Ok(())
    }

    async fn get(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<Option<AuthnRequestSession>, SessionError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(&(tenant_id, request_id.to_string())).cloned())
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<AuthnRequestSession>, SessionError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().find(|s| s.id == id).cloned())
    }

    async fn validate_and_consume(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<AuthnRequestSession, SessionError> {
        let mut sessions = self.sessions.write().await;
        let key = (tenant_id, request_id.to_string());

        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| SessionError::NotFound(request_id.to_string()))?;

        // Validate the session
        session.validate()?;

        // Mark as consumed
        session.consume();

        // Clone to return
        let consumed_session = session.clone();

        tracing::info!(
            tenant_id = %tenant_id,
            request_id = %request_id,
            "SAML AuthnRequest session consumed"
        );

        Ok(consumed_session)
    }

    async fn consume_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<AuthnRequestSession, SessionError> {
        let mut sessions = self.sessions.write().await;
        let key = sessions
            .iter()
            .find(|(_, s)| s.id == id && s.tenant_id == tenant_id)
            .map(|(k, _)| k.clone());
        let key = key.ok_or_else(|| SessionError::NotFound(format!("session id {id}")))?;
        let session = sessions.get_mut(&key).unwrap();
        session.validate()?;
        session.consume();
        let consumed = session.clone();
        tracing::info!(session_id = %id, "SAML AuthnRequest session consumed by ID");
        Ok(consumed)
    }

    async fn cleanup_expired(&self) -> Result<u64, SessionError> {
        let mut sessions = self.sessions.write().await;
        let before_count = sessions.len();

        sessions.retain(|_, session| !session.is_expired());

        let deleted = (before_count - sessions.len()) as u64;

        if deleted > 0 {
            tracing::debug!(deleted = deleted, "Cleaned up expired SAML sessions");
        }

        Ok(deleted)
    }
}

/// PostgreSQL-backed session store for production
pub struct PostgresSessionStore {
    pool: PgPool,
}

impl PostgresSessionStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn get_by_id(&self, id: Uuid) -> Result<Option<AuthnRequestSession>, SessionError> {
        let row = sqlx::query(
            r"
            SELECT id, tenant_id, request_id, sp_entity_id, created_at, expires_at, consumed_at, relay_state
            FROM saml_authn_request_sessions
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        Ok(row.map(|r| AuthnRequestSession {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            request_id: r.get("request_id"),
            sp_entity_id: r.get("sp_entity_id"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            consumed_at: r.get("consumed_at"),
            relay_state: r.get("relay_state"),
        }))
    }

    async fn consume_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<AuthnRequestSession, SessionError> {
        let now = Utc::now();

        // SECURITY: Filter by both id AND tenant_id to prevent cross-tenant session consumption
        let row = sqlx::query(
            r"
            UPDATE saml_authn_request_sessions
            SET consumed_at = $3
            WHERE id = $1
              AND tenant_id = $2
              AND consumed_at IS NULL
              AND expires_at > ($3 - INTERVAL '30 seconds')
            RETURNING id, tenant_id, request_id, sp_entity_id, created_at, expires_at, consumed_at, relay_state
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        if let Some(r) = row {
            let session = AuthnRequestSession {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                request_id: r.get("request_id"),
                sp_entity_id: r.get("sp_entity_id"),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                consumed_at: r.get("consumed_at"),
                relay_state: r.get("relay_state"),
            };
            tracing::info!(session_id = %id, "SAML AuthnRequest session consumed by ID");
            Ok(session)
        } else {
            // Determine why the update didn't match — look up without tenant filter
            // to provide the right error (not found vs consumed vs expired)
            let existing = self.get_by_id(id).await?;
            match existing {
                None => Err(SessionError::NotFound(format!("session id {id}"))),
                Some(session) if session.tenant_id != tenant_id => {
                    // Session exists but belongs to different tenant — report as not found
                    Err(SessionError::NotFound(format!("session id {id}")))
                }
                Some(session) => {
                    if session.is_consumed() {
                        Err(SessionError::AlreadyConsumed {
                            request_id: session.request_id,
                            consumed_at: session.consumed_at.unwrap(),
                        })
                    } else {
                        Err(SessionError::Expired {
                            request_id: session.request_id,
                            expired_at: session.expires_at,
                        })
                    }
                }
            }
        }
    }

    async fn store(&self, session: AuthnRequestSession) -> Result<(), SessionError> {
        // SECURITY: Detect duplicate request IDs (replay attack prevention).
        // Use RETURNING to distinguish insert-success from conflict-silenced.
        let request_id_for_err = session.request_id.clone();
        let row = sqlx::query(
            r"
            INSERT INTO saml_authn_request_sessions
                (id, tenant_id, request_id, sp_entity_id, created_at, expires_at, consumed_at, relay_state)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (tenant_id, request_id) DO NOTHING
            RETURNING id
            ",
        )
        .bind(session.id)
        .bind(session.tenant_id)
        .bind(&session.request_id)
        .bind(&session.sp_entity_id)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.consumed_at)
        .bind(&session.relay_state)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        if row.is_none() {
            // ON CONFLICT fired — duplicate request_id for this tenant
            return Err(SessionError::DuplicateRequestId(request_id_for_err));
        }

        tracing::debug!(
            tenant_id = %session.tenant_id,
            request_id = %session.request_id,
            sp_entity_id = %session.sp_entity_id,
            expires_at = %session.expires_at,
            "Stored SAML AuthnRequest session"
        );

        Ok(())
    }

    async fn get(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<Option<AuthnRequestSession>, SessionError> {
        let row = sqlx::query(
            r"
            SELECT id, tenant_id, request_id, sp_entity_id, created_at, expires_at, consumed_at, relay_state
            FROM saml_authn_request_sessions
            WHERE tenant_id = $1 AND request_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        Ok(row.map(|r| AuthnRequestSession {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            request_id: r.get("request_id"),
            sp_entity_id: r.get("sp_entity_id"),
            created_at: r.get("created_at"),
            expires_at: r.get("expires_at"),
            consumed_at: r.get("consumed_at"),
            relay_state: r.get("relay_state"),
        }))
    }

    async fn validate_and_consume(
        &self,
        tenant_id: Uuid,
        request_id: &str,
    ) -> Result<AuthnRequestSession, SessionError> {
        // Use a transaction for atomic read-validate-update
        let now = Utc::now();

        // Attempt to atomically update consumed_at where it's NULL and not expired
        // This prevents race conditions in concurrent requests
        let row = sqlx::query(
            r"
            UPDATE saml_authn_request_sessions
            SET consumed_at = $3
            WHERE tenant_id = $1
              AND request_id = $2
              AND consumed_at IS NULL
              AND expires_at > ($3 - INTERVAL '30 seconds')
            RETURNING id, tenant_id, request_id, sp_entity_id, created_at, expires_at, consumed_at, relay_state
            ",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        if let Some(r) = row {
            let session = AuthnRequestSession {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                request_id: r.get("request_id"),
                sp_entity_id: r.get("sp_entity_id"),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                consumed_at: r.get("consumed_at"),
                relay_state: r.get("relay_state"),
            };

            tracing::info!(
                tenant_id = %tenant_id,
                request_id = %request_id,
                "SAML AuthnRequest session consumed"
            );

            Ok(session)
        } else {
            // The update didn't match - need to determine why
            // Look up the session to provide the right error
            let existing = self.get(tenant_id, request_id).await?;

            match existing {
                None => Err(SessionError::NotFound(request_id.to_string())),
                Some(session) => {
                    if session.is_consumed() {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            request_id = %request_id,
                            consumed_at = ?session.consumed_at,
                            "Replay attack detected: AuthnRequest already consumed"
                        );
                        Err(SessionError::AlreadyConsumed {
                            request_id: request_id.to_string(),
                            consumed_at: session.consumed_at.unwrap(),
                        })
                    } else {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            request_id = %request_id,
                            expires_at = %session.expires_at,
                            "Expired AuthnRequest replay attempt"
                        );
                        Err(SessionError::Expired {
                            request_id: request_id.to_string(),
                            expired_at: session.expires_at,
                        })
                    }
                }
            }
        }
    }

    async fn cleanup_expired(&self) -> Result<u64, SessionError> {
        let result = sqlx::query(
            r"
            DELETE FROM saml_authn_request_sessions
            WHERE expires_at < NOW() - INTERVAL '30 seconds'
            ",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SessionError::StorageError(e.to_string()))?;

        let deleted = result.rows_affected();

        if deleted > 0 {
            tracing::info!(
                deleted = deleted,
                "Cleaned up expired SAML AuthnRequest sessions"
            );
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_in_memory_store_and_get() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            Some("relay-state".to_string()),
        );

        // Store
        store.store(session.clone()).await.unwrap();

        // Get
        let retrieved = store.get(tenant_id, "req-123").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.request_id, "req-123");
        assert_eq!(retrieved.relay_state, Some("relay-state".to_string()));
    }

    #[tokio::test]
    async fn test_in_memory_duplicate_request() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        // First store should succeed
        store.store(session.clone()).await.unwrap();

        // Second store should fail
        let result = store.store(session).await;
        assert!(matches!(result, Err(SessionError::DuplicateRequestId(_))));
    }

    #[tokio::test]
    async fn test_in_memory_validate_and_consume() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(session).await.unwrap();

        // First consume should succeed
        let consumed = store
            .validate_and_consume(tenant_id, "req-123")
            .await
            .unwrap();
        assert!(consumed.consumed_at.is_some());

        // Second consume should fail (replay attack)
        let result = store.validate_and_consume(tenant_id, "req-123").await;
        assert!(matches!(result, Err(SessionError::AlreadyConsumed { .. })));
    }

    #[tokio::test]
    async fn test_in_memory_not_found() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        let result = store.validate_and_consume(tenant_id, "nonexistent").await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_in_memory_tenant_isolation() {
        let store = InMemorySessionStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        // Store session for tenant A
        let session_a = AuthnRequestSession::new(
            tenant_a,
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        store.store(session_a).await.unwrap();

        // Tenant B should not see tenant A's session
        let result = store.get(tenant_b, "req-123").await.unwrap();
        assert!(result.is_none());

        // Tenant B's consume should fail
        let result = store.validate_and_consume(tenant_b, "req-123").await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_consume_by_id_success() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-by-id".to_string(),
            "https://sp.example.com".to_string(),
            Some("relay".to_string()),
        );
        let session_id = session.id;

        store.store(session).await.unwrap();

        let consumed = store.consume_by_id(tenant_id, session_id).await.unwrap();
        assert!(consumed.consumed_at.is_some());
        assert_eq!(consumed.request_id, "req-by-id");
        assert_eq!(consumed.relay_state, Some("relay".to_string()));

        // Second consume should fail (replay)
        let result = store.consume_by_id(tenant_id, session_id).await;
        assert!(matches!(result, Err(SessionError::AlreadyConsumed { .. })));
    }

    #[tokio::test]
    async fn test_consume_by_id_tenant_isolation() {
        let store = InMemorySessionStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        let session = AuthnRequestSession::new(
            tenant_a,
            "req-cross".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        let session_id = session.id;

        store.store(session).await.unwrap();

        // Tenant B should not be able to consume tenant A's session
        let result = store.consume_by_id(tenant_b, session_id).await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));

        // Tenant A should still be able to consume it
        let consumed = store.consume_by_id(tenant_a, session_id).await.unwrap();
        assert!(consumed.consumed_at.is_some());
    }

    #[tokio::test]
    async fn test_consume_by_id_not_found() {
        let store = InMemorySessionStore::new();
        let result = store.consume_by_id(Uuid::new_v4(), Uuid::new_v4()).await;
        assert!(matches!(result, Err(SessionError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();
        let session = AuthnRequestSession::new(
            tenant_id,
            "req-get-id".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        let session_id = session.id;

        store.store(session).await.unwrap();

        // Should find by ID
        let found = store.get_by_id(session_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().request_id, "req-get-id");

        // Non-existent ID should return None
        let not_found = store.get_by_id(Uuid::new_v4()).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_cleanup_expired() {
        let store = InMemorySessionStore::new();
        let tenant_id = Uuid::new_v4();

        // Create an expired session
        let mut expired_session = AuthnRequestSession::new(
            tenant_id,
            "expired-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        expired_session.expires_at = Utc::now() - Duration::minutes(10);

        // Create a valid session
        let valid_session = AuthnRequestSession::new(
            tenant_id,
            "valid-req".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );

        store.store(expired_session).await.unwrap();
        store.store(valid_session).await.unwrap();

        // Cleanup
        let deleted = store.cleanup_expired().await.unwrap();
        assert_eq!(deleted, 1);

        // Expired session should be gone
        assert!(store.get(tenant_id, "expired-req").await.unwrap().is_none());

        // Valid session should still exist
        assert!(store.get(tenant_id, "valid-req").await.unwrap().is_some());
    }
}
