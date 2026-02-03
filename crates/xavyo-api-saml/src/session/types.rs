//! Session types for SAML AuthnRequest tracking
//!
//! These types are used to store and validate AuthnRequest sessions
//! to prevent replay attacks.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Default TTL for AuthnRequest sessions (5 minutes)
pub const DEFAULT_SESSION_TTL_SECONDS: i64 = 300;

/// Grace period for clock skew (30 seconds)
pub const CLOCK_SKEW_GRACE_SECONDS: i64 = 30;

/// A stored AuthnRequest session for replay attack prevention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnRequestSession {
    /// Unique identifier for this session record
    pub id: Uuid,
    /// Tenant ID for multi-tenant isolation
    pub tenant_id: Uuid,
    /// The SAML AuthnRequest ID from the SP
    pub request_id: String,
    /// The Service Provider's entity ID
    pub sp_entity_id: String,
    /// When this request was received
    pub created_at: DateTime<Utc>,
    /// When this request expires (created_at + TTL)
    pub expires_at: DateTime<Utc>,
    /// When this request was consumed (None = unused)
    pub consumed_at: Option<DateTime<Utc>>,
    /// RelayState to preserve across the SSO flow
    pub relay_state: Option<String>,
}

impl AuthnRequestSession {
    /// Create a new session with default TTL
    pub fn new(
        tenant_id: Uuid,
        request_id: String,
        sp_entity_id: String,
        relay_state: Option<String>,
    ) -> Self {
        Self::with_ttl(
            tenant_id,
            request_id,
            sp_entity_id,
            relay_state,
            DEFAULT_SESSION_TTL_SECONDS,
        )
    }

    /// Create a new session with custom TTL
    pub fn with_ttl(
        tenant_id: Uuid,
        request_id: String,
        sp_entity_id: String,
        relay_state: Option<String>,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            request_id,
            sp_entity_id,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            consumed_at: None,
            relay_state,
        }
    }

    /// Check if this session has expired (with grace period for clock skew)
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let grace_period = Duration::seconds(CLOCK_SKEW_GRACE_SECONDS);
        now > self.expires_at + grace_period
    }

    /// Check if this session has been consumed
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    /// Mark this session as consumed
    pub fn consume(&mut self) {
        self.consumed_at = Some(Utc::now());
    }

    /// Validate that this session is valid for use
    pub fn validate(&self) -> Result<(), SessionError> {
        if self.is_expired() {
            return Err(SessionError::Expired {
                request_id: self.request_id.clone(),
                expired_at: self.expires_at,
            });
        }
        if self.is_consumed() {
            return Err(SessionError::AlreadyConsumed {
                request_id: self.request_id.clone(),
                consumed_at: self.consumed_at.unwrap(),
            });
        }
        Ok(())
    }
}

/// Session-related errors
#[derive(Debug, Error, Clone)]
pub enum SessionError {
    /// Request ID not found in session store
    #[error("AuthnRequest not found: {0}")]
    NotFound(String),

    /// Request has expired (past TTL + grace period)
    #[error("AuthnRequest expired: {request_id} (expired at {expired_at})")]
    Expired {
        request_id: String,
        expired_at: DateTime<Utc>,
    },

    /// Request was already consumed (replay attack detected)
    #[error("Replay attack detected: AuthnRequest {request_id} was already used at {consumed_at}")]
    AlreadyConsumed {
        request_id: String,
        consumed_at: DateTime<Utc>,
    },

    /// Request ID conflict (duplicate request received)
    #[error("Duplicate AuthnRequest ID: {0}")]
    DuplicateRequestId(String),

    /// Storage error
    #[error("Session storage error: {0}")]
    StorageError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session_not_expired() {
        let session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        assert!(!session.is_expired());
        assert!(!session.is_consumed());
        assert!(session.validate().is_ok());
    }

    #[test]
    fn test_expired_session() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        // Set expires_at to past
        session.expires_at = Utc::now() - Duration::minutes(1);
        assert!(session.is_expired());
        assert!(matches!(
            session.validate(),
            Err(SessionError::Expired { .. })
        ));
    }

    #[test]
    fn test_consumed_session() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        session.consume();
        assert!(session.is_consumed());
        assert!(matches!(
            session.validate(),
            Err(SessionError::AlreadyConsumed { .. })
        ));
    }

    #[test]
    fn test_grace_period() {
        let mut session = AuthnRequestSession::new(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            None,
        );
        // Set expires_at to just past, but within grace period
        session.expires_at = Utc::now() - Duration::seconds(15);
        // Should not be expired yet (grace period is 30 seconds)
        assert!(!session.is_expired());
    }

    #[test]
    fn test_custom_ttl() {
        let session = AuthnRequestSession::with_ttl(
            Uuid::new_v4(),
            "req-123".to_string(),
            "https://sp.example.com".to_string(),
            Some("state123".to_string()),
            60, // 1 minute TTL
        );
        let expected_expiry = session.created_at + Duration::seconds(60);
        assert_eq!(session.expires_at, expected_expiry);
        assert_eq!(session.relay_state, Some("state123".to_string()));
    }
}
