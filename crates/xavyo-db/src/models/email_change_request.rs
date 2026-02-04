//! Email change request entity model.
//!
//! Represents a pending email change request stored in the database
//! for secure email verification flow.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use xavyo_core::{TenantId, UserId};

/// An email change request record in the database.
///
/// Email change requests store the new email and a SHA-256 hashed
/// verification token. The actual token is only sent to the new email.
/// Requests expire after 24 hours if not verified.
#[derive(Debug, Clone, FromRow)]
pub struct EmailChangeRequest {
    /// Unique identifier for this request record.
    pub id: uuid::Uuid,

    /// The tenant this request belongs to (for RLS).
    pub tenant_id: uuid::Uuid,

    /// The user who requested the email change.
    pub user_id: uuid::Uuid,

    /// The new email address being requested.
    pub new_email: String,

    /// SHA-256 hash of the verification token.
    pub token_hash: String,

    /// When the request expires (24 hours from creation).
    pub expires_at: DateTime<Utc>,

    /// When the request was verified (None if pending).
    pub verified_at: Option<DateTime<Utc>>,

    /// When the request was cancelled (None if active).
    pub cancelled_at: Option<DateTime<Utc>>,

    /// When the request was created.
    pub created_at: DateTime<Utc>,
}

impl EmailChangeRequest {
    /// Check if the request is still pending (not verified, not cancelled, not expired).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.verified_at.is_none() && self.cancelled_at.is_none() && self.expires_at > Utc::now()
    }

    /// Check if the request has been verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Check if the request has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled_at.is_some()
    }

    /// Check if the request has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now() && self.verified_at.is_none() && self.cancelled_at.is_none()
    }

    /// Get the user ID as a typed `UserId`.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::from_uuid(self.user_id)
    }

    /// Get the tenant ID as a typed `TenantId`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// Find a pending email change request by token hash.
    pub async fn find_by_token_hash(
        pool: &sqlx::PgPool,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM email_change_requests
            WHERE token_hash = $1
            AND verified_at IS NULL
            AND cancelled_at IS NULL
            ",
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
    }

    /// Find all pending requests for a user.
    pub async fn find_pending_by_user(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM email_change_requests
            WHERE tenant_id = $1
            AND user_id = $2
            AND verified_at IS NULL
            AND cancelled_at IS NULL
            AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Check if new email is already requested (pending) within the tenant.
    pub async fn is_email_pending(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        new_email: &str,
    ) -> Result<bool, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM email_change_requests
            WHERE tenant_id = $1
            AND new_email = $2
            AND verified_at IS NULL
            AND cancelled_at IS NULL
            AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(new_email)
        .fetch_one(pool)
        .await?;

        Ok(result.0 > 0)
    }

    /// Create a new email change request.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        new_email: &str,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO email_change_requests (tenant_id, user_id, new_email, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(new_email)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_one(pool)
        .await
    }

    /// Mark the request as verified.
    pub async fn mark_verified(pool: &sqlx::PgPool, id: uuid::Uuid) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE email_change_requests
            SET verified_at = NOW()
            WHERE id = $1
            RETURNING *
            ",
        )
        .bind(id)
        .fetch_one(pool)
        .await
    }

    /// Cancel all pending requests for a user.
    pub async fn cancel_pending_for_user(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE email_change_requests
            SET cancelled_at = NOW()
            WHERE tenant_id = $1
            AND user_id = $2
            AND verified_at IS NULL
            AND cancelled_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_request(
        expires_at: DateTime<Utc>,
        verified_at: Option<DateTime<Utc>>,
        cancelled_at: Option<DateTime<Utc>>,
    ) -> EmailChangeRequest {
        EmailChangeRequest {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            new_email: "new@example.com".to_string(),
            token_hash: "testhash".to_string(),
            expires_at,
            verified_at,
            cancelled_at,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_pending_request() {
        let request = create_test_request(Utc::now() + Duration::hours(24), None, None);
        assert!(request.is_pending());
        assert!(!request.is_verified());
        assert!(!request.is_cancelled());
        assert!(!request.is_expired());
    }

    #[test]
    fn test_verified_request() {
        let request = create_test_request(Utc::now() + Duration::hours(24), Some(Utc::now()), None);
        assert!(!request.is_pending());
        assert!(request.is_verified());
        assert!(!request.is_cancelled());
        assert!(!request.is_expired());
    }

    #[test]
    fn test_cancelled_request() {
        let request = create_test_request(Utc::now() + Duration::hours(24), None, Some(Utc::now()));
        assert!(!request.is_pending());
        assert!(!request.is_verified());
        assert!(request.is_cancelled());
        assert!(!request.is_expired());
    }

    #[test]
    fn test_expired_request() {
        let request = create_test_request(Utc::now() - Duration::hours(1), None, None);
        assert!(!request.is_pending());
        assert!(!request.is_verified());
        assert!(!request.is_cancelled());
        assert!(request.is_expired());
    }

    #[test]
    fn test_typed_ids() {
        let tenant_uuid = uuid::Uuid::new_v4();
        let user_uuid = uuid::Uuid::new_v4();
        let request = EmailChangeRequest {
            id: uuid::Uuid::new_v4(),
            tenant_id: tenant_uuid,
            user_id: user_uuid,
            new_email: "new@example.com".to_string(),
            token_hash: "testhash".to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            verified_at: None,
            cancelled_at: None,
            created_at: Utc::now(),
        };

        assert_eq!(*request.user_id().as_uuid(), user_uuid);
        assert_eq!(*request.tenant_id().as_uuid(), tenant_uuid);
    }
}
