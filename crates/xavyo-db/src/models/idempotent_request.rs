//! IdempotentRequest model for HTTP-level idempotency.
//!
//! Stores request/response pairs keyed by client-provided idempotency keys
//! to enable safe request retries.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Default TTL for idempotent requests (24 hours).
pub const IDEMPOTENCY_TTL_HOURS: i64 = 24;

/// Lock timeout for processing requests (60 seconds).
pub const PROCESSING_TIMEOUT_SECONDS: i64 = 60;

/// State of an idempotent request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotentState {
    /// Request is currently being processed.
    Processing,
    /// Request completed successfully and response is cached.
    Completed,
    /// Request failed with an error response cached.
    Failed,
}

impl IdempotentState {
    /// Convert from database string representation.
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "processing" => Some(Self::Processing),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Convert to database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Record of an idempotent HTTP request.
#[derive(Debug, Clone, FromRow)]
pub struct IdempotentRequest {
    /// Primary key.
    pub id: Uuid,
    /// Tenant that owns this request.
    pub tenant_id: Uuid,
    /// Client-provided idempotency key.
    pub idempotency_key: String,
    /// SHA-256 hash of the request body.
    pub request_hash: String,
    /// API endpoint path.
    pub endpoint: String,
    /// HTTP method (POST, PUT, etc.).
    pub http_method: String,
    /// Response HTTP status code (when completed).
    pub response_status: Option<i16>,
    /// Response body bytes (when completed).
    pub response_body: Option<Vec<u8>>,
    /// Response headers as JSON (when completed).
    pub response_headers: Option<serde_json::Value>,
    /// Current state: processing, completed, failed.
    pub state: String,
    /// When the request was first received.
    pub created_at: DateTime<Utc>,
    /// When the response was stored.
    pub completed_at: Option<DateTime<Utc>>,
    /// When this record expires and can be cleaned up.
    pub expires_at: DateTime<Utc>,
}

impl IdempotentRequest {
    /// Get the typed state.
    pub fn state(&self) -> IdempotentState {
        IdempotentState::from_db(&self.state).unwrap_or(IdempotentState::Processing)
    }

    /// Check if this request has timed out while processing.
    pub fn is_processing_timed_out(&self) -> bool {
        if self.state() != IdempotentState::Processing {
            return false;
        }
        let timeout = Duration::seconds(PROCESSING_TIMEOUT_SECONDS);
        Utc::now() > self.created_at + timeout
    }
}

/// Data needed to create a new idempotent request record.
#[derive(Debug, Clone)]
pub struct CreateIdempotentRequest {
    pub tenant_id: Uuid,
    pub idempotency_key: String,
    pub request_hash: String,
    pub endpoint: String,
    pub http_method: String,
}

/// Result of trying to insert a new idempotent request.
#[derive(Debug)]
pub enum InsertResult {
    /// Successfully inserted a new record (should process the request).
    Inserted(IdempotentRequest),
    /// Key already exists, returning the existing record.
    Conflict(IdempotentRequest),
}

impl IdempotentRequest {
    /// Try to insert a new idempotent request.
    ///
    /// Uses INSERT with ON CONFLICT to atomically check-and-insert.
    /// Returns `InsertResult::Inserted` if new, `InsertResult::Conflict` if exists.
    pub async fn try_insert(
        pool: &PgPool,
        data: CreateIdempotentRequest,
    ) -> Result<InsertResult, sqlx::Error> {
        let expires_at = Utc::now() + Duration::hours(IDEMPOTENCY_TTL_HOURS);

        // Try to insert, returning nothing on conflict
        let inserted: Option<IdempotentRequest> = sqlx::query_as(
            r#"
            INSERT INTO idempotent_requests (
                tenant_id, idempotency_key, request_hash, endpoint, http_method, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(data.tenant_id)
        .bind(&data.idempotency_key)
        .bind(&data.request_hash)
        .bind(&data.endpoint)
        .bind(&data.http_method)
        .bind(expires_at)
        .fetch_optional(pool)
        .await?;

        match inserted {
            Some(record) => Ok(InsertResult::Inserted(record)),
            None => {
                // Conflict - fetch the existing record
                let existing = Self::find_by_key(pool, data.tenant_id, &data.idempotency_key)
                    .await?
                    .expect("Record must exist after conflict");
                Ok(InsertResult::Conflict(existing))
            }
        }
    }

    /// Find an idempotent request by tenant and key.
    pub async fn find_by_key(
        pool: &PgPool,
        tenant_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM idempotent_requests
            WHERE tenant_id = $1 AND idempotency_key = $2
            "#,
        )
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(pool)
        .await
    }

    /// Update request with successful response (marks as completed).
    pub async fn complete(
        pool: &PgPool,
        id: Uuid,
        status: i16,
        body: &[u8],
        headers: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE idempotent_requests
            SET state = 'completed',
                response_status = $2,
                response_body = $3,
                response_headers = $4,
                completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(body)
        .bind(headers)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark request as failed.
    pub async fn fail(
        pool: &PgPool,
        id: Uuid,
        status: i16,
        body: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE idempotent_requests
            SET state = 'failed',
                response_status = $2,
                response_body = $3,
                completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(body)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Delete a stale processing request (for timeout recovery).
    pub async fn delete_stale(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let timeout_threshold = Utc::now() - Duration::seconds(PROCESSING_TIMEOUT_SECONDS);

        let result = sqlx::query(
            r#"
            DELETE FROM idempotent_requests
            WHERE id = $1 AND state = 'processing' AND created_at < $2
            "#,
        )
        .bind(id)
        .bind(timeout_threshold)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete expired idempotent requests.
    ///
    /// Returns the number of deleted records.
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM idempotent_requests
            WHERE expires_at < NOW() AND state IN ('completed', 'failed')
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotent_state_roundtrip() {
        assert_eq!(
            IdempotentState::from_db("processing"),
            Some(IdempotentState::Processing)
        );
        assert_eq!(
            IdempotentState::from_db("completed"),
            Some(IdempotentState::Completed)
        );
        assert_eq!(
            IdempotentState::from_db("failed"),
            Some(IdempotentState::Failed)
        );
        assert_eq!(IdempotentState::from_db("invalid"), None);

        assert_eq!(IdempotentState::Processing.as_str(), "processing");
        assert_eq!(IdempotentState::Completed.as_str(), "completed");
        assert_eq!(IdempotentState::Failed.as_str(), "failed");
    }

    #[test]
    fn test_create_idempotent_request() {
        let data = CreateIdempotentRequest {
            tenant_id: Uuid::new_v4(),
            idempotency_key: "test-key-123".to_string(),
            request_hash: "abc123def456".to_string(),
            endpoint: "/tenants/provision".to_string(),
            http_method: "POST".to_string(),
        };

        assert!(!data.idempotency_key.is_empty());
        assert!(!data.request_hash.is_empty());
    }

    #[test]
    fn test_ttl_constant() {
        assert_eq!(IDEMPOTENCY_TTL_HOURS, 24);
    }

    #[test]
    fn test_timeout_constant() {
        assert_eq!(PROCESSING_TIMEOUT_SECONDS, 60);
    }
}
