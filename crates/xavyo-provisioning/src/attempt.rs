//! Attempt tracking service for provisioning operations.
//!
//! Records each execution attempt for an operation, enabling
//! retry history tracking and debugging.

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during attempt operations.
#[derive(Debug, Error)]
pub enum AttemptError {
    /// Database error during attempt recording.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Invalid attempt state.
    #[error("Invalid attempt state: {0}")]
    InvalidState(String),
}

/// Result type for attempt operations.
pub type AttemptResult<T> = Result<T, AttemptError>;

/// Details of an attempt completion.
#[derive(Debug, Clone)]
pub struct AttemptCompletion {
    /// Whether the attempt succeeded.
    pub success: bool,
    /// Error code (if failed).
    pub error_code: Option<String>,
    /// Error message (if failed).
    pub error_message: Option<String>,
    /// Response data from connector (sanitized).
    pub response_data: Option<serde_json::Value>,
}

impl AttemptCompletion {
    /// Create a successful completion.
    pub fn success() -> Self {
        Self {
            success: true,
            error_code: None,
            error_message: None,
            response_data: None,
        }
    }

    /// Create a successful completion with response data.
    pub fn success_with_data(response_data: serde_json::Value) -> Self {
        Self {
            success: true,
            error_code: None,
            error_message: None,
            response_data: Some(response_data),
        }
    }

    /// Create a failed completion.
    pub fn failure(error_code: impl Into<String>, error_message: impl Into<String>) -> Self {
        Self {
            success: false,
            error_code: Some(error_code.into()),
            error_message: Some(error_message.into()),
            response_data: None,
        }
    }

    /// Create a failed completion with response data.
    pub fn failure_with_data(
        error_code: impl Into<String>,
        error_message: impl Into<String>,
        response_data: serde_json::Value,
    ) -> Self {
        Self {
            success: false,
            error_code: Some(error_code.into()),
            error_message: Some(error_message.into()),
            response_data: Some(response_data),
        }
    }
}

/// Service for recording operation attempts.
///
/// Each provisioning operation can have multiple attempts (retries).
/// This service tracks each attempt with timing and outcome details.
#[derive(Debug, Clone)]
pub struct AttemptService;

impl AttemptService {
    /// Create a new attempt service.
    pub fn new() -> Self {
        Self
    }

    /// Start a new attempt for an operation.
    ///
    /// Returns the attempt ID and attempt number.
    pub async fn start_attempt(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<(Uuid, i32)> {
        // Get next attempt number
        let attempt_number = self
            .get_next_attempt_number(pool, tenant_id, operation_id)
            .await?;

        // Create the attempt record
        let attempt_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO operation_attempts (
                tenant_id, operation_id, attempt_number, started_at, success
            )
            VALUES ($1, $2, $3, NOW(), false)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(operation_id)
        .bind(attempt_number)
        .fetch_one(pool)
        .await?;

        Ok((attempt_id.0, attempt_number))
    }

    /// Complete an attempt with the given outcome.
    pub async fn complete_attempt(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        attempt_id: Uuid,
        completion: &AttemptCompletion,
    ) -> AttemptResult<()> {
        sqlx::query(
            r#"
            UPDATE operation_attempts
            SET completed_at = NOW(),
                success = $3,
                error_code = $4,
                error_message = $5,
                response_data = $6,
                duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at))::int * 1000
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(attempt_id)
        .bind(tenant_id)
        .bind(completion.success)
        .bind(&completion.error_code)
        .bind(&completion.error_message)
        .bind(&completion.response_data)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Record a complete attempt in one call.
    ///
    /// Use this for cases where the attempt timing is managed externally.
    pub async fn record_attempt(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
        started_at: DateTime<Utc>,
        completion: &AttemptCompletion,
        duration_ms: Option<i32>,
    ) -> AttemptResult<Uuid> {
        let attempt_number = self
            .get_next_attempt_number(pool, tenant_id, operation_id)
            .await?;

        let attempt_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO operation_attempts (
                tenant_id, operation_id, attempt_number, started_at, completed_at,
                success, error_code, error_message, response_data, duration_ms
            )
            VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(operation_id)
        .bind(attempt_number)
        .bind(started_at)
        .bind(completion.success)
        .bind(&completion.error_code)
        .bind(&completion.error_message)
        .bind(&completion.response_data)
        .bind(duration_ms)
        .fetch_one(pool)
        .await?;

        Ok(attempt_id.0)
    }

    /// Get the count of attempts for an operation.
    pub async fn count_attempts(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<i64> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    /// Get the latest attempt for an operation.
    pub async fn get_latest_attempt(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<Option<AttemptInfo>> {
        let result: Option<AttemptInfo> = sqlx::query_as(
            r#"
            SELECT id, attempt_number, started_at, completed_at, success,
                   error_code, error_message, duration_ms
            FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            ORDER BY attempt_number DESC
            LIMIT 1
            "#,
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        Ok(result)
    }

    /// List all attempts for an operation.
    pub async fn list_attempts(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<Vec<AttemptInfo>> {
        let attempts: Vec<AttemptInfo> = sqlx::query_as(
            r#"
            SELECT id, attempt_number, started_at, completed_at, success,
                   error_code, error_message, duration_ms
            FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            ORDER BY attempt_number ASC
            "#,
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        Ok(attempts)
    }

    /// Check if the last attempt was successful.
    pub async fn was_last_attempt_successful(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<bool> {
        match self
            .get_latest_attempt(pool, tenant_id, operation_id)
            .await?
        {
            Some(attempt) => Ok(attempt.success),
            None => Ok(false),
        }
    }

    /// Get the next attempt number for an operation.
    async fn get_next_attempt_number(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> AttemptResult<i32> {
        let count = self.count_attempts(pool, tenant_id, operation_id).await?;
        Ok((count + 1) as i32)
    }
}

impl Default for AttemptService {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary information about an attempt.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttemptInfo {
    /// Attempt ID.
    pub id: Uuid,
    /// Attempt sequence number.
    pub attempt_number: i32,
    /// When the attempt started.
    pub started_at: DateTime<Utc>,
    /// When the attempt completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Whether the attempt succeeded.
    pub success: bool,
    /// Error code (if failed).
    pub error_code: Option<String>,
    /// Error message (if failed).
    pub error_message: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_completion_success() {
        let completion = AttemptCompletion::success();
        assert!(completion.success);
        assert!(completion.error_code.is_none());
        assert!(completion.error_message.is_none());
    }

    #[test]
    fn test_attempt_completion_success_with_data() {
        let data = serde_json::json!({"uid": "cn=john,dc=example,dc=com"});
        let completion = AttemptCompletion::success_with_data(data.clone());
        assert!(completion.success);
        assert_eq!(completion.response_data, Some(data));
    }

    #[test]
    fn test_attempt_completion_failure() {
        let completion = AttemptCompletion::failure("CONNECTION_TIMEOUT", "Connection timed out");
        assert!(!completion.success);
        assert_eq!(completion.error_code.as_deref(), Some("CONNECTION_TIMEOUT"));
        assert_eq!(
            completion.error_message.as_deref(),
            Some("Connection timed out")
        );
    }

    #[test]
    fn test_attempt_completion_failure_with_data() {
        let data = serde_json::json!({"retryable": true});
        let completion =
            AttemptCompletion::failure_with_data("RATE_LIMITED", "Too many requests", data.clone());
        assert!(!completion.success);
        assert_eq!(completion.error_code.as_deref(), Some("RATE_LIMITED"));
        assert_eq!(completion.response_data, Some(data));
    }
}
