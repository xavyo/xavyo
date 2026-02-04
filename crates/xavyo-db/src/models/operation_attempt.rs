//! Operation Attempt model.
//!
//! Records each execution attempt for a provisioning operation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An operation attempt record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OperationAttempt {
    /// Unique identifier for the attempt.
    pub id: Uuid,

    /// The tenant this attempt belongs to.
    pub tenant_id: Uuid,

    /// The operation this attempt is for.
    pub operation_id: Uuid,

    /// Attempt sequence number (1, 2, 3...).
    pub attempt_number: i32,

    /// When the attempt started.
    pub started_at: DateTime<Utc>,

    /// When the attempt completed (null if still in progress).
    pub completed_at: Option<DateTime<Utc>>,

    /// Whether the attempt succeeded.
    pub success: bool,

    /// Error code (if failed).
    pub error_code: Option<String>,

    /// Error message (if failed).
    pub error_message: Option<String>,

    /// Response data from connector (sanitized).
    pub response_data: Option<serde_json::Value>,

    /// Duration of the attempt in milliseconds.
    pub duration_ms: Option<i32>,
}

/// Request to create an operation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOperationAttempt {
    pub operation_id: Uuid,
    pub attempt_number: i32,
}

/// Request to complete an operation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteOperationAttempt {
    pub success: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub response_data: Option<serde_json::Value>,
}

impl OperationAttempt {
    /// Find an attempt by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM operation_attempts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List attempts for an operation.
    pub async fn list_by_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            ORDER BY attempt_number ASC
            ",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get the latest attempt for an operation.
    pub async fn get_latest(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            ORDER BY attempt_number DESC
            LIMIT 1
            ",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Count attempts for an operation.
    pub async fn count_by_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM operation_attempts
            WHERE operation_id = $1 AND tenant_id = $2
            ",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Start a new attempt (creates record with `started_at` = now).
    pub async fn start(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
        attempt_number: i32,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO operation_attempts (
                tenant_id, operation_id, attempt_number, started_at, success
            )
            VALUES ($1, $2, $3, NOW(), false)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(operation_id)
        .bind(attempt_number)
        .fetch_one(pool)
        .await
    }

    /// Complete an attempt (success or failure).
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &CompleteOperationAttempt,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE operation_attempts
            SET completed_at = NOW(),
                success = $3,
                error_code = $4,
                error_message = $5,
                response_data = $6,
                duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at))::int * 1000
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.success)
        .bind(&input.error_code)
        .bind(&input.error_message)
        .bind(&input.response_data)
        .fetch_optional(pool)
        .await
    }

    /// Record a complete attempt in one call (for simpler cases).
    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
        attempt_number: i32,
        started_at: DateTime<Utc>,
        success: bool,
        error_code: Option<&str>,
        error_message: Option<&str>,
        response_data: Option<&serde_json::Value>,
        duration_ms: Option<i32>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO operation_attempts (
                tenant_id, operation_id, attempt_number, started_at, completed_at,
                success, error_code, error_message, response_data, duration_ms
            )
            VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(operation_id)
        .bind(attempt_number)
        .bind(started_at)
        .bind(success)
        .bind(error_code)
        .bind(error_message)
        .bind(response_data)
        .bind(duration_ms)
        .fetch_one(pool)
        .await
    }

    /// Delete attempts older than a given number of days (retention policy).
    pub async fn delete_older_than(pool: &sqlx::PgPool, days: i32) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM operation_attempts
            WHERE started_at < NOW() - ($1 || ' days')::interval
            ",
        )
        .bind(days.to_string())
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_attempt() {
        let input = CreateOperationAttempt {
            operation_id: Uuid::new_v4(),
            attempt_number: 1,
        };

        assert_eq!(input.attempt_number, 1);
    }

    #[test]
    fn test_complete_attempt_success() {
        let input = CompleteOperationAttempt {
            success: true,
            error_code: None,
            error_message: None,
            response_data: Some(serde_json::json!({"uid": "cn=john,dc=example,dc=com"})),
        };

        assert!(input.success);
        assert!(input.error_code.is_none());
    }

    #[test]
    fn test_complete_attempt_failure() {
        let input = CompleteOperationAttempt {
            success: false,
            error_code: Some("CONNECTION_TIMEOUT".to_string()),
            error_message: Some("Connection timed out after 30s".to_string()),
            response_data: None,
        };

        assert!(!input.success);
        assert_eq!(input.error_code.as_deref(), Some("CONNECTION_TIMEOUT"));
    }
}
