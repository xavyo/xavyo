//! Operation Log model.
//!
//! Audit trail for provisioning operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Log entry status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LogStatus {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Failure,
}

impl std::fmt::Display for LogStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogStatus::Success => write!(f, "success"),
            LogStatus::Failure => write!(f, "failure"),
        }
    }
}

impl std::str::FromStr for LogStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "success" => Ok(LogStatus::Success),
            "failure" => Ok(LogStatus::Failure),
            _ => Err(format!("Unknown log status: {s}")),
        }
    }
}

/// An operation log entry (audit trail).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OperationLog {
    /// Unique identifier for the log entry.
    pub id: Uuid,

    /// The tenant this log belongs to.
    pub tenant_id: Uuid,

    /// The operation this log entry is for.
    pub operation_id: Uuid,

    /// The connector that was used.
    pub connector_id: Uuid,

    /// The user being provisioned (optional for batch operations).
    pub user_id: Option<Uuid>,

    /// Type of operation performed.
    pub operation_type: String,

    /// Target system identifier.
    pub target_uid: Option<String>,

    /// Whether the operation succeeded or failed.
    pub status: LogStatus,

    /// Duration of the operation in milliseconds.
    pub duration_ms: Option<i32>,

    /// Request payload sent to target system.
    pub request_payload: Option<serde_json::Value>,

    /// Summary of the response (sanitized).
    pub response_summary: Option<serde_json::Value>,

    /// Error message (if failed).
    pub error_message: Option<String>,

    /// When the log entry was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create an operation log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOperationLog {
    pub operation_id: Uuid,
    pub connector_id: Uuid,
    pub user_id: Option<Uuid>,
    pub operation_type: String,
    pub target_uid: Option<String>,
    pub status: LogStatus,
    pub duration_ms: Option<i32>,
    pub request_payload: Option<serde_json::Value>,
    pub response_summary: Option<serde_json::Value>,
    pub error_message: Option<String>,
}

/// Filter for listing operation logs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationLogFilter {
    pub operation_id: Option<Uuid>,
    pub connector_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<LogStatus>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl OperationLog {
    /// Find a log entry by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM operation_logs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List logs for an operation.
    pub async fn list_by_operation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM operation_logs
            WHERE operation_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List logs with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OperationLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM operation_logs
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.operation_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operation_id = ${param_count}"));
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, OperationLog>(&query).bind(tenant_id);

        if let Some(operation_id) = filter.operation_id {
            q = q.bind(operation_id);
        }
        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new operation log entry.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateOperationLog,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO operation_logs (
                tenant_id, operation_id, connector_id, user_id, operation_type,
                target_uid, status, duration_ms, request_payload,
                response_summary, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.operation_id)
        .bind(input.connector_id)
        .bind(input.user_id)
        .bind(&input.operation_type)
        .bind(&input.target_uid)
        .bind(input.status.to_string())
        .bind(input.duration_ms)
        .bind(&input.request_payload)
        .bind(&input.response_summary)
        .bind(&input.error_message)
        .fetch_one(pool)
        .await
    }

    /// Count logs by status for a connector in the last 24 hours.
    pub async fn count_last_24h(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        status: LogStatus,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM operation_logs
            WHERE tenant_id = $1 AND connector_id = $2 AND status = $3
                AND created_at >= NOW() - INTERVAL '24 hours'
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(status.to_string())
        .fetch_one(pool)
        .await
    }

    /// Calculate average latency for a connector in the last 24 hours.
    pub async fn avg_latency_24h(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<f64>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT AVG(duration_ms)::float8 FROM operation_logs
            WHERE tenant_id = $1 AND connector_id = $2
                AND duration_ms IS NOT NULL
                AND created_at >= NOW() - INTERVAL '24 hours'
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(pool)
        .await
    }

    /// Delete old log entries (retention policy).
    pub async fn delete_older_than(pool: &sqlx::PgPool, days: i32) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM operation_logs
            WHERE created_at < NOW() - ($1 || ' days')::interval
            ",
        )
        .bind(days.to_string())
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if operation was successful.
    #[must_use] 
    pub fn is_success(&self) -> bool {
        matches!(self.status, LogStatus::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_status_display() {
        assert_eq!(LogStatus::Success.to_string(), "success");
        assert_eq!(LogStatus::Failure.to_string(), "failure");
    }

    #[test]
    fn test_log_status_from_str() {
        assert_eq!("success".parse::<LogStatus>().unwrap(), LogStatus::Success);
        assert_eq!("FAILURE".parse::<LogStatus>().unwrap(), LogStatus::Failure);
        assert!("unknown".parse::<LogStatus>().is_err());
    }

    #[test]
    fn test_create_log_request() {
        let request = CreateOperationLog {
            operation_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            operation_type: "create".to_string(),
            target_uid: Some("uid=jdoe,ou=users,dc=example,dc=com".to_string()),
            status: LogStatus::Success,
            duration_ms: Some(150),
            request_payload: Some(serde_json::json!({"email": "jdoe@example.com"})),
            response_summary: Some(
                serde_json::json!({"dn": "uid=jdoe,ou=users,dc=example,dc=com"}),
            ),
            error_message: None,
        };

        assert_eq!(request.operation_type, "create");
        assert_eq!(request.status, LogStatus::Success);
        assert_eq!(request.duration_ms, Some(150));
    }

    #[test]
    fn test_log_filter_default() {
        let filter = OperationLogFilter::default();
        assert!(filter.operation_id.is_none());
        assert!(filter.connector_id.is_none());
        assert!(filter.status.is_none());
    }
}
