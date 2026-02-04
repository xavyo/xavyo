//! SCIM Audit Log entity model.
//!
//! Audit trail for all SCIM operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// SCIM operation types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScimOperation {
    Create,
    Read,
    Update,
    Delete,
    List,
}

impl std::fmt::Display for ScimOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScimOperation::Create => write!(f, "CREATE"),
            ScimOperation::Read => write!(f, "READ"),
            ScimOperation::Update => write!(f, "UPDATE"),
            ScimOperation::Delete => write!(f, "DELETE"),
            ScimOperation::List => write!(f, "LIST"),
        }
    }
}

/// SCIM resource types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimResourceType {
    User,
    Group,
}

impl std::fmt::Display for ScimResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScimResourceType::User => write!(f, "User"),
            ScimResourceType::Group => write!(f, "Group"),
        }
    }
}

/// A SCIM audit log entry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScimAuditLog {
    /// Unique identifier for the log entry.
    pub id: Uuid,

    /// The tenant this operation was performed in.
    pub tenant_id: Uuid,

    /// The token used for authentication (None if auth failed).
    pub token_id: Option<Uuid>,

    /// The operation performed.
    pub operation: String,

    /// The resource type.
    pub resource_type: String,

    /// The target resource ID (None for LIST operations).
    pub resource_id: Option<Uuid>,

    /// Client IP address (stored as string for `SQLx` compatibility).
    pub source_ip: String,

    /// Client user agent.
    pub user_agent: Option<String>,

    /// Request payload (truncated if large).
    pub request_body: Option<serde_json::Value>,

    /// HTTP status code.
    pub response_code: i32,

    /// Error message if operation failed.
    pub error_message: Option<String>,

    /// When the operation was performed.
    pub created_at: DateTime<Utc>,
}

/// Request to create an audit log entry.
#[derive(Debug, Clone)]
pub struct CreateAuditLog {
    pub tenant_id: Uuid,
    pub token_id: Option<Uuid>,
    pub operation: ScimOperation,
    pub resource_type: ScimResourceType,
    pub resource_id: Option<Uuid>,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub request_body: Option<serde_json::Value>,
    pub response_code: i32,
    pub error_message: Option<String>,
}

impl ScimAuditLog {
    /// Create a new audit log entry.
    pub async fn create(pool: &sqlx::PgPool, log: CreateAuditLog) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO scim_audit_logs (
                tenant_id, token_id, operation, resource_type, resource_id,
                source_ip, user_agent, request_body, response_code, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(log.tenant_id)
        .bind(log.token_id)
        .bind(log.operation.to_string())
        .bind(log.resource_type.to_string())
        .bind(log.resource_id)
        .bind(log.source_ip)
        .bind(&log.user_agent)
        .bind(&log.request_body)
        .bind(log.response_code)
        .bind(&log.error_message)
        .fetch_one(pool)
        .await
    }

    /// List audit logs for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM scim_audit_logs
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List audit logs for a specific resource.
    pub async fn list_by_resource(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        resource_type: &str,
        resource_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM scim_audit_logs
            WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(resource_type)
        .bind(resource_id)
        .fetch_all(pool)
        .await
    }

    /// Count audit logs for a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM scim_audit_logs
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Delete old audit logs (retention policy).
    pub async fn delete_older_than(pool: &sqlx::PgPool, days: i32) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM scim_audit_logs
            WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
            ",
        )
        .bind(days)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_display() {
        assert_eq!(ScimOperation::Create.to_string(), "CREATE");
        assert_eq!(ScimOperation::List.to_string(), "LIST");
    }

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ScimResourceType::User.to_string(), "User");
        assert_eq!(ScimResourceType::Group.to_string(), "Group");
    }
}
