//! SCIM audit logging service.

use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use xavyo_db::models::{CreateAuditLog, ScimAuditLog, ScimOperation, ScimResourceType};

use crate::error::ScimResult;

/// Service for SCIM audit logging.
pub struct AuditService {
    pool: PgPool,
}

impl AuditService {
    /// Create a new audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log a SCIM operation.
    #[allow(clippy::too_many_arguments)]
    pub async fn log(
        &self,
        tenant_id: Uuid,
        token_id: Option<Uuid>,
        operation: ScimOperation,
        resource_type: ScimResourceType,
        resource_id: Option<Uuid>,
        source_ip: IpAddr,
        user_agent: Option<String>,
        request_body: Option<serde_json::Value>,
        response_code: i32,
        error_message: Option<String>,
    ) -> ScimResult<ScimAuditLog> {
        let log = CreateAuditLog {
            tenant_id,
            token_id,
            operation,
            resource_type,
            resource_id,
            source_ip: source_ip.to_string(),
            user_agent,
            request_body: request_body.map(|b| truncate_json(b, 10000)),
            response_code,
            error_message,
        };

        let entry = ScimAuditLog::create(&self.pool, log).await?;
        Ok(entry)
    }

    /// Log a successful user operation.
    pub async fn log_user_success(
        &self,
        tenant_id: Uuid,
        token_id: Uuid,
        operation: ScimOperation,
        user_id: Option<Uuid>,
        source_ip: IpAddr,
        user_agent: Option<String>,
        response_code: i32,
    ) {
        let _ = self
            .log(
                tenant_id,
                Some(token_id),
                operation,
                ScimResourceType::User,
                user_id,
                source_ip,
                user_agent,
                None,
                response_code,
                None,
            )
            .await;
    }

    /// Log a failed operation.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_error(
        &self,
        tenant_id: Uuid,
        token_id: Option<Uuid>,
        operation: ScimOperation,
        resource_type: ScimResourceType,
        resource_id: Option<Uuid>,
        source_ip: IpAddr,
        user_agent: Option<String>,
        response_code: i32,
        error_message: String,
    ) {
        let _ = self
            .log(
                tenant_id,
                token_id,
                operation,
                resource_type,
                resource_id,
                source_ip,
                user_agent,
                None,
                response_code,
                Some(error_message),
            )
            .await;
    }

    /// Log an authentication failure.
    ///
    /// **Architectural note**: This method requires a `tenant_id` parameter, but
    /// in the SCIM auth middleware the tenant is derived from the Bearer token.
    /// When authentication fails (invalid/revoked token), the tenant is unknown.
    /// Therefore this method cannot be called from the middleware on auth failure.
    /// Auth failures are instead logged via `tracing::warn!` in the middleware.
    /// This method is available for cases where the tenant is known from context
    /// (e.g., a valid token that lacks required permissions).
    pub async fn log_auth_failure(
        &self,
        tenant_id: Uuid,
        source_ip: IpAddr,
        user_agent: Option<String>,
    ) {
        let _ = self
            .log(
                tenant_id,
                None,
                ScimOperation::List, // Auth failures aren't tied to a specific CRUD operation
                ScimResourceType::User,
                None,
                source_ip,
                user_agent,
                None,
                401,
                Some("Authentication failed".to_string()),
            )
            .await;
    }

    /// List audit logs for a tenant.
    pub async fn list_logs(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> ScimResult<Vec<ScimAuditLog>> {
        let logs = ScimAuditLog::list_by_tenant(&self.pool, tenant_id, limit, offset).await?;
        Ok(logs)
    }

    /// Get logs for a specific resource.
    pub async fn get_resource_logs(
        &self,
        tenant_id: Uuid,
        resource_type: &str,
        resource_id: Uuid,
    ) -> ScimResult<Vec<ScimAuditLog>> {
        let logs =
            ScimAuditLog::list_by_resource(&self.pool, tenant_id, resource_type, resource_id)
                .await?;
        Ok(logs)
    }

    /// Cleanup old audit logs (retention policy).
    pub async fn cleanup_old_logs(&self, retention_days: i32) -> ScimResult<u64> {
        let deleted = ScimAuditLog::delete_older_than(&self.pool, retention_days).await?;
        Ok(deleted)
    }
}

/// Truncate a JSON value to a maximum size.
fn truncate_json(value: serde_json::Value, max_chars: usize) -> serde_json::Value {
    let json_str = serde_json::to_string(&value).unwrap_or_default();
    if json_str.len() <= max_chars {
        value
    } else {
        // Truncate and return a placeholder
        serde_json::json!({
            "_truncated": true,
            "_original_size": json_str.len(),
            "_preview": &json_str[..max_chars.min(1000)]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_small_json() {
        let value = serde_json::json!({"name": "John"});
        let result = truncate_json(value.clone(), 10000);
        assert_eq!(result, value);
    }

    #[test]
    fn test_truncate_large_json() {
        let large_str = "x".repeat(20000);
        let value = serde_json::json!({"data": large_str});
        let result = truncate_json(value, 10000);

        assert!(result.get("_truncated").is_some());
        assert!(result.get("_original_size").is_some());
    }
}
