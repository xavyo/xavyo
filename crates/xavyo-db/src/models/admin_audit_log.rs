//! Admin audit log model for delegated administration.
//!
//! Records all administrative actions for compliance and debugging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Admin action type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAction {
    Create,
    Update,
    Delete,
    Assign,
    Revoke,
    AccessDenied,
    /// Move in hierarchy (F088).
    Move,
}

impl std::fmt::Display for AdminAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminAction::Create => write!(f, "create"),
            AdminAction::Update => write!(f, "update"),
            AdminAction::Delete => write!(f, "delete"),
            AdminAction::Assign => write!(f, "assign"),
            AdminAction::Revoke => write!(f, "revoke"),
            AdminAction::AccessDenied => write!(f, "access_denied"),
            AdminAction::Move => write!(f, "move"),
        }
    }
}

impl std::str::FromStr for AdminAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(AdminAction::Create),
            "update" => Ok(AdminAction::Update),
            "delete" => Ok(AdminAction::Delete),
            "assign" => Ok(AdminAction::Assign),
            "revoke" => Ok(AdminAction::Revoke),
            "access_denied" => Ok(AdminAction::AccessDenied),
            "move" => Ok(AdminAction::Move),
            _ => Err(format!("Invalid admin action: {s}")),
        }
    }
}

/// Admin resource type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminResourceType {
    User,
    Template,
    Assignment,
    Permission,
    /// Governance role (F088).
    GovRole,
    /// Governance role inheritance block (F088).
    GovRoleInheritanceBlock,
    /// Governance role entitlement mapping (F088).
    GovRoleEntitlement,
    /// Tenant (F-AUDIT-PROV).
    Tenant,
    /// API key (F-AUDIT-PROV).
    ApiKey,
    /// OAuth client (F-AUDIT-PROV).
    OauthClient,
    /// Tenant settings (F-SETTINGS-API).
    TenantSettings,
    /// Tenant plan (F-PLAN-MGMT).
    TenantPlan,
    /// Admin invitation (F-ADMIN-INVITE).
    AdminInvitation,
}

impl std::fmt::Display for AdminResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminResourceType::User => write!(f, "user"),
            AdminResourceType::Template => write!(f, "template"),
            AdminResourceType::Assignment => write!(f, "assignment"),
            AdminResourceType::Permission => write!(f, "permission"),
            AdminResourceType::GovRole => write!(f, "gov_role"),
            AdminResourceType::GovRoleInheritanceBlock => write!(f, "gov_role_inheritance_block"),
            AdminResourceType::GovRoleEntitlement => write!(f, "gov_role_entitlement"),
            AdminResourceType::Tenant => write!(f, "tenant"),
            AdminResourceType::ApiKey => write!(f, "api_key"),
            AdminResourceType::OauthClient => write!(f, "oauth_client"),
            AdminResourceType::TenantSettings => write!(f, "tenant_settings"),
            AdminResourceType::TenantPlan => write!(f, "tenant_plan"),
            AdminResourceType::AdminInvitation => write!(f, "admin_invitation"),
        }
    }
}

impl std::str::FromStr for AdminResourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(AdminResourceType::User),
            "template" => Ok(AdminResourceType::Template),
            "assignment" => Ok(AdminResourceType::Assignment),
            "permission" => Ok(AdminResourceType::Permission),
            "gov_role" => Ok(AdminResourceType::GovRole),
            "gov_role_inheritance_block" => Ok(AdminResourceType::GovRoleInheritanceBlock),
            "gov_role_entitlement" => Ok(AdminResourceType::GovRoleEntitlement),
            "tenant" => Ok(AdminResourceType::Tenant),
            "api_key" => Ok(AdminResourceType::ApiKey),
            "oauth_client" => Ok(AdminResourceType::OauthClient),
            "tenant_settings" => Ok(AdminResourceType::TenantSettings),
            "tenant_plan" => Ok(AdminResourceType::TenantPlan),
            "admin_invitation" => Ok(AdminResourceType::AdminInvitation),
            _ => Err(format!("Invalid resource type: {s}")),
        }
    }
}

/// Admin audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminAuditLog {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Admin user who performed the action.
    pub admin_user_id: Uuid,
    /// Action type.
    pub action: String,
    /// Resource type.
    pub resource_type: String,
    /// Resource ID (optional).
    pub resource_id: Option<Uuid>,
    /// Previous state (for updates and deletes).
    pub old_value: Option<JsonValue>,
    /// New state (for creates and updates).
    pub new_value: Option<JsonValue>,
    /// Client IP address.
    pub ip_address: Option<String>,
    /// Client user agent.
    pub user_agent: Option<String>,
    /// When the action occurred.
    pub created_at: DateTime<Utc>,
}

/// Input for creating an audit log entry.
#[derive(Debug, Clone)]
pub struct CreateAuditLogEntry {
    pub tenant_id: Uuid,
    pub admin_user_id: Uuid,
    pub action: AdminAction,
    pub resource_type: AdminResourceType,
    pub resource_id: Option<Uuid>,
    pub old_value: Option<JsonValue>,
    pub new_value: Option<JsonValue>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Filter options for querying the audit log.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub admin_user_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

impl AdminAuditLog {
    /// Get the action as enum.
    #[must_use]
    pub fn action_enum(&self) -> Option<AdminAction> {
        self.action.parse().ok()
    }

    /// Get the resource type as enum.
    #[must_use]
    pub fn resource_type_enum(&self) -> Option<AdminResourceType> {
        self.resource_type.parse().ok()
    }

    /// Create a new audit log entry.
    pub async fn create<'e, E>(executor: E, input: CreateAuditLogEntry) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO admin_audit_log
                (tenant_id, admin_user_id, action, resource_type, resource_id,
                 old_value, new_value, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, tenant_id, admin_user_id, action, resource_type, resource_id,
                      old_value, new_value, ip_address, user_agent, created_at
            ",
        )
        .bind(input.tenant_id)
        .bind(input.admin_user_id)
        .bind(input.action.to_string())
        .bind(input.resource_type.to_string())
        .bind(input.resource_id)
        .bind(input.old_value)
        .bind(input.new_value)
        .bind(input.ip_address)
        .bind(input.user_agent)
        .fetch_one(executor)
        .await
    }

    /// Get an audit log entry by ID.
    pub async fn get_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, admin_user_id, action, resource_type, resource_id,
                   old_value, new_value, ip_address, user_agent, created_at
            FROM admin_audit_log
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// List audit log entries with optional filters.
    pub async fn list<'e, E>(
        executor: E,
        tenant_id: Uuid,
        filter: &AuditLogFilter,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 2;

        if filter.admin_user_id.is_some() {
            conditions.push(format!("admin_user_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.action.is_some() {
            conditions.push(format!("action = ${param_idx}"));
            param_idx += 1;
        }

        if filter.resource_type.is_some() {
            conditions.push(format!("resource_type = ${param_idx}"));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            conditions.push(format!("created_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            conditions.push(format!("created_at <= ${param_idx}"));
            param_idx += 1;
        }

        if cursor.is_some() {
            conditions.push(format!("created_at < ${param_idx}"));
            param_idx += 1;
        }

        let where_clause = conditions.join(" AND ");
        let query = format!(
            r"
            SELECT id, tenant_id, admin_user_id, action, resource_type, resource_id,
                   old_value, new_value, ip_address, user_agent, created_at
            FROM admin_audit_log
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT ${param_idx}
            "
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(admin_user_id) = filter.admin_user_id {
            q = q.bind(admin_user_id);
        }

        if let Some(action) = &filter.action {
            q = q.bind(action);
        }

        if let Some(resource_type) = &filter.resource_type {
            q = q.bind(resource_type);
        }

        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }

        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        if let Some(c) = cursor {
            q = q.bind(c);
        }

        q = q.bind(limit);

        q.fetch_all(executor).await
    }

    /// Count audit log entries for a tenant.
    pub async fn count<'e, E>(
        executor: E,
        tenant_id: Uuid,
        filter: &AuditLogFilter,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 2;

        if filter.admin_user_id.is_some() {
            conditions.push(format!("admin_user_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.action.is_some() {
            conditions.push(format!("action = ${param_idx}"));
            param_idx += 1;
        }

        if filter.resource_type.is_some() {
            conditions.push(format!("resource_type = ${param_idx}"));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            conditions.push(format!("created_at >= ${param_idx}"));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            conditions.push(format!("created_at <= ${param_idx}"));
            // param_idx += 1;  // Not needed after last parameter
        }

        let where_clause = conditions.join(" AND ");
        let query = format!(
            r"
            SELECT COUNT(*) FROM admin_audit_log
            WHERE {where_clause}
            "
        );

        let mut q = sqlx::query_as::<_, (i64,)>(&query).bind(tenant_id);

        if let Some(admin_user_id) = filter.admin_user_id {
            q = q.bind(admin_user_id);
        }

        if let Some(action) = &filter.action {
            q = q.bind(action);
        }

        if let Some(resource_type) = &filter.resource_type {
            q = q.bind(resource_type);
        }

        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }

        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        let row = q.fetch_one(executor).await?;
        Ok(row.0)
    }

    /// Get recent entries for a resource.
    pub async fn get_for_resource<'e, E>(
        executor: E,
        tenant_id: Uuid,
        resource_type: &str,
        resource_id: Uuid,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, admin_user_id, action, resource_type, resource_id,
                   old_value, new_value, ip_address, user_agent, created_at
            FROM admin_audit_log
            WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
            ORDER BY created_at DESC
            LIMIT $4
            ",
        )
        .bind(tenant_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(limit)
        .fetch_all(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_action_display() {
        assert_eq!(AdminAction::Create.to_string(), "create");
        assert_eq!(AdminAction::AccessDenied.to_string(), "access_denied");
    }

    #[test]
    fn test_admin_action_from_str() {
        assert_eq!(
            "create".parse::<AdminAction>().unwrap(),
            AdminAction::Create
        );
        assert_eq!(
            "ACCESS_DENIED".parse::<AdminAction>().unwrap(),
            AdminAction::AccessDenied
        );
        assert!("invalid".parse::<AdminAction>().is_err());
    }

    #[test]
    fn test_admin_resource_type_display() {
        assert_eq!(AdminResourceType::User.to_string(), "user");
        assert_eq!(AdminResourceType::Template.to_string(), "template");
    }

    #[test]
    fn test_admin_resource_type_from_str() {
        assert_eq!(
            "user".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::User
        );
        assert_eq!(
            "TEMPLATE".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::Template
        );
        assert!("invalid".parse::<AdminResourceType>().is_err());
    }

    #[test]
    fn test_provisioning_resource_types_display() {
        assert_eq!(AdminResourceType::Tenant.to_string(), "tenant");
        assert_eq!(AdminResourceType::ApiKey.to_string(), "api_key");
        assert_eq!(AdminResourceType::OauthClient.to_string(), "oauth_client");
        assert_eq!(
            AdminResourceType::TenantSettings.to_string(),
            "tenant_settings"
        );
    }

    #[test]
    fn test_provisioning_resource_types_from_str() {
        assert_eq!(
            "tenant".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::Tenant
        );
        assert_eq!(
            "API_KEY".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::ApiKey
        );
        assert_eq!(
            "oauth_client".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::OauthClient
        );
        assert_eq!(
            "tenant_settings".parse::<AdminResourceType>().unwrap(),
            AdminResourceType::TenantSettings
        );
    }
}
