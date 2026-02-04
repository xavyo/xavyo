//! Governance Application model.
//!
//! Represents target systems or services that users need access to.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Application type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_app_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovAppType {
    /// Internal application owned by the organization.
    Internal,
    /// External third-party application.
    External,
}

/// Application status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_app_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovAppStatus {
    /// Application is active and can have entitlements assigned.
    Active,
    /// Application is inactive; no new assignments allowed.
    Inactive,
}

/// A governance application in the IGA registry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApplication {
    /// Unique identifier for the application.
    pub id: Uuid,

    /// The tenant this application belongs to.
    pub tenant_id: Uuid,

    /// Application display name.
    pub name: String,

    /// Application type (internal or external).
    pub app_type: GovAppType,

    /// Application status (active or inactive).
    pub status: GovAppStatus,

    /// Application description.
    pub description: Option<String>,

    /// Application owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether entitlements in this application can be delegated (F053).
    /// Overrides entitlement-level setting when false.
    pub is_delegable: bool,

    /// Whether this application requires manual provisioning (F064).
    /// When true, provisioning operations create manual tasks instead of automated operations.
    pub is_semi_manual: bool,

    /// Default ticketing configuration for semi-manual provisioning tasks (F064).
    pub ticketing_config_id: Option<Uuid>,

    /// Default SLA policy for semi-manual provisioning tasks (F064).
    pub sla_policy_id: Option<Uuid>,

    /// Whether approval must complete before ticket creation (F064).
    /// When true, tickets are only created after access request approval completes.
    pub requires_approval_before_ticket: bool,

    /// When the application was created.
    pub created_at: DateTime<Utc>,

    /// When the application was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovApplication {
    pub name: String,
    pub app_type: GovAppType,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub external_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    /// Whether entitlements in this application can be delegated. Defaults to true.
    #[serde(default = "default_app_delegable")]
    pub is_delegable: bool,
    /// Whether this application requires manual provisioning (F064). Defaults to false.
    #[serde(default)]
    pub is_semi_manual: bool,
    /// Default ticketing configuration for semi-manual provisioning tasks (F064).
    pub ticketing_config_id: Option<Uuid>,
    /// Default SLA policy for semi-manual provisioning tasks (F064).
    pub sla_policy_id: Option<Uuid>,
    /// Whether approval must complete before ticket creation (F064).
    #[serde(default)]
    pub requires_approval_before_ticket: bool,
}

fn default_app_delegable() -> bool {
    true
}

/// Request to update an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovApplication {
    pub name: Option<String>,
    pub status: Option<GovAppStatus>,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub external_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    /// Whether entitlements in this application can be delegated.
    pub is_delegable: Option<bool>,
    /// Whether this application requires manual provisioning (F064).
    pub is_semi_manual: Option<bool>,
    /// Default ticketing configuration for semi-manual provisioning tasks (F064).
    pub ticketing_config_id: Option<Uuid>,
    /// Default SLA policy for semi-manual provisioning tasks (F064).
    pub sla_policy_id: Option<Uuid>,
    /// Whether approval must complete before ticket creation (F064).
    pub requires_approval_before_ticket: Option<bool>,
}

impl GovApplication {
    /// Find an application by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_applications
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an application by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_applications
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all applications for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: Option<GovAppStatus>,
        app_type: Option<GovAppType>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_applications
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if app_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND app_type = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovApplication>(&query).bind(tenant_id);

        if let Some(s) = status {
            q = q.bind(s);
        }
        if let Some(t) = app_type {
            q = q.bind(t);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count applications in a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: Option<GovAppStatus>,
        app_type: Option<GovAppType>,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_applications
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if app_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND app_type = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(s) = status {
            q = q.bind(s);
        }
        if let Some(t) = app_type {
            q = q.bind(t);
        }

        q.fetch_one(pool).await
    }

    /// Create a new application.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovApplication,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_applications (
                tenant_id, name, app_type, description, owner_id, external_id, metadata,
                is_delegable, is_semi_manual, ticketing_config_id, sla_policy_id,
                requires_approval_before_ticket
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.app_type)
        .bind(&input.description)
        .bind(input.owner_id)
        .bind(&input.external_id)
        .bind(&input.metadata)
        .bind(input.is_delegable)
        .bind(input.is_semi_manual)
        .bind(input.ticketing_config_id)
        .bind(input.sla_policy_id)
        .bind(input.requires_approval_before_ticket)
        .fetch_one(pool)
        .await
    }

    /// Update an application.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovApplication,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync>> = vec![];

        // Always bind id and tenant_id first
        params.push(Box::new(id));
        params.push(Box::new(tenant_id));
        let mut param_idx = 3;

        if let Some(ref name) = input.name {
            updates.push(format!("name = ${param_idx}"));
            params.push(Box::new(name.clone()));
            param_idx += 1;
        }
        if let Some(status) = input.status {
            updates.push(format!("status = ${param_idx}"));
            params.push(Box::new(status));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.owner_id.is_some() {
            updates.push(format!("owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.external_id.is_some() {
            updates.push(format!("external_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.metadata.is_some() {
            updates.push(format!("metadata = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_delegable.is_some() {
            updates.push(format!("is_delegable = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_semi_manual.is_some() {
            updates.push(format!("is_semi_manual = ${param_idx}"));
            param_idx += 1;
        }
        if input.ticketing_config_id.is_some() {
            updates.push(format!("ticketing_config_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.sla_policy_id.is_some() {
            updates.push(format!("sla_policy_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.requires_approval_before_ticket.is_some() {
            updates.push(format!("requires_approval_before_ticket = ${param_idx}"));
            // param_idx += 1; // unused after this
        }

        let query = format!(
            "UPDATE gov_applications SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovApplication>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(status) = input.status {
            q = q.bind(status);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(owner_id) = input.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(ref external_id) = input.external_id {
            q = q.bind(external_id);
        }
        if let Some(ref metadata) = input.metadata {
            q = q.bind(metadata);
        }
        if let Some(is_delegable) = input.is_delegable {
            q = q.bind(is_delegable);
        }
        if let Some(is_semi_manual) = input.is_semi_manual {
            q = q.bind(is_semi_manual);
        }
        if let Some(ticketing_config_id) = input.ticketing_config_id {
            q = q.bind(ticketing_config_id);
        }
        if let Some(sla_policy_id) = input.sla_policy_id {
            q = q.bind(sla_policy_id);
        }
        if let Some(requires_approval) = input.requires_approval_before_ticket {
            q = q.bind(requires_approval);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an application.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_applications
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count entitlements for this application.
    pub async fn count_entitlements(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_entitlements
            WHERE application_id = $1 AND tenant_id = $2
            ",
        )
        .bind(application_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Check if application is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovAppStatus::Active)
    }

    /// Check if application requires semi-manual provisioning (F064).
    #[must_use] 
    pub fn requires_manual_provisioning(&self) -> bool {
        self.is_semi_manual
    }

    /// List semi-manual applications for a tenant with pagination (F064).
    pub async fn list_semi_manual(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_applications
            WHERE tenant_id = $1 AND is_semi_manual = true AND status = 'active'
            ORDER BY name
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_application_request() {
        let request = CreateGovApplication {
            name: "HR System".to_string(),
            app_type: GovAppType::Internal,
            description: Some("Human Resources Management".to_string()),
            owner_id: Some(Uuid::new_v4()),
            external_id: None,
            metadata: None,
            is_delegable: true,
            is_semi_manual: false,
            ticketing_config_id: None,
            sla_policy_id: None,
            requires_approval_before_ticket: false,
        };

        assert_eq!(request.name, "HR System");
        assert_eq!(request.app_type, GovAppType::Internal);
        assert!(request.is_delegable);
        assert!(!request.is_semi_manual);
        assert!(!request.requires_approval_before_ticket);
    }

    #[test]
    fn test_create_semi_manual_application() {
        let ticketing_config_id = Uuid::new_v4();
        let sla_policy_id = Uuid::new_v4();

        let request = CreateGovApplication {
            name: "Legacy Mainframe".to_string(),
            app_type: GovAppType::Internal,
            description: Some("Legacy system requiring manual provisioning".to_string()),
            owner_id: Some(Uuid::new_v4()),
            external_id: None,
            metadata: None,
            is_delegable: true,
            is_semi_manual: true,
            ticketing_config_id: Some(ticketing_config_id),
            sla_policy_id: Some(sla_policy_id),
            requires_approval_before_ticket: true,
        };

        assert_eq!(request.name, "Legacy Mainframe");
        assert!(request.is_semi_manual);
        assert_eq!(request.ticketing_config_id, Some(ticketing_config_id));
        assert_eq!(request.sla_policy_id, Some(sla_policy_id));
        assert!(request.requires_approval_before_ticket);
    }

    #[test]
    fn test_app_status_serialization() {
        let active = GovAppStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");
    }
}
