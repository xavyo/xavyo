//! Ticketing Configuration model for semi-manual resources (F064).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_semi_manual_types::TicketingType;

/// Configuration for external ticketing system integration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTicketingConfiguration {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this configuration belongs to.
    pub tenant_id: Uuid,

    /// Display name for the configuration.
    pub name: String,

    /// Type of ticketing system.
    pub ticketing_type: TicketingType,

    /// API endpoint URL.
    pub endpoint_url: String,

    /// Encrypted credentials (username/password, API token, etc.).
    pub credentials: Vec<u8>,

    /// Custom field mappings for ticket creation.
    pub field_mappings: Option<serde_json::Value>,

    /// Default assignee for tickets.
    pub default_assignee: Option<String>,

    /// ServiceNow assignment group.
    pub default_assignment_group: Option<String>,

    /// Jira project key.
    pub project_key: Option<String>,

    /// Jira issue type.
    pub issue_type: Option<String>,

    /// Polling interval for status checks (seconds).
    pub polling_interval_seconds: i32,

    /// Encrypted webhook callback secret for signature verification.
    pub webhook_callback_secret: Option<Vec<u8>>,

    /// Mapping from external status to internal category.
    pub status_field_mapping: Option<serde_json::Value>,

    /// Whether this configuration is active.
    pub is_active: bool,

    /// When the configuration was created.
    pub created_at: DateTime<Utc>,

    /// When the configuration was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a ticketing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketingConfiguration {
    pub name: String,
    pub ticketing_type: TicketingType,
    pub endpoint_url: String,
    pub credentials: Vec<u8>,
    pub field_mappings: Option<serde_json::Value>,
    pub default_assignee: Option<String>,
    pub default_assignment_group: Option<String>,
    pub project_key: Option<String>,
    pub issue_type: Option<String>,
    pub polling_interval_seconds: Option<i32>,
    pub webhook_callback_secret: Option<Vec<u8>>,
    pub status_field_mapping: Option<serde_json::Value>,
}

/// Request to update a ticketing configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateTicketingConfiguration {
    pub name: Option<String>,
    pub endpoint_url: Option<String>,
    pub credentials: Option<Vec<u8>>,
    pub field_mappings: Option<serde_json::Value>,
    pub default_assignee: Option<String>,
    pub default_assignment_group: Option<String>,
    pub project_key: Option<String>,
    pub issue_type: Option<String>,
    pub polling_interval_seconds: Option<i32>,
    pub webhook_callback_secret: Option<Vec<u8>>,
    pub status_field_mapping: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

/// Filter options for listing configurations.
#[derive(Debug, Clone, Default)]
pub struct TicketingConfigFilter {
    pub ticketing_type: Option<TicketingType>,
    pub is_active: Option<bool>,
}

impl GovTicketingConfiguration {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_ticketing_configurations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List configurations for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TicketingConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_ticketing_configurations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.ticketing_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ticketing_type = ${}", param_count));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(ticketing_type) = filter.ticketing_type {
            q = q.bind(ticketing_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count configurations for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TicketingConfigFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_ticketing_configurations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.ticketing_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ticketing_type = ${}", param_count));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ticketing_type) = filter.ticketing_type {
            q = q.bind(ticketing_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.fetch_one(pool).await
    }

    /// Create a new configuration.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateTicketingConfiguration,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_ticketing_configurations (
                tenant_id, name, ticketing_type, endpoint_url, credentials,
                field_mappings, default_assignee, default_assignment_group,
                project_key, issue_type, polling_interval_seconds,
                webhook_callback_secret, status_field_mapping
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.ticketing_type)
        .bind(&input.endpoint_url)
        .bind(&input.credentials)
        .bind(&input.field_mappings)
        .bind(&input.default_assignee)
        .bind(&input.default_assignment_group)
        .bind(&input.project_key)
        .bind(&input.issue_type)
        .bind(input.polling_interval_seconds.unwrap_or(300))
        .bind(&input.webhook_callback_secret)
        .bind(&input.status_field_mapping)
        .fetch_one(pool)
        .await
    }

    /// Update a configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateTicketingConfiguration,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_ticketing_configurations
            SET
                name = COALESCE($3, name),
                endpoint_url = COALESCE($4, endpoint_url),
                credentials = COALESCE($5, credentials),
                field_mappings = COALESCE($6, field_mappings),
                default_assignee = COALESCE($7, default_assignee),
                default_assignment_group = COALESCE($8, default_assignment_group),
                project_key = COALESCE($9, project_key),
                issue_type = COALESCE($10, issue_type),
                polling_interval_seconds = COALESCE($11, polling_interval_seconds),
                webhook_callback_secret = COALESCE($12, webhook_callback_secret),
                status_field_mapping = COALESCE($13, status_field_mapping),
                is_active = COALESCE($14, is_active),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.endpoint_url)
        .bind(&input.credentials)
        .bind(&input.field_mappings)
        .bind(&input.default_assignee)
        .bind(&input.default_assignment_group)
        .bind(&input.project_key)
        .bind(&input.issue_type)
        .bind(input.polling_interval_seconds)
        .bind(&input.webhook_callback_secret)
        .bind(&input.status_field_mapping)
        .bind(input.is_active)
        .fetch_optional(pool)
        .await
    }

    /// Delete a configuration.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_ticketing_configurations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if configuration is in use by any application.
    pub async fn is_in_use(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_applications
            WHERE tenant_id = $1 AND ticketing_config_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_input() {
        let input = CreateTicketingConfiguration {
            name: "Test ServiceNow".to_string(),
            ticketing_type: TicketingType::ServiceNow,
            endpoint_url: "https://test.service-now.com".to_string(),
            credentials: vec![1, 2, 3, 4],
            field_mappings: None,
            default_assignee: Some("admin".to_string()),
            default_assignment_group: Some("IT Ops".to_string()),
            project_key: None,
            issue_type: None,
            polling_interval_seconds: Some(300),
            webhook_callback_secret: None,
            status_field_mapping: None,
        };

        assert_eq!(input.ticketing_type, TicketingType::ServiceNow);
    }

    #[test]
    fn test_update_input_default() {
        let input = UpdateTicketingConfiguration::default();
        assert!(input.name.is_none());
        assert!(input.is_active.is_none());
    }
}
