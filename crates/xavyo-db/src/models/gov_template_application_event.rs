//! Governance Template Application Event model (F058).
//!
//! Audit trail for template applications to objects.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{TemplateObjectType, TemplateOperation};

/// An audit event for when a template is applied to an object.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateApplicationEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The template that was applied (may be NULL if template was deleted).
    pub template_id: Option<Uuid>,

    /// The specific template version that was applied.
    pub template_version_id: Option<Uuid>,

    /// Type of object the template was applied to.
    pub object_type: TemplateObjectType,

    /// ID of the object the template was applied to.
    pub object_id: Uuid,

    /// Operation type (create or update).
    pub operation: TemplateOperation,

    /// List of rule IDs that were applied.
    pub rules_applied: serde_json::Value,

    /// Changes made to the object (before/after values).
    pub changes_made: serde_json::Value,

    /// Any validation errors that occurred (NULL if none).
    pub validation_errors: Option<serde_json::Value>,

    /// User who triggered the operation (may be NULL for system operations).
    pub actor_id: Option<Uuid>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new template application event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateApplicationEvent {
    pub template_id: Option<Uuid>,
    pub template_version_id: Option<Uuid>,
    pub object_type: TemplateObjectType,
    pub object_id: Uuid,
    pub operation: TemplateOperation,
    pub rules_applied: serde_json::Value,
    pub changes_made: serde_json::Value,
    pub validation_errors: Option<serde_json::Value>,
    pub actor_id: Option<Uuid>,
}

/// Filter options for listing template application events.
#[derive(Debug, Clone, Default)]
pub struct ApplicationEventFilter {
    pub template_id: Option<Uuid>,
    pub object_type: Option<TemplateObjectType>,
    pub object_id: Option<Uuid>,
    pub operation: Option<TemplateOperation>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub has_validation_errors: Option<bool>,
}

impl GovTemplateApplicationEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_application_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all events for a specific object.
    pub async fn list_by_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_application_events
            WHERE tenant_id = $1 AND object_type = $2 AND object_id = $3
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(object_type)
        .bind(object_id)
        .fetch_all(pool)
        .await
    }

    /// List all events for a template.
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_application_events
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_with_filter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ApplicationEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from("SELECT * FROM gov_template_application_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${}", param_count));
        }
        if filter.object_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_type = ${}", param_count));
        }
        if filter.object_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND object_id = ${}", param_count));
        }
        if filter.operation.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operation = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }
        if let Some(has_errors) = filter.has_validation_errors {
            if has_errors {
                query.push_str(" AND validation_errors IS NOT NULL");
            } else {
                query.push_str(" AND validation_errors IS NULL");
            }
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(object_type) = filter.object_type {
            q = q.bind(object_type);
        }
        if let Some(object_id) = filter.object_id {
            q = q.bind(object_id);
        }
        if let Some(operation) = filter.operation {
            q = q.bind(operation);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List recent events for a tenant.
    pub async fn list_recent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_application_events
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List events with validation errors.
    pub async fn list_with_errors(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_template_application_events
            WHERE tenant_id = $1 AND validation_errors IS NOT NULL
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Create a new template application event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovTemplateApplicationEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_template_application_events (
                tenant_id, template_id, template_version_id, object_type, object_id,
                operation, rules_applied, changes_made, validation_errors, actor_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.template_id)
        .bind(input.template_version_id)
        .bind(input.object_type)
        .bind(input.object_id)
        .bind(input.operation)
        .bind(&input.rules_applied)
        .bind(&input.changes_made)
        .bind(&input.validation_errors)
        .bind(input.actor_id)
        .fetch_one(pool)
        .await
    }

    /// Count events for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_application_events
            WHERE tenant_id = $1 AND template_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Count events with validation errors for a template.
    pub async fn count_errors_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_template_application_events
            WHERE tenant_id = $1 AND template_id = $2 AND validation_errors IS NOT NULL
            "#,
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }

    /// Check if this event had validation errors.
    pub fn has_validation_errors(&self) -> bool {
        self.validation_errors.is_some()
    }

    /// Get the rules applied as a Vec of UUIDs.
    pub fn get_rules_applied(&self) -> Option<Vec<Uuid>> {
        serde_json::from_value(self.rules_applied.clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_application_event() {
        let template_id = Uuid::new_v4();
        let object_id = Uuid::new_v4();

        let input = CreateGovTemplateApplicationEvent {
            template_id: Some(template_id),
            template_version_id: None,
            object_type: TemplateObjectType::User,
            object_id,
            operation: TemplateOperation::Create,
            rules_applied: serde_json::json!([]),
            changes_made: serde_json::json!({}),
            validation_errors: None,
            actor_id: None,
        };

        assert_eq!(input.template_id, Some(template_id));
        assert_eq!(input.object_type, TemplateObjectType::User);
        assert_eq!(input.operation, TemplateOperation::Create);
    }

    #[test]
    fn test_filter_default() {
        let filter = ApplicationEventFilter::default();
        assert!(filter.template_id.is_none());
        assert!(filter.object_type.is_none());
        assert!(filter.object_id.is_none());
        assert!(filter.operation.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
        assert!(filter.has_validation_errors.is_none());
    }
}
