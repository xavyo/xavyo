//! License Audit Event model (F065).
//!
//! Records all license-related operations for compliance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_license_types::LicenseAuditAction;

/// A license audit event recording a license operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicenseAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The license pool involved (if applicable).
    pub license_pool_id: Option<Uuid>,

    /// The assignment involved (if applicable).
    pub license_assignment_id: Option<Uuid>,

    /// The affected user (if applicable).
    pub user_id: Option<Uuid>,

    /// The action performed.
    pub action: String,

    /// Who performed the action.
    pub actor_id: Uuid,

    /// Additional details as JSON.
    pub details: serde_json::Value,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

impl GovLicenseAuditEvent {
    /// Get the action as an enum (if it's a known action type).
    pub fn action_type(&self) -> Option<LicenseAuditAction> {
        LicenseAuditAction::parse(&self.action)
    }

    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_audit_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Create a new audit event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovLicenseAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_license_audit_events (
                tenant_id, license_pool_id, license_assignment_id, user_id,
                action, actor_id, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.license_pool_id)
        .bind(input.license_assignment_id)
        .bind(input.user_id)
        .bind(input.action.as_str())
        .bind(input.actor_id)
        .bind(&input.details)
        .fetch_one(pool)
        .await
    }

    /// List events for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_license_audit_events
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.action.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovLicenseAuditEvent>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(ref action) = filter.action {
            q = q.bind(action.as_str());
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count events in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAuditEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_license_audit_events
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.action.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(ref action) = filter.action {
            q = q.bind(action.as_str());
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        q.fetch_one(pool).await
    }

    /// Get events for a pool.
    pub async fn list_by_pool(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_audit_events
            WHERE tenant_id = $1 AND license_pool_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(license_pool_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Get events for a user.
    pub async fn list_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_audit_events
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Get recent events (for dashboard).
    pub async fn get_recent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_audit_events
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

    /// Count events in a date range (for reporting).
    pub async fn count_in_range(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        license_pool_id: Option<Uuid>,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(pool_id) = license_pool_id {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*) FROM gov_license_audit_events
                WHERE tenant_id = $1 AND license_pool_id = $2
                  AND created_at >= $3 AND created_at <= $4
                "#,
            )
            .bind(tenant_id)
            .bind(pool_id)
            .bind(start_date)
            .bind(end_date)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*) FROM gov_license_audit_events
                WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
                "#,
            )
            .bind(tenant_id)
            .bind(start_date)
            .bind(end_date)
            .fetch_one(pool)
            .await
        }
    }
}

/// Request to create a new audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicenseAuditEvent {
    pub license_pool_id: Option<Uuid>,
    pub license_assignment_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub action: LicenseAuditAction,
    pub actor_id: Uuid,
    #[serde(default = "default_details")]
    pub details: serde_json::Value,
}

fn default_details() -> serde_json::Value {
    serde_json::json!({})
}

impl CreateGovLicenseAuditEvent {
    /// Create a pool-related event.
    pub fn pool_event(
        pool_id: Uuid,
        action: LicenseAuditAction,
        actor_id: Uuid,
        details: serde_json::Value,
    ) -> Self {
        Self {
            license_pool_id: Some(pool_id),
            license_assignment_id: None,
            user_id: None,
            action,
            actor_id,
            details,
        }
    }

    /// Create an assignment-related event.
    pub fn assignment_event(
        pool_id: Uuid,
        assignment_id: Uuid,
        user_id: Uuid,
        action: LicenseAuditAction,
        actor_id: Uuid,
        details: serde_json::Value,
    ) -> Self {
        Self {
            license_pool_id: Some(pool_id),
            license_assignment_id: Some(assignment_id),
            user_id: Some(user_id),
            action,
            actor_id,
            details,
        }
    }

    /// Create a bulk operation event.
    pub fn bulk_event(
        pool_id: Uuid,
        action: LicenseAuditAction,
        actor_id: Uuid,
        affected_users: Vec<Uuid>,
        details: serde_json::Value,
    ) -> Self {
        let mut full_details = details;
        full_details["affected_users"] = serde_json::json!(affected_users);
        full_details["affected_count"] = serde_json::json!(affected_users.len());

        Self {
            license_pool_id: Some(pool_id),
            license_assignment_id: None,
            user_id: None,
            action,
            actor_id,
            details: full_details,
        }
    }
}

/// Filter options for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct LicenseAuditEventFilter {
    pub license_pool_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub action: Option<LicenseAuditAction>,
    pub actor_id: Option<Uuid>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Extended audit event with actor and user names.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LicenseAuditEventWithDetails {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub license_pool_id: Option<Uuid>,
    pub pool_name: Option<String>,
    pub license_assignment_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub action: String,
    pub actor_id: Uuid,
    pub actor_email: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl LicenseAuditEventWithDetails {
    /// Get audit events with details.
    pub async fn list_with_details(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicenseAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT
                e.id, e.tenant_id, e.license_pool_id, p.name as pool_name,
                e.license_assignment_id, e.user_id, u.email as user_email,
                e.action, e.actor_id, actor.email as actor_email,
                e.details, e.created_at
            FROM gov_license_audit_events e
            LEFT JOIN gov_license_pools p ON e.license_pool_id = p.id
            LEFT JOIN users u ON e.user_id = u.id
            JOIN users actor ON e.actor_id = actor.id
            WHERE e.tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.license_pool_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.license_pool_id = ${}", param_count));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.user_id = ${}", param_count));
        }
        if filter.action.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.action = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.actor_id = ${}", param_count));
        }
        if filter.start_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.created_at >= ${}", param_count));
        }
        if filter.end_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND e.created_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY e.created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(pool_id) = filter.license_pool_id {
            q = q.bind(pool_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(ref action) = filter.action {
            q = q.bind(action.as_str());
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type() {
        let event = GovLicenseAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: Some(Uuid::new_v4()),
            license_assignment_id: None,
            user_id: None,
            action: "pool_created".to_string(),
            actor_id: Uuid::new_v4(),
            details: serde_json::json!({}),
            created_at: Utc::now(),
        };

        assert_eq!(event.action_type(), Some(LicenseAuditAction::PoolCreated));
    }

    #[test]
    fn test_create_pool_event() {
        let pool_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let event = CreateGovLicenseAuditEvent::pool_event(
            pool_id,
            LicenseAuditAction::PoolCreated,
            actor_id,
            serde_json::json!({"name": "Test Pool"}),
        );

        assert_eq!(event.license_pool_id, Some(pool_id));
        assert_eq!(event.actor_id, actor_id);
        assert!(event.license_assignment_id.is_none());
    }

    #[test]
    fn test_create_bulk_event() {
        let pool_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let users = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        let event = CreateGovLicenseAuditEvent::bulk_event(
            pool_id,
            LicenseAuditAction::BulkAssign,
            actor_id,
            users.clone(),
            serde_json::json!({}),
        );

        assert_eq!(event.details["affected_count"], 3);
    }
}
