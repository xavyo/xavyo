//! External Ticket model for semi-manual resources (F064).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_semi_manual_types::TicketStatusCategory;

/// Reference to a ticket in an external ticketing system.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovExternalTicket {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this ticket belongs to.
    pub tenant_id: Uuid,

    /// The manual task this ticket is for.
    pub task_id: Uuid,

    /// The ticketing configuration used.
    pub ticketing_config_id: Uuid,

    /// External system reference (`ServiceNow` `sys_id`, Jira key).
    pub external_reference: String,

    /// URL to the ticket in the external system.
    pub external_url: Option<String>,

    /// Raw status from external system.
    pub external_status: Option<String>,

    /// Normalized status category.
    pub status_category: TicketStatusCategory,

    /// When the ticket was created in the external system.
    pub created_externally_at: Option<DateTime<Utc>>,

    /// When the status was last synced.
    pub last_synced_at: Option<DateTime<Utc>>,

    /// Last sync error message.
    pub sync_error: Option<String>,

    /// Full API response for debugging.
    pub raw_response: Option<serde_json::Value>,

    /// When this record was created.
    pub created_at: DateTime<Utc>,

    /// When this record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create an external ticket record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExternalTicket {
    pub task_id: Uuid,
    pub ticketing_config_id: Uuid,
    pub external_reference: String,
    pub external_url: Option<String>,
    pub external_status: Option<String>,
    pub status_category: TicketStatusCategory,
    pub created_externally_at: Option<DateTime<Utc>>,
    pub raw_response: Option<serde_json::Value>,
}

impl GovExternalTicket {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_external_tickets
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by task ID.
    pub async fn find_by_task(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_external_tickets
            WHERE tenant_id = $1 AND task_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(task_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by external reference.
    pub async fn find_by_reference(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        ticketing_config_id: Uuid,
        external_reference: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_external_tickets
            WHERE tenant_id = $1 AND ticketing_config_id = $2 AND external_reference = $3
            ",
        )
        .bind(tenant_id)
        .bind(ticketing_config_id)
        .bind(external_reference)
        .fetch_optional(pool)
        .await
    }

    /// Create a new external ticket record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateExternalTicket,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_external_tickets (
                tenant_id, task_id, ticketing_config_id, external_reference,
                external_url, external_status, status_category,
                created_externally_at, raw_response, last_synced_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.task_id)
        .bind(input.ticketing_config_id)
        .bind(&input.external_reference)
        .bind(&input.external_url)
        .bind(&input.external_status)
        .bind(input.status_category)
        .bind(input.created_externally_at)
        .bind(&input.raw_response)
        .fetch_one(pool)
        .await
    }

    /// Update ticket status from external system.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        external_status: Option<&str>,
        status_category: TicketStatusCategory,
        raw_response: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_external_tickets
            SET
                external_status = $3,
                status_category = $4,
                raw_response = COALESCE($5, raw_response),
                last_synced_at = NOW(),
                sync_error = NULL,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(external_status)
        .bind(status_category)
        .bind(raw_response)
        .fetch_optional(pool)
        .await
    }

    /// Record sync error.
    pub async fn record_sync_error(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_external_tickets
            SET
                sync_error = $3,
                last_synced_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .fetch_optional(pool)
        .await
    }

    /// Find tickets needing status sync.
    pub async fn find_pending_sync(
        pool: &sqlx::PgPool,
        stale_threshold: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_external_tickets
            WHERE status_category NOT IN ('resolved', 'closed', 'rejected')
              AND (last_synced_at IS NULL OR last_synced_at < $1)
            ORDER BY last_synced_at ASC NULLS FIRST
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(stale_threshold)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Delete a ticket record.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_external_tickets
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_input() {
        let input = CreateExternalTicket {
            task_id: Uuid::new_v4(),
            ticketing_config_id: Uuid::new_v4(),
            external_reference: "INC0012345".to_string(),
            external_url: Some(
                "https://test.service-now.com/nav_to.do?uri=incident.do".to_string(),
            ),
            external_status: Some("New".to_string()),
            status_category: TicketStatusCategory::Open,
            created_externally_at: Some(Utc::now()),
            raw_response: None,
        };

        assert_eq!(input.external_reference, "INC0012345");
        assert_eq!(input.status_category, TicketStatusCategory::Open);
    }
}
