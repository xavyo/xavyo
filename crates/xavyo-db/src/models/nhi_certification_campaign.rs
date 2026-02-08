//! NHI Certification Campaign model (Feature 201 — persistent storage).
//!
//! Replaces the in-memory `Arc<RwLock<Vec<...>>>` store with PostgreSQL-backed
//! CRUD operations on the `nhi_certification_campaigns` table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A persisted NHI certification campaign.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiCertificationCampaign {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub nhi_type_filter: Option<String>,
    pub specific_nhi_ids: Option<Vec<Uuid>>,
    pub status: String,
    pub due_date: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new NHI certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNhiCertificationCampaign {
    pub name: String,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub nhi_type_filter: Option<String>,
    pub specific_nhi_ids: Option<Vec<Uuid>>,
    pub due_date: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
}

impl NhiCertificationCampaign {
    /// Insert a new certification campaign.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateNhiCertificationCampaign,
    ) -> Result<Self, sqlx::Error> {
        let scope = input.scope.unwrap_or_else(|| "all".to_string());
        sqlx::query_as(
            r"
            INSERT INTO nhi_certification_campaigns (
                tenant_id, name, description, scope, nhi_type_filter,
                specific_nhi_ids, due_date, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&scope)
        .bind(&input.nhi_type_filter)
        .bind(&input.specific_nhi_ids)
        .bind(input.due_date)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a campaign by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM nhi_certification_campaigns
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List campaigns for a tenant with optional status filter and pagination.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = limit.min(100);
        let offset = offset.max(0);

        if let Some(status) = status_filter {
            sqlx::query_as(
                r"
                SELECT * FROM nhi_certification_campaigns
                WHERE tenant_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM nhi_certification_campaigns
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
    }

    /// Update the status of a campaign.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE nhi_certification_campaigns
            SET status = $3, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_defaults() {
        let req = CreateNhiCertificationCampaign {
            name: "Q1 Review".to_string(),
            description: Some("Quarterly certification".to_string()),
            scope: None,
            nhi_type_filter: None,
            specific_nhi_ids: None,
            due_date: None,
            created_by: None,
        };
        assert_eq!(req.name, "Q1 Review");
        assert!(req.scope.is_none());
    }

    #[test]
    fn test_campaign_serialization() {
        let campaign = NhiCertificationCampaign {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Campaign".to_string(),
            description: None,
            scope: "all".to_string(),
            nhi_type_filter: None,
            specific_nhi_ids: None,
            status: "active".to_string(),
            due_date: None,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&campaign).unwrap();
        assert!(json.contains("Test Campaign"));
        assert!(json.contains("\"active\""));

        let deserialized: NhiCertificationCampaign = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "Test Campaign");
        assert_eq!(deserialized.status, "active");
    }
}
