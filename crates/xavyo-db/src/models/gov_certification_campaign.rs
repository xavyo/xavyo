//! Governance Certification Campaign model.
//!
//! Represents a review cycle with defined scope, deadline, and reviewer assignment rules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Scope type for certification campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "cert_scope_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CertScopeType {
    /// Certify all users in the tenant.
    AllUsers,
    /// Certify users in a specific department.
    Department,
    /// Certify users with access to a specific application.
    Application,
    /// Certify users with a specific entitlement.
    Entitlement,
}

/// Reviewer type for certification campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "cert_reviewer_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CertReviewerType {
    /// User's direct manager reviews.
    UserManager,
    /// Application owner reviews.
    ApplicationOwner,
    /// Entitlement owner reviews.
    EntitlementOwner,
    /// Specific users assigned as reviewers.
    SpecificUsers,
}

/// Status for certification campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "cert_campaign_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CertCampaignStatus {
    /// Campaign created but not yet launched.
    Draft,
    /// Campaign is active, reviewers can make decisions.
    Active,
    /// All items have been decided.
    Completed,
    /// Campaign was cancelled by admin.
    Cancelled,
    /// Deadline passed with pending items.
    Overdue,
}

impl CertCampaignStatus {
    /// Check if the campaign is in an active state (can accept decisions).
    #[must_use] 
    pub fn can_decide(&self) -> bool {
        matches!(self, Self::Active | Self::Overdue)
    }

    /// Check if the campaign is in a terminal state.
    #[must_use] 
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }

    /// Check if the campaign can be cancelled.
    #[must_use] 
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Draft | Self::Active | Self::Overdue)
    }

    /// Check if the campaign can be launched.
    #[must_use] 
    pub fn can_launch(&self) -> bool {
        matches!(self, Self::Draft)
    }
}

/// A governance certification campaign.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCertificationCampaign {
    /// Unique identifier for the campaign.
    pub id: Uuid,

    /// The tenant this campaign belongs to.
    pub tenant_id: Uuid,

    /// Campaign display name.
    pub name: String,

    /// Campaign description.
    pub description: Option<String>,

    /// What scope of access to certify.
    pub scope_type: CertScopeType,

    /// Scope configuration (e.g., `application_id`, department name).
    pub scope_config: Option<serde_json::Value>,

    /// How to assign reviewers.
    pub reviewer_type: CertReviewerType,

    /// Specific reviewer user IDs (when `reviewer_type` is `SpecificUsers`).
    pub specific_reviewers: Vec<Uuid>,

    /// Campaign status.
    pub status: CertCampaignStatus,

    /// Campaign deadline.
    pub deadline: DateTime<Utc>,

    /// When the campaign was launched.
    pub launched_at: Option<DateTime<Utc>>,

    /// When the campaign was completed.
    pub completed_at: Option<DateTime<Utc>>,

    /// Admin who created the campaign.
    pub created_by: Uuid,

    /// When the campaign was created.
    pub created_at: DateTime<Utc>,

    /// When the campaign was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificationCampaign {
    pub name: String,
    pub description: Option<String>,
    pub scope_type: CertScopeType,
    pub scope_config: Option<serde_json::Value>,
    pub reviewer_type: CertReviewerType,
    pub specific_reviewers: Option<Vec<Uuid>>,
    pub deadline: DateTime<Utc>,
    pub created_by: Uuid,
}

/// Request to update a certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCertificationCampaign {
    pub name: Option<String>,
    pub description: Option<String>,
    pub deadline: Option<DateTime<Utc>>,
}

/// Filter options for listing certification campaigns.
#[derive(Debug, Clone, Default)]
pub struct CampaignFilter {
    pub status: Option<CertCampaignStatus>,
    pub statuses: Option<Vec<CertCampaignStatus>>,
    pub created_by: Option<Uuid>,
}

impl GovCertificationCampaign {
    /// Find a campaign by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_certification_campaigns
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a campaign by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_certification_campaigns
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List campaigns for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CampaignFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_certification_campaigns
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovCertificationCampaign>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count campaigns in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CampaignFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_certification_campaigns
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new certification campaign.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateCertificationCampaign,
    ) -> Result<Self, sqlx::Error> {
        let specific_reviewers = input.specific_reviewers.unwrap_or_default();

        sqlx::query_as(
            r"
            INSERT INTO gov_certification_campaigns (
                tenant_id, name, description, scope_type, scope_config,
                reviewer_type, specific_reviewers, deadline, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.scope_type)
        .bind(&input.scope_config)
        .bind(input.reviewer_type)
        .bind(&specific_reviewers)
        .bind(input.deadline)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a campaign (only allowed in draft status).
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCertificationCampaign,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.deadline.is_some() {
            updates.push(format!("deadline = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_certification_campaigns SET {} WHERE id = $1 AND tenant_id = $2 AND status = 'draft' RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovCertificationCampaign>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(deadline) = input.deadline {
            q = q.bind(deadline);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a draft campaign.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_certification_campaigns
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Launch a campaign (change status from draft to active).
    pub async fn launch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_campaigns
            SET status = 'active',
                launched_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark campaign as completed.
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_campaigns
            SET status = 'completed',
                completed_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('active', 'overdue')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a campaign.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_certification_campaigns
            SET status = 'cancelled',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('draft', 'active', 'overdue')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark campaigns as overdue if deadline passed.
    pub async fn mark_overdue(pool: &sqlx::PgPool, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_certification_campaigns
            SET status = 'overdue', updated_at = NOW()
            WHERE status = 'active' AND deadline < $1
            ",
        )
        .bind(now)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find campaigns that need to be marked overdue.
    pub async fn find_due_for_overdue(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_certification_campaigns
            WHERE status = 'active' AND deadline < $1
            ",
        )
        .bind(now)
        .fetch_all(pool)
        .await
    }

    /// Check if the campaign is in draft status.
    #[must_use] 
    pub fn is_draft(&self) -> bool {
        matches!(self.status, CertCampaignStatus::Draft)
    }

    /// Check if the campaign can accept decisions.
    #[must_use] 
    pub fn can_decide(&self) -> bool {
        self.status.can_decide()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_status_can_decide() {
        assert!(CertCampaignStatus::Active.can_decide());
        assert!(CertCampaignStatus::Overdue.can_decide());
        assert!(!CertCampaignStatus::Draft.can_decide());
        assert!(!CertCampaignStatus::Completed.can_decide());
        assert!(!CertCampaignStatus::Cancelled.can_decide());
    }

    #[test]
    fn test_campaign_status_is_terminal() {
        assert!(CertCampaignStatus::Completed.is_terminal());
        assert!(CertCampaignStatus::Cancelled.is_terminal());
        assert!(!CertCampaignStatus::Draft.is_terminal());
        assert!(!CertCampaignStatus::Active.is_terminal());
        assert!(!CertCampaignStatus::Overdue.is_terminal());
    }

    #[test]
    fn test_campaign_status_can_cancel() {
        assert!(CertCampaignStatus::Draft.can_cancel());
        assert!(CertCampaignStatus::Active.can_cancel());
        assert!(CertCampaignStatus::Overdue.can_cancel());
        assert!(!CertCampaignStatus::Completed.can_cancel());
        assert!(!CertCampaignStatus::Cancelled.can_cancel());
    }

    #[test]
    fn test_status_serialization() {
        let draft = CertCampaignStatus::Draft;
        let json = serde_json::to_string(&draft).unwrap();
        assert_eq!(json, "\"draft\"");

        let active = CertCampaignStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");
    }

    #[test]
    fn test_scope_type_serialization() {
        let all_users = CertScopeType::AllUsers;
        let json = serde_json::to_string(&all_users).unwrap();
        assert_eq!(json, "\"all_users\"");

        let app = CertScopeType::Application;
        let json = serde_json::to_string(&app).unwrap();
        assert_eq!(json, "\"application\"");
    }

    #[test]
    fn test_reviewer_type_serialization() {
        let user_manager = CertReviewerType::UserManager;
        let json = serde_json::to_string(&user_manager).unwrap();
        assert_eq!(json, "\"user_manager\"");

        let specific = CertReviewerType::SpecificUsers;
        let json = serde_json::to_string(&specific).unwrap();
        assert_eq!(json, "\"specific_users\"");
    }

    #[test]
    fn test_create_campaign_request() {
        let request = CreateCertificationCampaign {
            name: "Q1 2026 Access Review".to_string(),
            description: Some("Quarterly access certification".to_string()),
            scope_type: CertScopeType::Application,
            scope_config: Some(
                serde_json::json!({"application_id": "123e4567-e89b-12d3-a456-426614174000"}),
            ),
            reviewer_type: CertReviewerType::UserManager,
            specific_reviewers: None,
            deadline: Utc::now(),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(request.name, "Q1 2026 Access Review");
        assert_eq!(request.scope_type, CertScopeType::Application);
        assert_eq!(request.reviewer_type, CertReviewerType::UserManager);
    }
}
