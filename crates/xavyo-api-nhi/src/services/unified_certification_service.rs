//! Service for unified certification campaigns across all NHI types.
//!
//! This service enables certification campaigns that can cover both
//! service accounts and AI agents in a single campaign.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::NonHumanIdentityView;

/// Error types for unified certification operations.
#[derive(Debug, thiserror::Error)]
pub enum UnifiedCertificationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Campaign not found: {0}")]
    CampaignNotFound(Uuid),

    #[error("Item not found: {0}")]
    ItemNotFound(Uuid),

    #[error("Campaign is not in draft status")]
    CampaignNotDraft,

    #[error("Campaign is not active")]
    CampaignNotActive,

    #[error("No NHIs match the campaign criteria")]
    NoMatchingNhis,

    #[error("Due date must be in the future")]
    DueDateInPast,

    #[error("At least one NHI type must be selected")]
    NoNhiTypesSelected,

    #[error("Item already decided")]
    ItemAlreadyDecided,
}

/// Campaign status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Active,
    Completed,
    Cancelled,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Active => write!(f, "active"),
            Self::Completed => write!(f, "completed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Certification item status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Pending,
    Certified,
    Revoked,
}

impl std::fmt::Display for ItemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Certified => write!(f, "certified"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// Certification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationDecision {
    Certify,
    Revoke,
}

/// Filter criteria for campaign NHI selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CampaignFilter {
    pub owner_id: Option<Uuid>,
    pub risk_min: Option<i32>,
    pub inactive_days: Option<i32>,
}

/// Unified certification campaign record.
#[derive(Debug, Clone)]
pub struct UnifiedCertificationCampaign {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub nhi_types: Vec<String>,
    pub status: CampaignStatus,
    pub reviewer_id: Uuid,
    pub filter: Option<CampaignFilter>,
    pub due_date: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub launched_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Unified certification item record.
#[derive(Debug, Clone)]
pub struct UnifiedCertificationItem {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub campaign_id: Uuid,
    pub nhi_id: Uuid,
    pub nhi_type: String,
    pub nhi_name: String,
    pub reviewer_id: Uuid,
    pub status: ItemStatus,
    pub decision: Option<CertificationDecision>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Item counts for a campaign.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemCounts {
    pub total: i64,
    pub pending: i64,
    pub certified: i64,
    pub revoked: i64,
}

/// Service for unified certification operations.
#[derive(Clone)]
pub struct UnifiedCertificationService {
    pool: PgPool,
}

impl UnifiedCertificationService {
    /// Creates a new UnifiedCertificationService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates a new certification campaign.
    ///
    /// The campaign is created in Draft status.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_campaign(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        nhi_types: Vec<String>,
        filter: Option<CampaignFilter>,
        reviewer_id: Uuid,
        due_date: DateTime<Utc>,
        created_by: Uuid,
    ) -> Result<UnifiedCertificationCampaign, UnifiedCertificationError> {
        // Validate inputs
        if nhi_types.is_empty() {
            return Err(UnifiedCertificationError::NoNhiTypesSelected);
        }

        if due_date <= Utc::now() {
            return Err(UnifiedCertificationError::DueDateInPast);
        }

        let id = Uuid::new_v4();
        let now = Utc::now();
        let nhi_types_json = serde_json::to_value(&nhi_types).unwrap_or_default();
        let filter_json = filter
            .as_ref()
            .map(|f| serde_json::to_value(f).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO unified_nhi_certification_campaigns
            (id, tenant_id, name, description, nhi_types, status, reviewer_id, filter, due_date, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&description)
        .bind(&nhi_types_json)
        .bind("draft")
        .bind(reviewer_id)
        .bind(&filter_json)
        .bind(due_date)
        .bind(created_by)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(UnifiedCertificationCampaign {
            id,
            tenant_id,
            name,
            description,
            nhi_types,
            status: CampaignStatus::Draft,
            reviewer_id,
            filter,
            due_date,
            created_by,
            created_at: now,
            launched_at: None,
            completed_at: None,
        })
    }

    /// Gets a campaign by ID.
    pub async fn get_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<UnifiedCertificationCampaign, UnifiedCertificationError> {
        let row = sqlx::query_as::<_, CampaignRow>(
            r#"
            SELECT id, tenant_id, name, description, nhi_types, status, reviewer_id, filter, due_date, created_by, created_at, launched_at, completed_at
            FROM unified_nhi_certification_campaigns
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UnifiedCertificationError::CampaignNotFound(campaign_id))?;

        Ok(row.into())
    }

    /// Lists campaigns for a tenant.
    pub async fn list_campaigns(
        &self,
        tenant_id: Uuid,
        status: Option<CampaignStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UnifiedCertificationCampaign>, UnifiedCertificationError> {
        let rows = if let Some(s) = status {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, tenant_id, name, description, nhi_types, status, reviewer_id, filter, due_date, created_by, created_at, launched_at, completed_at
                FROM unified_nhi_certification_campaigns
                WHERE tenant_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(tenant_id)
            .bind(s.to_string())
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, tenant_id, name, description, nhi_types, status, reviewer_id, filter, due_date, created_by, created_at, launched_at, completed_at
                FROM unified_nhi_certification_campaigns
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Counts campaigns for a tenant.
    pub async fn count_campaigns(
        &self,
        tenant_id: Uuid,
        status: Option<CampaignStatus>,
    ) -> Result<i64, UnifiedCertificationError> {
        let count: (i64,) = if let Some(s) = status {
            sqlx::query_as(
                r#"
                SELECT COUNT(*) FROM unified_nhi_certification_campaigns
                WHERE tenant_id = $1 AND status = $2
                "#,
            )
            .bind(tenant_id)
            .bind(s.to_string())
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT COUNT(*) FROM unified_nhi_certification_campaigns
                WHERE tenant_id = $1
                "#,
            )
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?
        };

        Ok(count.0)
    }

    /// Launches a campaign, generating certification items for matching NHIs.
    pub async fn launch_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<UnifiedCertificationCampaign, UnifiedCertificationError> {
        let campaign = self.get_campaign(tenant_id, campaign_id).await?;

        if campaign.status != CampaignStatus::Draft {
            return Err(UnifiedCertificationError::CampaignNotDraft);
        }

        // Get matching NHIs from the unified view
        let nhis = self.get_nhis_for_campaign(tenant_id, &campaign).await?;

        if nhis.is_empty() {
            return Err(UnifiedCertificationError::NoMatchingNhis);
        }

        // Create certification items
        let now = Utc::now();
        for nhi in &nhis {
            let item_id = Uuid::new_v4();
            sqlx::query(
                r#"
                INSERT INTO unified_nhi_certification_items
                (id, tenant_id, campaign_id, nhi_id, nhi_type, nhi_name, reviewer_id, status, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(item_id)
            .bind(tenant_id)
            .bind(campaign_id)
            .bind(nhi.id)
            .bind(&nhi.nhi_type)
            .bind(&nhi.name)
            .bind(campaign.reviewer_id)
            .bind("pending")
            .bind(now)
            .execute(&self.pool)
            .await?;
        }

        // Update campaign status to active
        sqlx::query(
            r#"
            UPDATE unified_nhi_certification_campaigns
            SET status = 'active', launched_at = $1
            WHERE id = $2 AND tenant_id = $3
            "#,
        )
        .bind(now)
        .bind(campaign_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        // Return updated campaign
        self.get_campaign(tenant_id, campaign_id).await
    }

    /// Gets NHIs matching campaign criteria.
    async fn get_nhis_for_campaign(
        &self,
        tenant_id: Uuid,
        campaign: &UnifiedCertificationCampaign,
    ) -> Result<Vec<NonHumanIdentityView>, UnifiedCertificationError> {
        // Build filter from campaign settings
        let mut filter = xavyo_db::models::NhiViewFilter::default();

        // Filter by NHI types - if both are specified or "all", don't filter
        if campaign.nhi_types.len() == 1 {
            filter.nhi_type = Some(campaign.nhi_types[0].clone());
        }

        // Apply additional filters from campaign
        if let Some(ref f) = campaign.filter {
            filter.owner_id = f.owner_id;
            filter.risk_min = f.risk_min;
        }

        let nhis = NonHumanIdentityView::list(&self.pool, tenant_id, &filter, 10000, 0).await?;

        Ok(nhis)
    }

    /// Gets item counts for a campaign.
    pub async fn get_item_counts(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<ItemCounts, UnifiedCertificationError> {
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'certified') as certified,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked
            FROM unified_nhi_certification_items
            WHERE campaign_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ItemCounts {
            total: row.0,
            pending: row.1,
            certified: row.2,
            revoked: row.3,
        })
    }

    /// Lists items for a campaign.
    pub async fn list_items(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        nhi_type: Option<String>,
        status: Option<ItemStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UnifiedCertificationItem>, UnifiedCertificationError> {
        let rows = sqlx::query_as::<_, ItemRow>(
            r#"
            SELECT id, tenant_id, campaign_id, nhi_id, nhi_type, nhi_name, reviewer_id, status, decision, decided_by, decided_at, comment, created_at
            FROM unified_nhi_certification_items
            WHERE campaign_id = $1 AND tenant_id = $2
                AND ($3::text IS NULL OR nhi_type = $3)
                AND ($4::text IS NULL OR status = $4)
            ORDER BY created_at
            LIMIT $5 OFFSET $6
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .bind(nhi_type)
        .bind(status.map(|s| s.to_string()))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Counts items for a campaign.
    pub async fn count_items(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        nhi_type: Option<String>,
        status: Option<ItemStatus>,
    ) -> Result<i64, UnifiedCertificationError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM unified_nhi_certification_items
            WHERE campaign_id = $1 AND tenant_id = $2
                AND ($3::text IS NULL OR nhi_type = $3)
                AND ($4::text IS NULL OR status = $4)
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .bind(nhi_type)
        .bind(status.map(|s| s.to_string()))
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }

    /// Gets a single item by ID.
    pub async fn get_item(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
    ) -> Result<UnifiedCertificationItem, UnifiedCertificationError> {
        let row = sqlx::query_as::<_, ItemRow>(
            r#"
            SELECT id, tenant_id, campaign_id, nhi_id, nhi_type, nhi_name, reviewer_id, status, decision, decided_by, decided_at, comment, created_at
            FROM unified_nhi_certification_items
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(item_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UnifiedCertificationError::ItemNotFound(item_id))?;

        Ok(row.into())
    }

    /// Makes a certification decision on an item.
    pub async fn decide_item(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        decision: CertificationDecision,
        comment: Option<String>,
        decided_by: Uuid,
    ) -> Result<UnifiedCertificationItem, UnifiedCertificationError> {
        let item = self.get_item(tenant_id, item_id).await?;

        if item.status != ItemStatus::Pending {
            return Err(UnifiedCertificationError::ItemAlreadyDecided);
        }

        // Verify campaign is active
        let campaign = self.get_campaign(tenant_id, item.campaign_id).await?;
        if campaign.status != CampaignStatus::Active {
            return Err(UnifiedCertificationError::CampaignNotActive);
        }

        let new_status = match decision {
            CertificationDecision::Certify => ItemStatus::Certified,
            CertificationDecision::Revoke => ItemStatus::Revoked,
        };
        let decision_str = match decision {
            CertificationDecision::Certify => "certify",
            CertificationDecision::Revoke => "revoke",
        };
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE unified_nhi_certification_items
            SET status = $1, decision = $2, decided_by = $3, decided_at = $4, comment = $5
            WHERE id = $6 AND tenant_id = $7
            "#,
        )
        .bind(new_status.to_string())
        .bind(decision_str)
        .bind(decided_by)
        .bind(now)
        .bind(&comment)
        .bind(item_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        // If revoked, update the underlying NHI
        if decision == CertificationDecision::Revoke {
            self.apply_revocation(tenant_id, &item).await?;
        }

        // Update NHI's last_certified_at if certified
        if decision == CertificationDecision::Certify {
            self.apply_certification(tenant_id, &item, decided_by)
                .await?;
        }

        self.get_item(tenant_id, item_id).await
    }

    /// Applies revocation to the underlying NHI.
    async fn apply_revocation(
        &self,
        tenant_id: Uuid,
        item: &UnifiedCertificationItem,
    ) -> Result<(), UnifiedCertificationError> {
        match item.nhi_type.as_str() {
            "service_account" => {
                // Suspend the service account
                sqlx::query(
                    r#"
                    UPDATE gov_service_accounts
                    SET status = 'suspended', suspension_reason = 'Certification revoked'
                    WHERE id = $1 AND tenant_id = $2
                    "#,
                )
                .bind(item.nhi_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;
            }
            "ai_agent" => {
                // Suspend the AI agent
                sqlx::query(
                    r#"
                    UPDATE ai_agents
                    SET status = 'suspended'
                    WHERE id = $1 AND tenant_id = $2
                    "#,
                )
                .bind(item.nhi_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Applies certification to the underlying NHI (updates last_certified_at).
    async fn apply_certification(
        &self,
        tenant_id: Uuid,
        item: &UnifiedCertificationItem,
        certified_by: Uuid,
    ) -> Result<(), UnifiedCertificationError> {
        let now = Utc::now();
        match item.nhi_type.as_str() {
            "service_account" => {
                sqlx::query(
                    r#"
                    UPDATE gov_service_accounts
                    SET last_certified_at = $1, certified_by = $2
                    WHERE id = $3 AND tenant_id = $4
                    "#,
                )
                .bind(now)
                .bind(certified_by)
                .bind(item.nhi_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;
            }
            "ai_agent" => {
                sqlx::query(
                    r#"
                    UPDATE ai_agents
                    SET last_certified_at = $1, last_certified_by = $2
                    WHERE id = $3 AND tenant_id = $4
                    "#,
                )
                .bind(now)
                .bind(certified_by)
                .bind(item.nhi_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Cancels a campaign.
    pub async fn cancel_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<UnifiedCertificationCampaign, UnifiedCertificationError> {
        let campaign = self.get_campaign(tenant_id, campaign_id).await?;

        if campaign.status == CampaignStatus::Completed
            || campaign.status == CampaignStatus::Cancelled
        {
            return Err(UnifiedCertificationError::CampaignNotActive);
        }

        sqlx::query(
            r#"
            UPDATE unified_nhi_certification_campaigns
            SET status = 'cancelled'
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        self.get_campaign(tenant_id, campaign_id).await
    }

    /// Gets campaign summary statistics.
    pub async fn get_campaign_summary(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<CampaignSummary, UnifiedCertificationError> {
        let campaign = self.get_campaign(tenant_id, campaign_id).await?;
        let counts = self.get_item_counts(tenant_id, campaign_id).await?;

        // Get counts by NHI type
        let by_type: Vec<(String, i64, i64, i64)> = sqlx::query_as(
            r#"
            SELECT
                nhi_type,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'certified') as certified,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked
            FROM unified_nhi_certification_items
            WHERE campaign_id = $1 AND tenant_id = $2
            GROUP BY nhi_type
            "#,
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let progress_percent = if counts.total > 0 {
            ((counts.certified + counts.revoked) as f64 / counts.total as f64 * 100.0) as i32
        } else {
            0
        };

        Ok(CampaignSummary {
            campaign_id,
            campaign_name: campaign.name,
            status: campaign.status,
            due_date: campaign.due_date,
            item_counts: counts,
            by_type: by_type
                .into_iter()
                .map(|(nhi_type, pending, certified, revoked)| NhiTypeCounts {
                    nhi_type,
                    pending,
                    certified,
                    revoked,
                })
                .collect(),
            progress_percent,
        })
    }

    /// Applies bulk decisions to multiple items.
    pub async fn bulk_decide(
        &self,
        tenant_id: Uuid,
        item_ids: Vec<Uuid>,
        decision: CertificationDecision,
        comment: Option<String>,
        decided_by: Uuid,
    ) -> Result<BulkDecisionResult, UnifiedCertificationError> {
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        for item_id in item_ids {
            match self
                .decide_item(tenant_id, item_id, decision, comment.clone(), decided_by)
                .await
            {
                Ok(item) => succeeded.push(item),
                Err(e) => failed.push(BulkDecisionFailure {
                    item_id,
                    error: e.to_string(),
                }),
            }
        }

        Ok(BulkDecisionResult { succeeded, failed })
    }

    /// Gets pending certification items for the current user (reviewer).
    pub async fn get_my_pending_items(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UnifiedCertificationItem>, UnifiedCertificationError> {
        let rows = sqlx::query_as::<_, ItemRow>(
            r#"
            SELECT i.id, i.tenant_id, i.campaign_id, i.nhi_id, i.nhi_type, i.nhi_name, i.reviewer_id, i.status, i.decision, i.decided_by, i.decided_at, i.comment, i.created_at
            FROM unified_nhi_certification_items i
            JOIN unified_nhi_certification_campaigns c ON i.campaign_id = c.id
            WHERE i.tenant_id = $1 AND i.reviewer_id = $2 AND i.status = 'pending' AND c.status = 'active'
            ORDER BY c.due_date ASC, i.created_at ASC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(reviewer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Counts pending certification items for the current user.
    pub async fn count_my_pending_items(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
    ) -> Result<i64, UnifiedCertificationError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM unified_nhi_certification_items i
            JOIN unified_nhi_certification_campaigns c ON i.campaign_id = c.id
            WHERE i.tenant_id = $1 AND i.reviewer_id = $2 AND i.status = 'pending' AND c.status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(reviewer_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }
}

/// Campaign summary with detailed statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub campaign_id: Uuid,
    pub campaign_name: String,
    pub status: CampaignStatus,
    pub due_date: DateTime<Utc>,
    pub item_counts: ItemCounts,
    pub by_type: Vec<NhiTypeCounts>,
    pub progress_percent: i32,
}

/// Counts per NHI type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiTypeCounts {
    pub nhi_type: String,
    pub pending: i64,
    pub certified: i64,
    pub revoked: i64,
}

/// Result of a bulk decision operation.
#[derive(Debug, Clone)]
pub struct BulkDecisionResult {
    pub succeeded: Vec<UnifiedCertificationItem>,
    pub failed: Vec<BulkDecisionFailure>,
}

/// Information about a failed bulk decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDecisionFailure {
    pub item_id: Uuid,
    pub error: String,
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    nhi_types: serde_json::Value,
    status: String,
    reviewer_id: Uuid,
    filter: Option<serde_json::Value>,
    due_date: DateTime<Utc>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    launched_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<CampaignRow> for UnifiedCertificationCampaign {
    fn from(row: CampaignRow) -> Self {
        let nhi_types: Vec<String> = serde_json::from_value(row.nhi_types).unwrap_or_default();
        let filter: Option<CampaignFilter> =
            row.filter.and_then(|v| serde_json::from_value(v).ok());
        let status = match row.status.as_str() {
            "draft" => CampaignStatus::Draft,
            "active" => CampaignStatus::Active,
            "completed" => CampaignStatus::Completed,
            "cancelled" => CampaignStatus::Cancelled,
            _ => CampaignStatus::Draft,
        };

        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            nhi_types,
            status,
            reviewer_id: row.reviewer_id,
            filter,
            due_date: row.due_date,
            created_by: row.created_by,
            created_at: row.created_at,
            launched_at: row.launched_at,
            completed_at: row.completed_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ItemRow {
    id: Uuid,
    tenant_id: Uuid,
    campaign_id: Uuid,
    nhi_id: Uuid,
    nhi_type: String,
    nhi_name: String,
    reviewer_id: Uuid,
    status: String,
    decision: Option<String>,
    decided_by: Option<Uuid>,
    decided_at: Option<DateTime<Utc>>,
    comment: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<ItemRow> for UnifiedCertificationItem {
    fn from(row: ItemRow) -> Self {
        let status = match row.status.as_str() {
            "pending" => ItemStatus::Pending,
            "certified" => ItemStatus::Certified,
            "revoked" => ItemStatus::Revoked,
            _ => ItemStatus::Pending,
        };
        let decision = row.decision.and_then(|d| match d.as_str() {
            "certify" => Some(CertificationDecision::Certify),
            "revoke" => Some(CertificationDecision::Revoke),
            _ => None,
        });

        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            campaign_id: row.campaign_id,
            nhi_id: row.nhi_id,
            nhi_type: row.nhi_type,
            nhi_name: row.nhi_name,
            reviewer_id: row.reviewer_id,
            status,
            decision,
            decided_by: row.decided_by,
            decided_at: row.decided_at,
            comment: row.comment,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_status_display() {
        assert_eq!(CampaignStatus::Draft.to_string(), "draft");
        assert_eq!(CampaignStatus::Active.to_string(), "active");
        assert_eq!(CampaignStatus::Completed.to_string(), "completed");
        assert_eq!(CampaignStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_item_status_display() {
        assert_eq!(ItemStatus::Pending.to_string(), "pending");
        assert_eq!(ItemStatus::Certified.to_string(), "certified");
        assert_eq!(ItemStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_campaign_filter_default() {
        let filter = CampaignFilter::default();
        assert!(filter.owner_id.is_none());
        assert!(filter.risk_min.is_none());
        assert!(filter.inactive_days.is_none());
    }

    #[test]
    fn test_item_counts_default() {
        let counts = ItemCounts::default();
        assert_eq!(counts.total, 0);
        assert_eq!(counts.pending, 0);
        assert_eq!(counts.certified, 0);
        assert_eq!(counts.revoked, 0);
    }

    #[test]
    fn test_certification_decision_serialization() {
        let certify = CertificationDecision::Certify;
        let revoke = CertificationDecision::Revoke;

        let certify_json = serde_json::to_string(&certify).unwrap();
        let revoke_json = serde_json::to_string(&revoke).unwrap();

        assert_eq!(certify_json, "\"certify\"");
        assert_eq!(revoke_json, "\"revoke\"");
    }
}
