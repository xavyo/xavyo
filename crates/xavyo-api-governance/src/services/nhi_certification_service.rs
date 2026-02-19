//! NHI Certification Service (F061 - User Story 5).
//!
//! Provides certification campaign management for Non-Human Identities.
//! Integrates with the existing certification infrastructure while handling
//! NHI-specific requirements like credential invalidation on revocation.

#[cfg(feature = "kafka")]
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::info;
#[cfg(feature = "kafka")]
use tracing::warn;
use uuid::Uuid;

use xavyo_db::GovServiceAccount;
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

use crate::models::{
    BulkCertificationError, BulkNhiCertificationResult, NhiCertCampaignStatus, NhiCertReviewerType,
    NhiCertificationCampaignResponse, NhiCertificationDecision, NhiCertificationItemResponse,
    NhiCertificationStatus, NhiCertificationSummary,
};

// ============================================================================
// Database Models for NHI Certification (stored in-memory for now)
// In production, these would be in xavyo-db migrations
// ============================================================================

/// Internal certification campaign record.
#[derive(Debug, Clone)]
pub struct NhiCertificationCampaign {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: NhiCertCampaignStatus,
    pub reviewer_type: NhiCertReviewerType,
    pub specific_reviewers: Option<Vec<Uuid>>,
    pub deadline: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub launched_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Internal certification item record.
#[derive(Debug, Clone)]
pub struct NhiCertificationItem {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub campaign_id: Uuid,
    pub nhi_id: Uuid,
    pub reviewer_id: Uuid,
    pub status: NhiCertificationStatus,
    pub decision: Option<NhiCertificationDecision>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    pub comment: Option<String>,
    pub delegated_by: Option<Uuid>,
    pub original_reviewer_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// NHI Certification Service
// ============================================================================

/// Service for NHI certification operations.
pub struct NhiCertificationService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiCertificationService {
    /// Create a new NHI certification service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new service with event producer for Kafka events.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    // =========================================================================
    // Campaign Management
    // =========================================================================

    /// Create a new NHI certification campaign.
    ///
    /// The campaign is created in Draft status. Call `launch_campaign` to activate it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_campaign(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        owner_filter: Option<Uuid>,
        needs_certification_only: bool,
        reviewer_type: NhiCertReviewerType,
        specific_reviewers: Option<Vec<Uuid>>,
        deadline: DateTime<Utc>,
        created_by: Uuid,
    ) -> Result<NhiCertificationCampaignResponse> {
        // Validate deadline is in the future
        if deadline <= Utc::now() {
            return Err(GovernanceError::DeadlineInPast);
        }

        // Validate specific reviewers if required
        if reviewer_type == NhiCertReviewerType::SpecificUsers
            && specific_reviewers
                .as_ref()
                .is_none_or(std::vec::Vec::is_empty)
        {
            return Err(GovernanceError::SpecificReviewersRequired);
        }

        // Create campaign in database
        let campaign = self
            .create_campaign_record(
                tenant_id,
                name,
                description,
                reviewer_type,
                specific_reviewers,
                deadline,
                created_by,
            )
            .await?;

        // Count NHIs that would be included
        let nhis = self
            .get_nhis_for_campaign(tenant_id, owner_filter, needs_certification_only)
            .await?;

        info!(
            campaign_id = %campaign.id,
            nhi_count = nhis.len(),
            "NHI certification campaign created"
        );

        Ok(self.campaign_to_response(campaign, nhis.len() as i64, 0, 0, 0, 0))
    }

    /// Launch a campaign, generating certification items for matching NHIs.
    pub async fn launch_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        owner_filter: Option<Uuid>,
        needs_certification_only: bool,
    ) -> Result<NhiCertificationCampaignResponse> {
        // Get the campaign
        let campaign = self.get_campaign_record(tenant_id, campaign_id).await?;

        // Verify it's in draft status
        if campaign.status != NhiCertCampaignStatus::Draft {
            return Err(GovernanceError::CampaignNotDraft(campaign_id));
        }

        // Get NHIs to include
        let nhis = self
            .get_nhis_for_campaign(tenant_id, owner_filter, needs_certification_only)
            .await?;

        if nhis.is_empty() {
            return Err(GovernanceError::CampaignNoItems);
        }

        // Generate certification items
        let items_created = self
            .generate_certification_items(tenant_id, &campaign, &nhis)
            .await?;

        // Update campaign status to Active
        let campaign = self
            .update_campaign_status(tenant_id, campaign_id, NhiCertCampaignStatus::Active)
            .await?;

        info!(
            campaign_id = %campaign_id,
            items_created = items_created,
            "NHI certification campaign launched"
        );

        #[cfg(feature = "kafka")]
        self.emit_campaign_launched_event(tenant_id, campaign_id, items_created)
            .await;

        Ok(self.campaign_to_response(
            campaign,
            items_created as i64,
            items_created as i64,
            0,
            0,
            0,
        ))
    }

    /// Get campaign by ID.
    pub async fn get_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<NhiCertificationCampaignResponse> {
        let campaign = self.get_campaign_record(tenant_id, campaign_id).await?;
        let summary = self.get_campaign_summary(tenant_id, campaign_id).await?;

        Ok(self.campaign_to_response(
            campaign,
            summary.total,
            summary.pending,
            summary.certified,
            summary.revoked,
            summary.expired,
        ))
    }

    /// List campaigns for a tenant.
    pub async fn list_campaigns(
        &self,
        tenant_id: Uuid,
        status: Option<NhiCertCampaignStatus>,
        created_by: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<NhiCertificationCampaignResponse>, i64)> {
        let (campaigns, total) = self
            .list_campaign_records(tenant_id, status, created_by, limit, offset)
            .await?;

        let mut responses = Vec::with_capacity(campaigns.len());
        for campaign in campaigns {
            let summary = self.get_campaign_summary(tenant_id, campaign.id).await?;
            responses.push(self.campaign_to_response(
                campaign,
                summary.total,
                summary.pending,
                summary.certified,
                summary.revoked,
                summary.expired,
            ));
        }

        Ok((responses, total))
    }

    /// Cancel a campaign.
    pub async fn cancel_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<NhiCertificationCampaignResponse> {
        let campaign = self.get_campaign_record(tenant_id, campaign_id).await?;

        if !campaign.status.can_cancel() {
            return Err(GovernanceError::CannotCancelCampaign(format!(
                "{:?}",
                campaign.status
            )));
        }

        let campaign = self
            .update_campaign_status(tenant_id, campaign_id, NhiCertCampaignStatus::Cancelled)
            .await?;

        info!(campaign_id = %campaign_id, "NHI certification campaign cancelled");

        let summary = self.get_campaign_summary(tenant_id, campaign_id).await?;
        Ok(self.campaign_to_response(
            campaign,
            summary.total,
            summary.pending,
            summary.certified,
            summary.revoked,
            summary.expired,
        ))
    }

    // =========================================================================
    // Certification Item Operations
    // =========================================================================

    /// Get a certification item by ID.
    pub async fn get_item(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
    ) -> Result<NhiCertificationItemResponse> {
        let item = self.get_item_record(tenant_id, item_id).await?;
        self.item_to_response(tenant_id, item).await
    }

    /// List certification items.
    pub async fn list_items(
        &self,
        tenant_id: Uuid,
        campaign_id: Option<Uuid>,
        status: Option<NhiCertificationStatus>,
        reviewer_id: Option<Uuid>,
        owner_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<NhiCertificationItemResponse>, i64)> {
        let (items, total) = self
            .list_item_records(
                tenant_id,
                campaign_id,
                status,
                reviewer_id,
                owner_id,
                limit,
                offset,
            )
            .await?;

        let mut responses = Vec::with_capacity(items.len());
        for item in items {
            responses.push(self.item_to_response(tenant_id, item).await?);
        }

        Ok((responses, total))
    }

    /// Get pending items for a reviewer.
    pub async fn get_my_pending_items(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<NhiCertificationItemResponse>, i64)> {
        self.list_items(
            tenant_id,
            None,
            Some(NhiCertificationStatus::Pending),
            Some(reviewer_id),
            None,
            limit,
            offset,
        )
        .await
    }

    /// Make a decision on a certification item.
    pub async fn decide(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        decided_by: Uuid,
        decision: NhiCertificationDecision,
        comment: Option<String>,
        delegate_to: Option<Uuid>,
    ) -> Result<NhiCertificationItemResponse> {
        let item = self.get_item_record(tenant_id, item_id).await?;

        // Verify the user can decide
        if !self.can_decide(&item, decided_by) {
            return Err(GovernanceError::MicroCertCannotDecide(item_id, decided_by));
        }

        // Check if already decided
        if item.status != NhiCertificationStatus::Pending {
            return Err(GovernanceError::MicroCertificationAlreadyDecided(item_id));
        }

        // Handle delegation
        if decision == NhiCertificationDecision::Delegate {
            return self
                .delegate(tenant_id, item_id, decided_by, delegate_to, comment)
                .await;
        }

        // Get the NHI for this item
        let nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, item.nhi_id)
            .await?
            .ok_or(GovernanceError::NhiNotFound(item.nhi_id))?;

        // Process the decision
        let new_status = match decision {
            NhiCertificationDecision::Certify => {
                // Update NHI's last_certified_at
                GovServiceAccount::certify(&self.pool, tenant_id, item.nhi_id, decided_by).await?;
                NhiCertificationStatus::Certified
            }
            NhiCertificationDecision::Revoke => {
                // Suspend the NHI
                self.revoke_nhi(tenant_id, item.nhi_id, decided_by).await?;
                NhiCertificationStatus::Revoked
            }
            NhiCertificationDecision::Delegate => unreachable!("Handled above"),
        };

        // Update the certification item
        let item = self
            .update_item_decision(
                tenant_id,
                item_id,
                new_status,
                Some(decision),
                Some(decided_by),
                Some(Utc::now()),
                comment.clone(),
            )
            .await?;

        info!(
            item_id = %item_id,
            nhi_id = %nhi.id,
            decision = ?decision,
            decided_by = %decided_by,
            "NHI certification decision recorded"
        );

        // Check if campaign is complete
        let _ = self
            .check_and_complete_campaign(tenant_id, item.campaign_id)
            .await;

        #[cfg(feature = "kafka")]
        self.emit_decision_event(tenant_id, &item, &nhi, decision, decided_by)
            .await;

        self.item_to_response(tenant_id, item).await
    }

    /// Delegate a certification decision to another reviewer.
    async fn delegate(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        delegated_by: Uuid,
        delegate_to: Option<Uuid>,
        comment: Option<String>,
    ) -> Result<NhiCertificationItemResponse> {
        let item = self.get_item_record(tenant_id, item_id).await?;

        let delegate_to = delegate_to.ok_or_else(|| {
            GovernanceError::MicroCertDelegationError("delegate_to is required".to_string())
        })?;

        // Cannot delegate to self
        if delegate_to == delegated_by {
            return Err(GovernanceError::MicroCertSelfDelegationNotAllowed);
        }

        // Get NHI to verify delegate is not the owner
        let nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, item.nhi_id)
            .await?
            .ok_or(GovernanceError::NhiNotFound(item.nhi_id))?;

        // Cannot delegate to NHI owner (would be self-certification)
        if delegate_to == nhi.owner_id {
            return Err(GovernanceError::MicroCertDelegationError(
                "Cannot delegate to NHI owner".to_string(),
            ));
        }

        // Update item with new reviewer
        let original_reviewer = item.original_reviewer_id.unwrap_or(item.reviewer_id);
        let item = self
            .update_item_delegation(
                tenant_id,
                item_id,
                delegate_to,
                Some(delegated_by),
                Some(original_reviewer),
                comment,
            )
            .await?;

        info!(
            item_id = %item_id,
            delegated_by = %delegated_by,
            delegate_to = %delegate_to,
            "NHI certification delegated"
        );

        self.item_to_response(tenant_id, item).await
    }

    /// Make the same decision on multiple items.
    pub async fn bulk_decide(
        &self,
        tenant_id: Uuid,
        item_ids: &[Uuid],
        decided_by: Uuid,
        decision: NhiCertificationDecision,
        comment: Option<String>,
    ) -> Result<BulkNhiCertificationResult> {
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        for item_id in item_ids {
            match self
                .decide(
                    tenant_id,
                    *item_id,
                    decided_by,
                    decision,
                    comment.clone(),
                    None,
                )
                .await
            {
                Ok(_) => succeeded.push(*item_id),
                Err(e) => failed.push(BulkCertificationError {
                    item_id: *item_id,
                    error: e.to_string(),
                }),
            }
        }

        info!(
            succeeded = succeeded.len(),
            failed = failed.len(),
            "Bulk NHI certification decision completed"
        );

        Ok(BulkNhiCertificationResult { succeeded, failed })
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Revoke an NHI: suspend the identity.
    async fn revoke_nhi(&self, tenant_id: Uuid, nhi_id: Uuid, _revoked_by: Uuid) -> Result<()> {
        // Suspend the NHI
        sqlx::query(
            r"
            UPDATE gov_service_accounts
            SET status = 'suspended',
                suspension_reason = 'certification_revoked',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(nhi_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        info!(nhi_id = %nhi_id, "NHI suspended due to certification revocation");

        Ok(())
    }

    /// Check if a user can make a decision on an item.
    fn can_decide(&self, item: &NhiCertificationItem, user_id: Uuid) -> bool {
        // Primary reviewer or delegated reviewer can decide
        item.reviewer_id == user_id
    }

    /// Get NHIs matching campaign criteria.
    async fn get_nhis_for_campaign(
        &self,
        tenant_id: Uuid,
        owner_filter: Option<Uuid>,
        needs_certification_only: bool,
    ) -> Result<Vec<GovServiceAccount>> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
              AND status = 'active'
            ",
        );

        let mut param_idx = 2;

        if owner_filter.is_some() {
            query.push_str(&format!(" AND owner_id = ${param_idx}"));
            #[allow(unused_assignments)]
            {
                param_idx += 1;
            }
        }

        if needs_certification_only {
            query.push_str(
                " AND (last_certified_at IS NULL OR last_certified_at < NOW() - INTERVAL '365 days')",
            );
        }

        query.push_str(" ORDER BY name ASC");

        let mut q = sqlx::query_as::<_, GovServiceAccount>(&query).bind(tenant_id);

        if let Some(owner_id) = owner_filter {
            q = q.bind(owner_id);
        }

        q.fetch_all(&self.pool)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Generate certification items for NHIs in a campaign.
    async fn generate_certification_items(
        &self,
        tenant_id: Uuid,
        campaign: &NhiCertificationCampaign,
        nhis: &[GovServiceAccount],
    ) -> Result<u64> {
        let mut count = 0u64;

        for nhi in nhis {
            // Resolve reviewer based on campaign settings
            let reviewer_id = self.resolve_reviewer(tenant_id, campaign, nhi).await?;

            // Create certification item
            self.create_item_record(
                tenant_id,
                campaign.id,
                nhi.id,
                reviewer_id,
                campaign.deadline,
            )
            .await?;

            count += 1;
        }

        Ok(count)
    }

    /// Resolve the reviewer for an NHI based on campaign settings.
    async fn resolve_reviewer(
        &self,
        _tenant_id: Uuid,
        campaign: &NhiCertificationCampaign,
        nhi: &GovServiceAccount,
    ) -> Result<Uuid> {
        match campaign.reviewer_type {
            NhiCertReviewerType::Owner => {
                // NHI owner certifies their own NHIs
                Ok(nhi.owner_id)
            }
            NhiCertReviewerType::BackupOwner => {
                // Use backup owner if available, otherwise fall back to primary owner
                Ok(nhi.backup_owner_id.unwrap_or(nhi.owner_id))
            }
            NhiCertReviewerType::SpecificUsers => {
                // Use first specific reviewer (could be round-robin in future)
                campaign
                    .specific_reviewers
                    .as_ref()
                    .and_then(|r| r.first().copied())
                    .ok_or_else(|| {
                        GovernanceError::ReviewerNotFound(
                            "No specific reviewers configured".to_string(),
                        )
                    })
            }
            NhiCertReviewerType::OwnerManager => {
                // TODO: Would need manager relationship lookup
                // For now, fall back to owner
                Ok(nhi.owner_id)
            }
        }
    }

    /// Check if campaign is complete and update status.
    async fn check_and_complete_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<bool> {
        let summary = self.get_campaign_summary(tenant_id, campaign_id).await?;

        if summary.pending == 0 && summary.total > 0 {
            self.update_campaign_status(tenant_id, campaign_id, NhiCertCampaignStatus::Completed)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Get campaign summary.
    pub async fn get_campaign_summary(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<NhiCertificationSummary> {
        let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'certified') as certified,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked,
                COUNT(*) FILTER (WHERE status = 'expired') as expired
            FROM gov_nhi_certification_items
            WHERE tenant_id = $1 AND campaign_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0, 0, 0, 0, 0));

        Ok(NhiCertificationSummary {
            total: row.0,
            pending: row.1,
            certified: row.2,
            revoked: row.3,
            expired: row.4,
        })
    }

    // =========================================================================
    // Database Operations (would normally be in xavyo-db models)
    // =========================================================================

    async fn create_campaign_record(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        reviewer_type: NhiCertReviewerType,
        specific_reviewers: Option<Vec<Uuid>>,
        deadline: DateTime<Utc>,
        created_by: Uuid,
    ) -> Result<NhiCertificationCampaign> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let reviewer_type_str = match reviewer_type {
            NhiCertReviewerType::Owner => "owner",
            NhiCertReviewerType::BackupOwner => "backup_owner",
            NhiCertReviewerType::SpecificUsers => "specific_users",
            NhiCertReviewerType::OwnerManager => "owner_manager",
        };

        let reviewers_json = specific_reviewers
            .as_ref()
            .and_then(|r| serde_json::to_value(r).ok());

        sqlx::query(
            r"
            INSERT INTO gov_nhi_certification_campaigns (
                id, tenant_id, name, description, status, reviewer_type,
                specific_reviewers, deadline, created_by, created_at
            )
            VALUES ($1, $2, $3, $4, 'draft', $5, $6, $7, $8, $9)
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&description)
        .bind(reviewer_type_str)
        .bind(&reviewers_json)
        .bind(deadline)
        .bind(created_by)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(NhiCertificationCampaign {
            id,
            tenant_id,
            name,
            description,
            status: NhiCertCampaignStatus::Draft,
            reviewer_type,
            specific_reviewers,
            deadline,
            created_by,
            created_at: now,
            launched_at: None,
            completed_at: None,
        })
    }

    async fn get_campaign_record(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<NhiCertificationCampaign> {
        let row: Option<(
            Uuid,
            Uuid,
            String,
            Option<String>,
            String,
            String,
            Option<serde_json::Value>,
            DateTime<Utc>,
            Uuid,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            r"
            SELECT id, tenant_id, name, description, status, reviewer_type,
                   specific_reviewers, deadline, created_by, created_at,
                   launched_at, completed_at
            FROM gov_nhi_certification_campaigns
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let row = row.ok_or(GovernanceError::CampaignNotFound(campaign_id))?;

        let status = match row.4.as_str() {
            "draft" => NhiCertCampaignStatus::Draft,
            "active" => NhiCertCampaignStatus::Active,
            "overdue" => NhiCertCampaignStatus::Overdue,
            "completed" => NhiCertCampaignStatus::Completed,
            "cancelled" => NhiCertCampaignStatus::Cancelled,
            _ => NhiCertCampaignStatus::Draft,
        };

        let reviewer_type = match row.5.as_str() {
            "owner" => NhiCertReviewerType::Owner,
            "backup_owner" => NhiCertReviewerType::BackupOwner,
            "specific_users" => NhiCertReviewerType::SpecificUsers,
            "owner_manager" => NhiCertReviewerType::OwnerManager,
            _ => NhiCertReviewerType::Owner,
        };

        let specific_reviewers = row.6.and_then(|v| serde_json::from_value(v).ok());

        Ok(NhiCertificationCampaign {
            id: row.0,
            tenant_id: row.1,
            name: row.2,
            description: row.3,
            status,
            reviewer_type,
            specific_reviewers,
            deadline: row.7,
            created_by: row.8,
            created_at: row.9,
            launched_at: row.10,
            completed_at: row.11,
        })
    }

    async fn list_campaign_records(
        &self,
        tenant_id: Uuid,
        status: Option<NhiCertCampaignStatus>,
        created_by: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<NhiCertificationCampaign>, i64)> {
        let mut query = String::from(
            r"
            SELECT id, tenant_id, name, description, status, reviewer_type,
                   specific_reviewers, deadline, created_by, created_at,
                   launched_at, completed_at
            FROM gov_nhi_certification_campaigns
            WHERE tenant_id = $1
            ",
        );

        let mut count_query = String::from(
            r"
            SELECT COUNT(*) FROM gov_nhi_certification_campaigns
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            count_query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if created_by.is_some() {
            query.push_str(&format!(" AND created_by = ${param_idx}"));
            count_query.push_str(&format!(" AND created_by = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let status_str = status.map(|s| match s {
            NhiCertCampaignStatus::Draft => "draft",
            NhiCertCampaignStatus::Active => "active",
            NhiCertCampaignStatus::Overdue => "overdue",
            NhiCertCampaignStatus::Completed => "completed",
            NhiCertCampaignStatus::Cancelled => "cancelled",
        });

        // Build and execute queries
        type CampaignRow = (
            Uuid,
            Uuid,
            String,
            Option<String>,
            String,
            String,
            Option<serde_json::Value>,
            DateTime<Utc>,
            Uuid,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        );

        let mut q = sqlx::query_as::<_, CampaignRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(s) = &status_str {
            q = q.bind(*s);
            cq = cq.bind(*s);
        }

        if let Some(cb) = created_by {
            q = q.bind(cb);
            cq = cq.bind(cb);
        }

        q = q.bind(limit).bind(offset);

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;
        let total = cq
            .fetch_one(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;

        let campaigns = rows
            .into_iter()
            .map(|row| {
                let status = match row.4.as_str() {
                    "draft" => NhiCertCampaignStatus::Draft,
                    "active" => NhiCertCampaignStatus::Active,
                    "overdue" => NhiCertCampaignStatus::Overdue,
                    "completed" => NhiCertCampaignStatus::Completed,
                    "cancelled" => NhiCertCampaignStatus::Cancelled,
                    _ => NhiCertCampaignStatus::Draft,
                };

                let reviewer_type = match row.5.as_str() {
                    "owner" => NhiCertReviewerType::Owner,
                    "backup_owner" => NhiCertReviewerType::BackupOwner,
                    "specific_users" => NhiCertReviewerType::SpecificUsers,
                    "owner_manager" => NhiCertReviewerType::OwnerManager,
                    _ => NhiCertReviewerType::Owner,
                };

                NhiCertificationCampaign {
                    id: row.0,
                    tenant_id: row.1,
                    name: row.2,
                    description: row.3,
                    status,
                    reviewer_type,
                    specific_reviewers: row.6.and_then(|v| serde_json::from_value(v).ok()),
                    deadline: row.7,
                    created_by: row.8,
                    created_at: row.9,
                    launched_at: row.10,
                    completed_at: row.11,
                }
            })
            .collect();

        Ok((campaigns, total))
    }

    async fn update_campaign_status(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        status: NhiCertCampaignStatus,
    ) -> Result<NhiCertificationCampaign> {
        let status_str = match status {
            NhiCertCampaignStatus::Draft => "draft",
            NhiCertCampaignStatus::Active => "active",
            NhiCertCampaignStatus::Overdue => "overdue",
            NhiCertCampaignStatus::Completed => "completed",
            NhiCertCampaignStatus::Cancelled => "cancelled",
        };

        let launched_at = if status == NhiCertCampaignStatus::Active {
            Some(Utc::now())
        } else {
            None
        };

        let completed_at = if status == NhiCertCampaignStatus::Completed {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(
            r"
            UPDATE gov_nhi_certification_campaigns
            SET status = $3,
                launched_at = COALESCE($4, launched_at),
                completed_at = COALESCE($5, completed_at)
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(campaign_id)
        .bind(tenant_id)
        .bind(status_str)
        .bind(launched_at)
        .bind(completed_at)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        self.get_campaign_record(tenant_id, campaign_id).await
    }

    async fn create_item_record(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        nhi_id: Uuid,
        reviewer_id: Uuid,
        _deadline: DateTime<Utc>,
    ) -> Result<NhiCertificationItem> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r"
            INSERT INTO gov_nhi_certification_items (
                id, tenant_id, campaign_id, nhi_id, reviewer_id, status, created_at
            )
            VALUES ($1, $2, $3, $4, $5, 'pending', $6)
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(campaign_id)
        .bind(nhi_id)
        .bind(reviewer_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(NhiCertificationItem {
            id,
            tenant_id,
            campaign_id,
            nhi_id,
            reviewer_id,
            status: NhiCertificationStatus::Pending,
            decision: None,
            decided_by: None,
            decided_at: None,
            comment: None,
            delegated_by: None,
            original_reviewer_id: None,
            created_at: now,
        })
    }

    async fn get_item_record(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
    ) -> Result<NhiCertificationItem> {
        let row: Option<(
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            Option<String>,
            Option<Uuid>,
            Option<Uuid>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r"
            SELECT id, tenant_id, campaign_id, nhi_id, reviewer_id, status,
                   decision, decided_by, decided_at, comment,
                   delegated_by, original_reviewer_id, created_at
            FROM gov_nhi_certification_items
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let row = row.ok_or(GovernanceError::MicroCertificationNotFound(item_id))?;

        let status = match row.5.as_str() {
            "pending" => NhiCertificationStatus::Pending,
            "certified" => NhiCertificationStatus::Certified,
            "revoked" => NhiCertificationStatus::Revoked,
            "expired" => NhiCertificationStatus::Expired,
            _ => NhiCertificationStatus::Pending,
        };

        let decision = row.6.as_ref().map(|d| match d.as_str() {
            "certify" => NhiCertificationDecision::Certify,
            "revoke" => NhiCertificationDecision::Revoke,
            "delegate" => NhiCertificationDecision::Delegate,
            _ => NhiCertificationDecision::Certify,
        });

        Ok(NhiCertificationItem {
            id: row.0,
            tenant_id: row.1,
            campaign_id: row.2,
            nhi_id: row.3,
            reviewer_id: row.4,
            status,
            decision,
            decided_by: row.7,
            decided_at: row.8,
            comment: row.9,
            delegated_by: row.10,
            original_reviewer_id: row.11,
            created_at: row.12,
        })
    }

    async fn list_item_records(
        &self,
        tenant_id: Uuid,
        campaign_id: Option<Uuid>,
        status: Option<NhiCertificationStatus>,
        reviewer_id: Option<Uuid>,
        owner_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<NhiCertificationItem>, i64)> {
        let mut query = String::from(
            r"
            SELECT i.id, i.tenant_id, i.campaign_id, i.nhi_id, i.reviewer_id, i.status,
                   i.decision, i.decided_by, i.decided_at, i.comment,
                   i.delegated_by, i.original_reviewer_id, i.created_at
            FROM gov_nhi_certification_items i
            JOIN gov_service_accounts s ON i.nhi_id = s.id AND s.tenant_id = i.tenant_id
            WHERE i.tenant_id = $1
            ",
        );

        let mut count_query = String::from(
            r"
            SELECT COUNT(*)
            FROM gov_nhi_certification_items i
            JOIN gov_service_accounts s ON i.nhi_id = s.id AND s.tenant_id = i.tenant_id
            WHERE i.tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if campaign_id.is_some() {
            query.push_str(&format!(" AND i.campaign_id = ${param_idx}"));
            count_query.push_str(&format!(" AND i.campaign_id = ${param_idx}"));
            param_idx += 1;
        }

        if status.is_some() {
            query.push_str(&format!(" AND i.status = ${param_idx}"));
            count_query.push_str(&format!(" AND i.status = ${param_idx}"));
            param_idx += 1;
        }

        if reviewer_id.is_some() {
            query.push_str(&format!(" AND i.reviewer_id = ${param_idx}"));
            count_query.push_str(&format!(" AND i.reviewer_id = ${param_idx}"));
            param_idx += 1;
        }

        if owner_id.is_some() {
            query.push_str(&format!(" AND s.owner_id = ${param_idx}"));
            count_query.push_str(&format!(" AND s.owner_id = ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY i.created_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let status_str = status.map(|s| match s {
            NhiCertificationStatus::Pending => "pending",
            NhiCertificationStatus::Certified => "certified",
            NhiCertificationStatus::Revoked => "revoked",
            NhiCertificationStatus::Expired => "expired",
        });

        type ItemRow = (
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            Option<String>,
            Option<Uuid>,
            Option<Uuid>,
            DateTime<Utc>,
        );

        let mut q = sqlx::query_as::<_, ItemRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(cid) = campaign_id {
            q = q.bind(cid);
            cq = cq.bind(cid);
        }

        if let Some(s) = &status_str {
            q = q.bind(*s);
            cq = cq.bind(*s);
        }

        if let Some(rid) = reviewer_id {
            q = q.bind(rid);
            cq = cq.bind(rid);
        }

        if let Some(oid) = owner_id {
            q = q.bind(oid);
            cq = cq.bind(oid);
        }

        q = q.bind(limit).bind(offset);

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;
        let total = cq
            .fetch_one(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;

        let items = rows
            .into_iter()
            .map(|row| {
                let status = match row.5.as_str() {
                    "pending" => NhiCertificationStatus::Pending,
                    "certified" => NhiCertificationStatus::Certified,
                    "revoked" => NhiCertificationStatus::Revoked,
                    "expired" => NhiCertificationStatus::Expired,
                    _ => NhiCertificationStatus::Pending,
                };

                let decision = row.6.as_ref().map(|d| match d.as_str() {
                    "certify" => NhiCertificationDecision::Certify,
                    "revoke" => NhiCertificationDecision::Revoke,
                    "delegate" => NhiCertificationDecision::Delegate,
                    _ => NhiCertificationDecision::Certify,
                });

                NhiCertificationItem {
                    id: row.0,
                    tenant_id: row.1,
                    campaign_id: row.2,
                    nhi_id: row.3,
                    reviewer_id: row.4,
                    status,
                    decision,
                    decided_by: row.7,
                    decided_at: row.8,
                    comment: row.9,
                    delegated_by: row.10,
                    original_reviewer_id: row.11,
                    created_at: row.12,
                }
            })
            .collect();

        Ok((items, total))
    }

    async fn update_item_decision(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        status: NhiCertificationStatus,
        decision: Option<NhiCertificationDecision>,
        decided_by: Option<Uuid>,
        decided_at: Option<DateTime<Utc>>,
        comment: Option<String>,
    ) -> Result<NhiCertificationItem> {
        let status_str = match status {
            NhiCertificationStatus::Pending => "pending",
            NhiCertificationStatus::Certified => "certified",
            NhiCertificationStatus::Revoked => "revoked",
            NhiCertificationStatus::Expired => "expired",
        };

        let decision_str = decision.map(|d| match d {
            NhiCertificationDecision::Certify => "certify",
            NhiCertificationDecision::Revoke => "revoke",
            NhiCertificationDecision::Delegate => "delegate",
        });

        sqlx::query(
            r"
            UPDATE gov_nhi_certification_items
            SET status = $3, decision = $4, decided_by = $5, decided_at = $6, comment = $7
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .bind(status_str)
        .bind(decision_str)
        .bind(decided_by)
        .bind(decided_at)
        .bind(&comment)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        self.get_item_record(tenant_id, item_id).await
    }

    async fn update_item_delegation(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        new_reviewer_id: Uuid,
        delegated_by: Option<Uuid>,
        original_reviewer_id: Option<Uuid>,
        comment: Option<String>,
    ) -> Result<NhiCertificationItem> {
        sqlx::query(
            r"
            UPDATE gov_nhi_certification_items
            SET reviewer_id = $3, delegated_by = $4, original_reviewer_id = $5, comment = $6
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .bind(new_reviewer_id)
        .bind(delegated_by)
        .bind(original_reviewer_id)
        .bind(&comment)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        self.get_item_record(tenant_id, item_id).await
    }

    // =========================================================================
    // Response Conversion
    // =========================================================================

    fn campaign_to_response(
        &self,
        campaign: NhiCertificationCampaign,
        total: i64,
        pending: i64,
        certified: i64,
        revoked: i64,
        expired: i64,
    ) -> NhiCertificationCampaignResponse {
        let completion_rate = if total == 0 {
            0.0
        } else {
            ((total - pending) as f64 / total as f64) * 100.0
        };

        NhiCertificationCampaignResponse {
            id: campaign.id,
            name: campaign.name,
            description: campaign.description,
            status: campaign.status,
            total_items: total,
            pending_items: pending,
            certified_items: certified,
            revoked_items: revoked,
            expired_items: expired,
            completion_rate,
            deadline: campaign.deadline,
            created_by: campaign.created_by,
            created_at: campaign.created_at,
            launched_at: campaign.launched_at,
            completed_at: campaign.completed_at,
        }
    }

    async fn item_to_response(
        &self,
        tenant_id: Uuid,
        item: NhiCertificationItem,
    ) -> Result<NhiCertificationItemResponse> {
        // Get NHI details
        let nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, item.nhi_id)
            .await?
            .ok_or(GovernanceError::NhiNotFound(item.nhi_id))?;

        // Get campaign deadline
        let campaign = self
            .get_campaign_record(tenant_id, item.campaign_id)
            .await?;

        Ok(NhiCertificationItemResponse {
            id: item.id,
            campaign_id: item.campaign_id,
            nhi_id: item.nhi_id,
            nhi_name: nhi.name,
            nhi_purpose: nhi.purpose,
            owner_id: nhi.owner_id,
            owner_name: None, // Would need user lookup
            reviewer_id: item.reviewer_id,
            status: item.status,
            deadline: campaign.deadline,
            decision: item.decision,
            decided_by: item.decided_by,
            decided_at: item.decided_at,
            comment: item.comment,
            created_at: item.created_at,
        })
    }

    // =========================================================================
    // Kafka Event Emission
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_campaign_launched_event(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        item_count: u64,
    ) {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::NhiCertificationCampaignLaunched;
            let event = NhiCertificationCampaignLaunched {
                campaign_id,
                tenant_id,
                item_count,
                launched_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    campaign_id = %campaign_id,
                    error = %e,
                    "Failed to publish NhiCertificationCampaignLaunched event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_decision_event(
        &self,
        tenant_id: Uuid,
        item: &NhiCertificationItem,
        nhi: &GovServiceAccount,
        decision: NhiCertificationDecision,
        decided_by: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::NhiCertificationDecisionMade;
            let event = NhiCertificationDecisionMade {
                item_id: item.id,
                campaign_id: item.campaign_id,
                nhi_id: item.nhi_id,
                tenant_id,
                decision: match decision {
                    NhiCertificationDecision::Certify => "certify".to_string(),
                    NhiCertificationDecision::Revoke => "revoke".to_string(),
                    NhiCertificationDecision::Delegate => "delegate".to_string(),
                },
                decided_by,
                decided_at: Utc::now(),
                nhi_suspended: decision == NhiCertificationDecision::Revoke,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    item_id = %item.id,
                    error = %e,
                    "Failed to publish NhiCertificationDecisionMade event"
                );
            }
        }
    }

    /// Get database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certification_status_is_decided() {
        assert!(!NhiCertificationStatus::Pending.is_decided());
        assert!(NhiCertificationStatus::Certified.is_decided());
        assert!(NhiCertificationStatus::Revoked.is_decided());
        assert!(NhiCertificationStatus::Expired.is_decided());
    }

    #[test]
    fn test_certification_decision_is_approval() {
        assert!(NhiCertificationDecision::Certify.is_approval());
        assert!(!NhiCertificationDecision::Revoke.is_approval());
        assert!(!NhiCertificationDecision::Delegate.is_approval());
    }

    #[test]
    fn test_campaign_status_can_cancel() {
        assert!(NhiCertCampaignStatus::Draft.can_cancel());
        assert!(NhiCertCampaignStatus::Active.can_cancel());
        assert!(NhiCertCampaignStatus::Overdue.can_cancel());
        assert!(!NhiCertCampaignStatus::Completed.can_cancel());
        assert!(!NhiCertCampaignStatus::Cancelled.can_cancel());
    }

    #[test]
    fn test_certification_summary_completion_rate() {
        let summary = NhiCertificationSummary {
            total: 100,
            pending: 20,
            certified: 60,
            revoked: 15,
            expired: 5,
        };
        assert_eq!(summary.completion_rate(), 80.0);

        let empty = NhiCertificationSummary {
            total: 0,
            pending: 0,
            certified: 0,
            revoked: 0,
            expired: 0,
        };
        assert_eq!(empty.completion_rate(), 0.0);
    }
}
