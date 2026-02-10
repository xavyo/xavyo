//! Certification campaign service for governance API.
//!
//! Handles the lifecycle of certification campaigns from creation through completion.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CampaignFilter, CertCampaignStatus, CertItemSummary, CertReviewerType, CertScopeType,
    CreateCertificationCampaign, CreateCertificationItem, GovApplication, GovCertificationCampaign,
    GovCertificationItem, GovEntitlement, GovEntitlementAssignment, UpdateCertificationCampaign,
    User,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::ScopeConfig;

/// Service for certification campaign operations.
pub struct CertificationCampaignService {
    pool: PgPool,
}

impl CertificationCampaignService {
    /// Create a new certification campaign service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new certification campaign.
    ///
    /// The campaign is created in Draft status and can be configured before launching.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        scope_type: CertScopeType,
        scope_config: Option<ScopeConfig>,
        reviewer_type: CertReviewerType,
        specific_reviewers: Option<Vec<Uuid>>,
        deadline: chrono::DateTime<Utc>,
        created_by: Uuid,
    ) -> Result<GovCertificationCampaign> {
        // Validate deadline is in the future
        if deadline <= Utc::now() {
            return Err(GovernanceError::DeadlineInPast);
        }

        // Validate specific reviewers if reviewer type requires them
        if reviewer_type == CertReviewerType::SpecificUsers
            && specific_reviewers
                .as_ref()
                .is_none_or(std::vec::Vec::is_empty)
        {
            return Err(GovernanceError::SpecificReviewersRequired);
        }

        // Check for duplicate name
        if GovCertificationCampaign::find_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::CampaignNameExists(name));
        }

        // Convert scope config to JSON
        let scope_config_json = scope_config
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;

        let input = CreateCertificationCampaign {
            name,
            description,
            scope_type,
            scope_config: scope_config_json,
            reviewer_type,
            specific_reviewers,
            deadline,
            created_by,
        };

        let campaign = GovCertificationCampaign::create(&self.pool, tenant_id, input).await?;

        Ok(campaign)
    }

    /// Get a campaign by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<GovCertificationCampaign> {
        GovCertificationCampaign::find_by_id(&self.pool, tenant_id, campaign_id)
            .await?
            .ok_or(GovernanceError::CampaignNotFound(campaign_id))
    }

    /// List campaigns for a tenant.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        status: Option<CertCampaignStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovCertificationCampaign>, i64)> {
        let filter = CampaignFilter {
            status,
            ..Default::default()
        };

        let campaigns =
            GovCertificationCampaign::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            GovCertificationCampaign::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((campaigns, total))
    }

    /// Update a campaign (only allowed in draft status).
    pub async fn update(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        name: Option<String>,
        description: Option<String>,
        deadline: Option<chrono::DateTime<Utc>>,
    ) -> Result<GovCertificationCampaign> {
        // Get existing campaign
        let campaign = self.get(tenant_id, campaign_id).await?;

        // Verify campaign is in draft status
        if !campaign.is_draft() {
            return Err(GovernanceError::CampaignNotDraft(campaign_id));
        }

        // Validate deadline if being updated
        if let Some(ref dl) = deadline {
            if *dl <= Utc::now() {
                return Err(GovernanceError::DeadlineInPast);
            }
        }

        // Check for duplicate name if being updated
        if let Some(ref new_name) = name {
            if new_name != &campaign.name
                && GovCertificationCampaign::find_by_name(&self.pool, tenant_id, new_name)
                    .await?
                    .is_some()
            {
                return Err(GovernanceError::CampaignNameExists(new_name.clone()));
            }
        }

        let input = UpdateCertificationCampaign {
            name,
            description,
            deadline,
        };

        GovCertificationCampaign::update(&self.pool, tenant_id, campaign_id, input)
            .await?
            .ok_or(GovernanceError::CampaignNotDraft(campaign_id))
    }

    /// Delete a draft campaign.
    pub async fn delete(&self, tenant_id: Uuid, campaign_id: Uuid) -> Result<()> {
        // Get existing campaign
        let campaign = self.get(tenant_id, campaign_id).await?;

        // Verify campaign is in draft status
        if !campaign.is_draft() {
            return Err(GovernanceError::CannotDeleteNonDraftCampaign);
        }

        if !GovCertificationCampaign::delete(&self.pool, tenant_id, campaign_id).await? {
            return Err(GovernanceError::CampaignNotFound(campaign_id));
        }

        Ok(())
    }

    /// Launch a campaign.
    ///
    /// This generates certification items from current entitlement assignments
    /// based on the campaign scope and transitions the campaign to Active status.
    pub async fn launch(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<GovCertificationCampaign> {
        // Get existing campaign
        let campaign = self.get(tenant_id, campaign_id).await?;

        // Verify campaign is in draft status
        if !campaign.is_draft() {
            return Err(GovernanceError::CampaignNotDraft(campaign_id));
        }

        // Generate certification items
        let items_created = self
            .generate_items_for_campaign(tenant_id, &campaign)
            .await?;

        // Verify at least one item was generated
        if items_created == 0 {
            return Err(GovernanceError::CampaignNoItems);
        }

        // Launch the campaign
        GovCertificationCampaign::launch(&self.pool, tenant_id, campaign_id)
            .await?
            .ok_or(GovernanceError::CampaignNotDraft(campaign_id))
    }

    /// Generate certification items for a campaign based on its scope.
    ///
    /// **Snapshot semantics**: Items are generated from assignments that exist at launch time.
    /// Assignments created after launch are NOT retroactively added to the campaign.
    /// This is by design — each campaign represents a point-in-time access review.
    /// New assignments will be covered by subsequent campaigns.
    async fn generate_items_for_campaign(
        &self,
        tenant_id: Uuid,
        campaign: &GovCertificationCampaign,
    ) -> Result<u64> {
        // Get assignments based on scope
        let assignments = self.get_assignments_for_scope(tenant_id, campaign).await?;

        if assignments.is_empty() {
            return Ok(0);
        }

        // Convert assignments to certification items
        let mut items: Vec<CreateCertificationItem> = Vec::new();
        let mut skipped_count: u64 = 0;

        for (idx, assignment) in assignments.iter().enumerate() {
            // Skip if there's already a pending item for this user-entitlement in this campaign
            if GovCertificationItem::exists_pending_for_user_entitlement(
                &self.pool,
                tenant_id,
                campaign.id,
                assignment.target_id,
                assignment.entitlement_id,
            )
            .await?
            {
                skipped_count += 1;
                continue;
            }

            // Resolve reviewer
            let reviewer_id = match self
                .resolve_reviewer_for_assignment(tenant_id, campaign, assignment, idx)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    // Log warning but continue with other assignments
                    tracing::warn!(
                        "Failed to resolve reviewer for assignment {}: {}",
                        assignment.id,
                        e
                    );
                    skipped_count += 1;
                    continue;
                }
            };

            // Create snapshot of assignment
            let snapshot = serde_json::json!({
                "assignment_id": assignment.id,
                "assigned_at": assignment.assigned_at,
                "assigned_by": assignment.assigned_by,
                "justification": assignment.justification,
                "expires_at": assignment.expires_at,
            });

            items.push(CreateCertificationItem {
                campaign_id: campaign.id,
                assignment_id: Some(assignment.id),
                user_id: assignment.target_id,
                entitlement_id: assignment.entitlement_id,
                reviewer_id,
                assignment_snapshot: snapshot,
            });
        }

        if skipped_count > 0 {
            tracing::warn!(
                campaign_id = %campaign.id,
                skipped_count,
                "Skipped {skipped_count} assignments during campaign item generation"
            );
        }

        if items.is_empty() {
            return Ok(0);
        }

        // Bulk create items
        GovCertificationItem::bulk_create(&self.pool, tenant_id, items)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get assignments matching the campaign scope.
    async fn get_assignments_for_scope(
        &self,
        tenant_id: Uuid,
        campaign: &GovCertificationCampaign,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        let scope_config: Option<ScopeConfig> = campaign
            .scope_config
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        match campaign.scope_type {
            CertScopeType::AllUsers => {
                // Get all active assignments
                self.get_all_active_assignments(tenant_id).await
            }
            CertScopeType::Application => {
                let app_id = scope_config.and_then(|c| c.application_id).ok_or_else(|| {
                    GovernanceError::Validation(
                        "Application ID required for application scope".to_string(),
                    )
                })?;
                self.get_assignments_for_application(tenant_id, app_id)
                    .await
            }
            CertScopeType::Entitlement => {
                let ent_id = scope_config.and_then(|c| c.entitlement_id).ok_or_else(|| {
                    GovernanceError::Validation(
                        "Entitlement ID required for entitlement scope".to_string(),
                    )
                })?;
                self.get_assignments_for_entitlement(tenant_id, ent_id)
                    .await
            }
            CertScopeType::Department => {
                let dept = scope_config.and_then(|c| c.department).ok_or_else(|| {
                    GovernanceError::Validation(
                        "Department required for department scope".to_string(),
                    )
                })?;
                self.get_assignments_for_department(tenant_id, &dept).await
            }
        }
    }

    /// Get all active user assignments.
    /// Safety limit of 50,000 to prevent unbounded memory growth.
    async fn get_all_active_assignments(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        // Get all active user assignments (not group assignments for certification).
        // JOIN gov_entitlements to ensure the referenced entitlement still exists,
        // preventing FK violations when creating certification items.
        sqlx::query_as::<_, GovEntitlementAssignment>(
            r"
            SELECT a.* FROM gov_entitlement_assignments a
            JOIN gov_entitlements e ON a.entitlement_id = e.id AND e.tenant_id = $1
            WHERE a.tenant_id = $1
              AND a.target_type = 'user'
              AND a.status = 'active'
            ORDER BY a.created_at
            LIMIT 50000
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)
    }

    /// Get assignments for a specific application.
    async fn get_assignments_for_application(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        sqlx::query_as::<_, GovEntitlementAssignment>(
            r"
            SELECT a.* FROM gov_entitlement_assignments a
            JOIN gov_entitlements e ON a.entitlement_id = e.id
            WHERE a.tenant_id = $1
              AND e.application_id = $2
              AND a.target_type = 'user'
              AND a.status = 'active'
            ORDER BY a.created_at
            LIMIT 50000
            ",
        )
        .bind(tenant_id)
        .bind(application_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)
    }

    /// Get assignments for a specific entitlement.
    async fn get_assignments_for_entitlement(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        sqlx::query_as::<_, GovEntitlementAssignment>(
            r"
            SELECT * FROM gov_entitlement_assignments
            WHERE tenant_id = $1
              AND entitlement_id = $2
              AND target_type = 'user'
              AND status = 'active'
            ORDER BY created_at
            LIMIT 50000
            ",
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)
    }

    /// Get assignments for users in a specific department.
    async fn get_assignments_for_department(
        &self,
        tenant_id: Uuid,
        department: &str,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        // Note: This assumes users have a department field. Adjust based on actual schema.
        sqlx::query_as::<_, GovEntitlementAssignment>(
            r"
            SELECT a.* FROM gov_entitlement_assignments a
            JOIN users u ON a.target_id = u.id
            WHERE a.tenant_id = $1
              AND u.department = $2
              AND a.target_type = 'user'
              AND a.status = 'active'
            ORDER BY a.created_at
            LIMIT 50000
            ",
        )
        .bind(tenant_id)
        .bind(department)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)
    }

    /// Resolve the reviewer for an assignment based on campaign reviewer type.
    async fn resolve_reviewer_for_assignment(
        &self,
        tenant_id: Uuid,
        campaign: &GovCertificationCampaign,
        assignment: &GovEntitlementAssignment,
        item_index: usize,
    ) -> Result<Uuid> {
        match campaign.reviewer_type {
            CertReviewerType::UserManager => {
                // Get user's manager
                self.get_user_manager(tenant_id, assignment.target_id).await
            }
            CertReviewerType::ApplicationOwner => {
                // Get application owner for this entitlement
                self.get_application_owner(tenant_id, assignment.entitlement_id)
                    .await
            }
            CertReviewerType::EntitlementOwner => {
                // Get entitlement owner
                self.get_entitlement_owner(tenant_id, assignment.entitlement_id)
                    .await
            }
            CertReviewerType::SpecificUsers => {
                // Round-robin across configured reviewers
                let reviewers = &campaign.specific_reviewers;
                if reviewers.is_empty() {
                    return Err(GovernanceError::ReviewerNotFound(
                        "No specific reviewers configured".to_string(),
                    ));
                }
                Ok(reviewers[item_index % reviewers.len()])
            }
        }
    }

    /// Get a user's manager from their `manager_id` field.
    async fn get_user_manager(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Uuid> {
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        match user.and_then(|u| u.manager_id) {
            Some(manager_id) => Ok(manager_id),
            None => Err(GovernanceError::ReviewerNotFound(format!(
                "User {user_id} has no manager assigned"
            ))),
        }
    }

    /// Get the application owner for an entitlement.
    async fn get_application_owner(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<Uuid> {
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        let application =
            GovApplication::find_by_id(&self.pool, tenant_id, entitlement.application_id)
                .await?
                .ok_or(GovernanceError::ApplicationNotFound(
                    entitlement.application_id,
                ))?;

        application.owner_id.ok_or_else(|| {
            GovernanceError::ReviewerNotFound(format!(
                "Application {} has no owner assigned",
                entitlement.application_id
            ))
        })
    }

    /// Get the entitlement owner.
    async fn get_entitlement_owner(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<Uuid> {
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        entitlement.owner_id.ok_or_else(|| {
            GovernanceError::ReviewerNotFound(format!(
                "Entitlement {entitlement_id} has no owner assigned"
            ))
        })
    }

    /// Cancel a campaign.
    pub async fn cancel(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<GovCertificationCampaign> {
        let campaign = self.get(tenant_id, campaign_id).await?;

        if !campaign.status.can_cancel() {
            return Err(GovernanceError::CannotCancelCampaign(format!(
                "{:?}",
                campaign.status
            )));
        }

        GovCertificationCampaign::cancel(&self.pool, tenant_id, campaign_id)
            .await?
            .ok_or(GovernanceError::CampaignNotFound(campaign_id))
    }

    /// Get campaign progress summary.
    pub async fn get_progress(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<CertItemSummary> {
        // Verify campaign exists
        let _ = self.get(tenant_id, campaign_id).await?;

        GovCertificationItem::get_campaign_summary(&self.pool, tenant_id, campaign_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Check if campaign should be marked as completed.
    ///
    /// Returns true if all items are decided and campaign status changed.
    pub async fn check_and_complete_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<bool> {
        let summary = self.get_progress(tenant_id, campaign_id).await?;

        if summary.pending == 0 && summary.total > 0 {
            GovCertificationCampaign::complete(&self.pool, tenant_id, campaign_id).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Check and mark overdue campaigns (for background job).
    pub async fn mark_overdue_campaigns(&self) -> Result<u64> {
        GovCertificationCampaign::mark_overdue(&self.pool, Utc::now())
            .await
            .map_err(GovernanceError::Database)
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
    fn test_reviewer_type_specific_users_requires_list() {
        // This is a validation test - specific_users type needs reviewers
        let reviewer_type = CertReviewerType::SpecificUsers;
        let specific_reviewers: Option<Vec<Uuid>> = None;

        let requires = reviewer_type == CertReviewerType::SpecificUsers
            && specific_reviewers.as_ref().is_none_or(|r| r.is_empty());

        assert!(requires);
    }

    #[test]
    fn test_scope_types() {
        let all_users = CertScopeType::AllUsers;
        let app = CertScopeType::Application;
        let ent = CertScopeType::Entitlement;
        let dept = CertScopeType::Department;

        // Just verify they can be compared
        assert_ne!(all_users, app);
        assert_ne!(app, ent);
        assert_ne!(ent, dept);
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
    fn test_assignment_snapshot_format() {
        let snapshot = serde_json::json!({
            "assignment_id": Uuid::new_v4(),
            "assigned_at": "2026-01-24T00:00:00Z",
            "assigned_by": Uuid::new_v4(),
            "justification": "Test justification",
            "expires_at": null,
        });

        assert!(snapshot.get("assignment_id").is_some());
        assert!(snapshot.get("assigned_at").is_some());
        assert!(snapshot.get("justification").is_some());
    }
}
