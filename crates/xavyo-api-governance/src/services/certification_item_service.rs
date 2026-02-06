//! Certification item service for governance API.
//!
//! Handles reviewer decisions on certification items.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CertDecisionType, CertItemFilter, CertItemStatus, CreateCertificationDecision,
    GovCertificationDecision, GovCertificationItem,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::CertificationRemediationService;

/// Minimum justification length for revocations.
const MIN_JUSTIFICATION_LENGTH: usize = 20;

/// Service for certification item operations.
pub struct CertificationItemService {
    pool: PgPool,
    remediation_service: CertificationRemediationService,
}

impl CertificationItemService {
    /// Create a new certification item service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            remediation_service: CertificationRemediationService::new(pool.clone()),
            pool,
        }
    }

    /// Get an item by ID.
    pub async fn get(&self, tenant_id: Uuid, item_id: Uuid) -> Result<GovCertificationItem> {
        GovCertificationItem::find_by_id(&self.pool, tenant_id, item_id)
            .await?
            .ok_or(GovernanceError::CertificationItemNotFound(item_id))
    }

    /// List items for a campaign.
    pub async fn list_for_campaign(
        &self,
        tenant_id: Uuid,
        campaign_id: Uuid,
        status: Option<CertItemStatus>,
        reviewer_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovCertificationItem>, i64)> {
        let filter = CertItemFilter {
            campaign_id: Some(campaign_id),
            status,
            reviewer_id,
            ..Default::default()
        };

        let items =
            GovCertificationItem::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovCertificationItem::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((items, total))
    }

    /// List pending items for a reviewer (my-certifications).
    pub async fn list_for_reviewer(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
        campaign_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovCertificationItem>, i64)> {
        let filter = CertItemFilter {
            reviewer_id: Some(reviewer_id),
            campaign_id,
            status: Some(CertItemStatus::Pending),
            ..Default::default()
        };

        let items =
            GovCertificationItem::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovCertificationItem::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((items, total))
    }

    /// Get reviewer's pending item count.
    pub async fn get_reviewer_pending_count(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
    ) -> Result<i64> {
        GovCertificationItem::get_reviewer_pending_count(&self.pool, tenant_id, reviewer_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Submit a decision for an item.
    ///
    /// If the decision is a revocation, triggers auto-remediation.
    pub async fn decide(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        user_id: Uuid,
        decision_type: CertDecisionType,
        justification: Option<String>,
    ) -> Result<(GovCertificationItem, GovCertificationDecision)> {
        // Get the item
        let item = self.get(tenant_id, item_id).await?;

        // Verify item is pending
        if !item.is_pending() {
            return Err(GovernanceError::ItemNotPending(item_id));
        }

        // Verify user is the authorized reviewer (or admin - could add admin check)
        if item.reviewer_id != user_id {
            return Err(GovernanceError::NotAuthorizedReviewer);
        }

        // Validate justification for revocations
        if decision_type == CertDecisionType::Revoked {
            let just = justification
                .as_ref()
                .ok_or(GovernanceError::RevocationJustificationRequired)?;
            if just.trim().len() < MIN_JUSTIFICATION_LENGTH {
                return Err(GovernanceError::RevocationJustificationRequired);
            }
        }

        // Update item status
        let updated_item = match decision_type {
            CertDecisionType::Approved => {
                GovCertificationItem::approve(&self.pool, tenant_id, item_id).await?
            }
            CertDecisionType::Revoked => {
                GovCertificationItem::revoke(&self.pool, tenant_id, item_id).await?
            }
        }
        .ok_or(GovernanceError::ItemNotPending(item_id))?;

        // Create decision record
        let decision_input = CreateCertificationDecision {
            item_id,
            decision_type,
            justification,
            decided_by: user_id,
        };

        let decision = GovCertificationDecision::create(&self.pool, decision_input).await?;

        // If revoked, trigger remediation
        if decision_type == CertDecisionType::Revoked {
            if let Some(assignment_id) = item.assignment_id {
                self.remediation_service
                    .revoke_assignment(tenant_id, assignment_id, &item, &decision)
                    .await?;
            }
        }

        Ok((updated_item, decision))
    }

    /// Reassign an item to a different reviewer (admin action).
    pub async fn reassign(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        new_reviewer_id: Uuid,
    ) -> Result<GovCertificationItem> {
        // Get the item
        let item = self.get(tenant_id, item_id).await?;

        // Verify item is pending
        if !item.is_pending() {
            return Err(GovernanceError::ItemNotPending(item_id));
        }

        GovCertificationItem::reassign(&self.pool, tenant_id, item_id, new_reviewer_id)
            .await?
            .ok_or(GovernanceError::ItemNotPending(item_id))
    }

    /// Get the decision for an item.
    pub async fn get_decision(&self, item_id: Uuid) -> Result<Option<GovCertificationDecision>> {
        GovCertificationDecision::find_by_item_id(&self.pool, item_id)
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
    fn test_min_justification_length() {
        assert_eq!(MIN_JUSTIFICATION_LENGTH, 20);
    }

    #[test]
    fn test_justification_validation() {
        let short = "Too short";
        let valid = "This is a valid justification for revoking access.";

        assert!(short.trim().len() < MIN_JUSTIFICATION_LENGTH);
        assert!(valid.trim().len() >= MIN_JUSTIFICATION_LENGTH);
    }

    #[test]
    fn test_decision_type_revoked() {
        let approved = CertDecisionType::Approved;
        let revoked = CertDecisionType::Revoked;

        assert!(!approved.is_revoked());
        assert!(revoked.is_revoked());
    }

    #[test]
    fn test_item_status_pending() {
        let pending = CertItemStatus::Pending;
        let approved = CertItemStatus::Approved;
        let revoked = CertItemStatus::Revoked;
        let skipped = CertItemStatus::Skipped;

        assert!(pending.is_pending());
        assert!(!approved.is_pending());
        assert!(!revoked.is_pending());
        assert!(!skipped.is_pending());
    }
}
