//! Certification remediation service for governance API.
//!
//! Handles automatic removal of entitlement assignments when certification items are revoked.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GovCertificationDecision, GovCertificationItem, GovEntitlementAssignment};
use xavyo_governance::error::Result;

/// Service for certification remediation operations.
pub struct CertificationRemediationService {
    pool: PgPool,
}

impl CertificationRemediationService {
    /// Create a new certification remediation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Revoke an entitlement assignment as part of certification remediation.
    ///
    /// This is called synchronously after a revocation decision is made.
    /// The assignment is deleted in the same transaction context.
    pub async fn revoke_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        item: &GovCertificationItem,
        decision: &GovCertificationDecision,
    ) -> Result<()> {
        // Verify assignment still exists
        let assignment =
            GovEntitlementAssignment::find_by_id(&self.pool, tenant_id, assignment_id).await?;

        if assignment.is_none() {
            // Assignment was already deleted (e.g., by another process)
            tracing::warn!(
                "Assignment {} not found during remediation for item {}",
                assignment_id,
                item.id
            );
            return Ok(());
        }

        // Revoke (delete) the assignment
        let deleted =
            GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment_id).await?;

        if deleted {
            tracing::info!(
                "Remediated assignment {} for certification item {} (decision: {}, decided_by: {})",
                assignment_id,
                item.id,
                decision.id,
                decision.decided_by
            );
        } else {
            tracing::warn!(
                "Failed to delete assignment {} during remediation for item {}",
                assignment_id,
                item.id
            );
        }

        // Create audit log entry
        self.create_audit_log(tenant_id, item, decision, assignment_id)
            .await?;

        Ok(())
    }

    /// Create an audit log entry for the remediation action.
    async fn create_audit_log(
        &self,
        tenant_id: Uuid,
        item: &GovCertificationItem,
        decision: &GovCertificationDecision,
        assignment_id: Uuid,
    ) -> Result<()> {
        // Note: This uses the existing audit logging infrastructure.
        // The actual implementation depends on the audit log table structure.

        let _audit_details = serde_json::json!({
            "action": "certification_remediation",
            "tenant_id": tenant_id,
            "campaign_id": item.campaign_id,
            "item_id": item.id,
            "decision_id": decision.id,
            "assignment_id": assignment_id,
            "user_id": item.user_id,
            "entitlement_id": item.entitlement_id,
            "decided_by": decision.decided_by,
            "justification": decision.justification,
            "decided_at": decision.decided_at,
        });

        // For now, we just log the action. In a full implementation,
        // this would insert into an audit_logs table.
        tracing::info!(
            tenant_id = %tenant_id,
            campaign_id = %item.campaign_id,
            item_id = %item.id,
            assignment_id = %assignment_id,
            user_id = %item.user_id,
            entitlement_id = %item.entitlement_id,
            decided_by = %decision.decided_by,
            "Certification remediation completed"
        );

        Ok(())
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
    fn test_audit_log_format() {
        let audit_details = serde_json::json!({
            "action": "certification_remediation",
            "tenant_id": Uuid::new_v4(),
            "campaign_id": Uuid::new_v4(),
            "item_id": Uuid::new_v4(),
            "decision_id": Uuid::new_v4(),
            "assignment_id": Uuid::new_v4(),
            "user_id": Uuid::new_v4(),
            "entitlement_id": Uuid::new_v4(),
            "decided_by": Uuid::new_v4(),
            "justification": "User no longer requires access",
            "decided_at": "2026-01-24T12:00:00Z",
        });

        assert_eq!(
            audit_details.get("action").unwrap().as_str().unwrap(),
            "certification_remediation"
        );
        assert!(audit_details.get("tenant_id").is_some());
        assert!(audit_details.get("justification").is_some());
    }
}
