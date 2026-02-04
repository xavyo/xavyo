//! Access request service for governance API.
//!
//! Handles the lifecycle of access requests from submission through approval.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    AccessRequestFilter, CreateGovAccessRequest, GovAccessRequest, GovApprovalWorkflow,
    GovEntitlement, GovEntitlementAssignment, GovRequestStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::SodViolationSummary;
use crate::services::{SodEnforcementService, SodViolationInfo};

/// Default request expiration in days.
const DEFAULT_REQUEST_EXPIRY_DAYS: i64 = 14;

/// Minimum justification length.
const MIN_JUSTIFICATION_LENGTH: usize = 20;

/// Service for access request operations.
pub struct AccessRequestService {
    pool: PgPool,
    sod_enforcement_service: SodEnforcementService,
}

impl AccessRequestService {
    /// Create a new access request service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            sod_enforcement_service: SodEnforcementService::new(pool.clone()),
            pool,
        }
    }

    /// Submit a new access request.
    ///
    /// Performs validation, `SoD` pre-check, and creates the request.
    pub async fn create_request(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        entitlement_id: Uuid,
        justification: String,
        requested_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<GovAccessRequest> {
        // Validate justification length
        if justification.trim().len() < MIN_JUSTIFICATION_LENGTH {
            return Err(GovernanceError::JustificationTooShort);
        }

        // Validate requested expiration if provided
        if let Some(expires_at) = requested_expires_at {
            if expires_at <= Utc::now() {
                return Err(GovernanceError::InvalidRequestedExpiration);
            }
        }

        // Verify entitlement exists
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        if !entitlement.is_active() {
            return Err(GovernanceError::Validation(
                "Cannot request inactive entitlement".to_string(),
            ));
        }

        // Check for existing pending request
        if GovAccessRequest::find_pending_for_user_entitlement(
            &self.pool,
            tenant_id,
            requester_id,
            entitlement_id,
        )
        .await?
        .is_some()
        {
            return Err(GovernanceError::AccessRequestAlreadyExists);
        }

        // Check if user already has this entitlement assigned
        let existing_assignment = GovEntitlementAssignment::find_by_target(
            &self.pool,
            tenant_id,
            entitlement_id,
            xavyo_db::GovAssignmentTargetType::User,
            requester_id,
        )
        .await?;

        if existing_assignment.is_some() {
            return Err(GovernanceError::EntitlementAlreadyAssigned);
        }

        // Perform SoD pre-check (warn but don't block)
        let sod_result = self
            .sod_enforcement_service
            .check_assignment(tenant_id, requester_id, entitlement_id, true)
            .await?;

        let has_sod_warning = !sod_result.violations.is_empty();
        let sod_violations = if has_sod_warning {
            Some(serde_json::to_value(Self::convert_sod_violations(
                &sod_result.violations,
            ))?)
        } else {
            None
        };

        // Find applicable workflow
        let workflow = self
            .find_workflow_for_entitlement(tenant_id, &entitlement)
            .await?;
        let workflow_id = workflow.as_ref().map(|w| w.id);

        // Set request expiration
        let expires_at = Some(Utc::now() + Duration::days(DEFAULT_REQUEST_EXPIRY_DAYS));

        // Create the request
        let input = CreateGovAccessRequest {
            requester_id,
            entitlement_id,
            workflow_id,
            justification,
            requested_expires_at,
            has_sod_warning,
            sod_violations,
            expires_at,
        };

        let request = GovAccessRequest::create(&self.pool, tenant_id, input).await?;

        Ok(request)
    }

    /// Convert `SoD` violation info to summary format for storage.
    fn convert_sod_violations(violations: &[SodViolationInfo]) -> Vec<SodViolationSummary> {
        violations
            .iter()
            .map(|v| SodViolationSummary {
                rule_id: v.rule_id,
                rule_name: v.rule_name.clone(),
                severity: v.severity,
                conflicting_entitlement_id: v.conflicting_entitlement_id,
            })
            .collect()
    }

    /// Find the applicable workflow for an entitlement.
    ///
    /// Priority: entitlement-specific → application-default → tenant-default
    async fn find_workflow_for_entitlement(
        &self,
        tenant_id: Uuid,
        _entitlement: &GovEntitlement,
    ) -> Result<Option<GovApprovalWorkflow>> {
        // For now, just use tenant default workflow
        // Future: check entitlement.workflow_id, then application.default_workflow_id
        GovApprovalWorkflow::find_default(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List requests for the authenticated user.
    pub async fn list_my_requests(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        status: Option<GovRequestStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovAccessRequest>, i64)> {
        let filter = AccessRequestFilter {
            requester_id: Some(user_id),
            status,
            ..Default::default()
        };

        let requests =
            GovAccessRequest::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovAccessRequest::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((requests, total))
    }

    /// Get a specific request by ID.
    pub async fn get_request(&self, tenant_id: Uuid, request_id: Uuid) -> Result<GovAccessRequest> {
        GovAccessRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::AccessRequestNotFound(request_id))
    }

    /// Cancel a pending request.
    ///
    /// Only the requester can cancel their own pending request.
    pub async fn cancel_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        user_id: Uuid,
    ) -> Result<GovAccessRequest> {
        let request = self.get_request(tenant_id, request_id).await?;

        // Verify the user is the requester
        if request.requester_id != user_id {
            return Err(GovernanceError::NotAuthorizedApprover);
        }

        // Verify request is in pending state
        if !request.status.is_pending() {
            return Err(GovernanceError::CannotCancelNonPendingRequest);
        }

        GovAccessRequest::update_status(
            &self.pool,
            tenant_id,
            request_id,
            GovRequestStatus::Cancelled,
        )
        .await?
        .ok_or(GovernanceError::AccessRequestNotFound(request_id))
    }

    /// Expire stale requests (for background job).
    pub async fn expire_stale_requests(&self) -> Result<u64> {
        let now = Utc::now();
        GovAccessRequest::expire_stale(&self.pool, now)
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
    use xavyo_db::GovSodSeverity;

    #[test]
    fn test_min_justification_length() {
        assert_eq!(MIN_JUSTIFICATION_LENGTH, 20);
    }

    #[test]
    fn test_default_request_expiry() {
        assert_eq!(DEFAULT_REQUEST_EXPIRY_DAYS, 14);
    }

    #[test]
    fn test_convert_sod_violations() {
        let violations = vec![SodViolationInfo {
            rule_id: Uuid::new_v4(),
            rule_name: "Test Rule".to_string(),
            severity: GovSodSeverity::High,
            conflicting_entitlement_id: Uuid::new_v4(),
            has_exemption: false,
            source: None,
        }];

        let summaries = AccessRequestService::convert_sod_violations(&violations);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].rule_name, "Test Rule");
    }

    #[test]
    fn test_convert_multiple_sod_violations() {
        let violations = vec![
            SodViolationInfo {
                rule_id: Uuid::new_v4(),
                rule_name: "SoD Rule 1".to_string(),
                severity: GovSodSeverity::High,
                conflicting_entitlement_id: Uuid::new_v4(),
                has_exemption: false,
                source: None,
            },
            SodViolationInfo {
                rule_id: Uuid::new_v4(),
                rule_name: "SoD Rule 2".to_string(),
                severity: GovSodSeverity::Critical,
                conflicting_entitlement_id: Uuid::new_v4(),
                has_exemption: true,
                source: None,
            },
        ];

        let summaries = AccessRequestService::convert_sod_violations(&violations);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].rule_name, "SoD Rule 1");
        assert_eq!(summaries[1].rule_name, "SoD Rule 2");
        assert!(matches!(summaries[0].severity, GovSodSeverity::High));
        assert!(matches!(summaries[1].severity, GovSodSeverity::Critical));
    }

    #[test]
    fn test_convert_empty_sod_violations() {
        let violations: Vec<SodViolationInfo> = vec![];
        let summaries = AccessRequestService::convert_sod_violations(&violations);
        assert!(summaries.is_empty());
    }

    #[test]
    fn test_justification_length_validation() {
        // Too short (less than 20 chars)
        let short_justification = "Too short";
        assert!(short_justification.trim().len() < MIN_JUSTIFICATION_LENGTH);

        // Exactly 20 chars
        let valid_justification = "12345678901234567890";
        assert!(valid_justification.trim().len() >= MIN_JUSTIFICATION_LENGTH);

        // Longer justification
        let long_justification =
            "This is a proper business justification explaining why access is needed.";
        assert!(long_justification.trim().len() >= MIN_JUSTIFICATION_LENGTH);
    }

    #[test]
    fn test_request_status_is_pending() {
        assert!(GovRequestStatus::Pending.is_pending());
        assert!(GovRequestStatus::PendingApproval.is_pending());
        assert!(!GovRequestStatus::Approved.is_pending());
        assert!(!GovRequestStatus::Provisioned.is_pending());
        assert!(!GovRequestStatus::Rejected.is_pending());
        assert!(!GovRequestStatus::Cancelled.is_pending());
        assert!(!GovRequestStatus::Expired.is_pending());
        assert!(!GovRequestStatus::Failed.is_pending());
    }

    #[test]
    fn test_request_expiration_calculation() {
        let now = Utc::now();
        let expires_at = now + Duration::days(DEFAULT_REQUEST_EXPIRY_DAYS);

        assert!(expires_at > now);
        assert!((expires_at - now).num_days() == DEFAULT_REQUEST_EXPIRY_DAYS);
    }

    #[test]
    fn test_sod_violation_summary_fields() {
        let rule_id = Uuid::new_v4();
        let conflicting_id = Uuid::new_v4();

        let summary = SodViolationSummary {
            rule_id,
            rule_name: "Test SoD Rule".to_string(),
            severity: GovSodSeverity::Medium,
            conflicting_entitlement_id: conflicting_id,
        };

        assert_eq!(summary.rule_id, rule_id);
        assert_eq!(summary.rule_name, "Test SoD Rule");
        assert!(matches!(summary.severity, GovSodSeverity::Medium));
        assert_eq!(summary.conflicting_entitlement_id, conflicting_id);
    }
}
