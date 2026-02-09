//! License Assignment Service (F065).
//!
//! Provides business logic for managing license assignments including
//! individual and bulk assignment, deallocation, reclamation, and listing.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicenseAssignment, GovLicenseAssignment, GovLicenseIncompatibility, GovLicensePool,
    IncompatibilityViolation, LicenseAssignmentFilter, LicensePoolStatus, LicenseReclaimReason,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::LicenseAuditService;
use crate::models::license::{
    AssignLicenseRequest, BulkAssignLicenseRequest, BulkOperationFailure, BulkOperationResult,
    BulkReclaimLicenseRequest, LicenseAssignmentListResponse, LicenseAssignmentResponse,
    ListLicenseAssignmentsParams,
};

// ============================================================================
// Pure Business Logic Functions
// ============================================================================

/// Validate that a pool's status allows new assignments.
///
/// Returns an error if the pool is Archived or Expired.
pub(crate) fn validate_pool_status_for_assignment(
    status: LicensePoolStatus,
    pool_id: Uuid,
) -> Result<()> {
    match status {
        LicensePoolStatus::Archived | LicensePoolStatus::Expired => {
            Err(GovernanceError::LicensePoolArchived(pool_id))
        }
        LicensePoolStatus::Active => Ok(()),
    }
}

/// Format incompatibility violations into a human-readable string.
///
/// Each violation is formatted as "Incompatible with '<`pool_name`>': <reason>"
/// and multiple violations are joined with "; ".
pub(crate) fn format_violation_message(violations: &[IncompatibilityViolation]) -> String {
    violations
        .iter()
        .map(|v| format!("Incompatible with '{}': {}", v.existing_pool_name, v.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Enforce pagination limits on list queries.
///
/// Clamps `limit` to the range [1, 100] and ensures `offset` is non-negative.
pub(crate) fn enforce_list_limits(limit: i64, offset: i64) -> (i64, i64) {
    (limit.clamp(1, 100), offset.max(0))
}

/// Compute the list of successful user IDs from a bulk operation.
///
/// Filters out any user IDs that appear in the failures list.
pub(crate) fn build_successful_user_ids(
    all_user_ids: &[Uuid],
    failures: &[BulkOperationFailure],
) -> Vec<Uuid> {
    all_user_ids
        .iter()
        .filter(|uid| !failures.iter().any(|f| f.item_id == **uid))
        .copied()
        .collect()
}

/// Build a `BulkOperationResult` from success count and failures.
pub(crate) fn aggregate_bulk_result(
    success_count: i32,
    failures: Vec<BulkOperationFailure>,
) -> BulkOperationResult {
    let failure_count = failures.len() as i32;
    BulkOperationResult {
        success_count,
        failure_count,
        failures,
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service for license assignment operations.
pub struct LicenseAssignmentService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

impl LicenseAssignmentService {
    /// Create a new license assignment service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    /// Assign a license from a pool to a user.
    ///
    /// Validates pool existence, capacity, duplicate assignment, and
    /// incompatibility rules before creating the assignment.
    /// The capacity increment and assignment creation are wrapped in a
    /// transaction to prevent TOCTOU race conditions.
    pub async fn assign(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: AssignLicenseRequest,
    ) -> Result<LicenseAssignmentResponse> {
        // 1. Check pool exists and is active
        let license_pool =
            GovLicensePool::find_by_id(&self.pool, tenant_id, request.license_pool_id)
                .await?
                .ok_or_else(|| GovernanceError::LicensePoolNotFound(request.license_pool_id))?;

        validate_pool_status_for_assignment(license_pool.status, request.license_pool_id)?;

        // 2. Check user doesn't already have an active assignment from this pool
        if let Some(_existing) = GovLicenseAssignment::find_active_by_user_and_pool(
            &self.pool,
            tenant_id,
            request.user_id,
            request.license_pool_id,
        )
        .await?
        {
            return Err(GovernanceError::LicenseAlreadyAssigned);
        }

        // 3. Check incompatibility rules
        let violations = GovLicenseIncompatibility::check_user_violations(
            &self.pool,
            tenant_id,
            request.user_id,
            request.license_pool_id,
        )
        .await?;

        if !violations.is_empty() {
            let message = format_violation_message(&violations);
            return Err(GovernanceError::LicenseIncompatibilityConflict(message));
        }

        // 4+5. Atomically increment pool capacity and create assignment in a transaction.
        // This prevents a leaked slot if the assignment INSERT fails after the
        // capacity has been incremented.
        let mut tx = self.pool.begin().await.map_err(GovernanceError::Database)?;

        GovLicensePool::increment_allocated_in_tx(&mut tx, tenant_id, request.license_pool_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::LicensePoolNoCapacity(request.license_pool_id))?;

        let input = CreateGovLicenseAssignment {
            license_pool_id: request.license_pool_id,
            user_id: request.user_id,
            assigned_by: actor_id,
            source: request.source,
            entitlement_link_id: None,
            session_id: None,
            notes: request.notes,
        };

        let assignment = GovLicenseAssignment::create_in_tx(&mut tx, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        tx.commit().await.map_err(GovernanceError::Database)?;

        // 6. Log audit event (outside transaction — non-critical)
        let source_str = format!("{:?}", request.source).to_lowercase();
        self.audit_service
            .log_license_assigned(
                tenant_id,
                request.license_pool_id,
                assignment.id,
                request.user_id,
                actor_id,
                &source_str,
            )
            .await?;

        let mut response = LicenseAssignmentResponse::from(assignment);
        response.pool_name = Some(license_pool.name);
        Ok(response)
    }

    /// Deallocate (release) an active license assignment.
    ///
    /// Marks the assignment as released and decrements the pool's allocated count.
    /// Both operations are wrapped in a transaction to prevent count drift.
    pub async fn deallocate(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Uuid,
    ) -> Result<LicenseAssignmentResponse> {
        // Find the assignment and verify it's active
        let existing = GovLicenseAssignment::find_by_id(&self.pool, tenant_id, assignment_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseAssignmentNotFound(assignment_id))?;

        if !existing.is_active() {
            return Err(GovernanceError::Validation(format!(
                "Assignment {} is not active (status: {:?})",
                assignment_id, existing.status
            )));
        }

        // Release assignment + decrement pool count in a single transaction
        let mut tx = self.pool.begin().await.map_err(GovernanceError::Database)?;

        let released = GovLicenseAssignment::release_in_tx(&mut tx, tenant_id, assignment_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::LicenseAssignmentNotFound(assignment_id))?;

        GovLicensePool::decrement_allocated_in_tx(&mut tx, tenant_id, existing.license_pool_id)
            .await
            .map_err(GovernanceError::Database)?;

        tx.commit().await.map_err(GovernanceError::Database)?;

        // Log audit event (outside transaction — non-critical)
        self.audit_service
            .log_license_deallocated(
                tenant_id,
                existing.license_pool_id,
                assignment_id,
                existing.user_id,
                actor_id,
            )
            .await?;

        Ok(LicenseAssignmentResponse::from(released))
    }

    /// Get a license assignment by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<LicenseAssignmentResponse>> {
        let assignment =
            GovLicenseAssignment::find_by_id(&self.pool, tenant_id, assignment_id).await?;
        Ok(assignment.map(LicenseAssignmentResponse::from))
    }

    /// Get a license assignment by ID, returning an error if not found.
    pub async fn get_required(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<LicenseAssignmentResponse> {
        self.get(tenant_id, assignment_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseAssignmentNotFound(assignment_id))
    }

    /// List license assignments with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        params: ListLicenseAssignmentsParams,
    ) -> Result<LicenseAssignmentListResponse> {
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);

        let filter = LicenseAssignmentFilter {
            license_pool_id: params.license_pool_id,
            user_id: params.user_id,
            status: params.status,
            source: params.source,
        };

        let assignments =
            GovLicenseAssignment::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovLicenseAssignment::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(LicenseAssignmentListResponse {
            items: assignments
                .into_iter()
                .map(LicenseAssignmentResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Assign licenses to multiple users at once.
    ///
    /// Iterates over the user list, attempting to assign each one.
    /// Collects successes and failures rather than failing fast.
    pub async fn bulk_assign(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: BulkAssignLicenseRequest,
    ) -> Result<BulkOperationResult> {
        let mut success_count: i32 = 0;
        let mut failures: Vec<BulkOperationFailure> = Vec::new();

        for user_id in &request.user_ids {
            let assign_request = AssignLicenseRequest {
                license_pool_id: request.license_pool_id,
                user_id: *user_id,
                source: request.source,
                notes: None,
            };

            match self.assign(tenant_id, actor_id, assign_request).await {
                Ok(_) => {
                    success_count += 1;
                }
                Err(e) => {
                    failures.push(BulkOperationFailure {
                        item_id: *user_id,
                        error: e.to_string(),
                    });
                }
            }
        }

        // Log bulk audit event if any successes
        if success_count > 0 {
            let successful_user_ids = build_successful_user_ids(&request.user_ids, &failures);

            self.audit_service
                .log_bulk_assign(
                    tenant_id,
                    request.license_pool_id,
                    successful_user_ids,
                    actor_id,
                )
                .await?;
        }

        Ok(aggregate_bulk_result(success_count, failures))
    }

    /// Reclaim multiple license assignments.
    ///
    /// Iterates over the assignment IDs, reclaiming each one with a manual reason.
    /// Collects successes and failures rather than failing fast.
    pub async fn bulk_reclaim(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: BulkReclaimLicenseRequest,
    ) -> Result<BulkOperationResult> {
        let mut success_count: i32 = 0;
        let mut failures: Vec<BulkOperationFailure> = Vec::new();
        let mut reclaimed_user_ids: Vec<Uuid> = Vec::new();

        for assignment_id in &request.assignment_ids {
            // Look up the assignment
            let assignment =
                match GovLicenseAssignment::find_by_id(&self.pool, tenant_id, *assignment_id).await
                {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        failures.push(BulkOperationFailure {
                            item_id: *assignment_id,
                            error: format!("Assignment {assignment_id} not found"),
                        });
                        continue;
                    }
                    Err(e) => {
                        failures.push(BulkOperationFailure {
                            item_id: *assignment_id,
                            error: e.to_string(),
                        });
                        continue;
                    }
                };

            if !assignment.is_active() {
                failures.push(BulkOperationFailure {
                    item_id: *assignment_id,
                    error: format!(
                        "Assignment {} is not active (status: {:?})",
                        assignment_id, assignment.status
                    ),
                });
                continue;
            }

            // Reclaim the assignment + decrement pool count in a transaction
            let tx_result: std::result::Result<(), String> = async {
                let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

                let reclaimed = GovLicenseAssignment::reclaim_in_tx(
                    &mut tx,
                    tenant_id,
                    *assignment_id,
                    LicenseReclaimReason::Manual,
                )
                .await
                .map_err(|e| e.to_string())?;

                if reclaimed.is_none() {
                    return Err(format!(
                        "Failed to reclaim assignment {assignment_id} (may not be active)"
                    ));
                }

                GovLicensePool::decrement_allocated_in_tx(
                    &mut tx,
                    tenant_id,
                    assignment.license_pool_id,
                )
                .await
                .map_err(|e| e.to_string())?;

                tx.commit().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            .await;

            match tx_result {
                Ok(()) => {
                    // Log individual reclamation audit event (outside tx — non-critical)
                    let _ = self
                        .audit_service
                        .log_license_reclaimed(
                            tenant_id,
                            assignment.license_pool_id,
                            *assignment_id,
                            assignment.user_id,
                            &request.reason,
                            actor_id,
                        )
                        .await;

                    reclaimed_user_ids.push(assignment.user_id);
                    success_count += 1;
                }
                Err(e) => {
                    failures.push(BulkOperationFailure {
                        item_id: *assignment_id,
                        error: e,
                    });
                }
            }
        }

        // Log bulk reclaim audit event if any successes
        if success_count > 0 {
            self.audit_service
                .log_bulk_reclaim(
                    tenant_id,
                    request.license_pool_id,
                    reclaimed_user_ids,
                    &request.reason,
                    actor_id,
                )
                .await?;
        }

        Ok(aggregate_bulk_result(success_count, failures))
    }

    /// Get the underlying database pool reference.
    #[must_use]
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the audit service reference.
    #[must_use]
    pub fn audit_service(&self) -> &LicenseAuditService {
        &self.audit_service
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::license::{
        AssignLicenseRequest, BulkAssignLicenseRequest, BulkOperationFailure,
        BulkReclaimLicenseRequest, ListLicenseAssignmentsParams,
    };
    use xavyo_db::models::{LicenseAssignmentSource, LicenseAssignmentStatus};

    // ========================================================================
    // validate_pool_status_for_assignment tests
    // ========================================================================

    #[test]
    fn test_validate_pool_status_active_succeeds() {
        let pool_id = Uuid::new_v4();
        let result = validate_pool_status_for_assignment(LicensePoolStatus::Active, pool_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_pool_status_archived_fails() {
        let pool_id = Uuid::new_v4();
        let result = validate_pool_status_for_assignment(LicensePoolStatus::Archived, pool_id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            GovernanceError::LicensePoolArchived(id) => assert_eq!(id, pool_id),
            other => panic!("Expected LicensePoolArchived, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_pool_status_expired_fails() {
        let pool_id = Uuid::new_v4();
        let result = validate_pool_status_for_assignment(LicensePoolStatus::Expired, pool_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            GovernanceError::LicensePoolArchived(id) => assert_eq!(id, pool_id),
            other => panic!("Expected LicensePoolArchived, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_pool_status_preserves_pool_id() {
        // Verify the error carries the exact pool ID we passed in
        let specific_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let result = validate_pool_status_for_assignment(LicensePoolStatus::Archived, specific_id);
        match result.unwrap_err() {
            GovernanceError::LicensePoolArchived(id) => assert_eq!(id, specific_id),
            other => panic!("Expected LicensePoolArchived, got: {:?}", other),
        }
    }

    // ========================================================================
    // format_violation_message tests
    // ========================================================================

    #[test]
    fn test_format_violations_single() {
        let violations = vec![IncompatibilityViolation {
            rule_id: Uuid::new_v4(),
            existing_pool_id: Uuid::new_v4(),
            existing_pool_name: "Office 365 E3".to_string(),
            requested_pool_id: Uuid::new_v4(),
            requested_pool_name: "Office 365 E5".to_string(),
            reason: "Cannot hold both E3 and E5".to_string(),
        }];

        let msg = format_violation_message(&violations);
        assert_eq!(
            msg,
            "Incompatible with 'Office 365 E3': Cannot hold both E3 and E5"
        );
    }

    #[test]
    fn test_format_violations_multiple() {
        let violations = vec![
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool A".to_string(),
                requested_pool_id: Uuid::new_v4(),
                requested_pool_name: "Pool C".to_string(),
                reason: "License overlap".to_string(),
            },
            IncompatibilityViolation {
                rule_id: Uuid::new_v4(),
                existing_pool_id: Uuid::new_v4(),
                existing_pool_name: "Pool B".to_string(),
                requested_pool_id: Uuid::new_v4(),
                requested_pool_name: "Pool C".to_string(),
                reason: "Vendor conflict".to_string(),
            },
        ];

        let msg = format_violation_message(&violations);
        assert_eq!(
            msg,
            "Incompatible with 'Pool A': License overlap; Incompatible with 'Pool B': Vendor conflict"
        );
    }

    #[test]
    fn test_format_violations_empty() {
        let violations: Vec<IncompatibilityViolation> = vec![];
        let msg = format_violation_message(&violations);
        assert_eq!(msg, "");
    }

    #[test]
    fn test_format_violations_special_characters() {
        let violations = vec![IncompatibilityViolation {
            rule_id: Uuid::new_v4(),
            existing_pool_id: Uuid::new_v4(),
            existing_pool_name: "Pool with 'quotes' & <angles>".to_string(),
            requested_pool_id: Uuid::new_v4(),
            requested_pool_name: "Target".to_string(),
            reason: "Reason with \"double quotes\"".to_string(),
        }];

        let msg = format_violation_message(&violations);
        assert!(msg.contains("Pool with 'quotes' & <angles>"));
        assert!(msg.contains("Reason with \"double quotes\""));
    }

    // ========================================================================
    // enforce_list_limits tests
    // ========================================================================

    #[test]
    fn test_enforce_list_limits_normal_values() {
        let (limit, offset) = enforce_list_limits(20, 0);
        assert_eq!(limit, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_list_limits_zero_limit_becomes_one() {
        let (limit, _) = enforce_list_limits(0, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_negative_limit_becomes_one() {
        let (limit, _) = enforce_list_limits(-5, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_over_max_clamped_to_100() {
        let (limit, _) = enforce_list_limits(500, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_exactly_100() {
        let (limit, _) = enforce_list_limits(100, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_exactly_1() {
        let (limit, _) = enforce_list_limits(1, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_negative_offset_becomes_zero() {
        let (_, offset) = enforce_list_limits(20, -10);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_list_limits_positive_offset_unchanged() {
        let (_, offset) = enforce_list_limits(20, 50);
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_enforce_list_limits_both_extremes() {
        let (limit, offset) = enforce_list_limits(999, -999);
        assert_eq!(limit, 100);
        assert_eq!(offset, 0);
    }

    // ========================================================================
    // build_successful_user_ids tests
    // ========================================================================

    #[test]
    fn test_build_successful_user_ids_all_succeed() {
        let ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let failures: Vec<BulkOperationFailure> = vec![];

        let result = build_successful_user_ids(&ids, &failures);
        assert_eq!(result.len(), 3);
        assert_eq!(result, ids);
    }

    #[test]
    fn test_build_successful_user_ids_none_succeed() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let ids = vec![id1, id2];
        let failures = vec![
            BulkOperationFailure {
                item_id: id1,
                error: "error1".to_string(),
            },
            BulkOperationFailure {
                item_id: id2,
                error: "error2".to_string(),
            },
        ];

        let result = build_successful_user_ids(&ids, &failures);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_successful_user_ids_partial_success() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let ids = vec![id1, id2, id3];
        let failures = vec![BulkOperationFailure {
            item_id: id2,
            error: "failed".to_string(),
        }];

        let result = build_successful_user_ids(&ids, &failures);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&id1));
        assert!(!result.contains(&id2));
        assert!(result.contains(&id3));
    }

    #[test]
    fn test_build_successful_user_ids_empty_input() {
        let ids: Vec<Uuid> = vec![];
        let failures: Vec<BulkOperationFailure> = vec![];

        let result = build_successful_user_ids(&ids, &failures);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_successful_user_ids_preserves_order() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let id4 = Uuid::new_v4();
        let ids = vec![id1, id2, id3, id4];
        let failures = vec![BulkOperationFailure {
            item_id: id3,
            error: "failed".to_string(),
        }];

        let result = build_successful_user_ids(&ids, &failures);
        assert_eq!(result, vec![id1, id2, id4]);
    }

    // ========================================================================
    // aggregate_bulk_result tests
    // ========================================================================

    #[test]
    fn test_aggregate_bulk_result_all_success() {
        let result = aggregate_bulk_result(10, vec![]);
        assert_eq!(result.success_count, 10);
        assert_eq!(result.failure_count, 0);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_aggregate_bulk_result_all_failures() {
        let failures = vec![
            BulkOperationFailure {
                item_id: Uuid::new_v4(),
                error: "err1".to_string(),
            },
            BulkOperationFailure {
                item_id: Uuid::new_v4(),
                error: "err2".to_string(),
            },
        ];
        let result = aggregate_bulk_result(0, failures);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 2);
        assert_eq!(result.failures.len(), 2);
    }

    #[test]
    fn test_aggregate_bulk_result_mixed() {
        let failures = vec![BulkOperationFailure {
            item_id: Uuid::new_v4(),
            error: "conflict".to_string(),
        }];
        let result = aggregate_bulk_result(5, failures);
        assert_eq!(result.success_count, 5);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].error, "conflict");
    }

    #[test]
    fn test_aggregate_bulk_result_empty_operation() {
        let result = aggregate_bulk_result(0, vec![]);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_aggregate_bulk_result_failure_count_derived_from_vec() {
        // Verify failure_count is always derived from failures.len(),
        // not passed separately.
        let failures = vec![
            BulkOperationFailure {
                item_id: Uuid::new_v4(),
                error: "a".to_string(),
            },
            BulkOperationFailure {
                item_id: Uuid::new_v4(),
                error: "b".to_string(),
            },
            BulkOperationFailure {
                item_id: Uuid::new_v4(),
                error: "c".to_string(),
            },
        ];
        let result = aggregate_bulk_result(2, failures);
        assert_eq!(result.failure_count, 3);
        assert_eq!(result.failures.len(), 3);
    }

    // ========================================================================
    // Serde/deserialization tests (kept: these exercise real default behavior)
    // ========================================================================

    #[test]
    fn test_list_params_from_json_empty() {
        let json = r#"{}"#;
        let params: ListLicenseAssignmentsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 20); // default_limit()
        assert_eq!(params.offset, 0);
        assert!(params.license_pool_id.is_none());
        assert!(params.user_id.is_none());
    }

    #[test]
    fn test_list_params_roundtrip_serialization() {
        let pool_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let params = ListLicenseAssignmentsParams {
            license_pool_id: Some(pool_id),
            user_id: Some(user_id),
            status: Some(LicenseAssignmentStatus::Active),
            source: Some(LicenseAssignmentSource::Manual),
            limit: 50,
            offset: 25,
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ListLicenseAssignmentsParams = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.license_pool_id, Some(pool_id));
        assert_eq!(deserialized.user_id, Some(user_id));
        assert_eq!(deserialized.status, Some(LicenseAssignmentStatus::Active));
        assert_eq!(deserialized.source, Some(LicenseAssignmentSource::Manual));
        assert_eq!(deserialized.limit, 50);
        assert_eq!(deserialized.offset, 25);
    }

    #[test]
    fn test_assign_license_request_from_json_defaults() {
        let json = format!(
            r#"{{"license_pool_id": "{}", "user_id": "{}"}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let request: AssignLicenseRequest = serde_json::from_str(&json).unwrap();
        // default_assignment_source() returns Manual
        assert_eq!(request.source, LicenseAssignmentSource::Manual);
        assert!(request.notes.is_none());
    }

    #[test]
    fn test_bulk_assign_request_from_json_defaults() {
        let pool_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let json = format!(
            r#"{{"license_pool_id": "{}", "user_ids": ["{}"]}}"#,
            pool_id, user_id
        );
        let request: BulkAssignLicenseRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.license_pool_id, pool_id);
        assert_eq!(request.user_ids.len(), 1);
        assert_eq!(request.source, LicenseAssignmentSource::Manual);
    }

    #[test]
    fn test_bulk_reclaim_request_serialization_roundtrip() {
        let request = BulkReclaimLicenseRequest {
            license_pool_id: Uuid::new_v4(),
            assignment_ids: vec![Uuid::new_v4()],
            reason: "Audit finding".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BulkReclaimLicenseRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.assignment_ids.len(), 1);
        assert_eq!(deserialized.reason, "Audit finding");
    }
}
