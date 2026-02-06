//! License Reclamation Service (F065).
//!
//! Provides business logic for managing automatic license reclamation rules
//! including CRUD operations, finding reclamation candidates, executing
//! reclamations, and handling lifecycle events.
//!
//! Pure business logic functions are extracted as module-level functions
//! so they can be tested without requiring a database connection.

use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicenseReclamationRule, GovLicenseAssignment, GovLicensePool,
    GovLicenseReclamationRule, LicenseAuditAction, LicenseReclaimReason,
    LicenseReclamationRuleFilter, LicenseReclamationRuleId, LicenseReclamationTrigger,
    UpdateGovLicenseReclamationRule,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::LicenseAuditService;
use crate::models::license::{
    CreateReclamationRuleRequest, ListReclamationRulesParams, ReclamationRuleListResponse,
    ReclamationRuleResponse, UpdateReclamationRuleRequest,
};

/// A candidate for license reclamation.
#[derive(Debug, Clone)]
pub struct ReclaimCandidate {
    /// The assignment to reclaim.
    pub assignment_id: Uuid,
    /// The user who holds the license.
    pub user_id: Uuid,
    /// The license pool the assignment belongs to.
    pub pool_id: Uuid,
    /// The name of the pool (for display/audit).
    pub pool_name: String,
    /// Number of days the user has been inactive (for inactivity rules).
    pub days_inactive: Option<i32>,
    /// The rule that triggered this candidate.
    pub rule_id: Uuid,
    /// The reason for reclamation.
    pub reason: LicenseReclaimReason,
}

/// Result of executing a reclamation batch.
#[derive(Debug, Clone)]
pub struct ReclamationExecutionResult {
    /// Number of licenses successfully reclaimed.
    pub reclaimed_count: i32,
    /// Number of candidates that failed to reclaim.
    pub failed_count: i32,
    /// Error messages for failed reclamations.
    pub errors: Vec<String>,
}

// ============================================================================
// Pure Business Logic Functions (no I/O, fully testable)
// ============================================================================

/// The system actor UUID used for automated reclamation (all zeros).
///
/// When reclamation is triggered automatically (e.g., by a lifecycle event),
/// this nil UUID is used as the `actor_id` in audit logs to distinguish
/// system-initiated actions from human-initiated ones.
pub(crate) fn system_actor_id() -> Uuid {
    Uuid::nil()
}

/// Validate that trigger-specific fields are present for the given trigger type.
///
/// - `Inactivity` trigger requires `threshold_days` to be set.
/// - `LifecycleState` trigger requires `lifecycle_state` to be set.
///
/// Extra fields for other trigger types are silently ignored.
pub(crate) fn validate_trigger_fields(
    trigger_type: LicenseReclamationTrigger,
    threshold_days: Option<i32>,
    lifecycle_state: Option<&str>,
) -> Result<()> {
    match trigger_type {
        LicenseReclamationTrigger::Inactivity => match threshold_days {
            None => {
                return Err(GovernanceError::Validation(
                    "Inactivity rules require threshold_days".to_string(),
                ));
            }
            Some(days) if days <= 0 => {
                return Err(GovernanceError::Validation(
                    "threshold_days must be a positive number".to_string(),
                ));
            }
            _ => {}
        },
        LicenseReclamationTrigger::LifecycleState => {
            if lifecycle_state.is_none() {
                return Err(GovernanceError::Validation(
                    "Lifecycle state rules require lifecycle_state".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Enforce pagination limits: clamp `limit` to [1, 100] and `offset` to [0, ...).
///
/// Returns `(clamped_limit, clamped_offset)`.
pub(crate) fn enforce_list_limits(limit: i64, offset: i64) -> (i64, i64) {
    let clamped_limit = limit.clamp(1, 100);
    let clamped_offset = offset.max(0);
    (clamped_limit, clamped_offset)
}

/// Aggregate individual reclamation outcomes into a summary result.
///
/// Takes a slice of per-candidate outcomes where each entry is:
/// - `Ok(true)` -- successfully reclaimed
/// - `Ok(false)` -- candidate was not reclaimable (e.g., already inactive)
/// - `Err(message)` -- reclamation failed with the given error
///
/// Returns a `ReclamationExecutionResult` with correct counts and collected errors.
pub(crate) fn aggregate_reclamation_result(
    outcomes: &[std::result::Result<bool, String>],
) -> ReclamationExecutionResult {
    let mut reclaimed_count: i32 = 0;
    let mut failed_count: i32 = 0;
    let mut errors: Vec<String> = Vec::new();

    for outcome in outcomes {
        match outcome {
            Ok(true) => {
                reclaimed_count += 1;
            }
            Ok(false) => {
                failed_count += 1;
            }
            Err(msg) => {
                failed_count += 1;
                errors.push(msg.clone());
            }
        }
    }

    ReclamationExecutionResult {
        reclaimed_count,
        failed_count,
        errors,
    }
}

/// Minimal data needed to evaluate lifecycle-based reclamation rule matching.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct LifecycleRuleData {
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// The lifecycle state this rule targets (e.g., "terminated").
    pub lifecycle_state: Option<String>,
}

/// Determine whether reclamation should happen for a given lifecycle state
/// based on the provided rules.
///
/// Returns `true` if at least one enabled rule targets the given state.
#[allow(dead_code)]
pub(crate) fn should_reclaim_for_lifecycle_state(
    lifecycle_state: &str,
    rules: &[LifecycleRuleData],
) -> bool {
    rules
        .iter()
        .any(|rule| rule.enabled && (rule.lifecycle_state.as_deref() == Some(lifecycle_state)))
}

/// Build a list of `ReclaimCandidate` entries from rule and assignment data.
///
/// For each `(rule_id, pool_id, pool_name)` tuple paired with an assignment,
/// this produces a `ReclaimCandidate` for the lifecycle termination reason.
///
/// This is the pure logic extracted from `handle_lifecycle_event`.
pub(crate) fn build_lifecycle_candidates(
    user_id: Uuid,
    rule_assignment_pairs: &[(Uuid, Uuid, String, Uuid)], // (rule_id, pool_id, pool_name, assignment_id)
) -> Vec<ReclaimCandidate> {
    rule_assignment_pairs
        .iter()
        .map(
            |(rule_id, pool_id, pool_name, assignment_id)| ReclaimCandidate {
                assignment_id: *assignment_id,
                user_id,
                pool_id: *pool_id,
                pool_name: pool_name.clone(),
                days_inactive: None,
                rule_id: *rule_id,
                reason: LicenseReclaimReason::Termination,
            },
        )
        .collect()
}

/// Placeholder: `cancel_if_active` always returns false in the current
/// implementation since reclamation is immediate (no grace period).
pub(crate) fn cancel_if_active_placeholder() -> bool {
    false
}

// ============================================================================
// Service Implementation
// ============================================================================

/// Service for license reclamation rule operations.
pub struct LicenseReclamationService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

impl LicenseReclamationService {
    /// Create a new license reclamation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    // ========================================================================
    // CRUD Operations
    // ========================================================================

    /// Create a new reclamation rule.
    ///
    /// Validates that the target pool exists and creates the rule with
    /// appropriate audit logging.
    pub async fn create_rule(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: CreateReclamationRuleRequest,
    ) -> Result<ReclamationRuleResponse> {
        // Validate pool exists
        let pool = GovLicensePool::find_by_id(&self.pool, tenant_id, request.license_pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(request.license_pool_id))?;

        // Validate trigger-specific fields (delegated to pure function)
        validate_trigger_fields(
            request.trigger_type,
            request.threshold_days,
            request.lifecycle_state.as_deref(),
        )?;

        // Create the rule
        let input = CreateGovLicenseReclamationRule {
            license_pool_id: request.license_pool_id,
            trigger_type: request.trigger_type,
            threshold_days: request.threshold_days,
            lifecycle_state: request.lifecycle_state,
            notification_days_before: Some(request.notification_days_before),
            enabled: Some(true),
            created_by: actor_id,
        };

        let created = GovLicenseReclamationRule::create(&self.pool, tenant_id, &input).await?;

        // Log audit event
        self.audit_service
            .record_pool_event(
                tenant_id,
                super::license_audit_service::RecordPoolEventParams {
                    pool_id: request.license_pool_id,
                    action: LicenseAuditAction::RuleCreated,
                    actor_id,
                    details: Some(serde_json::json!({
                        "rule_id": created.id,
                        "trigger_type": format!("{:?}", created.trigger_type).to_lowercase(),
                        "pool_name": pool.name,
                    })),
                },
            )
            .await?;

        let mut response = ReclamationRuleResponse::from(created);
        response.pool_name = Some(pool.name);
        response.pool_vendor = Some(pool.vendor);
        Ok(response)
    }

    /// Get a reclamation rule by ID.
    pub async fn get_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Option<ReclamationRuleResponse>> {
        let rule = GovLicenseReclamationRule::find_by_id(
            &self.pool,
            tenant_id,
            LicenseReclamationRuleId::from(rule_id),
        )
        .await?;

        match rule {
            Some(r) => {
                let mut response = ReclamationRuleResponse::from(r.clone());
                // Enrich with pool details
                if let Some(pool) =
                    GovLicensePool::find_by_id(&self.pool, tenant_id, r.license_pool_id).await?
                {
                    response.pool_name = Some(pool.name);
                    response.pool_vendor = Some(pool.vendor);
                }
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    /// Get a reclamation rule by ID, returning an error if not found.
    pub async fn get_rule_required(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<ReclamationRuleResponse> {
        self.get_rule(tenant_id, rule_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseReclamationRuleNotFound(rule_id))
    }

    /// List reclamation rules with filtering and pagination.
    pub async fn list_rules(
        &self,
        tenant_id: Uuid,
        params: ListReclamationRulesParams,
    ) -> Result<ReclamationRuleListResponse> {
        // Enforce reasonable limits (delegated to pure function)
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);

        let filter = LicenseReclamationRuleFilter {
            license_pool_id: params.license_pool_id,
            trigger_type: params.trigger_type,
            enabled: params.enabled,
        };

        let rules_with_details = GovLicenseReclamationRule::list_with_details(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;
        let total = GovLicenseReclamationRule::count(&self.pool, tenant_id, &filter).await?;

        let items = rules_with_details
            .into_iter()
            .map(|r| ReclamationRuleResponse {
                id: r.id,
                license_pool_id: r.license_pool_id,
                pool_name: r.pool_name,
                pool_vendor: r.pool_vendor,
                trigger_type: r.trigger_type,
                threshold_days: r.threshold_days,
                lifecycle_state: r.lifecycle_state,
                notification_days_before: r.notification_days_before,
                enabled: r.enabled,
                created_at: r.created_at,
                updated_at: r.updated_at,
                created_by: r.created_by,
            })
            .collect();

        Ok(ReclamationRuleListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Update a reclamation rule.
    pub async fn update_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        actor_id: Uuid,
        request: UpdateReclamationRuleRequest,
    ) -> Result<ReclamationRuleResponse> {
        // Verify rule exists
        let existing = GovLicenseReclamationRule::find_by_id(
            &self.pool,
            tenant_id,
            LicenseReclamationRuleId::from(rule_id),
        )
        .await?
        .ok_or_else(|| GovernanceError::LicenseReclamationRuleNotFound(rule_id))?;

        // Build update input
        let update = UpdateGovLicenseReclamationRule {
            threshold_days: request.threshold_days,
            lifecycle_state: request.lifecycle_state,
            notification_days_before: request.notification_days_before,
            enabled: request.enabled,
        };

        let updated = GovLicenseReclamationRule::update(
            &self.pool,
            tenant_id,
            LicenseReclamationRuleId::from(rule_id),
            &update,
        )
        .await?
        .ok_or_else(|| GovernanceError::LicenseReclamationRuleNotFound(rule_id))?;

        // Log audit event
        self.audit_service
            .record_pool_event(
                tenant_id,
                super::license_audit_service::RecordPoolEventParams {
                    pool_id: existing.license_pool_id,
                    action: LicenseAuditAction::RuleUpdated,
                    actor_id,
                    details: Some(serde_json::json!({
                        "rule_id": rule_id,
                    })),
                },
            )
            .await?;

        let mut response = ReclamationRuleResponse::from(updated);
        // Enrich with pool details
        if let Some(pool) =
            GovLicensePool::find_by_id(&self.pool, tenant_id, existing.license_pool_id).await?
        {
            response.pool_name = Some(pool.name);
            response.pool_vendor = Some(pool.vendor);
        }
        Ok(response)
    }

    /// Delete a reclamation rule.
    pub async fn delete_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        actor_id: Uuid,
    ) -> Result<bool> {
        // Verify rule exists and get pool info for audit
        let existing = GovLicenseReclamationRule::find_by_id(
            &self.pool,
            tenant_id,
            LicenseReclamationRuleId::from(rule_id),
        )
        .await?
        .ok_or_else(|| GovernanceError::LicenseReclamationRuleNotFound(rule_id))?;

        let deleted = GovLicenseReclamationRule::delete(
            &self.pool,
            tenant_id,
            LicenseReclamationRuleId::from(rule_id),
        )
        .await?;

        if deleted {
            // Log audit event
            self.audit_service
                .record_pool_event(
                    tenant_id,
                    super::license_audit_service::RecordPoolEventParams {
                        pool_id: existing.license_pool_id,
                        action: LicenseAuditAction::RuleDeleted,
                        actor_id,
                        details: Some(serde_json::json!({
                            "rule_id": rule_id,
                            "trigger_type": format!("{:?}", existing.trigger_type).to_lowercase(),
                        })),
                    },
                )
                .await?;
        }

        Ok(deleted)
    }

    // ========================================================================
    // Reclamation Candidate Discovery
    // ========================================================================

    /// Find license assignments eligible for reclamation based on inactivity rules.
    ///
    /// # Current Status: Placeholder
    ///
    /// This method currently returns an empty list. The full implementation
    /// would query the `login_history` table to find users who have not logged
    /// in for the threshold number of days specified in each enabled inactivity
    /// rule, then build a `ReclaimCandidate` for each match.
    ///
    /// ## What the full implementation would do
    ///
    /// 1. Fetch all enabled inactivity rules for the tenant.
    /// 2. For each rule, query active assignments from the rule's license pool.
    /// 3. Cross-reference with `login_history` to identify users inactive longer
    ///    than `threshold_days`.
    /// 4. Return a `ReclaimCandidate` for every qualifying assignment.
    ///
    /// ## Working alternative
    ///
    /// The [`execute_reclamation`](Self::execute_reclamation) method is fully
    /// functional and can process any candidates provided to it. For
    /// Kafka-driven lifecycle reclamation, see
    /// [`handle_lifecycle_event`](Self::handle_lifecycle_event).
    pub async fn find_inactive_licenses(&self, tenant_id: Uuid) -> Result<Vec<ReclaimCandidate>> {
        // Get all enabled inactivity rules for this tenant
        let _rules =
            GovLicenseReclamationRule::find_enabled_inactivity_rules(&self.pool, tenant_id).await?;

        // Placeholder: login_history integration not yet implemented.
        // See doc comment above for what the full implementation would do.
        warn!("find_inactive_licenses is a placeholder - login_history integration not yet implemented");

        Ok(Vec::new())
    }

    /// Find license assignments eligible for reclamation based on lifecycle state rules.
    ///
    /// # Current Status: Placeholder
    ///
    /// This method currently returns an empty list. Lifecycle-based reclamation
    /// is designed to be event-driven rather than poll-based: when a Kafka
    /// lifecycle event arrives with both a `user_id` and a lifecycle state, the
    /// preferred entry point is
    /// [`handle_lifecycle_event`](Self::handle_lifecycle_event), which is fully
    /// implemented.
    ///
    /// ## What the full implementation would do
    ///
    /// 1. Fetch all enabled lifecycle rules matching `lifecycle_state`.
    /// 2. For each rule, find active assignments in the rule's license pool
    ///    whose holder has entered the specified lifecycle state.
    /// 3. Return a `ReclaimCandidate` for every qualifying assignment.
    ///
    /// This method lacks a `user_id` parameter, so it cannot narrow candidates
    /// to a specific user. Use
    /// [`handle_lifecycle_event`](Self::handle_lifecycle_event) for the working
    /// Kafka-driven path that receives `user_id` from the event payload.
    pub async fn find_lifecycle_reclaim_candidates(
        &self,
        tenant_id: Uuid,
        lifecycle_state: &str,
    ) -> Result<Vec<ReclaimCandidate>> {
        // Get all enabled lifecycle rules matching this state
        let rules = GovLicenseReclamationRule::find_enabled_lifecycle_rules(
            &self.pool,
            tenant_id,
            lifecycle_state,
        )
        .await?;

        let candidates = Vec::new();

        // Placeholder: use handle_lifecycle_event for Kafka-driven reclamation.
        // See doc comment above for details.
        let _ = &rules;
        warn!("find_lifecycle_reclaim_candidates is a placeholder - use handle_lifecycle_event for Kafka-driven reclamation");

        Ok(candidates)
    }

    // ========================================================================
    // Reclamation Execution
    // ========================================================================

    /// Execute reclamation for a list of candidates.
    ///
    /// For each candidate:
    /// 1. Reclaims the assignment using `GovLicenseAssignment::reclaim`
    /// 2. Decrements the pool's allocated count
    /// 3. Logs an audit event
    ///
    /// Returns the count of successfully reclaimed licenses and any errors.
    pub async fn execute_reclamation(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        candidates: &[ReclaimCandidate],
    ) -> Result<ReclamationExecutionResult> {
        let mut outcomes: Vec<std::result::Result<bool, String>> = Vec::new();

        for candidate in candidates {
            // Reclaim the assignment + decrement pool count in a single transaction
            let tx_result: std::result::Result<bool, String> = async {
                let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;

                let reclaimed = GovLicenseAssignment::reclaim_in_tx(
                    &mut tx,
                    tenant_id,
                    candidate.assignment_id,
                    candidate.reason,
                )
                .await
                .map_err(|e| {
                    format!(
                        "Failed to reclaim assignment {}: {}",
                        candidate.assignment_id, e
                    )
                })?;

                if reclaimed.is_none() {
                    return Ok(false);
                }

                GovLicensePool::decrement_allocated_in_tx(&mut tx, tenant_id, candidate.pool_id)
                    .await
                    .map_err(|e| e.to_string())?;

                tx.commit().await.map_err(|e| e.to_string())?;
                Ok(true)
            }
            .await;

            match tx_result {
                Ok(true) => {
                    // Log audit event (outside transaction — non-critical)
                    let reason_str = format!("{:?}", candidate.reason).to_lowercase();
                    let _ = self
                        .audit_service
                        .log_license_reclaimed(
                            tenant_id,
                            candidate.pool_id,
                            candidate.assignment_id,
                            candidate.user_id,
                            &reason_str,
                            actor_id,
                        )
                        .await;

                    outcomes.push(Ok(true));
                }
                Ok(false) => {
                    outcomes.push(Ok(false));
                }
                Err(e) => {
                    outcomes.push(Err(e));
                }
            }
        }

        Ok(aggregate_reclamation_result(&outcomes))
    }

    // ========================================================================
    // Lifecycle Event Integration (T032)
    // ========================================================================

    /// Process a JML lifecycle event (e.g., employee terminated).
    ///
    /// In production, this would be called from a Kafka consumer when a
    /// lifecycle event is received. It finds all matching reclamation rules
    /// for the given lifecycle state and reclaims any active license
    /// assignments the user has in the affected pools.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `user_id` - The user whose lifecycle state changed
    /// * `event_type` - The lifecycle state (e.g., "terminated", "`on_leave`")
    ///
    /// # Returns
    /// The number of licenses reclaimed.
    pub async fn handle_lifecycle_event(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        event_type: &str,
    ) -> Result<i32> {
        // Find enabled lifecycle rules matching this event type
        let rules = GovLicenseReclamationRule::find_enabled_lifecycle_rules(
            &self.pool, tenant_id, event_type,
        )
        .await?;

        if rules.is_empty() {
            return Ok(0);
        }

        let mut rule_assignment_pairs = Vec::new();

        for rule in &rules {
            // Check if user has an active assignment in the rule's pool
            if let Some(assignment) = GovLicenseAssignment::find_active_by_user_and_pool(
                &self.pool,
                tenant_id,
                user_id,
                rule.license_pool_id,
            )
            .await?
            {
                // Get pool name for audit
                let pool_name =
                    GovLicensePool::find_by_id(&self.pool, tenant_id, rule.license_pool_id)
                        .await?
                        .map_or_else(|| "Unknown Pool".to_string(), |p| p.name);

                rule_assignment_pairs.push((
                    rule.id,
                    rule.license_pool_id,
                    pool_name,
                    assignment.id,
                ));
            }
        }

        let candidates = build_lifecycle_candidates(user_id, &rule_assignment_pairs);

        if candidates.is_empty() {
            return Ok(0);
        }

        // Use a system actor ID for automated reclamation
        let result = self
            .execute_reclamation(tenant_id, system_actor_id(), &candidates)
            .await?;

        Ok(result.reclaimed_count)
    }

    /// Cancel a pending reclamation if user becomes active again.
    ///
    /// In a full implementation, this would be invoked when a user logs in
    /// or their lifecycle state reverts (e.g., from "`on_leave`" back to "active"),
    /// cancelling any scheduled reclamation.
    ///
    /// Since reclamation in this implementation is immediate rather than
    /// scheduled, this method serves as a placeholder for future grace-period
    /// based reclamation where assignments might be marked as "`pending_reclamation`"
    /// before being fully reclaimed.
    pub async fn cancel_if_active(&self, _tenant_id: Uuid, _user_id: Uuid) -> Result<bool> {
        Ok(cancel_if_active_placeholder())
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
    use crate::models::license::{CreateReclamationRuleRequest, ListReclamationRulesParams};
    use xavyo_db::models::LicenseReclamationTrigger;

    // ========================================================================
    // validate_trigger_fields tests
    // ========================================================================

    #[test]
    fn test_validate_inactivity_with_threshold_days_succeeds() {
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, Some(90), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactivity_without_threshold_days_fails() {
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("threshold_days"),
            "Error should mention threshold_days, got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_lifecycle_with_state_succeeds() {
        let result = validate_trigger_fields(
            LicenseReclamationTrigger::LifecycleState,
            None,
            Some("terminated"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_lifecycle_without_state_fails() {
        let result = validate_trigger_fields(LicenseReclamationTrigger::LifecycleState, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("lifecycle_state"),
            "Error should mention lifecycle_state, got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_inactivity_with_extra_lifecycle_state_succeeds() {
        // Extra fields are silently ignored; only the required field matters.
        let result = validate_trigger_fields(
            LicenseReclamationTrigger::Inactivity,
            Some(30),
            Some("terminated"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_lifecycle_with_extra_threshold_days_succeeds() {
        // Extra threshold_days is ignored for lifecycle trigger.
        let result = validate_trigger_fields(
            LicenseReclamationTrigger::LifecycleState,
            Some(90),
            Some("on_leave"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inactivity_with_zero_threshold_days_fails() {
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, Some(0), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("positive"),
            "Error should mention 'positive', got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_inactivity_with_negative_threshold_days_fails() {
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, Some(-5), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("positive"),
            "Error should mention 'positive', got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_inactivity_with_one_threshold_day_succeeds() {
        // Boundary case: threshold_days = 1 is the minimum valid value.
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, Some(1), None);
        assert!(result.is_ok());
    }

    // ========================================================================
    // enforce_list_limits tests
    // ========================================================================

    #[test]
    fn test_enforce_limits_normal_values() {
        let (limit, offset) = enforce_list_limits(20, 0);
        assert_eq!(limit, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_limits_zero_limit_clamps_to_one() {
        let (limit, _) = enforce_list_limits(0, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_limits_negative_limit_clamps_to_one() {
        let (limit, _) = enforce_list_limits(-5, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_limits_excessive_limit_clamps_to_100() {
        let (limit, _) = enforce_list_limits(500, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_limits_exactly_100() {
        let (limit, _) = enforce_list_limits(100, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_limits_exactly_1() {
        let (limit, _) = enforce_list_limits(1, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_limits_negative_offset_clamps_to_zero() {
        let (_, offset) = enforce_list_limits(20, -10);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_limits_positive_offset_unchanged() {
        let (_, offset) = enforce_list_limits(20, 50);
        assert_eq!(offset, 50);
    }

    // ========================================================================
    // aggregate_reclamation_result tests
    // ========================================================================

    #[test]
    fn test_aggregate_all_success() {
        let outcomes = vec![Ok(true), Ok(true), Ok(true)];
        let result = aggregate_reclamation_result(&outcomes);
        assert_eq!(result.reclaimed_count, 3);
        assert_eq!(result.failed_count, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_aggregate_all_not_reclaimable() {
        // Ok(false) = candidate was not active / not reclaimable
        let outcomes = vec![Ok(false), Ok(false)];
        let result = aggregate_reclamation_result(&outcomes);
        assert_eq!(result.reclaimed_count, 0);
        assert_eq!(result.failed_count, 2);
        assert!(
            result.errors.is_empty(),
            "Ok(false) should not produce error messages"
        );
    }

    #[test]
    fn test_aggregate_all_errors() {
        let outcomes = vec![
            Err("DB timeout".to_string()),
            Err("Not found".to_string()),
            Err("Permission denied".to_string()),
        ];
        let result = aggregate_reclamation_result(&outcomes);
        assert_eq!(result.reclaimed_count, 0);
        assert_eq!(result.failed_count, 3);
        assert_eq!(result.errors.len(), 3);
        assert!(result.errors.contains(&"DB timeout".to_string()));
        assert!(result.errors.contains(&"Not found".to_string()));
        assert!(result.errors.contains(&"Permission denied".to_string()));
    }

    #[test]
    fn test_aggregate_mixed_outcomes() {
        let outcomes = vec![
            Ok(true),
            Ok(false),
            Err("DB error".to_string()),
            Ok(true),
            Ok(true),
        ];
        let result = aggregate_reclamation_result(&outcomes);
        assert_eq!(result.reclaimed_count, 3);
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "DB error");
    }

    #[test]
    fn test_aggregate_empty_outcomes() {
        let outcomes: Vec<std::result::Result<bool, String>> = vec![];
        let result = aggregate_reclamation_result(&outcomes);
        assert_eq!(result.reclaimed_count, 0);
        assert_eq!(result.failed_count, 0);
        assert!(result.errors.is_empty());
    }

    // ========================================================================
    // should_reclaim_for_lifecycle_state tests
    // ========================================================================

    #[test]
    fn test_should_reclaim_matching_state() {
        let rules = vec![LifecycleRuleData {
            enabled: true,
            lifecycle_state: Some("terminated".to_string()),
        }];
        assert!(should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    #[test]
    fn test_should_not_reclaim_non_matching_state() {
        let rules = vec![LifecycleRuleData {
            enabled: true,
            lifecycle_state: Some("terminated".to_string()),
        }];
        assert!(!should_reclaim_for_lifecycle_state("on_leave", &rules));
    }

    #[test]
    fn test_should_not_reclaim_empty_rules() {
        let rules: Vec<LifecycleRuleData> = vec![];
        assert!(!should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    #[test]
    fn test_should_not_reclaim_disabled_rule() {
        let rules = vec![LifecycleRuleData {
            enabled: false,
            lifecycle_state: Some("terminated".to_string()),
        }];
        assert!(!should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    #[test]
    fn test_should_reclaim_multiple_rules_one_matching() {
        let rules = vec![
            LifecycleRuleData {
                enabled: true,
                lifecycle_state: Some("on_leave".to_string()),
            },
            LifecycleRuleData {
                enabled: true,
                lifecycle_state: Some("terminated".to_string()),
            },
        ];
        assert!(should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    #[test]
    fn test_should_not_reclaim_rule_with_none_state() {
        let rules = vec![LifecycleRuleData {
            enabled: true,
            lifecycle_state: None,
        }];
        assert!(!should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    #[test]
    fn test_should_reclaim_case_sensitive() {
        let rules = vec![LifecycleRuleData {
            enabled: true,
            lifecycle_state: Some("Terminated".to_string()),
        }];
        // Case-sensitive: "terminated" != "Terminated"
        assert!(!should_reclaim_for_lifecycle_state("terminated", &rules));
    }

    // ========================================================================
    // build_lifecycle_candidates tests
    // ========================================================================

    #[test]
    fn test_build_candidates_single_pair() {
        let user_id = Uuid::new_v4();
        let rule_id = Uuid::new_v4();
        let pool_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();

        let pairs = vec![(rule_id, pool_id, "M365 E3".to_string(), assignment_id)];
        let candidates = build_lifecycle_candidates(user_id, &pairs);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].user_id, user_id);
        assert_eq!(candidates[0].rule_id, rule_id);
        assert_eq!(candidates[0].pool_id, pool_id);
        assert_eq!(candidates[0].assignment_id, assignment_id);
        assert_eq!(candidates[0].pool_name, "M365 E3");
        assert_eq!(candidates[0].reason, LicenseReclaimReason::Termination);
        assert!(candidates[0].days_inactive.is_none());
    }

    #[test]
    fn test_build_candidates_multiple_pairs() {
        let user_id = Uuid::new_v4();
        let pairs = vec![
            (
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Pool A".to_string(),
                Uuid::new_v4(),
            ),
            (
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Pool B".to_string(),
                Uuid::new_v4(),
            ),
            (
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Pool C".to_string(),
                Uuid::new_v4(),
            ),
        ];
        let candidates = build_lifecycle_candidates(user_id, &pairs);
        assert_eq!(candidates.len(), 3);
        // All candidates share the same user_id
        for c in &candidates {
            assert_eq!(c.user_id, user_id);
            assert_eq!(c.reason, LicenseReclaimReason::Termination);
        }
        assert_eq!(candidates[0].pool_name, "Pool A");
        assert_eq!(candidates[1].pool_name, "Pool B");
        assert_eq!(candidates[2].pool_name, "Pool C");
    }

    #[test]
    fn test_build_candidates_empty_pairs() {
        let user_id = Uuid::new_v4();
        let pairs: Vec<(Uuid, Uuid, String, Uuid)> = vec![];
        let candidates = build_lifecycle_candidates(user_id, &pairs);
        assert!(candidates.is_empty());
    }

    // ========================================================================
    // cancel_if_active_placeholder tests
    // ========================================================================

    #[test]
    fn test_cancel_placeholder_returns_false() {
        // Current implementation has no grace period, so cancellation
        // always returns false.
        assert!(!cancel_if_active_placeholder());
    }

    // ========================================================================
    // system_actor_id tests
    // ========================================================================

    #[test]
    fn test_system_actor_id_is_nil() {
        let id = system_actor_id();
        assert_eq!(id, Uuid::nil());
        assert!(id.is_nil());
    }

    #[test]
    fn test_system_actor_id_is_all_zeros() {
        let id = system_actor_id();
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_system_actor_id_consistent_across_calls() {
        assert_eq!(system_actor_id(), system_actor_id());
    }

    // ========================================================================
    // Serde: CreateReclamationRuleRequest default_notification_days
    // ========================================================================

    #[test]
    fn test_create_request_default_notification_days() {
        let json = format!(
            r#"{{
                "license_pool_id": "{}",
                "trigger_type": "inactivity",
                "threshold_days": 60
            }}"#,
            Uuid::new_v4()
        );

        let request: CreateReclamationRuleRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.notification_days_before, 7); // default
    }

    // ========================================================================
    // Serde: ListReclamationRulesParams defaults
    // ========================================================================

    #[test]
    fn test_list_params_from_json_empty() {
        let json = r#"{}"#;
        let params: ListReclamationRulesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 20); // default_limit()
        assert_eq!(params.offset, 0);
    }

    // ========================================================================
    // Integration-style: validation + candidate building pipeline
    // ========================================================================

    #[test]
    fn test_full_lifecycle_reclamation_pipeline() {
        // 1. Validate a lifecycle rule request.
        let result = validate_trigger_fields(
            LicenseReclamationTrigger::LifecycleState,
            None,
            Some("terminated"),
        );
        assert!(result.is_ok());

        // 2. Check that the lifecycle state should trigger reclamation.
        let rules = vec![
            LifecycleRuleData {
                enabled: true,
                lifecycle_state: Some("terminated".to_string()),
            },
            LifecycleRuleData {
                enabled: true,
                lifecycle_state: Some("on_leave".to_string()),
            },
        ];
        assert!(should_reclaim_for_lifecycle_state("terminated", &rules));
        assert!(!should_reclaim_for_lifecycle_state("active", &rules));

        // 3. Build candidates from matching rule+assignment pairs.
        let user_id = Uuid::new_v4();
        let rule_id = Uuid::new_v4();
        let pool_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();
        let pairs = vec![(rule_id, pool_id, "Adobe CC".to_string(), assignment_id)];
        let candidates = build_lifecycle_candidates(user_id, &pairs);
        assert_eq!(candidates.len(), 1);

        // 4. Simulate execution outcomes and aggregate.
        let outcomes = vec![Ok(true)];
        let exec_result = aggregate_reclamation_result(&outcomes);
        assert_eq!(exec_result.reclaimed_count, 1);
        assert_eq!(exec_result.failed_count, 0);
        assert!(exec_result.errors.is_empty());

        // 5. Verify system actor is used.
        assert!(system_actor_id().is_nil());
    }

    #[test]
    fn test_inactivity_validation_rejects_missing_threshold() {
        // This mirrors what create_rule() does internally.
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, None, None);
        assert!(result.is_err());

        // With threshold provided, it passes.
        let result = validate_trigger_fields(LicenseReclamationTrigger::Inactivity, Some(1), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_enforce_limits_boundary_values() {
        // i64::MIN should clamp to 1 for limit, 0 for offset
        let (limit, offset) = enforce_list_limits(i64::MIN, i64::MIN);
        assert_eq!(limit, 1);
        assert_eq!(offset, 0);

        // i64::MAX should clamp to 100 for limit, stay as-is for offset
        let (limit, offset) = enforce_list_limits(i64::MAX, i64::MAX);
        assert_eq!(limit, 100);
        assert_eq!(offset, i64::MAX);
    }
}
