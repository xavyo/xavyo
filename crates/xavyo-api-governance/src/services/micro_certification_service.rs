//! Micro-certification service for governance API (F055).
//!
//! Handles micro-certification lifecycle including creation from events,
//! reviewer resolution, decision processing, and auto-revoke.

// Event processing functions naturally require multiple context parameters
#![allow(clippy::too_many_arguments)]

#[cfg(feature = "kafka")]
use std::sync::Arc;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::info;
#[cfg(feature = "kafka")]
use tracing::warn;
use uuid::Uuid;

use xavyo_db::models::{
    CreateMicroCertEvent, CreateMicroCertification, DecideMicroCertification, GovAssignmentFilter,
    GovAssignmentStatus, GovAssignmentTargetType, GovEntitlement, GovEntitlementAssignment,
    GovMicroCertEvent, GovMicroCertTrigger, GovMicroCertification, MicroCertDecision,
    MicroCertEventType, MicroCertReviewerType, MicroCertStatus, MicroCertTriggerType,
    MicroCertificationFilter, MicroCertificationStats, User,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::{
    events::{
        MicroCertificationAutoRevoked, MicroCertificationCreated, MicroCertificationDecided,
        MicroCertificationEscalated, MicroCertificationExpired, MicroCertificationReminder,
    },
    EventProducer,
};

/// Result of creating a micro-certification.
#[derive(Debug, Clone)]
pub struct MicroCertCreationResult {
    /// The created certification.
    pub certification: GovMicroCertification,
    /// Whether a duplicate was detected and skipped.
    pub duplicate_skipped: bool,
    /// The trigger rule used.
    pub trigger_rule: GovMicroCertTrigger,
}

/// Result of deciding on a micro-certification.
#[derive(Debug, Clone)]
pub struct MicroCertDecisionResult {
    /// The updated certification.
    pub certification: GovMicroCertification,
    /// Whether auto-revoke was triggered.
    pub auto_revoked: bool,
    /// The revoked assignment ID (if any).
    pub revoked_assignment_id: Option<Uuid>,
    /// The created exemption ID (for `SoD` approvals).
    pub created_exemption_id: Option<Uuid>,
}

/// Result of bulk decision.
#[derive(Debug, Clone)]
pub struct BulkDecisionResult {
    /// Successfully processed certifications.
    pub succeeded: Vec<Uuid>,
    /// Failed certifications with errors.
    pub failed: Vec<(Uuid, String)>,
}

/// Service for micro-certification operations.
pub struct MicroCertificationService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl MicroCertificationService {
    /// Create a new micro-certification service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new micro-certification service with event producer.
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
    // T020: Find matching trigger rule for high_risk_assignment
    // T039: Extend for sod_violation trigger type
    // T047: Extend for manager_change trigger type
    // =========================================================================

    /// Find the best matching trigger rule for an event.
    ///
    /// Priority: entitlement-specific > application-specific > tenant-wide default
    pub async fn find_matching_trigger_rule(
        &self,
        tenant_id: Uuid,
        trigger_type: MicroCertTriggerType,
        entitlement_id: Option<Uuid>,
        application_id: Option<Uuid>,
    ) -> Result<Option<GovMicroCertTrigger>> {
        GovMicroCertTrigger::find_matching_rule(
            &self.pool,
            tenant_id,
            trigger_type,
            entitlement_id,
            application_id,
        )
        .await
        .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // T021: Resolve reviewer with user_manager support
    // =========================================================================

    /// Resolve the reviewer for a micro-certification.
    ///
    /// Handles different reviewer types:
    /// - `user_manager`: Get the user's manager
    /// - `entitlement_owner`: Get the entitlement owner
    /// - `application_owner`: Get the application owner
    /// - `specific_user`: Use the configured user ID
    ///
    /// Falls back to `fallback_reviewer_id` if primary cannot be resolved.
    pub async fn resolve_reviewer(
        &self,
        tenant_id: Uuid,
        rule: &GovMicroCertTrigger,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<(Uuid, Option<Uuid>)> {
        let primary_reviewer = match rule.reviewer_type {
            MicroCertReviewerType::UserManager => {
                // Get user's manager
                let manager = User::get_manager(&self.pool, tenant_id, user_id).await?;
                manager.map(|m| *m.user_id().as_uuid())
            }
            MicroCertReviewerType::EntitlementOwner => {
                // Get entitlement owner
                let entitlement =
                    GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id).await?;
                entitlement.and_then(|e| e.owner_id)
            }
            MicroCertReviewerType::ApplicationOwner => {
                // Get application owner via entitlement
                let entitlement =
                    GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id).await?;
                if let Some(ent) = entitlement {
                    let app = xavyo_db::models::GovApplication::find_by_id(
                        &self.pool,
                        tenant_id,
                        ent.application_id,
                    )
                    .await?;
                    app.and_then(|a| a.owner_id)
                } else {
                    None
                }
            }
            MicroCertReviewerType::SpecificUser => rule.specific_reviewer_id,
        };

        // T091: Self-review prevention - if reviewer is the same as the user, use fallback
        let effective_reviewer = if primary_reviewer == Some(user_id) {
            info!(
                user_id = %user_id,
                "Self-review detected, using fallback reviewer"
            );
            rule.fallback_reviewer_id
        } else {
            primary_reviewer
        };

        // Fall back to fallback_reviewer_id if primary cannot be resolved
        let reviewer_id = effective_reviewer
            .or(rule.fallback_reviewer_id)
            .ok_or_else(|| {
                GovernanceError::MicroCertReviewerNotResolved(format!(
                    "Cannot resolve reviewer for rule {}",
                    rule.id
                ))
            })?;

        // Use fallback as backup reviewer if different from primary
        let backup_reviewer = if rule.fallback_reviewer_id.is_some()
            && rule.fallback_reviewer_id != Some(reviewer_id)
        {
            rule.fallback_reviewer_id
        } else {
            None
        };

        Ok((reviewer_id, backup_reviewer))
    }

    // =========================================================================
    // T022: Create from assignment event (high_risk_assignment)
    // =========================================================================

    /// Create a micro-certification from an entitlement assignment event.
    ///
    /// This is triggered when a high-risk entitlement is assigned to a user.
    pub async fn create_from_assignment_event(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        event_type: &str,
        event_id: Uuid,
        event_data: Option<serde_json::Value>,
    ) -> Result<Option<MicroCertCreationResult>> {
        // Get entitlement to find application
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        // Find matching trigger rule
        let rule = self
            .find_matching_trigger_rule(
                tenant_id,
                MicroCertTriggerType::HighRiskAssignment,
                Some(entitlement_id),
                Some(entitlement.application_id),
            )
            .await?;

        let Some(rule) = rule else {
            // No matching rule, no certification needed
            return Ok(None);
        };

        // T090: Check for duplicate - if pending certification exists, skip
        let existing = GovMicroCertification::find_pending_for_assignment(
            &self.pool,
            tenant_id,
            assignment_id,
            rule.id,
        )
        .await?;

        if let Some(existing_cert) = existing {
            info!(
                assignment_id = %assignment_id,
                rule_id = %rule.id,
                "Duplicate micro-certification skipped"
            );
            return Ok(Some(MicroCertCreationResult {
                certification: existing_cert,
                duplicate_skipped: true,
                trigger_rule: rule,
            }));
        }

        // Resolve reviewer
        let (reviewer_id, backup_reviewer_id) = self
            .resolve_reviewer(tenant_id, &rule, user_id, entitlement_id)
            .await?;

        // Calculate deadlines
        let deadline = rule.calculate_deadline();
        let escalation_deadline = rule.calculate_escalation_deadline();

        // Create the certification
        let input = CreateMicroCertification {
            trigger_rule_id: rule.id,
            assignment_id: Some(assignment_id),
            user_id,
            entitlement_id,
            reviewer_id,
            backup_reviewer_id,
            triggering_event_type: event_type.to_string(),
            triggering_event_id: event_id,
            triggering_event_data: event_data,
            deadline,
            escalation_deadline,
        };

        let certification = GovMicroCertification::create(&self.pool, tenant_id, input).await?;

        // Record creation event
        self.record_event(
            tenant_id,
            certification.id,
            MicroCertEventType::Created,
            None,
            Some(serde_json::json!({
                "trigger_rule_id": rule.id,
                "trigger_type": "high_risk_assignment",
                "assignment_id": assignment_id,
                "reviewer_id": reviewer_id,
                "deadline": deadline.to_rfc3339(),
            })),
        )
        .await?;

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_created_event(tenant_id, &certification, &rule)
            .await;

        info!(
            certification_id = %certification.id,
            assignment_id = %assignment_id,
            reviewer_id = %reviewer_id,
            "Micro-certification created for high-risk assignment"
        );

        Ok(Some(MicroCertCreationResult {
            certification,
            duplicate_skipped: false,
            trigger_rule: rule,
        }))
    }

    // =========================================================================
    // T040: Create from SoD violation
    // =========================================================================

    /// Create a micro-certification from an `SoD` violation event.
    ///
    /// When a user receives conflicting entitlements, a certification is created
    /// to decide whether to approve (create exemption) or revoke the triggering assignment.
    pub async fn create_from_sod_violation(
        &self,
        tenant_id: Uuid,
        violation_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        assignment_id: Uuid,
        conflicting_entitlement_id: Uuid,
        event_type: &str,
        event_id: Uuid,
        event_data: Option<serde_json::Value>,
    ) -> Result<Option<MicroCertCreationResult>> {
        // Get entitlement to find application
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        // Find matching trigger rule for SoD violations
        let rule = self
            .find_matching_trigger_rule(
                tenant_id,
                MicroCertTriggerType::SodViolation,
                Some(entitlement_id),
                Some(entitlement.application_id),
            )
            .await?;

        let Some(rule) = rule else {
            return Ok(None);
        };

        // Check for duplicate
        let existing = GovMicroCertification::find_pending_for_assignment(
            &self.pool,
            tenant_id,
            assignment_id,
            rule.id,
        )
        .await?;

        if let Some(existing_cert) = existing {
            return Ok(Some(MicroCertCreationResult {
                certification: existing_cert,
                duplicate_skipped: true,
                trigger_rule: rule,
            }));
        }

        // Resolve reviewer
        let (reviewer_id, backup_reviewer_id) = self
            .resolve_reviewer(tenant_id, &rule, user_id, entitlement_id)
            .await?;

        let deadline = rule.calculate_deadline();
        let escalation_deadline = rule.calculate_escalation_deadline();

        let input = CreateMicroCertification {
            trigger_rule_id: rule.id,
            assignment_id: Some(assignment_id),
            user_id,
            entitlement_id,
            reviewer_id,
            backup_reviewer_id,
            triggering_event_type: event_type.to_string(),
            triggering_event_id: event_id,
            triggering_event_data: Some(serde_json::json!({
                "violation_id": violation_id,
                "conflicting_entitlement_id": conflicting_entitlement_id,
                "original_event_data": event_data,
            })),
            deadline,
            escalation_deadline,
        };

        let certification = GovMicroCertification::create(&self.pool, tenant_id, input).await?;

        self.record_event(
            tenant_id,
            certification.id,
            MicroCertEventType::Created,
            None,
            Some(serde_json::json!({
                "trigger_rule_id": rule.id,
                "trigger_type": "sod_violation",
                "violation_id": violation_id,
                "assignment_id": assignment_id,
                "conflicting_entitlement_id": conflicting_entitlement_id,
            })),
        )
        .await?;

        #[cfg(feature = "kafka")]
        self.emit_created_event(tenant_id, &certification, &rule)
            .await;

        info!(
            certification_id = %certification.id,
            violation_id = %violation_id,
            "Micro-certification created for SoD violation"
        );

        Ok(Some(MicroCertCreationResult {
            certification,
            duplicate_skipped: false,
            trigger_rule: rule,
        }))
    }

    // =========================================================================
    // T048: Create from manager change
    // =========================================================================

    /// Create micro-certifications for all applicable entitlements when a user's manager changes.
    ///
    /// Returns a list of created certifications.
    pub async fn create_from_manager_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        old_manager_id: Option<Uuid>,
        new_manager_id: Uuid,
        event_type: &str,
        event_id: Uuid,
    ) -> Result<Vec<MicroCertCreationResult>> {
        // Find matching trigger rule for manager change
        let rule = self
            .find_matching_trigger_rule(tenant_id, MicroCertTriggerType::ManagerChange, None, None)
            .await?;

        let Some(rule) = rule else {
            return Ok(vec![]);
        };

        // Get all active assignments for the user
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            status: Some(GovAssignmentStatus::Active),
            ..Default::default()
        };
        let assignments = GovEntitlementAssignment::list_by_tenant(
            &self.pool, tenant_id, &filter, 1000, // Reasonable limit
            0,
        )
        .await?;

        let mut results = Vec::new();

        for assignment in assignments {
            // Get entitlement to check if it's high-risk (has risk_level set)
            let entitlement =
                GovEntitlement::find_by_id(&self.pool, tenant_id, assignment.entitlement_id)
                    .await?;

            let Some(entitlement) = entitlement else {
                continue;
            };

            // Only create certifications for entitlements that warrant review on manager change
            // This could be based on risk level or other criteria
            // For now, we create for all active assignments

            // Check for duplicate
            let existing = GovMicroCertification::find_pending_for_assignment(
                &self.pool,
                tenant_id,
                assignment.id,
                rule.id,
            )
            .await?;

            if let Some(existing_cert) = existing {
                results.push(MicroCertCreationResult {
                    certification: existing_cert,
                    duplicate_skipped: true,
                    trigger_rule: rule.clone(),
                });
                continue;
            }

            // Resolve reviewer - for manager change, the new manager should review
            let (reviewer_id, backup_reviewer_id) = self
                .resolve_reviewer(tenant_id, &rule, user_id, entitlement.id)
                .await?;

            let deadline = rule.calculate_deadline();
            let escalation_deadline = rule.calculate_escalation_deadline();

            let input = CreateMicroCertification {
                trigger_rule_id: rule.id,
                assignment_id: Some(assignment.id),
                user_id,
                entitlement_id: entitlement.id,
                reviewer_id,
                backup_reviewer_id,
                triggering_event_type: event_type.to_string(),
                triggering_event_id: event_id,
                triggering_event_data: Some(serde_json::json!({
                    "old_manager_id": old_manager_id,
                    "new_manager_id": new_manager_id,
                    "assignment_id": assignment.id,
                })),
                deadline,
                escalation_deadline,
            };

            let certification = GovMicroCertification::create(&self.pool, tenant_id, input).await?;

            self.record_event(
                tenant_id,
                certification.id,
                MicroCertEventType::Created,
                None,
                Some(serde_json::json!({
                    "trigger_rule_id": rule.id,
                    "trigger_type": "manager_change",
                    "old_manager_id": old_manager_id,
                    "new_manager_id": new_manager_id,
                })),
            )
            .await?;

            #[cfg(feature = "kafka")]
            self.emit_created_event(tenant_id, &certification, &rule)
                .await;

            results.push(MicroCertCreationResult {
                certification,
                duplicate_skipped: false,
                trigger_rule: rule.clone(),
            });
        }

        info!(
            user_id = %user_id,
            count = results.len(),
            "Micro-certifications created for manager change"
        );

        Ok(results)
    }

    // =========================================================================
    // T023: Decide method (approve/revoke)
    // T024: Auto-revoke on reject
    // T041: SoD-specific decision handling
    // T042-43: Revoke triggering assignment for SoD
    // =========================================================================

    /// Make a decision on a micro-certification.
    ///
    /// For approval:
    /// - For `SoD` violations: Creates an exemption
    /// - For other types: Simply approves the access
    ///
    /// For revocation:
    /// - Revokes the triggering assignment
    /// - For `SoD`: Revokes the newest assignment that caused the conflict
    pub async fn decide(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
        decided_by: Uuid,
        decision: MicroCertDecision,
        comment: Option<String>,
    ) -> Result<MicroCertDecisionResult> {
        // Get the certification
        let certification =
            GovMicroCertification::find_by_id(&self.pool, tenant_id, certification_id)
                .await?
                .ok_or(GovernanceError::MicroCertificationNotFound(
                    certification_id,
                ))?;

        // Verify the user can decide
        if !certification.can_decide(decided_by) {
            return Err(GovernanceError::MicroCertCannotDecide(
                certification_id,
                decided_by,
            ));
        }

        // Check if already decided
        if certification.status != MicroCertStatus::Pending {
            return Err(GovernanceError::MicroCertificationAlreadyDecided(
                certification_id,
            ));
        }

        // Get the trigger rule for context
        let rule =
            GovMicroCertTrigger::find_by_id(&self.pool, tenant_id, certification.trigger_rule_id)
                .await?
                .ok_or(GovernanceError::MicroCertTriggerNotFound(
                    certification.trigger_rule_id,
                ))?;

        let input = DecideMicroCertification {
            decision,
            comment: comment.clone(),
        };

        // Record the decision
        let updated = GovMicroCertification::decide(
            &self.pool,
            tenant_id,
            certification_id,
            decided_by,
            input,
        )
        .await?
        .ok_or(GovernanceError::MicroCertificationAlreadyDecided(
            certification_id,
        ))?;

        let mut auto_revoked = false;
        let mut revoked_assignment_id = None;
        let created_exemption_id = None;

        match decision {
            MicroCertDecision::Approve => {
                // Record approval event
                self.record_event(
                    tenant_id,
                    certification_id,
                    MicroCertEventType::Approved,
                    Some(decided_by),
                    Some(serde_json::json!({
                        "comment": comment,
                    })),
                )
                .await?;

                // For SoD violations, create an exemption (would need SodExemptionService)
                // This is a placeholder - actual implementation depends on SoD integration
                if rule.trigger_type == MicroCertTriggerType::SodViolation {
                    // TODO: Create SoD exemption via SodExemptionService
                    info!(
                        certification_id = %certification_id,
                        "SoD violation approved - exemption should be created"
                    );
                }

                #[cfg(feature = "kafka")]
                self.emit_decided_event(tenant_id, &updated, decided_by, "approved", None)
                    .await;
            }
            MicroCertDecision::Revoke => {
                auto_revoked = true;

                // Revoke the assignment
                if let Some(assignment_id) = certification.assignment_id {
                    // For SoD violations with revoke_triggering_assignment, revoke the newest assignment
                    if rule.trigger_type == MicroCertTriggerType::SodViolation
                        && rule.revoke_triggering_assignment
                    {
                        // The assignment_id on the certification is the triggering one
                        revoked_assignment_id = Some(assignment_id);
                    } else {
                        revoked_assignment_id = Some(assignment_id);
                    }

                    // Actually revoke the assignment
                    if let Some(to_revoke) = revoked_assignment_id {
                        let _ = GovEntitlementAssignment::revoke(&self.pool, tenant_id, to_revoke)
                            .await;

                        // Update certification with revoked assignment
                        GovMicroCertification::set_revoked_assignment(
                            &self.pool,
                            tenant_id,
                            certification_id,
                            to_revoke,
                        )
                        .await?;
                    }
                }

                self.record_event(
                    tenant_id,
                    certification_id,
                    MicroCertEventType::Rejected,
                    Some(decided_by),
                    Some(serde_json::json!({
                        "comment": comment,
                        "revoked_assignment_id": revoked_assignment_id,
                    })),
                )
                .await?;

                #[cfg(feature = "kafka")]
                self.emit_decided_event(
                    tenant_id,
                    &updated,
                    decided_by,
                    "revoked",
                    revoked_assignment_id,
                )
                .await;
            }
            MicroCertDecision::Reduce => {
                // Flag for review - access remains but is marked for investigation
                // This is the IGA "Reduce" pattern - suspicious but needs more info
                self.record_event(
                    tenant_id,
                    certification_id,
                    MicroCertEventType::FlaggedForReview,
                    Some(decided_by),
                    Some(serde_json::json!({
                        "comment": comment,
                        "reason": "Flagged for investigation without immediate revocation",
                    })),
                )
                .await?;

                info!(
                    certification_id = %certification_id,
                    decided_by = %decided_by,
                    "Micro-certification flagged for review (Reduce decision)"
                );

                #[cfg(feature = "kafka")]
                self.emit_decided_event(
                    tenant_id,
                    &updated,
                    decided_by,
                    "flagged_for_review",
                    None,
                )
                .await;
            }
            MicroCertDecision::Delegate => {
                // Delegate decision should not reach here - it's handled separately
                // via delegate() method which changes the reviewer
                return Err(GovernanceError::MicroCertDelegateRequiresDedicatedEndpoint);
            }
        }

        info!(
            certification_id = %certification_id,
            decision = ?decision,
            decided_by = %decided_by,
            auto_revoked = auto_revoked,
            "Micro-certification decision recorded"
        );

        Ok(MicroCertDecisionResult {
            certification: updated,
            auto_revoked,
            revoked_assignment_id,
            created_exemption_id,
        })
    }

    // =========================================================================
    // Delegate decision to another reviewer (IGA pattern: Delegate)
    // =========================================================================

    /// Delegate a certification decision to another reviewer.
    ///
    /// The original reviewer transfers responsibility to a new reviewer.
    /// The certification remains pending but with the new reviewer assigned.
    pub async fn delegate(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
        delegated_by: Uuid,
        delegate_to: Uuid,
        comment: Option<String>,
    ) -> Result<GovMicroCertification> {
        // Get the certification
        let certification =
            GovMicroCertification::find_by_id(&self.pool, tenant_id, certification_id)
                .await?
                .ok_or(GovernanceError::MicroCertificationNotFound(
                    certification_id,
                ))?;

        // Verify the user can delegate
        if !certification.can_decide(delegated_by) {
            return Err(GovernanceError::MicroCertCannotDecide(
                certification_id,
                delegated_by,
            ));
        }

        // Check if already decided
        if certification.status != MicroCertStatus::Pending {
            return Err(GovernanceError::MicroCertificationAlreadyDecided(
                certification_id,
            ));
        }

        // Cannot delegate to self
        if delegate_to == delegated_by {
            return Err(GovernanceError::MicroCertSelfDelegationNotAllowed);
        }

        // Cannot delegate to the user being certified
        if delegate_to == certification.user_id {
            return Err(GovernanceError::MicroCertDelegationError(
                "Cannot delegate to the user being certified".to_string(),
            ));
        }

        // Update the certification with new reviewer
        let original_reviewer_id = certification
            .original_reviewer_id
            .unwrap_or(certification.reviewer_id);

        let updated = GovMicroCertification::delegate(
            &self.pool,
            tenant_id,
            certification_id,
            delegate_to,
            delegated_by,
            original_reviewer_id,
            comment.clone(),
        )
        .await?
        .ok_or(GovernanceError::MicroCertificationNotFound(
            certification_id,
        ))?;

        // Record delegation event
        self.record_event(
            tenant_id,
            certification_id,
            MicroCertEventType::Delegated,
            Some(delegated_by),
            Some(serde_json::json!({
                "delegated_to": delegate_to,
                "original_reviewer_id": original_reviewer_id,
                "comment": comment,
            })),
        )
        .await?;

        info!(
            certification_id = %certification_id,
            delegated_by = %delegated_by,
            delegate_to = %delegate_to,
            "Micro-certification delegated to new reviewer"
        );

        Ok(updated)
    }

    // =========================================================================
    // T049: Bulk decide for multiple certifications
    // =========================================================================

    /// Make the same decision on multiple certifications at once.
    ///
    /// Used for manager change scenarios where the new manager reviews all access.
    pub async fn bulk_decide(
        &self,
        tenant_id: Uuid,
        certification_ids: &[Uuid],
        decided_by: Uuid,
        decision: MicroCertDecision,
        comment: Option<String>,
    ) -> Result<BulkDecisionResult> {
        let mut succeeded = Vec::new();
        let mut failed = Vec::new();

        for cert_id in certification_ids {
            match self
                .decide(tenant_id, *cert_id, decided_by, decision, comment.clone())
                .await
            {
                Ok(_) => succeeded.push(*cert_id),
                Err(e) => failed.push((*cert_id, e.to_string())),
            }
        }

        info!(
            succeeded = succeeded.len(),
            failed = failed.len(),
            "Bulk micro-certification decision completed"
        );

        Ok(BulkDecisionResult { succeeded, failed })
    }

    // =========================================================================
    // T025: Record event for audit trail
    // =========================================================================

    /// Record an audit event for a micro-certification.
    pub async fn record_event(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
        event_type: MicroCertEventType,
        actor_id: Option<Uuid>,
        details: Option<serde_json::Value>,
    ) -> Result<GovMicroCertEvent> {
        let input = CreateMicroCertEvent {
            micro_certification_id: certification_id,
            event_type,
            actor_id,
            details,
        };

        GovMicroCertEvent::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /// Get a micro-certification by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<GovMicroCertification> {
        GovMicroCertification::find_by_id(&self.pool, tenant_id, certification_id)
            .await?
            .ok_or(GovernanceError::MicroCertificationNotFound(
                certification_id,
            ))
    }

    /// List certifications with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &MicroCertificationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMicroCertification>, i64)> {
        let items =
            GovMicroCertification::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        let total = GovMicroCertification::count_by_tenant(&self.pool, tenant_id, filter).await?;
        Ok((items, total))
    }

    /// Get pending certifications for the current user.
    pub async fn get_my_pending(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovMicroCertification>> {
        // Get certifications where user is the primary reviewer
        let mut pending = GovMicroCertification::find_pending_by_reviewer(
            &self.pool, tenant_id, user_id, limit, offset,
        )
        .await?;

        // Also get escalated certifications where user is the backup reviewer
        let escalated = GovMicroCertification::find_pending_by_backup_reviewer(
            &self.pool, tenant_id, user_id, limit, offset,
        )
        .await?;

        pending.extend(escalated);

        // Sort by deadline
        pending.sort_by(|a, b| a.deadline.cmp(&b.deadline));

        // Truncate to limit
        pending.truncate(limit as usize);

        Ok(pending)
    }

    /// Get statistics for the tenant.
    pub async fn get_stats(&self, tenant_id: Uuid) -> Result<MicroCertificationStats> {
        GovMicroCertification::get_stats(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get events for a certification.
    pub async fn get_events(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<Vec<GovMicroCertEvent>> {
        GovMicroCertEvent::find_by_certification(&self.pool, tenant_id, certification_id)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // T089: Manual trigger
    // =========================================================================

    /// Manually trigger a micro-certification for a user's entitlement.
    ///
    /// This allows administrators to manually initiate a certification review.
    pub async fn create_manual(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        trigger_rule_id: Option<Uuid>,
        reviewer_id: Option<Uuid>,
        reason: &str,
        triggered_by: Uuid,
    ) -> Result<MicroCertCreationResult> {
        // Get entitlement details
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        // Find or use specified trigger rule
        let rule = if let Some(rule_id) = trigger_rule_id {
            GovMicroCertTrigger::find_by_id(&self.pool, tenant_id, rule_id)
                .await?
                .ok_or(GovernanceError::MicroCertTriggerNotFound(rule_id))?
        } else {
            // Look for a Manual trigger type default rule
            self.find_matching_trigger_rule(
                tenant_id,
                MicroCertTriggerType::Manual,
                Some(entitlement_id),
                Some(entitlement.application_id),
            )
            .await?
            .ok_or_else(|| GovernanceError::MicroCertTriggerNotFound(Uuid::nil()))?
        };

        // Find an active assignment for this user and entitlement
        let filter = GovAssignmentFilter {
            target_id: Some(user_id),
            entitlement_id: Some(entitlement_id),
            status: Some(GovAssignmentStatus::Active),
            target_type: Some(GovAssignmentTargetType::User),
            ..Default::default()
        };
        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1, 0).await?;
        let assignment = assignments.first();

        // T090: Check for duplicate
        if let Some(assignment) = assignment {
            let existing = GovMicroCertification::find_pending_for_assignment(
                &self.pool,
                tenant_id,
                assignment.id,
                rule.id,
            )
            .await?;

            if let Some(cert) = existing {
                info!(
                    assignment_id = %assignment.id,
                    rule_id = %rule.id,
                    "Duplicate manual micro-certification skipped"
                );
                return Ok(MicroCertCreationResult {
                    certification: cert,
                    duplicate_skipped: true,
                    trigger_rule: rule,
                });
            }
        }

        // Resolve reviewer (use provided reviewer_id if given, otherwise resolve from rule)
        let (resolved_reviewer, backup_reviewer) = if let Some(rev_id) = reviewer_id {
            (rev_id, rule.fallback_reviewer_id)
        } else {
            self.resolve_reviewer(tenant_id, &rule, user_id, entitlement_id)
                .await?
        };

        // Calculate deadlines
        let deadline = rule.calculate_deadline();
        let escalation_deadline = rule.calculate_escalation_deadline();

        // Create the certification
        let event_id = Uuid::new_v4();
        let input = CreateMicroCertification {
            trigger_rule_id: rule.id,
            assignment_id: assignment.map(|a| a.id),
            user_id,
            entitlement_id,
            reviewer_id: resolved_reviewer,
            backup_reviewer_id: backup_reviewer,
            triggering_event_type: "manual_trigger".to_string(),
            triggering_event_id: event_id,
            triggering_event_data: Some(serde_json::json!({
                "reason": reason,
                "triggered_by": triggered_by,
            })),
            deadline,
            escalation_deadline,
        };

        let certification = GovMicroCertification::create(&self.pool, tenant_id, input).await?;

        // Record creation event
        self.record_event(
            tenant_id,
            certification.id,
            MicroCertEventType::Created,
            Some(triggered_by),
            Some(serde_json::json!({
                "trigger_rule_id": rule.id,
                "trigger_type": "manual",
                "reason": reason,
                "reviewer_id": resolved_reviewer,
                "deadline": deadline.to_rfc3339(),
            })),
        )
        .await?;

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_created_event(tenant_id, &certification, &rule)
            .await;

        info!(
            certification_id = %certification.id,
            user_id = %user_id,
            entitlement_id = %entitlement_id,
            triggered_by = %triggered_by,
            "Manual micro-certification created"
        );

        Ok(MicroCertCreationResult {
            certification,
            duplicate_skipped: false,
            trigger_rule: rule,
        })
    }

    /// Search events across all certifications with filtering.
    pub async fn search_events(
        &self,
        tenant_id: Uuid,
        filter: &xavyo_db::MicroCertEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMicroCertEvent>, i64)> {
        let events =
            GovMicroCertEvent::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovMicroCertEvent::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((events, total))
    }

    // =========================================================================
    // T092: Skip on delete handling
    // =========================================================================

    /// Mark certifications as skipped when the assignment is deleted.
    pub async fn skip_by_assignment(&self, tenant_id: Uuid, assignment_id: Uuid) -> Result<u64> {
        let count =
            GovMicroCertification::skip_by_assignment(&self.pool, tenant_id, assignment_id).await?;

        if count > 0 {
            info!(
                assignment_id = %assignment_id,
                count = count,
                "Micro-certifications skipped due to assignment deletion"
            );
        }

        Ok(count)
    }

    // =========================================================================
    // Expiration and escalation methods (used by background job)
    // =========================================================================

    /// Find certifications past deadline for expiration processing.
    pub async fn find_past_deadline(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GovMicroCertification>> {
        GovMicroCertification::find_past_deadline(&self.pool, tenant_id, limit)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Find certifications needing escalation.
    pub async fn find_needing_escalation(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GovMicroCertification>> {
        GovMicroCertification::find_needing_escalation(&self.pool, tenant_id, limit)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Find certifications needing reminder.
    pub async fn find_needing_reminder(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GovMicroCertification>> {
        // Calculate reminder time - certifications where deadline minus threshold is past
        // We need to get the trigger rule for each certification to know the threshold
        // For simplicity, we use a default of 75% (so reminder at 25% remaining time)
        // A more sophisticated implementation would join with trigger rules
        let now = Utc::now();
        let reminder_time = now + Duration::hours(6); // Default 6 hours before deadline

        GovMicroCertification::find_needing_reminder(&self.pool, tenant_id, reminder_time, limit)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Mark a certification as escalated.
    pub async fn mark_escalated(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<Option<GovMicroCertification>> {
        let result =
            GovMicroCertification::mark_escalated(&self.pool, tenant_id, certification_id).await?;

        if let Some(ref cert) = result {
            self.record_event(
                tenant_id,
                certification_id,
                MicroCertEventType::Escalated,
                None,
                Some(serde_json::json!({
                    "backup_reviewer_id": cert.backup_reviewer_id,
                })),
            )
            .await?;

            #[cfg(feature = "kafka")]
            if let Some(backup_id) = cert.backup_reviewer_id {
                self.emit_escalated_event(tenant_id, cert, backup_id).await;
            }
        }

        Ok(result)
    }

    /// Mark a certification as expired (timeout without auto-revoke).
    pub async fn mark_expired(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<Option<GovMicroCertification>> {
        let result =
            GovMicroCertification::mark_expired(&self.pool, tenant_id, certification_id).await?;

        if result.is_some() {
            self.record_event(
                tenant_id,
                certification_id,
                MicroCertEventType::Expired,
                None,
                None,
            )
            .await?;

            #[cfg(feature = "kafka")]
            if let Some(ref cert) = result {
                self.emit_expired_event(tenant_id, cert).await;
            }
        }

        Ok(result)
    }

    /// Mark a certification as auto-revoked (timeout with auto-revoke).
    pub async fn mark_auto_revoked(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<Option<GovMicroCertification>> {
        // Get the certification first to know the assignment
        let cert =
            GovMicroCertification::find_by_id(&self.pool, tenant_id, certification_id).await?;

        let Some(cert) = cert else {
            return Ok(None);
        };

        // Revoke the assignment if it exists
        let revoked_assignment_id = if let Some(assignment_id) = cert.assignment_id {
            let _ = GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment_id).await;
            Some(assignment_id)
        } else {
            None
        };

        let result = GovMicroCertification::mark_auto_revoked(
            &self.pool,
            tenant_id,
            certification_id,
            revoked_assignment_id,
        )
        .await?;

        if result.is_some() {
            self.record_event(
                tenant_id,
                certification_id,
                MicroCertEventType::AutoRevoked,
                None,
                Some(serde_json::json!({
                    "revoked_assignment_id": revoked_assignment_id,
                })),
            )
            .await?;

            #[cfg(feature = "kafka")]
            if let Some(ref updated_cert) = result {
                self.emit_revoked_event(tenant_id, updated_cert, revoked_assignment_id)
                    .await;
            }
        }

        Ok(result)
    }

    /// Mark reminder as sent.
    pub async fn mark_reminder_sent(
        &self,
        tenant_id: Uuid,
        certification_id: Uuid,
    ) -> Result<bool> {
        let result =
            GovMicroCertification::mark_reminder_sent(&self.pool, tenant_id, certification_id)
                .await?;

        if result {
            self.record_event(
                tenant_id,
                certification_id,
                MicroCertEventType::ReminderSent,
                None,
                None,
            )
            .await?;

            #[cfg(feature = "kafka")]
            {
                let cert =
                    GovMicroCertification::find_by_id(&self.pool, tenant_id, certification_id)
                        .await?;
                if let Some(ref c) = cert {
                    // Get auto_revoke from trigger rule
                    let auto_revoke = if let Ok(Some(rule)) =
                        GovMicroCertTrigger::find_by_id(&self.pool, tenant_id, c.trigger_rule_id)
                            .await
                    {
                        rule.auto_revoke
                    } else {
                        true // default to true for safety
                    };
                    self.emit_reminder_event(tenant_id, c, auto_revoke).await;
                }
            }
        }

        Ok(result)
    }

    /// Get reference to the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Kafka event emission (T026: notification integration)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_created_event(
        &self,
        tenant_id: Uuid,
        certification: &GovMicroCertification,
        rule: &GovMicroCertTrigger,
    ) {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::MicroCertTriggerTypeEvent;
            let trigger_type = match rule.trigger_type {
                MicroCertTriggerType::HighRiskAssignment => {
                    MicroCertTriggerTypeEvent::HighRiskAssignment
                }
                MicroCertTriggerType::SodViolation => MicroCertTriggerTypeEvent::SodViolation,
                MicroCertTriggerType::ManagerChange => MicroCertTriggerTypeEvent::ManagerChange,
                MicroCertTriggerType::PeriodicRecert => MicroCertTriggerTypeEvent::PeriodicRecert,
                MicroCertTriggerType::Manual => MicroCertTriggerTypeEvent::Manual,
            };
            let event = MicroCertificationCreated {
                certification_id: certification.id,
                tenant_id,
                trigger_rule_id: rule.id,
                assignment_id: certification.assignment_id,
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                reviewer_id: certification.reviewer_id,
                backup_reviewer_id: certification.backup_reviewer_id,
                trigger_type,
                triggering_event_id: certification.triggering_event_id,
                deadline: certification.deadline,
                escalation_deadline: certification.escalation_deadline,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationCreated event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_decided_event(
        &self,
        tenant_id: Uuid,
        certification: &GovMicroCertification,
        decided_by: Uuid,
        outcome: &str,
        revoked_assignment_id: Option<Uuid>,
    ) {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::MicroCertDecisionEvent;
            let decision = match outcome {
                "approve" => MicroCertDecisionEvent::Approve,
                _ => MicroCertDecisionEvent::Revoke,
            };
            let event = MicroCertificationDecided {
                certification_id: certification.id,
                tenant_id,
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                assignment_id: certification.assignment_id,
                decided_by,
                decision,
                comment: certification.decision_comment.clone(),
                revoked_assignment_id,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationDecided event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_escalated_event(
        &self,
        tenant_id: Uuid,
        certification: &GovMicroCertification,
        new_reviewer_id: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = MicroCertificationEscalated {
                certification_id: certification.id,
                tenant_id,
                original_reviewer_id: certification.reviewer_id,
                backup_reviewer_id: new_reviewer_id,
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                deadline: certification.deadline,
                seconds_remaining: certification.time_until_deadline().num_seconds().max(0),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationEscalated event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_reminder_event(
        &self,
        tenant_id: Uuid,
        certification: &GovMicroCertification,
        auto_revoke: bool,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = MicroCertificationReminder {
                certification_id: certification.id,
                tenant_id,
                reviewer_id: if certification.escalated {
                    certification
                        .backup_reviewer_id
                        .unwrap_or(certification.reviewer_id)
                } else {
                    certification.reviewer_id
                },
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                deadline: certification.deadline,
                seconds_remaining: certification.time_until_deadline().num_seconds().max(0),
                auto_revoke,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationReminder event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_expired_event(&self, tenant_id: Uuid, certification: &GovMicroCertification) {
        if let Some(ref producer) = self.event_producer {
            let event = MicroCertificationExpired {
                certification_id: certification.id,
                tenant_id,
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                assignment_id: certification.assignment_id,
                reviewer_id: certification.reviewer_id,
                backup_reviewer_id: certification.backup_reviewer_id,
                deadline: certification.deadline,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationExpired event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_revoked_event(
        &self,
        tenant_id: Uuid,
        certification: &GovMicroCertification,
        _revoked_assignment_id: Option<Uuid>,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = MicroCertificationAutoRevoked {
                certification_id: certification.id,
                tenant_id,
                user_id: certification.user_id,
                entitlement_id: certification.entitlement_id,
                assignment_id: certification.assignment_id,
                reviewer_id: certification.reviewer_id,
                backup_reviewer_id: certification.backup_reviewer_id,
                deadline: certification.deadline,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                warn!(
                    certification_id = %certification.id,
                    error = %e,
                    "Failed to publish MicroCertificationAutoRevoked event"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::MicroCertScopeType;

    #[test]
    fn test_creation_result() {
        let result = MicroCertCreationResult {
            certification: create_test_certification(),
            duplicate_skipped: false,
            trigger_rule: create_test_rule(),
        };

        assert!(!result.duplicate_skipped);
    }

    #[test]
    fn test_decision_result() {
        let result = MicroCertDecisionResult {
            certification: create_test_certification(),
            auto_revoked: true,
            revoked_assignment_id: Some(Uuid::new_v4()),
            created_exemption_id: None,
        };

        assert!(result.auto_revoked);
        assert!(result.revoked_assignment_id.is_some());
    }

    #[test]
    fn test_bulk_decision_result() {
        let result = BulkDecisionResult {
            succeeded: vec![Uuid::new_v4(), Uuid::new_v4()],
            failed: vec![(Uuid::new_v4(), "Error".to_string())],
        };

        assert_eq!(result.succeeded.len(), 2);
        assert_eq!(result.failed.len(), 1);
    }

    fn create_test_certification() -> GovMicroCertification {
        GovMicroCertification {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            status: MicroCertStatus::Pending,
            triggering_event_type: "test".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
            decision_comment: None,
            decided_by: None,
            decided_at: None,
            revoked_assignment_id: None,
            delegated_by_id: None,
            original_reviewer_id: None,
            delegation_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn create_test_rule() -> GovMicroCertTrigger {
        GovMicroCertTrigger {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: MicroCertScopeType::Tenant,
            scope_id: None,
            reviewer_type: MicroCertReviewerType::UserManager,
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: 86400,
            reminder_threshold_percent: 75,
            auto_revoke: true,
            revoke_triggering_assignment: true,
            is_active: true,
            is_default: true,
            priority: 0,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
