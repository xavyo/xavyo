//! Error types for the governance domain.

use thiserror::Error;
use uuid::Uuid;

/// Governance domain errors.
#[derive(Debug, Error)]
pub enum GovernanceError {
    /// Application not found.
    #[error("Application not found: {0}")]
    ApplicationNotFound(Uuid),

    /// Application name already exists.
    #[error("Application name '{0}' already exists in this tenant")]
    ApplicationNameExists(String),

    /// Application is inactive.
    #[error("Application is inactive: {0}")]
    ApplicationInactive(Uuid),

    /// Cannot delete application with active entitlements.
    #[error("Cannot delete application with {0} active entitlements")]
    ApplicationHasEntitlements(i64),

    /// Entitlement not found.
    #[error("Entitlement not found: {0}")]
    EntitlementNotFound(Uuid),

    /// Entitlement name already exists.
    #[error("Entitlement name '{0}' already exists for this application")]
    EntitlementNameExists(String),

    /// Cannot delete entitlement with active assignments.
    #[error("Cannot delete entitlement with {0} active assignments")]
    EntitlementHasAssignments(i64),

    /// Assignment not found.
    #[error("Assignment not found: {0}")]
    AssignmentNotFound(Uuid),

    /// Assignment already exists.
    #[error("This entitlement is already assigned to this target")]
    AssignmentAlreadyExists,

    /// Invalid expiration date.
    #[error("Expiration date must be in the future")]
    InvalidExpirationDate,

    /// User not found.
    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    /// Group not found.
    #[error("Group not found: {0}")]
    GroupNotFound(Uuid),

    /// Role entitlement mapping not found.
    #[error("Role entitlement mapping not found: {0}")]
    RoleEntitlementNotFound(Uuid),

    /// Role entitlement mapping already exists.
    #[error("Entitlement is already mapped to role '{0}'")]
    RoleEntitlementExists(String),

    /// Invalid role name.
    #[error("Invalid role name: {0}")]
    InvalidRoleName(String),

    // =========================================================================
    // SoD (Separation of Duties) Errors
    // =========================================================================
    /// `SoD` rule not found.
    #[error("SoD rule not found: {0}")]
    SodRuleNotFound(Uuid),

    /// `SoD` rule name already exists.
    #[error("SoD rule name '{0}' already exists in this tenant")]
    SodRuleNameExists(String),

    /// Duplicate `SoD` rule (entitlement pair already exists).
    #[error("SoD rule already exists for this entitlement pair")]
    SodRuleDuplicate,

    /// `SoD` rule entitlement pair already exists (with details).
    #[error("SoD rule '{rule_name}' already exists for this entitlement pair (id: {rule_id})")]
    SodRulePairExists { rule_id: Uuid, rule_name: String },

    /// Cannot use the same entitlement twice in an `SoD` rule.
    #[error("First and second entitlement cannot be the same")]
    SodSameEntitlement,

    /// Cannot delete `SoD` rule with active violations.
    #[error("Cannot delete SoD rule with {0} active violations (use force=true)")]
    SodRuleHasViolations(i64),

    /// `SoD` violation detected - blocks assignment.
    #[error("Assignment would create SoD violation: rule '{rule_name}' (severity: {severity})")]
    SodViolationBlocked {
        rule_id: Uuid,
        rule_name: String,
        severity: String,
        conflicting_entitlement_id: Uuid,
    },

    /// `SoD` violation not found.
    #[error("SoD violation not found: {0}")]
    SodViolationNotFound(Uuid),

    /// `SoD` violation already remediated.
    #[error("SoD violation already remediated: {0}")]
    SodViolationAlreadyRemediated(Uuid),

    /// `SoD` exemption not found.
    #[error("SoD exemption not found: {0}")]
    SodExemptionNotFound(Uuid),

    /// `SoD` exemption already exists.
    #[error("Active SoD exemption already exists for this user/rule combination")]
    SodExemptionAlreadyExists,

    /// `SoD` exemption already inactive (expired or revoked).
    #[error("SoD exemption is already inactive: {0}")]
    SodExemptionAlreadyInactive(Uuid),

    /// `SoD` exemption justification required.
    #[error("SoD exemption requires a non-empty justification")]
    SodExemptionJustificationRequired,

    /// `SoD` exemption justification too short.
    #[error("SoD exemption justification must be at least {0} characters")]
    SodExemptionJustificationTooShort(usize),

    /// `SoD` exemption expiry date must be in the future.
    #[error("SoD exemption expiry date must be in the future")]
    SodExemptionExpiryInPast,

    /// `SoD` rule requires at least 2 entitlements.
    #[error("SoD rule requires at least 2 entitlements, got {0}")]
    SodRuleTooFewEntitlements(usize),

    /// `SoD` cardinality `max_count` must be less than entitlement count.
    #[error("SoD cardinality max_count ({0}) must be less than entitlement count ({1})")]
    SodRuleInvalidMaxCount(u32, usize),

    /// `SoD` cardinality `max_count` is required.
    #[error("SoD cardinality rule requires max_count to be set")]
    SodRuleMaxCountRequired,

    /// Multiple `SoD` violations detected.
    #[error("Assignment blocked by {0} SoD violation(s)")]
    SodMultipleViolations(usize),

    // =========================================================================
    // Access Request Workflow Errors (F035)
    // =========================================================================
    /// Approval workflow not found.
    #[error("Approval workflow not found: {0}")]
    WorkflowNotFound(Uuid),

    /// Approval workflow name already exists.
    #[error("Approval workflow name '{0}' already exists in this tenant")]
    WorkflowNameExists(String),

    /// Cannot delete workflow with pending requests.
    #[error("Cannot delete workflow with {0} pending requests")]
    WorkflowHasPendingRequests(i64),

    /// Invalid workflow steps count.
    #[error("Workflow must have between 1 and 5 steps")]
    InvalidWorkflowSteps,

    /// Access request not found.
    #[error("Access request not found: {0}")]
    AccessRequestNotFound(Uuid),

    /// Access request already exists for this entitlement.
    #[error("Pending access request already exists for this entitlement")]
    AccessRequestAlreadyExists,

    /// Access request already has this entitlement assigned.
    #[error("User already has this entitlement assigned")]
    EntitlementAlreadyAssigned,

    /// Access request justification too short.
    #[error("Justification must be at least 20 characters")]
    JustificationTooShort,

    /// Access request is not pending.
    #[error("Access request is not in a pending state")]
    RequestNotPending,

    /// Self-approval not allowed.
    #[error("Cannot approve your own access request")]
    SelfApprovalNotAllowed,

    /// User is not an authorized approver.
    #[error("User is not authorized to approve this request")]
    NotAuthorizedApprover,

    /// Rejection requires comments.
    #[error("Rejection comments are required")]
    RejectionCommentsRequired,

    /// Approval step already has a decision (concurrent deputy conflict - F053).
    #[error("This approval step has already been decided by another user")]
    StepAlreadyDecided,

    /// Approval delegation not found.
    #[error("Approval delegation not found: {0}")]
    DelegationNotFound(Uuid),

    /// Approval delegation already exists.
    #[error("Active delegation already exists for this period")]
    DelegationAlreadyExists,

    /// Invalid delegation period.
    #[error("Delegation end date must be after start date")]
    InvalidDelegationPeriod,

    /// Cannot delegate to self.
    #[error("Cannot delegate approval authority to yourself")]
    SelfDelegationNotAllowed,

    /// Delegation is not active.
    #[error("Delegation is not active: {0}")]
    DelegationNotActive(Uuid),

    /// Delegation scope violation - work item doesn't match scope.
    #[error("Work item does not match delegation scope: delegation {delegation_id} does not cover {work_item_type} for {details}")]
    DelegationScopeViolation {
        delegation_id: Uuid,
        work_item_type: String,
        details: String,
    },

    /// Duplicate delegation for the same period/scope.
    #[error(
        "Duplicate delegation: user already has an active delegation for the overlapping period"
    )]
    DuplicateDelegation,

    /// Invalid delegation period - start after end.
    #[error("Invalid delegation period: start date ({start}) must be before end date ({end})")]
    InvalidDelegationPeriodDates { start: String, end: String },

    /// Delegation period too long.
    #[error("Delegation period exceeds maximum allowed duration of {max_days} days")]
    DelegationPeriodTooLong { max_days: i32 },

    /// Delegation scope references invalid entities.
    #[error("Delegation scope references invalid entities: {0}")]
    InvalidDelegationScopeReferences(String),

    /// Cannot extend expired delegation.
    #[error("Cannot extend expired delegation: {0}")]
    CannotExtendExpiredDelegation(Uuid),

    /// Cannot extend revoked delegation.
    #[error("Cannot extend revoked delegation: {0}")]
    CannotExtendRevokedDelegation(Uuid),

    /// Delegation extension date must be after current end date.
    #[error("Extension date must be after current end date")]
    InvalidDelegationExtension,

    /// Deputy cannot act on work item - no matching delegation.
    #[error("No valid delegation found for deputy {deputy_id} to act on behalf of user for this work item")]
    NoMatchingDelegation { deputy_id: Uuid },

    /// Requested expiration date invalid.
    #[error("Requested expiration date must be in the future")]
    InvalidRequestedExpiration,

    /// Cannot cancel non-pending request.
    #[error("Only pending requests can be cancelled")]
    CannotCancelNonPendingRequest,

    // =========================================================================
    // Certification Campaign Errors (F036)
    // =========================================================================
    /// Certification campaign not found.
    #[error("Certification campaign not found: {0}")]
    CampaignNotFound(Uuid),

    /// Campaign name already exists.
    #[error("Campaign name '{0}' already exists in this tenant")]
    CampaignNameExists(String),

    /// Campaign is not in draft status.
    #[error("Campaign is not in draft status: {0}")]
    CampaignNotDraft(Uuid),

    /// Campaign is not active (cannot make decisions).
    #[error("Campaign is not active: {0}")]
    CampaignNotActive(Uuid),

    /// Cannot launch campaign - no items would be generated.
    #[error("Cannot launch campaign - no items would be generated")]
    CampaignNoItems,

    /// Cannot delete non-draft campaign.
    #[error("Cannot delete campaign that is not in draft status")]
    CannotDeleteNonDraftCampaign,

    /// Cannot cancel campaign in current status.
    #[error("Cannot cancel campaign in current status: {0}")]
    CannotCancelCampaign(String),

    /// Certification item not found.
    #[error("Certification item not found: {0}")]
    CertificationItemNotFound(Uuid),

    /// Certification item already decided.
    #[error("Certification item already decided: {0}")]
    ItemAlreadyDecided(Uuid),

    /// Certification item not pending.
    #[error("Certification item is not pending: {0}")]
    ItemNotPending(Uuid),

    /// Duplicate pending certification item.
    #[error("Pending certification item already exists for this user-entitlement combination")]
    DuplicatePendingItem,

    /// User is not the authorized reviewer for this item.
    #[error("User is not authorized to decide on this item")]
    NotAuthorizedReviewer,

    /// Revocation justification required.
    #[error("Revocation requires a justification of at least 20 characters")]
    RevocationJustificationRequired,

    /// Deadline must be in the future.
    #[error("Campaign deadline must be in the future")]
    DeadlineInPast,

    /// Specific reviewers required.
    #[error("Specific reviewers must be provided when reviewer type is 'specific_users'")]
    SpecificReviewersRequired,

    /// Reviewer not found for assignment.
    #[error("Cannot determine reviewer for assignment: {0}")]
    ReviewerNotFound(String),

    // =========================================================================
    // Lifecycle Workflow Errors (F037)
    // =========================================================================
    /// Birthright policy not found.
    #[error("Birthright policy not found: {0}")]
    BirthrightPolicyNotFound(Uuid),

    /// Birthright policy name already exists.
    #[error("Birthright policy name '{0}' already exists in this tenant")]
    BirthrightPolicyNameExists(String),

    /// Cannot delete active birthright policy.
    #[error("Cannot delete active birthright policy (disable first)")]
    CannotDeleteActivePolicy,

    /// Invalid policy conditions.
    #[error("Invalid policy conditions: {0}")]
    InvalidPolicyConditions(String),

    /// Invalid policy condition operator.
    #[error("Invalid condition operator: {0}")]
    InvalidConditionOperator(String),

    /// Invalid policy condition attribute.
    #[error("Invalid condition attribute: {0}")]
    InvalidConditionAttribute(String),

    /// Policy entitlements not found.
    #[error("One or more entitlements not found: {0:?}")]
    PolicyEntitlementsNotFound(Vec<Uuid>),

    /// Lifecycle event not found.
    #[error("Lifecycle event not found: {0}")]
    LifecycleEventNotFound(Uuid),

    /// Lifecycle event already processed.
    #[error("Lifecycle event already processed: {0}")]
    LifecycleEventAlreadyProcessed(Uuid),

    /// Invalid lifecycle event type for operation.
    #[error("Invalid lifecycle event type for this operation: {0}")]
    InvalidLifecycleEventType(String),

    /// Lifecycle action not found.
    #[error("Lifecycle action not found: {0}")]
    LifecycleActionNotFound(Uuid),

    /// Lifecycle action already executed.
    #[error("Lifecycle action already executed: {0}")]
    LifecycleActionAlreadyExecuted(Uuid),

    /// Lifecycle action already cancelled.
    #[error("Lifecycle action already cancelled: {0}")]
    LifecycleActionAlreadyCancelled(Uuid),

    /// Cannot cancel non-scheduled action.
    #[error("Cannot cancel action that is not a scheduled revocation")]
    CannotCancelNonScheduledAction,

    /// Mover event requires `attributes_before`.
    #[error("Mover event requires attributes_before")]
    MoverEventRequiresAttributesBefore,

    /// Joiner/mover event requires `attributes_after`.
    #[error("Joiner or mover event requires attributes_after")]
    EventRequiresAttributesAfter,

    /// Access snapshot not found.
    #[error("Access snapshot not found: {0}")]
    AccessSnapshotNotFound(Uuid),

    // =========================================================================
    // Risk Scoring Errors (F039)
    // =========================================================================
    /// Risk factor not found.
    #[error("Risk factor not found: {0}")]
    RiskFactorNotFound(Uuid),

    /// Risk factor name already exists.
    #[error("Risk factor name '{0}' already exists in this tenant")]
    RiskFactorNameExists(String),

    /// Risk score not found.
    #[error("Risk score not found for user: {0}")]
    RiskScoreNotFound(Uuid),

    /// Risk threshold not found.
    #[error("Risk threshold not found: {0}")]
    RiskThresholdNotFound(Uuid),

    /// Risk threshold name already exists.
    #[error("Risk threshold name '{0}' already exists in this tenant")]
    RiskThresholdNameExists(String),

    /// Risk alert not found.
    #[error("Risk alert not found: {0}")]
    RiskAlertNotFound(Uuid),

    /// Risk alert already acknowledged.
    #[error("Risk alert already acknowledged: {0}")]
    RiskAlertAlreadyAcknowledged(Uuid),

    /// Peer group not found.
    #[error("Peer group not found: {0}")]
    PeerGroupNotFound(Uuid),

    /// Peer group attribute already exists.
    #[error("Peer group already exists for attribute: {0}")]
    PeerGroupAttributeExists(String),

    /// Invalid risk factor weight.
    #[error("Risk factor weight must be between 0.0 and 10.0, got: {0}")]
    InvalidWeight(f64),

    /// Invalid risk threshold score.
    #[error("Risk threshold score must be between 1 and 100, got: {0}")]
    InvalidThresholdScore(i32),

    /// Invalid cooldown hours.
    #[error("Cooldown hours must be between 1 and 720, got: {0}")]
    InvalidCooldownHours(i32),

    /// Peer group too small for comparison.
    #[error("Peer group has fewer than minimum required members ({0}) for statistical comparison")]
    PeerGroupTooSmall(i32),

    /// Risk event not found.
    #[error("Risk event not found: {0}")]
    RiskEventNotFound(Uuid),

    // =========================================================================
    // Risk Assessment Errors (F-006)
    // =========================================================================
    /// Invalid risk threshold configuration.
    #[error("Invalid risk threshold configuration: {reason}")]
    RiskThresholdInvalid { reason: String },

    /// Risk calculation failed.
    #[error("Risk calculation failed: {reason}")]
    RiskCalculationFailed { reason: String },

    // =========================================================================
    // Orphan Account Detection Errors (F040)
    // =========================================================================
    /// Orphan detection not found.
    #[error("Orphan detection not found: {0}")]
    OrphanDetectionNotFound(Uuid),

    /// Reconciliation run not found.
    #[error("Reconciliation run not found: {0}")]
    ReconciliationRunNotFound(Uuid),

    /// Detection rule not found.
    #[error("Detection rule not found: {0}")]
    DetectionRuleNotFound(Uuid),

    /// Detection rule name already exists.
    #[error("Detection rule name '{0}' already exists in this tenant")]
    DetectionRuleNameExists(String),

    /// Service account not found.
    #[error("Service account not found: {0}")]
    ServiceAccountNotFound(Uuid),

    /// Service account user already registered.
    #[error("User is already registered as a service account")]
    ServiceAccountUserExists,

    /// Reconciliation already running.
    #[error("A reconciliation is already running for this tenant")]
    ReconciliationAlreadyRunning,

    /// Invalid remediation action for current status.
    #[error("Invalid remediation action '{action}' for orphan status '{status}'")]
    InvalidRemediationAction { action: String, status: String },

    /// Orphan detection already remediated.
    #[error("Orphan detection already remediated: {0}")]
    OrphanAlreadyRemediated(Uuid),

    /// Orphan detection already dismissed.
    #[error("Orphan detection already dismissed: {0}")]
    OrphanAlreadyDismissed(Uuid),

    /// Cannot cancel non-running reconciliation.
    #[error("Cannot cancel reconciliation that is not running")]
    CannotCancelNonRunningReconciliation,

    /// New owner required for reassignment.
    #[error("New owner ID is required for reassignment action")]
    NewOwnerRequiredForReassignment,

    /// Service account expired.
    #[error("Service account has expired: {0}")]
    ServiceAccountExpired(Uuid),

    /// Service account suspended.
    #[error("Service account is suspended: {0}")]
    ServiceAccountSuspended(Uuid),

    // =========================================================================
    // Compliance Reporting Errors (F042)
    // =========================================================================
    /// Report template not found.
    #[error("Report template not found: {0}")]
    ReportTemplateNotFound(Uuid),

    /// Report template name already exists.
    #[error("Report template name '{0}' already exists in this tenant")]
    ReportTemplateNameExists(String),

    /// Cannot modify system template.
    #[error("Cannot modify system template: {0}")]
    CannotModifySystemTemplate(Uuid),

    /// Cannot archive system template.
    #[error("Cannot archive system template: {0}")]
    CannotArchiveSystemTemplate(Uuid),

    /// Report template already archived.
    #[error("Report template is already archived: {0}")]
    ReportTemplateAlreadyArchived(Uuid),

    /// Generated report not found.
    #[error("Generated report not found: {0}")]
    GeneratedReportNotFound(Uuid),

    /// Report still generating.
    #[error("Report is still being generated: {0}")]
    ReportStillGenerating(Uuid),

    /// Report generation failed.
    #[error("Report generation failed: {0}")]
    ReportGenerationFailed(String),

    /// Cannot modify completed report.
    #[error("Cannot modify completed/failed report: {0}")]
    CannotModifyCompletedReport(Uuid),

    /// Report schedule not found.
    #[error("Report schedule not found: {0}")]
    ReportScheduleNotFound(Uuid),

    /// Report schedule name already exists.
    #[error("Report schedule name '{0}' already exists in this tenant")]
    ReportScheduleNameExists(String),

    /// Report schedule already paused.
    #[error("Report schedule is already paused: {0}")]
    ReportScheduleAlreadyPaused(Uuid),

    /// Report schedule already active.
    #[error("Report schedule is already active: {0}")]
    ReportScheduleAlreadyActive(Uuid),

    /// Invalid schedule hour.
    #[error("Schedule hour must be between 0 and 23, got: {0}")]
    InvalidScheduleHour(i32),

    /// Invalid schedule day of week.
    #[error("Schedule day of week must be between 0 (Sunday) and 6 (Saturday), got: {0}")]
    InvalidScheduleDayOfWeek(i32),

    /// Invalid schedule day of month.
    #[error("Schedule day of month must be between 1 and 28, got: {0}")]
    InvalidScheduleDayOfMonth(i32),

    /// Missing schedule day for weekly frequency.
    #[error("Weekly schedules require schedule_day_of_week")]
    MissingScheduleDayOfWeek,

    /// Missing schedule day for monthly frequency.
    #[error("Monthly schedules require schedule_day_of_month")]
    MissingScheduleDayOfMonth,

    /// No recipients specified for schedule.
    #[error("At least one recipient email is required for scheduled reports")]
    NoRecipientsSpecified,

    /// Invalid recipient email.
    #[error("Invalid recipient email format: {0}")]
    InvalidRecipientEmail(String),

    // =========================================================================
    // Role Mining and Analytics Errors (F041)
    // =========================================================================
    /// Mining job not found.
    #[error("Mining job not found: {0}")]
    MiningJobNotFound(Uuid),

    /// Mining job already running for tenant.
    #[error("A mining job is already running for this tenant")]
    MiningJobAlreadyRunning,

    /// Mining job not in pending status.
    #[error("Mining job is not in pending status: {0}")]
    MiningJobNotPending(Uuid),

    /// Mining job not in running status.
    #[error("Mining job is not in running status: {0}")]
    MiningJobNotRunning(Uuid),

    /// Mining job already completed.
    #[error("Mining job is already completed: {0}")]
    MiningJobAlreadyCompleted(Uuid),

    /// Cannot cancel non-running mining job.
    #[error("Cannot cancel mining job that is not running: {0}")]
    CannotCancelMiningJob(Uuid),

    /// Insufficient data for mining.
    #[error("Insufficient data for mining: need at least {0} users with entitlements")]
    InsufficientMiningData(i32),

    /// Role candidate not found.
    #[error("Role candidate not found: {0}")]
    RoleCandidateNotFound(Uuid),

    /// Role candidate already promoted.
    #[error("Role candidate is already promoted: {0}")]
    RoleCandidateAlreadyPromoted(Uuid),

    /// Role candidate already dismissed.
    #[error("Role candidate is already dismissed: {0}")]
    RoleCandidateAlreadyDismissed(Uuid),

    /// Role candidate not pending.
    #[error("Role candidate is not in pending status: {0}")]
    RoleCandidateNotPending(Uuid),

    /// Excessive privilege flag not found.
    #[error("Excessive privilege flag not found: {0}")]
    ExcessivePrivilegeFlagNotFound(Uuid),

    /// Excessive privilege flag already reviewed.
    #[error("Excessive privilege flag is already reviewed: {0}")]
    ExcessivePrivilegeFlagAlreadyReviewed(Uuid),

    /// Consolidation suggestion not found.
    #[error("Consolidation suggestion not found: {0}")]
    ConsolidationSuggestionNotFound(Uuid),

    /// Consolidation suggestion already processed.
    #[error("Consolidation suggestion is already processed: {0}")]
    ConsolidationSuggestionAlreadyProcessed(Uuid),

    /// Role simulation not found.
    #[error("Role simulation not found: {0}")]
    RoleSimulationNotFound(Uuid),

    /// Role simulation not in draft status.
    #[error("Role simulation is not in draft status: {0}")]
    RoleSimulationNotDraft(Uuid),

    /// Role simulation not executed.
    #[error("Role simulation has not been executed: {0}")]
    RoleSimulationNotExecuted(Uuid),

    /// Role simulation already applied.
    #[error("Role simulation is already applied: {0}")]
    RoleSimulationAlreadyApplied(Uuid),

    /// Role metrics not found.
    #[error("Role metrics not found for role: {0}")]
    RoleMetricsNotFound(Uuid),

    /// Role not found for mining.
    #[error("Role not found: {0}")]
    RoleNotFoundForMining(Uuid),

    /// Invalid mining parameters.
    #[error("Invalid mining parameters: {0}")]
    InvalidMiningParameters(String),

    /// Mining job timeout.
    #[error("Mining job timed out after {0} minutes")]
    MiningJobTimeout(i32),

    // =========================================================================
    // Object Lifecycle States Errors (F052)
    // =========================================================================
    /// Lifecycle configuration not found.
    #[error("Lifecycle configuration not found: {0}")]
    LifecycleConfigNotFound(Uuid),

    /// Lifecycle configuration already exists for object type.
    #[error("Lifecycle configuration already exists for object type '{0}' in this tenant")]
    LifecycleConfigAlreadyExists(String),

    /// Lifecycle state not found.
    #[error("Lifecycle state not found: {0}")]
    LifecycleStateNotFound(Uuid),

    /// Lifecycle state name already exists.
    #[error("Lifecycle state name '{0}' already exists in this configuration")]
    LifecycleStateNameExists(String),

    /// Cannot delete lifecycle state with objects in it.
    #[error("Cannot delete lifecycle state '{0}' - {1} objects are currently in this state")]
    LifecycleStateHasObjects(String, i64),

    /// Lifecycle transition not found.
    #[error("Lifecycle transition not found: {0}")]
    LifecycleTransitionNotFound(Uuid),

    /// Lifecycle transition name already exists.
    #[error("Lifecycle transition name '{0}' already exists in this configuration")]
    LifecycleTransitionNameExists(String),

    /// Lifecycle transition already exists for state pair.
    #[error("Transition already exists from state '{0}' to state '{1}'")]
    LifecycleTransitionStatePairExists(String, String),

    /// Invalid lifecycle transition - not allowed from current state.
    #[error("Transition '{0}' not allowed from current state '{1}'. Allowed transitions: {2}")]
    InvalidLifecycleTransition(String, String, String),

    /// Invalid transition - object not in required state.
    #[error("Invalid transition: {0}")]
    InvalidTransition(String),

    /// Transition conditions not satisfied.
    #[error(
        "Transition conditions not satisfied: {failed_count} of {total_count} conditions failed"
    )]
    TransitionConditionsNotSatisfied {
        /// Number of conditions that failed
        failed_count: usize,
        /// Total number of conditions
        total_count: usize,
        /// Summary of why conditions failed
        summary: String,
    },

    /// Lifecycle action execution failed.
    #[error("Lifecycle action execution failed: {0}")]
    ActionExecutionFailed(String),

    /// Transition audit record not found.
    #[error("Transition audit record not found: {0}")]
    TransitionAuditNotFound(Uuid),

    /// State transition request not found.
    #[error("State transition request not found: {0}")]
    StateTransitionRequestNotFound(Uuid),

    /// State transition request not in expected status.
    #[error("State transition request is not in '{0}' status")]
    InvalidTransitionRequestStatus(String),

    /// Rollback not available - not within grace period.
    #[error("Rollback not available for transition request: {0}")]
    RollbackNotAvailable(Uuid),

    /// Grace period has expired.
    #[error("Grace period has expired for transition request: {0}")]
    GracePeriodExpired(Uuid),

    /// Scheduled transition not found.
    #[error("Scheduled transition not found: {0}")]
    ScheduledTransitionNotFound(Uuid),

    /// Scheduled transition already exists for object.
    #[error("A pending scheduled transition already exists for this object")]
    ScheduledTransitionAlreadyExists,

    /// Cannot cancel scheduled transition - already executed.
    #[error("Cannot cancel scheduled transition - already executed: {0}")]
    ScheduledTransitionAlreadyExecuted(Uuid),

    /// Scheduled time must be in the future.
    #[error("Scheduled time must be in the future")]
    ScheduledTimeInPast,

    /// Bulk state operation not found.
    #[error("Bulk state operation not found: {0}")]
    BulkStateOperationNotFound(Uuid),

    /// Bulk operation exceeds maximum objects limit.
    #[error("Bulk operation exceeds maximum limit of {0} objects")]
    BulkOperationTooLarge(i32),

    /// Bulk operation already running.
    #[error("A bulk state operation is already running: {0}")]
    BulkOperationAlreadyRunning(Uuid),

    /// Bulk operation already completed.
    #[error("Bulk state operation already completed: {0}")]
    BulkOperationAlreadyCompleted(Uuid),

    /// Object not found for lifecycle transition.
    #[error("Object not found: {object_type} with id {object_id}")]
    LifecycleObjectNotFound {
        object_type: String,
        object_id: Uuid,
    },

    /// Object does not have a lifecycle configuration.
    #[error("No lifecycle configuration exists for object type '{0}'")]
    NoLifecycleConfigForObjectType(String),

    /// Object is not in expected state.
    #[error("Object is not in expected state '{0}', current state is '{1}'")]
    ObjectNotInExpectedState(String, String),

    /// Invalid grace period value.
    #[error("Grace period must be between 0 and 720 hours, got: {0}")]
    InvalidGracePeriodHours(i32),

    /// Terminal state cannot have outgoing transitions.
    #[error("Terminal state '{0}' cannot have outgoing transitions")]
    TerminalStateCannotHaveTransitions(String),

    /// Multiple initial states not allowed.
    #[error("Configuration already has an initial state: '{0}'")]
    MultipleInitialStatesNotAllowed(String),

    // =========================================================================
    // Workflow Escalation Errors (F054)
    // =========================================================================
    /// Escalation policy not found.
    #[error("Escalation policy not found: {0}")]
    EscalationPolicyNotFound(Uuid),

    /// Escalation policy name already exists.
    #[error("Escalation policy name '{0}' already exists in this tenant")]
    EscalationPolicyNameExists(String),

    /// Escalation rule not found.
    #[error("Escalation rule not found: {0}")]
    EscalationRuleNotFound(Uuid),

    /// Escalation level not found.
    #[error("Escalation level not found: {0}")]
    EscalationLevelNotFound(Uuid),

    /// Escalation event not found.
    #[error("Escalation event not found: {0}")]
    EscalationEventNotFound(Uuid),

    /// Approval group not found.
    #[error("Approval group not found: {0}")]
    ApprovalGroupNotFound(Uuid),

    /// Approval group name already exists.
    #[error("Approval group name '{0}' already exists in this tenant")]
    ApprovalGroupNameExists(String),

    /// Approval group is in use (cannot delete).
    #[error("Approval group is in use by escalation rules and cannot be deleted: {0}")]
    ApprovalGroupInUse(Uuid),

    /// No escalation target available.
    #[error("No escalation target available for step {step_order} at level {level}")]
    NoEscalationTargetAvailable { step_order: i32, level: i32 },

    /// Escalation already exhausted.
    #[error("All escalation levels exhausted for request: {0}")]
    EscalationExhausted(Uuid),

    /// Cannot escalate non-pending request.
    #[error("Cannot escalate request that is not pending: {0}")]
    CannotEscalateNonPendingRequest(Uuid),

    /// Cannot reset escalation for non-escalated request.
    #[error("Cannot reset escalation for request that has not been escalated: {0}")]
    CannotResetNonEscalatedRequest(Uuid),

    /// Manager not found for escalation.
    #[error("Manager not found for user {0} during escalation")]
    ManagerNotFoundForEscalation(Uuid),

    /// Circular manager chain detected.
    #[error("Circular manager chain detected starting from user: {0}")]
    CircularManagerChain(Uuid),

    // =========================================================================
    // Micro-certification Errors (F055)
    // =========================================================================
    /// Micro-certification trigger rule not found.
    #[error("Micro-certification trigger rule not found: {0}")]
    MicroCertTriggerNotFound(Uuid),

    /// Micro-certification trigger rule name already exists.
    #[error("Micro-certification trigger rule name '{0}' already exists in this tenant")]
    MicroCertTriggerNameExists(String),

    /// Micro-certification not found.
    #[error("Micro-certification not found: {0}")]
    MicroCertificationNotFound(Uuid),

    /// Micro-certification already decided.
    #[error("Micro-certification already decided: {0}")]
    MicroCertificationAlreadyDecided(Uuid),

    /// Micro-certification not pending.
    #[error("Micro-certification is not pending: {0}")]
    MicroCertificationNotPending(Uuid),

    /// Micro-certification already expired.
    #[error("Micro-certification already expired: {0}")]
    MicroCertificationAlreadyExpired(Uuid),

    /// User is not authorized to decide on this micro-certification.
    #[error("User is not authorized to decide on this micro-certification")]
    NotAuthorizedMicroCertReviewer,

    /// Micro-certification revocation requires justification.
    #[error("Revocation requires a justification")]
    MicroCertRevocationJustificationRequired,

    /// Micro-certification event not found.
    #[error("Micro-certification event not found: {0}")]
    MicroCertEventNotFound(Uuid),

    /// No matching trigger rule found.
    #[error("No matching micro-certification trigger rule found for event")]
    NoMatchingTriggerRule,

    /// Duplicate pending micro-certification.
    #[error("Pending micro-certification already exists for this assignment")]
    DuplicatePendingMicroCertification,

    /// Invalid trigger scope configuration.
    #[error("Invalid trigger scope: {0}")]
    InvalidTriggerScope(String),

    /// Micro-certification skip reason required.
    #[error("Skip reason must be at least 10 characters")]
    MicroCertSkipReasonRequired,

    /// Cannot skip non-pending micro-certification.
    #[error("Cannot skip micro-certification that is not pending: {0}")]
    CannotSkipNonPendingMicroCert(Uuid),

    /// Micro-certification trigger rule is not active.
    #[error("Micro-certification trigger rule is not active: {0}")]
    MicroCertTriggerNotActive(Uuid),

    /// Micro-certification reviewer could not be resolved.
    #[error("Could not resolve reviewer for micro-certification: {0}")]
    MicroCertReviewerNotResolved(String),

    /// User cannot decide on this micro-certification.
    #[error("User {1} is not authorized to decide on micro-certification {0}")]
    MicroCertCannotDecide(Uuid, Uuid),

    /// Micro-certification delegation error.
    #[error("Micro-certification delegation error: {0}")]
    MicroCertDelegationError(String),

    /// Cannot self-delegate micro-certification.
    #[error("Cannot delegate micro-certification to yourself")]
    MicroCertSelfDelegationNotAllowed,

    /// Delegate decision must use dedicated delegate method.
    #[error("Delegate decision requires using the delegate endpoint, not decide")]
    MicroCertDelegateRequiresDedicatedEndpoint,

    // =========================================================================
    // Meta-role Errors (F056)
    // =========================================================================
    /// Meta-role not found.
    #[error("Meta-role not found: {0}")]
    MetaRoleNotFound(Uuid),

    /// Meta-role name already exists.
    #[error("Meta-role name '{0}' already exists in this tenant")]
    MetaRoleNameExists(String),

    /// Meta-role criteria not found.
    #[error("Meta-role criteria not found: {0}")]
    MetaRoleCriteriaNotFound(Uuid),

    /// Meta-role entitlement not found.
    #[error("Meta-role entitlement not found: {0}")]
    MetaRoleEntitlementNotFound(Uuid),

    /// Meta-role entitlement already exists.
    #[error("Entitlement is already added to this meta-role")]
    MetaRoleEntitlementAlreadyExists,

    /// Meta-role constraint not found.
    #[error("Meta-role constraint not found: {0}")]
    MetaRoleConstraintNotFound(Uuid),

    /// Meta-role constraint already exists.
    #[error("Constraint type '{0}' is already defined for this meta-role")]
    MetaRoleConstraintAlreadyExists(String),

    /// Meta-role inheritance not found.
    #[error("Meta-role inheritance not found: {0}")]
    MetaRoleInheritanceNotFound(Uuid),

    /// Meta-role conflict not found.
    #[error("Meta-role conflict not found: {0}")]
    MetaRoleConflictNotFound(Uuid),

    /// Meta-role conflict already resolved.
    #[error("Meta-role conflict is already resolved: {0}")]
    MetaRoleConflictAlreadyResolved(Uuid),

    /// Meta-role is disabled.
    #[error("Meta-role is disabled: {0}")]
    MetaRoleDisabled(Uuid),

    /// Meta-role is already active.
    #[error("Meta-role is already active: {0}")]
    MetaRoleAlreadyActive(Uuid),

    /// Meta-role is already disabled.
    #[error("Meta-role is already disabled: {0}")]
    MetaRoleAlreadyDisabled(Uuid),

    /// Cannot delete meta-role with active inheritances.
    #[error("Cannot delete meta-role with {0} active inheritances (disable first)")]
    MetaRoleHasActiveInheritances(i64),

    /// Invalid meta-role criteria field.
    #[error("Invalid criteria field: {0}. Allowed fields: risk_level, application_id, owner_id, status, is_delegable, metadata.<key>")]
    InvalidMetaRoleCriteriaField(String),

    /// Invalid meta-role criteria value.
    #[error("Invalid criteria value for field '{field}' with operator '{operator}': {reason}")]
    InvalidMetaRoleCriteriaValue {
        field: String,
        operator: String,
        reason: String,
    },

    /// Invalid meta-role constraint type.
    #[error("Invalid constraint type: {0}. Allowed types: max_session_duration, require_mfa, ip_whitelist, approval_required")]
    InvalidMetaRoleConstraintType(String),

    /// Invalid meta-role priority.
    #[error("Meta-role priority must be between 1 and 1000, got: {0}")]
    InvalidMetaRolePriority(i32),

    /// Meta-role circular reference detected.
    #[error("Meta-role criteria would create circular reference: meta-roles cannot apply to other meta-roles")]
    MetaRoleCircularReference,

    /// Meta-role cascade failed.
    #[error("Meta-role cascade failed: {0}")]
    MetaRoleCascadeFailed(String),

    /// Meta-role simulation failed.
    #[error("Meta-role simulation failed: {0}")]
    MetaRoleSimulationFailed(String),

    // =========================================================================
    // Outlier Detection Errors (F059)
    // =========================================================================
    /// Outlier configuration not found.
    #[error("Outlier configuration not found: {0}")]
    OutlierConfigNotFound(Uuid),

    /// Outlier analysis not found.
    #[error("Outlier analysis not found: {0}")]
    OutlierAnalysisNotFound(Uuid),

    /// Outlier analysis already running.
    #[error("Outlier analysis is already running for this tenant")]
    OutlierAnalysisAlreadyRunning,

    /// Outlier analysis cannot be cancelled.
    #[error("Cannot cancel outlier analysis that is not running: {0}")]
    OutlierAnalysisCannotCancel(Uuid),

    /// Outlier result not found.
    #[error("Outlier result not found: {0}")]
    OutlierResultNotFound(Uuid),

    /// Outlier disposition not found.
    #[error("Outlier disposition not found: {0}")]
    OutlierDispositionNotFound(Uuid),

    /// Outlier disposition already exists.
    #[error("Disposition already exists for this user in this analysis")]
    OutlierDispositionAlreadyExists,

    /// Outlier disposition invalid state transition.
    #[error("Invalid disposition status transition from '{0}' to '{1}'")]
    OutlierDispositionInvalidTransition(String, String),

    /// Outlier alert not found.
    #[error("Outlier alert not found: {0}")]
    OutlierAlertNotFound(Uuid),

    /// Outlier alert already dismissed.
    #[error("Outlier alert already dismissed: {0}")]
    OutlierAlertAlreadyDismissed(Uuid),

    /// Invalid confidence threshold.
    #[error("Confidence threshold must be between 0.5 and 5.0, got: {0}")]
    InvalidConfidenceThreshold(f64),

    /// Invalid scoring weight.
    #[error("Scoring weight '{name}' must be between 0.0 and 1.0, got: {value}")]
    InvalidScoringWeight { name: String, value: f64 },

    /// Scoring weights must sum to 1.0.
    #[error("Scoring weights must sum to 1.0, got: {0}")]
    ScoringWeightsSumInvalid(f64),

    /// Invalid cron expression.
    #[error("Invalid cron expression: {0}")]
    InvalidCronExpression(String),

    /// No peer groups available for analysis.
    #[error("No peer groups available for outlier analysis")]
    NoPeerGroupsForAnalysis,

    // =========================================================================
    // Enhanced Simulation Errors (F060)
    // =========================================================================
    /// Policy simulation not found.
    #[error("Policy simulation not found: {0}")]
    PolicySimulationNotFound(Uuid),

    /// Batch simulation not found.
    #[error("Batch simulation not found: {0}")]
    BatchSimulationNotFound(Uuid),

    /// Simulation comparison not found.
    #[error("Simulation comparison not found: {0}")]
    SimulationComparisonNotFound(Uuid),

    /// Scope warning required - affected users exceed threshold.
    #[error("Operation affects {affected_users} users, exceeding warning threshold of {threshold}. Acknowledge to proceed.")]
    ScopeWarningRequired { affected_users: i32, threshold: i32 },

    /// Policy simulation already executed.
    #[error("Policy simulation is already executed: {0}")]
    PolicySimulationAlreadyExecuted(Uuid),

    /// Batch simulation already executed.
    #[error("Batch simulation is already executed: {0}")]
    BatchSimulationAlreadyExecuted(Uuid),

    /// Batch simulation already applied.
    #[error("Batch simulation is already applied: {0}")]
    BatchSimulationAlreadyApplied(Uuid),

    /// Simulation is stale (underlying data has changed).
    #[error("Simulation {0} is stale - underlying data has changed since execution")]
    SimulationStale(Uuid),

    /// Simulation comparison is stale.
    #[error("Simulation comparison {0} is stale - one or more simulations have been modified")]
    SimulationComparisonStale(Uuid),

    /// Invalid simulation type.
    #[error("Invalid simulation type: {0}")]
    InvalidSimulationType(String),

    /// Cannot compare simulations of different tenants.
    #[error("Cannot compare simulations from different tenants")]
    SimulationTenantMismatch,

    /// Simulation too large - exceeds configured limits.
    #[error("Simulation too large: requested {requested} users, maximum allowed is {max_allowed}")]
    SimulationTooLarge {
        requested: usize,
        max_allowed: usize,
    },

    /// Simulation partially failed during chunked processing.
    #[error("Simulation partially failed: {successful} of {total} chunks processed successfully. First error: {first_error}")]
    SimulationPartialFailure {
        successful: usize,
        total: usize,
        first_error: String,
    },

    /// User deleted during simulation execution.
    #[error("User {user_id} was deleted during simulation execution")]
    UserDeletedDuringSimulation { user_id: Uuid },

    /// Cascade policy detection - policies trigger other policies.
    #[error("Policy cascade detected: {policy_chain:?} would trigger each other")]
    PolicyCascadeDetected { policy_chain: Vec<String> },

    // =========================================================================
    // NHI Lifecycle Errors (F061)
    // =========================================================================
    /// NHI (Non-Human Identity) not found.
    #[error("NHI not found: {0}")]
    NhiNotFound(Uuid),

    /// NHI name already exists.
    #[error("NHI name '{0}' already exists in this tenant")]
    NhiNameExists(String),

    /// User is already registered as an NHI.
    #[error("User is already registered as an NHI: {0}")]
    NhiUserAlreadyRegistered(Uuid),

    /// NHI is suspended.
    #[error("NHI is suspended: {0}")]
    NhiSuspended(Uuid),

    /// NHI is expired.
    #[error("NHI has expired: {0}")]
    NhiExpired(Uuid),

    /// NHI is inactive.
    #[error("NHI is inactive (no usage for {1} days): {0}")]
    NhiInactive(Uuid, i32),

    /// NHI credential not found.
    #[error("NHI credential not found: {0}")]
    NhiCredentialNotFound(Uuid),

    /// NHI credential already revoked.
    #[error("NHI credential already revoked: {0}")]
    NhiCredentialAlreadyRevoked(Uuid),

    /// NHI credential invalid (authentication failure).
    #[error("Invalid NHI credentials")]
    NhiCredentialInvalid,

    /// NHI credential expired.
    #[error("NHI credential has expired: {0}")]
    NhiCredentialExpired(Uuid),

    /// NHI rotation required.
    #[error("NHI credential rotation is required: {0}")]
    NhiRotationRequired(Uuid),

    /// NHI request not found.
    #[error("NHI request not found: {0}")]
    NhiRequestNotFound(Uuid),

    /// NHI request already exists.
    #[error("Pending NHI request already exists for this name")]
    NhiRequestAlreadyExists,

    /// NHI request not pending.
    #[error("NHI request is not pending: {0}")]
    NhiRequestNotPending(Uuid),

    /// NHI request expired.
    #[error("NHI request has expired: {0}")]
    NhiRequestExpired(Uuid),

    /// Cannot cancel non-pending NHI request.
    #[error("Can only cancel pending NHI requests")]
    CannotCancelNhiRequest,

    /// NHI self-approval not allowed.
    #[error("Cannot approve your own NHI request")]
    NhiSelfApprovalNotAllowed,

    /// NHI is already suspended.
    #[error("NHI is already suspended: {0}")]
    NhiAlreadySuspended(Uuid),

    /// NHI is not suspended (cannot reactivate).
    #[error("NHI is not suspended: {0}")]
    NhiNotSuspended(Uuid),

    /// NHI cannot be reactivated (e.g., expired).
    #[error("NHI cannot be reactivated: {reason}")]
    NhiCannotReactivate { nhi_id: Uuid, reason: String },

    /// NHI owner not found.
    #[error("NHI owner not found: {0}")]
    NhiOwnerNotFound(Uuid),

    /// NHI backup owner same as primary owner.
    #[error("Backup owner cannot be the same as primary owner")]
    NhiBackupOwnerSameAsPrimary,

    /// NHI ownership transfer to self.
    #[error("Cannot transfer ownership to yourself")]
    NhiOwnershipTransferToSelf,

    /// NHI risk score calculation failed.
    #[error("NHI risk score calculation failed: {0}")]
    NhiRiskCalculationFailed(String),

    /// NHI certification not found.
    #[error("NHI certification not found")]
    NhiCertificationNotFound,

    /// NHI audit event not found.
    #[error("NHI audit event not found: {0}")]
    NhiAuditEventNotFound(Uuid),

    /// NHI usage tracking failed.
    #[error("NHI usage tracking failed: {0}")]
    NhiUsageTrackingFailed(String),

    /// NHI invalid rotation interval.
    #[error("Rotation interval must be between 1 and 365 days, got: {0}")]
    NhiInvalidRotationInterval(i32),

    /// NHI invalid inactivity threshold.
    #[error("Inactivity threshold must be between 1 and 365 days, got: {0}")]
    NhiInvalidInactivityThreshold(i32),

    /// NHI grace period still active.
    #[error("NHI is in grace period until {0}")]
    NhiInGracePeriod(String),

    // =========================================================================
    // Parametric Role Errors (F057)
    // =========================================================================
    /// Role parameter not found.
    #[error("Role parameter not found: {0}")]
    RoleParameterNotFound(Uuid),

    /// Role parameter name already exists.
    #[error("Role parameter name '{0}' already exists for this role")]
    RoleParameterNameExists(String),

    /// Assignment parameter not found.
    #[error("Assignment parameter not found: {0}")]
    AssignmentParameterNotFound(Uuid),

    /// Parametric assignment already exists with same parameters.
    #[error("Assignment with same parameters already exists for this target")]
    ParametricAssignmentAlreadyExists,

    /// Required parameter missing.
    #[error("Required parameter '{0}' is missing")]
    RequiredParameterMissing(String),

    /// Parameter validation failed.
    #[error("Parameter '{parameter_name}' validation failed: {reason}")]
    ParameterValidationFailed {
        parameter_name: String,
        reason: String,
    },

    /// Invalid parameter type.
    #[error("Invalid parameter type '{value_type}' for parameter '{parameter_name}', expected '{expected_type}'")]
    InvalidParameterType {
        parameter_name: String,
        expected_type: String,
        value_type: String,
    },

    /// Integer parameter out of range.
    #[error("Integer parameter '{parameter_name}' value {value} is out of range [min: {min:?}, max: {max:?}]")]
    IntegerParameterOutOfRange {
        parameter_name: String,
        value: i64,
        min: Option<i64>,
        max: Option<i64>,
    },

    /// String parameter length invalid.
    #[error("String parameter '{parameter_name}' length {length} is invalid (min: {min:?}, max: {max:?})")]
    StringParameterLengthInvalid {
        parameter_name: String,
        length: usize,
        min: Option<usize>,
        max: Option<usize>,
    },

    /// String parameter pattern mismatch.
    #[error("String parameter '{parameter_name}' value does not match pattern '{pattern}'")]
    StringParameterPatternMismatch {
        parameter_name: String,
        pattern: String,
    },

    /// Enum parameter value not allowed.
    #[error(
        "Enum parameter '{parameter_name}' value '{value}' is not in allowed values: {allowed:?}"
    )]
    EnumParameterValueNotAllowed {
        parameter_name: String,
        value: String,
        allowed: Vec<String>,
    },

    /// Date parameter out of range.
    #[error("Date parameter '{parameter_name}' is out of allowed range")]
    DateParameterOutOfRange {
        parameter_name: String,
        min_date: Option<String>,
        max_date: Option<String>,
    },

    /// Cannot delete parameter with active assignments.
    #[error("Cannot delete parameter with {0} active assignments")]
    ParameterHasAssignments(i64),

    /// Invalid parameter name format.
    #[error("Parameter name '{0}' is invalid - must start with letter and contain only alphanumeric characters and underscores")]
    InvalidParameterNameFormat(String),

    /// Parameter audit event not found.
    #[error("Parameter audit event not found: {0}")]
    ParameterAuditEventNotFound(Uuid),

    /// Role is not parametric.
    #[error("Role {0} has no parameters defined")]
    RoleNotParametric(Uuid),

    /// Invalid temporal validity period.
    #[error("Invalid temporal validity: valid_from must be before valid_to")]
    InvalidTemporalValidity,

    /// Assignment not temporally active.
    #[error("Assignment is not currently active (outside valid_from/valid_to window)")]
    AssignmentNotTemporallyActive,

    /// Parameter schema changed - assignment flagged.
    #[error("Assignment parameters do not conform to current schema: {0}")]
    ParameterSchemaViolation(String),

    // =========================================================================
    // Object Template Errors (F058)
    // =========================================================================
    /// Object template not found.
    #[error("Object template not found: {0}")]
    ObjectTemplateNotFound(Uuid),

    /// Object template name already exists.
    #[error("Object template name '{0}' already exists in this tenant")]
    ObjectTemplateNameExists(String),

    /// Object template is not in draft status.
    #[error("Object template {0} is not in draft status")]
    ObjectTemplateNotDraft(Uuid),

    /// Object template is not active.
    #[error("Object template {0} is not active")]
    ObjectTemplateNotActive(Uuid),

    /// Object template is already active.
    #[error("Object template {0} is already active")]
    ObjectTemplateAlreadyActive(Uuid),

    /// Object template is already disabled.
    #[error("Object template {0} is already disabled")]
    ObjectTemplateAlreadyDisabled(Uuid),

    /// Object template parent not found.
    #[error("Parent template not found: {0}")]
    ObjectTemplateParentNotFound(Uuid),

    /// Object template parent type mismatch.
    #[error("Parent template must target the same object type")]
    ObjectTemplateParentTypeMismatch,

    /// Object template circular inheritance detected.
    #[error("Circular inheritance detected in template hierarchy")]
    ObjectTemplateCircularInheritance,

    /// Object template requires at least one scope for activation.
    #[error("Object template must have at least one scope defined before activation")]
    ObjectTemplateNoScopes,

    /// Object template has active child templates.
    #[error("Object template has {0} active child templates that must be deleted first")]
    ObjectTemplateHasActiveChildren(usize),

    /// Object template rule not found.
    #[error("Template rule not found: {0}")]
    TemplateRuleNotFound(Uuid),

    /// Template rule circular dependency detected.
    #[error("Circular dependency detected in computed values: {0}")]
    TemplateRuleCircularDependency(String),

    /// Template rule expression parse error.
    #[error("Expression parse error in rule {rule_id}: {message}")]
    TemplateRuleExpressionError { rule_id: Uuid, message: String },

    /// Template rule expression evaluation error.
    #[error("Expression evaluation error for attribute '{attribute}': {message}")]
    TemplateRuleEvaluationError { attribute: String, message: String },

    /// Template rule invalid attribute.
    #[error("Attribute '{attribute}' is not valid for object type '{object_type}'")]
    TemplateRuleInvalidAttribute {
        attribute: String,
        object_type: String,
    },

    /// Template scope not found.
    #[error("Template scope not found: {0}")]
    TemplateScopeNotFound(Uuid),

    /// Template scope invalid organization.
    #[error("Organization not found for scope: {0}")]
    TemplateScopeInvalidOrganization(String),

    /// Template scope condition parse error.
    #[error("Scope condition parse error: {0}")]
    TemplateScopeConditionError(String),

    /// Template scope invalid configuration.
    #[error("Invalid scope configuration: {0}")]
    TemplateScopeInvalid(String),

    /// Template version not found.
    #[error("Template version not found: {0}")]
    TemplateVersionNotFound(Uuid),

    /// Template merge policy not found.
    #[error("Template merge policy not found: {0}")]
    TemplateMergePolicyNotFound(Uuid),

    /// Template merge policy already exists.
    #[error("Merge policy already exists for attribute '{0}' in this template")]
    TemplateMergePolicyExists(String),

    /// Template exclusion not found.
    #[error("Template exclusion not found: {0}")]
    TemplateExclusionNotFound(Uuid),

    /// Template exclusion already exists.
    #[error("Rule {0} is already excluded from this template")]
    TemplateExclusionAlreadyExists(Uuid),

    /// Template exclusion invalid rule (not from parent).
    #[error("Rule {0} is not from a parent template and cannot be excluded")]
    TemplateExclusionInvalidRule(Uuid),

    /// Template validation failed.
    #[error("Template validation failed: {violations} violation(s)")]
    TemplateValidationFailed { violations: i32 },

    /// Template application event not found.
    #[error("Template application event not found: {0}")]
    TemplateApplicationEventNotFound(Uuid),

    /// Template event not found.
    #[error("Template event not found: {0}")]
    TemplateEventNotFound(Uuid),

    /// Invalid template priority.
    #[error("Template priority must be between 1 and 1000")]
    InvalidTemplatePriority,

    /// Invalid rule priority.
    #[error("Rule priority must be between 1 and 1000")]
    InvalidTemplateRulePriority,

    // =========================================================================
    // Identity Merge Errors (F062)
    // =========================================================================
    /// Identity not found (for merge operations).
    #[error("Identity not found: {0}")]
    IdentityNotFound(Uuid),

    /// Duplicate candidate not found.
    #[error("Duplicate candidate not found: {0}")]
    DuplicateNotFound(Uuid),

    /// Merge operation not found.
    #[error("Merge operation not found: {0}")]
    MergeOperationNotFound(Uuid),

    /// Correlation rule not found.
    #[error("Correlation rule not found: {0}")]
    CorrelationRuleNotFound(Uuid),

    /// Correlation rule name already exists.
    #[error("Correlation rule name '{0}' already exists in this tenant")]
    CorrelationRuleNameExists(String),

    /// Circular merge detected.
    #[error("Circular merge detected: cannot merge {source_id} into {target_id} while a pending merge exists in the opposite direction")]
    CircularMergeDetected { source_id: Uuid, target_id: Uuid },

    /// Merge already in progress for identity.
    #[error("A merge operation is already in progress involving identity: {identity_id}")]
    MergeAlreadyInProgress { identity_id: Uuid },

    /// Source and target identities must be different.
    #[error("Source and target identities must be different")]
    MergeIdentitiesMustBeDifferent,

    /// `SoD` override reason required.
    #[error("SoD override reason is required when overriding SoD violations")]
    SodOverrideReasonRequired,

    /// Duplicate already dismissed.
    #[error("Duplicate candidate has already been dismissed: {0}")]
    DuplicateAlreadyDismissed(Uuid),

    /// Duplicate already merged.
    #[error("Duplicate candidate has already been merged: {0}")]
    DuplicateAlreadyMerged(Uuid),

    /// Invalid confidence score.
    #[error("Confidence score must be between 0 and 100, got: {0}")]
    InvalidConfidenceScore(f64),

    /// Invalid correlation threshold.
    #[error("Correlation threshold must be between 0.0 and 1.0, got: {0}")]
    InvalidCorrelationThreshold(f64),

    /// Invalid correlation weight.
    #[error("Correlation weight must be positive, got: {0}")]
    InvalidCorrelationWeight(f64),

    // Correlation Engine errors (F067)
    /// Correlation threshold not found for connector.
    #[error("Correlation threshold not found for connector: {0}")]
    CorrelationThresholdNotFound(Uuid),

    /// Correlation case not found.
    #[error("Correlation case not found: {0}")]
    CorrelationCaseNotFound(Uuid),

    /// Correlation case already resolved.
    #[error("Correlation case already resolved: {0}")]
    CorrelationCaseAlreadyResolved(Uuid),

    /// Correlation candidate not found.
    #[error("Correlation candidate not found: {0}")]
    CorrelationCandidateNotFound(Uuid),

    /// Correlation total weight exceeds limit.
    #[error("Total correlation weight would exceed 1.0: current={current}, adding={adding}")]
    CorrelationWeightExceedsLimit { current: f64, adding: f64 },

    /// Correlation expression validation failed.
    #[error("Correlation expression validation failed: {0}")]
    CorrelationExpressionInvalid(String),

    /// Correlation audit event not found.
    #[error("Correlation audit event not found: {0}")]
    CorrelationAuditEventNotFound(Uuid),

    /// Invalid correlation thresholds ordering.
    #[error("Auto-confirm threshold ({auto_confirm}) must be greater than manual review threshold ({manual_review})")]
    InvalidThresholdOrdering {
        auto_confirm: f64,
        manual_review: f64,
    },

    /// Invalid correlation batch size.
    #[error("Correlation batch size must be between 50 and 5000, got: {0}")]
    InvalidCorrelationBatchSize(i32),

    /// Correlation job not found.
    #[error("Correlation job not found: {0}")]
    CorrelationJobNotFound(Uuid),

    /// Merge audit not found.
    #[error("Merge audit record not found: {0}")]
    MergeAuditNotFound(Uuid),

    /// Archived identity not found.
    #[error("Archived identity not found: {0}")]
    ArchivedIdentityNotFound(Uuid),

    /// Batch merge job not found.
    #[error("Batch merge job not found: {0}")]
    BatchMergeJobNotFound(Uuid),

    /// Batch merge job already running.
    #[error("A batch merge job is already running for this tenant")]
    BatchMergeJobAlreadyRunning,

    // =========================================================================
    // Persona Management Errors (F063)
    // =========================================================================
    /// Persona archetype not found.
    #[error("Persona archetype not found: {0}")]
    PersonaArchetypeNotFound(Uuid),

    /// Persona archetype name already exists.
    #[error("Persona archetype name '{0}' already exists in this tenant")]
    PersonaArchetypeNameExists(String),

    /// Cannot delete archetype with active personas.
    #[error("Cannot delete persona archetype with {0} active personas")]
    PersonaArchetypeHasActivePersonas(i64),

    /// Persona archetype is not active.
    #[error("Persona archetype is not active: {0}")]
    PersonaArchetypeNotActive(Uuid),

    /// Persona not found.
    #[error("Persona not found: {0}")]
    PersonaNotFound(Uuid),

    /// Persona name already exists.
    #[error("Persona name '{0}' already exists in this tenant")]
    PersonaNameExists(String),

    /// One persona per archetype per user (IGA constraint).
    #[error("User already has a persona of this archetype")]
    PersonaArchetypeDuplicate,

    /// Persona is not active.
    #[error("Persona is not active: {0}")]
    PersonaNotActive(Uuid),

    /// Persona is expired.
    #[error("Persona has expired: {0}")]
    PersonaExpired(Uuid),

    /// Persona is suspended.
    #[error("Persona is suspended: {0}")]
    PersonaSuspended(Uuid),

    /// Persona is already archived.
    #[error("Persona is already archived: {0}")]
    PersonaAlreadyArchived(Uuid),

    /// Persona is already active.
    #[error("Persona is already active: {0}")]
    PersonaAlreadyActive(Uuid),

    /// Persona does not belong to user.
    #[error("Persona does not belong to this user")]
    PersonaNotOwnedByUser,

    /// Cannot switch to inactive/expired persona.
    #[error("Cannot switch to inactive or expired persona: {0}")]
    CannotSwitchToInactivePersona(Uuid),

    /// Persona extension exceeds maximum validity period.
    #[error("Persona {persona_id} extension exceeds maximum validity of {max_days} days")]
    PersonaExtensionExceedsMax { persona_id: Uuid, max_days: i32 },

    /// Persona session not found.
    #[error("Persona session not found: {0}")]
    PersonaSessionNotFound(Uuid),

    /// Persona session expired.
    #[error("Persona session has expired")]
    PersonaSessionExpired,

    /// No active persona to switch back from.
    #[error("No active persona context to switch back from")]
    NoActivePersonaContext,

    /// Persona link not found.
    #[error("Persona link not found: {0}")]
    PersonaLinkNotFound(Uuid),

    /// Persona link already exists.
    #[error("Persona link already exists for this user and persona")]
    PersonaLinkAlreadyExists,

    /// Invalid naming pattern.
    #[error("Invalid naming pattern: must contain at least one placeholder like {{username}}")]
    InvalidNamingPattern,

    /// Naming pattern placeholder missing user attribute.
    #[error("Naming pattern placeholder '{0}' references unknown user attribute")]
    NamingPatternPlaceholderUnknown(String),

    /// Invalid lifecycle policy.
    #[error("Invalid lifecycle policy: {0}")]
    InvalidLifecyclePolicy(String),

    /// Invalid attribute mappings.
    #[error("Invalid attribute mappings: {0}")]
    InvalidAttributeMappings(String),

    /// Persona extension requires approval.
    #[error("Persona extension requires approval (extension_requires_approval is true)")]
    PersonaExtensionRequiresApproval,

    /// Extension date must be in the future.
    #[error("Extension date must be in the future")]
    InvalidPersonaExtensionDate,

    /// Extension exceeds maximum validity.
    #[error("Extension would exceed maximum validity of {0} days")]
    PersonaExtensionExceedsMaximum(i32),

    /// Persona audit event not found.
    #[error("Persona audit event not found: {0}")]
    PersonaAuditEventNotFound(Uuid),

    /// Physical user deactivation cascade error.
    #[error("Failed to cascade deactivation to personas: {0}")]
    PersonaCascadeDeactivationFailed(String),

    /// User not authorized to create personas.
    #[error("User is not authorized to create personas")]
    PersonaCreationNotAuthorized,

    /// User not authorized to manage persona of this archetype.
    #[error("User is not authorized to manage personas of archetype: {0}")]
    PersonaArchetypeNotAuthorized(Uuid),

    /// Conflicting archetype constructions.
    #[error("Archetype {0} has conflicting constructions with existing persona archetypes")]
    PersonaArchetypeConflict(Uuid),

    /// Multi-persona operation partially failed.
    #[error("Multi-persona operation failed: {succeeded} succeeded, {failed} failed - {details}")]
    PersonaMultiOperationPartialFailure {
        succeeded: i32,
        failed: i32,
        details: String,
    },

    /// Persona operation would trigger approval workflow.
    #[error("Persona operations must not be subject to approval workflows - operation on {0} would trigger approval")]
    PersonaOperationRequiresApproval(String),

    // =========================================================================
    // Power of Attorney Errors (F-061)
    // =========================================================================
    /// Power of Attorney not found.
    #[error("Power of Attorney not found: {0}")]
    PoaNotFound(Uuid),

    /// Cannot grant PoA to self.
    #[error("Cannot grant Power of Attorney to yourself")]
    PoaSelfDelegationNotAllowed,

    /// PoA duration exceeds maximum (90 days).
    #[error("Power of Attorney duration exceeds maximum of 90 days")]
    PoaDurationExceedsMaximum,

    /// PoA start date must not be in the past.
    #[error("Power of Attorney start date cannot be in the past")]
    PoaStartDateInPast,

    /// PoA end date must be after start date.
    #[error("Power of Attorney end date must be after start date")]
    PoaInvalidPeriod,

    /// PoA is not active (cannot assume identity).
    #[error("Power of Attorney is not active: {0}")]
    PoaNotActive(Uuid),

    /// PoA is in terminal state (expired or revoked).
    #[error("Power of Attorney is in terminal state: {0}")]
    PoaTerminalState(Uuid),

    /// PoA has already been revoked.
    #[error("Power of Attorney has already been revoked: {0}")]
    PoaAlreadyRevoked(Uuid),

    /// Assumed session not found.
    #[error("Assumed session not found: {0}")]
    PoaAssumedSessionNotFound(Uuid),

    /// User is not currently assuming an identity.
    #[error("User is not currently assuming an identity")]
    PoaNotAssuming,

    /// User is already assuming an identity.
    #[error("User is already assuming an identity - drop current assumption first")]
    PoaAlreadyAssuming,

    /// PoA donor user not found.
    #[error("Power of Attorney donor not found: {0}")]
    PoaDonorNotFound(Uuid),

    /// PoA attorney user not found.
    #[error("Power of Attorney attorney not found: {0}")]
    PoaAttorneyNotFound(Uuid),

    /// PoA donor user is not active.
    #[error("Power of Attorney donor is not active: {0}")]
    PoaDonorNotActive(Uuid),

    /// PoA attorney user is not active.
    #[error("Power of Attorney attorney is not active: {0}")]
    PoaAttorneyNotActive(Uuid),

    /// PoA scope violation - action not in scope.
    #[error("Action not permitted under Power of Attorney scope: {0}")]
    PoaScopeViolation(String),

    /// PoA audit event not found.
    #[error("Power of Attorney audit event not found: {0}")]
    PoaAuditEventNotFound(Uuid),

    /// Cannot extend PoA - would exceed 90 days from original start.
    #[error("Extension would exceed maximum 90 days from original start")]
    PoaExtensionExceedsMaximum,

    /// Cannot extend expired PoA.
    #[error("Cannot extend expired Power of Attorney: {0}")]
    PoaCannotExtendExpired(Uuid),

    /// Cannot extend revoked PoA.
    #[error("Cannot extend revoked Power of Attorney: {0}")]
    PoaCannotExtendRevoked(Uuid),

    /// New end date must be after current end date.
    #[error("New end date must be after current end date")]
    PoaInvalidExtension,

    // =========================================================================
    // Semi-manual Resources Errors (F064)
    // =========================================================================
    /// SLA policy not found.
    #[error("SLA policy not found: {0}")]
    SlaPolicyNotFound(Uuid),

    /// Ticketing configuration not found.
    #[error("Ticketing configuration not found: {0}")]
    TicketingConfigurationNotFound(Uuid),

    /// Manual provisioning task not found.
    #[error("Manual provisioning task not found: {0}")]
    ManualProvisioningTaskNotFound(Uuid),

    /// External ticket not found.
    #[error("External ticket not found: {0}")]
    ExternalTicketNotFound(Uuid),

    /// SLA policy is in use.
    #[error("SLA policy is in use by one or more applications")]
    SlaPolicyInUse(Uuid),

    /// Ticketing configuration is in use.
    #[error("Ticketing configuration is in use by one or more applications")]
    TicketingConfigurationInUse(Uuid),

    // =========================================================================
    // License Management Errors (F065)
    // =========================================================================
    /// License pool not found.
    #[error("License pool not found: {0}")]
    LicensePoolNotFound(Uuid),

    /// License pool name already exists.
    #[error("License pool name '{0}' already exists in this tenant")]
    LicensePoolNameExists(String),

    /// License pool is archived.
    #[error("License pool is archived: {0}")]
    LicensePoolArchived(Uuid),

    /// License pool has no capacity.
    #[error("License pool has no available capacity: {0}")]
    LicensePoolNoCapacity(Uuid),

    /// License assignment not found.
    #[error("License assignment not found: {0}")]
    LicenseAssignmentNotFound(Uuid),

    /// License already assigned to user.
    #[error("User already has a license from this pool")]
    LicenseAlreadyAssigned,

    /// License incompatibility conflict.
    #[error("License assignment blocked due to incompatibility with pool '{0}'")]
    LicenseIncompatibilityConflict(String),

    /// License incompatibility rule not found.
    #[error("License incompatibility rule not found: {0}")]
    LicenseIncompatibilityNotFound(Uuid),

    /// License entitlement link not found.
    #[error("License entitlement link not found: {0}")]
    LicenseEntitlementLinkNotFound(Uuid),

    /// License reclamation rule not found.
    #[error("License reclamation rule not found: {0}")]
    LicenseReclamationRuleNotFound(Uuid),

    /// License pool has active assignments.
    #[error("Cannot delete license pool with {0} active assignments")]
    LicensePoolHasAssignments(i32),

    /// License pool capacity reduction invalid.
    #[error("Cannot reduce capacity below allocated count ({0} allocated)")]
    LicenseCapacityReductionInvalid(i32),

    // =========================================================================
    // Provisioning Scripts Errors (F066)
    // =========================================================================
    /// Provisioning script not found.
    #[error("Provisioning script not found: {0}")]
    ProvisioningScriptNotFound(Uuid),

    /// Provisioning script name already exists.
    #[error("Provisioning script name '{0}' already exists in this tenant")]
    ProvisioningScriptNameExists(String),

    /// Script version not found.
    #[error("Script version not found: script={0}, version={1}")]
    ScriptVersionNotFound(Uuid, i32),

    /// Script hook binding not found.
    #[error("Script hook binding not found: {0}")]
    ScriptHookBindingNotFound(Uuid),

    /// Script template not found.
    #[error("Script template not found: {0}")]
    ScriptTemplateNotFound(Uuid),

    /// Script template name already exists.
    #[error("Script template name '{0}' already exists in this tenant")]
    ScriptTemplateNameExists(String),

    /// Cannot modify system script or template.
    #[error("Cannot modify system resource: {0}")]
    CannotModifySystemScript(Uuid),

    /// Script is not active (cannot bind or execute).
    #[error("Script is not active: {0}")]
    ScriptNotActive(Uuid),

    /// Script is already in the requested status.
    #[error("Script is already {0}: {1}")]
    ScriptAlreadyInStatus(String, Uuid),

    /// Script has active bindings (cannot delete).
    #[error("Cannot delete script with {0} active bindings")]
    ScriptHasActiveBindings(i64),

    /// Maximum bindings per hook point exceeded.
    #[error("Maximum of {0} bindings per connector/phase/operation exceeded")]
    MaxBindingsExceeded(i32),

    /// Script body exceeds maximum size.
    #[error("Script body exceeds maximum size of {0} bytes")]
    ScriptBodyTooLarge(usize),

    /// Script syntax error.
    #[error("Script syntax error: {0}")]
    ScriptSyntaxError(String),

    /// Script execution failed.
    #[error("Script execution failed: {0}")]
    ScriptExecutionFailed(String),

    /// Script execution timed out.
    #[error("Script execution timed out after {0} seconds")]
    ScriptExecutionTimeout(i32),

    /// Invalid rollback target version.
    #[error("Invalid rollback target: version {0} does not exist for script {1}")]
    InvalidRollbackVersion(i32, Uuid),

    /// Binding execution order conflict.
    #[error("Execution order {0} already exists for this connector/phase/operation")]
    BindingOrderConflict(i32),

    // =========================================================================
    // SIEM Integration Errors (F078)
    // =========================================================================
    /// SIEM destination not found.
    #[error("SIEM destination not found: {0}")]
    SiemDestinationNotFound(Uuid),

    /// SIEM destination name already exists.
    #[error("SIEM destination name '{0}' already exists in this tenant")]
    SiemDestinationNameExists(String),

    /// SIEM batch export not found.
    #[error("SIEM batch export not found: {0}")]
    SiemBatchExportNotFound(Uuid),

    /// SIEM batch export not ready for download.
    #[error("SIEM batch export {0} not ready: {1}")]
    SiemBatchExportNotReady(Uuid, String),

    // =========================================================================
    // Business Role Hierarchy Errors (F088)
    // =========================================================================
    /// Governance role not found.
    #[error("Governance role not found: {0}")]
    GovRoleNotFound(Uuid),

    /// Governance role name already exists.
    #[error("Governance role name '{0}' already exists in this tenant")]
    GovRoleNameExists(String),

    /// Governance role is abstract and cannot be assigned.
    #[error("Cannot assign abstract role '{0}' directly to users")]
    GovRoleIsAbstract(String),

    /// Governance role hierarchy circular reference.
    #[error("Setting this parent would create a circular reference in the role hierarchy")]
    GovRoleCircularReference,

    /// Governance role hierarchy depth exceeded.
    #[error("Maximum role hierarchy depth of {0} exceeded")]
    GovRoleDepthExceeded(i32),

    /// Governance role version conflict.
    #[error("Role was modified by another process (version conflict)")]
    GovRoleVersionConflict,

    /// Governance role parent not found.
    #[error("Parent role not found: {0}")]
    GovRoleParentNotFound(Uuid),

    /// Governance role inheritance block not found.
    #[error("Inheritance block not found: {0}")]
    GovRoleInheritanceBlockNotFound(Uuid),

    /// Governance role inheritance block already exists.
    #[error("Inheritance block already exists for this role and entitlement")]
    GovRoleInheritanceBlockExists,

    /// Governance role has child roles and cannot be deleted.
    #[error("Cannot delete role with {0} child roles")]
    GovRoleHasChildren(i64),

    /// Governance role move would exceed depth.
    #[error("Moving this role would cause descendants to exceed maximum hierarchy depth of {0}")]
    GovRoleMoveExceedsDepth(i32),

    // =========================================================================
    // Role Inducements & Constructions Errors (F-063)
    // =========================================================================
    /// Role construction not found.
    #[error("Role construction not found: {0}")]
    RoleConstructionNotFound(Uuid),

    /// Role construction version conflict.
    #[error("Role construction was modified by another process (version conflict)")]
    RoleConstructionVersionConflict,

    /// Role construction already exists.
    #[error(
        "Construction already exists for this role/connector/object_class/account_type combination"
    )]
    RoleConstructionExists,

    /// Role inducement not found.
    #[error("Role inducement not found: {0}")]
    RoleInducementNotFound(Uuid),

    /// Role inducement already exists.
    #[error("Inducement already exists between these roles")]
    RoleInducementExists,

    /// Role inducement cycle detected.
    #[error("Creating this inducement would create a circular reference: {0}")]
    RoleInducementCycleDetected(String),

    /// Connector not found (for construction validation).
    #[error("Connector not found: {0}")]
    ConnectorNotFound(Uuid),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// JSON serialization error.
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    // =========================================================================
    // Validation Errors (F-004 Entitlement Service)
    // =========================================================================
    /// Validation failed with one or more errors.
    #[error("Validation failed: {0:?}")]
    ValidationFailed(Vec<String>),

    /// Prerequisite entitlement not assigned.
    #[error("Prerequisite entitlement not assigned: {0}")]
    PrerequisiteNotAssigned(Uuid),

    // =========================================================================
    // Self-Service Request Catalog Errors (F-062)
    // =========================================================================
    /// Catalog category not found.
    #[error("Catalog category not found: {0}")]
    CatalogCategoryNotFound(Uuid),

    /// Catalog category name already exists.
    #[error("Catalog category name '{0}' already exists at this level")]
    CatalogCategoryNameExists(String),

    /// Catalog category has children and cannot be deleted.
    #[error("Cannot delete category with {0} child categories")]
    CatalogCategoryHasChildren(i64),

    /// Catalog category has items and cannot be deleted.
    #[error("Cannot delete category with {0} catalog items")]
    CatalogCategoryHasItems(i64),

    /// Catalog item not found.
    #[error("Catalog item not found: {0}")]
    CatalogItemNotFound(Uuid),

    /// Catalog item name already exists.
    #[error("Catalog item name '{0}' already exists")]
    CatalogItemNameExists(String),

    /// Catalog item is disabled.
    #[error("Catalog item is disabled: {0}")]
    CatalogItemDisabled(Uuid),

    /// Catalog item has pending requests in carts.
    #[error("Cannot delete item with {0} pending cart references")]
    CatalogItemInCarts(i64),

    /// Request cart not found.
    #[error("Request cart not found: {0}")]
    RequestCartNotFound(Uuid),

    /// Request cart item not found.
    #[error("Request cart item not found: {0}")]
    RequestCartItemNotFound(Uuid),

    /// Request cart item already exists (duplicate item in cart).
    #[error("Item is already in the cart")]
    RequestCartItemDuplicate,

    /// Request cart is empty.
    #[error("Cannot submit an empty cart")]
    RequestCartEmpty,

    /// Catalog item not requestable.
    #[error("Item is not requestable: {0}")]
    CatalogItemNotRequestable(String),

    /// Beneficiary validation failed.
    #[error("Invalid beneficiary: {0}")]
    InvalidBeneficiary(String),
}

impl GovernanceError {
    /// Returns true if this is a not-found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::ApplicationNotFound(_)
                | Self::EntitlementNotFound(_)
                | Self::AssignmentNotFound(_)
                | Self::UserNotFound(_)
                | Self::GroupNotFound(_)
                | Self::RoleEntitlementNotFound(_)
                | Self::SodRuleNotFound(_)
                | Self::SodViolationNotFound(_)
                | Self::SodExemptionNotFound(_)
                | Self::WorkflowNotFound(_)
                | Self::AccessRequestNotFound(_)
                | Self::DelegationNotFound(_)
                | Self::CampaignNotFound(_)
                | Self::CertificationItemNotFound(_)
                | Self::BirthrightPolicyNotFound(_)
                | Self::LifecycleEventNotFound(_)
                | Self::LifecycleActionNotFound(_)
                | Self::AccessSnapshotNotFound(_)
                | Self::RiskFactorNotFound(_)
                | Self::RiskScoreNotFound(_)
                | Self::RiskThresholdNotFound(_)
                | Self::RiskAlertNotFound(_)
                | Self::PeerGroupNotFound(_)
                | Self::RiskEventNotFound(_)
                | Self::OrphanDetectionNotFound(_)
                | Self::ReconciliationRunNotFound(_)
                | Self::DetectionRuleNotFound(_)
                | Self::ServiceAccountNotFound(_)
                | Self::ReportTemplateNotFound(_)
                | Self::GeneratedReportNotFound(_)
                | Self::ReportScheduleNotFound(_)
                | Self::MiningJobNotFound(_)
                | Self::RoleCandidateNotFound(_)
                | Self::ExcessivePrivilegeFlagNotFound(_)
                | Self::ConsolidationSuggestionNotFound(_)
                | Self::RoleSimulationNotFound(_)
                | Self::RoleMetricsNotFound(_)
                | Self::RoleNotFoundForMining(_)
                | Self::LifecycleConfigNotFound(_)
                | Self::LifecycleStateNotFound(_)
                | Self::LifecycleTransitionNotFound(_)
                | Self::StateTransitionRequestNotFound(_)
                | Self::TransitionAuditNotFound(_)
                | Self::ScheduledTransitionNotFound(_)
                | Self::BulkStateOperationNotFound(_)
                | Self::LifecycleObjectNotFound { .. }
                | Self::EscalationPolicyNotFound(_)
                | Self::EscalationRuleNotFound(_)
                | Self::EscalationLevelNotFound(_)
                | Self::EscalationEventNotFound(_)
                | Self::ApprovalGroupNotFound(_)
                | Self::MicroCertTriggerNotFound(_)
                | Self::MicroCertificationNotFound(_)
                | Self::MicroCertEventNotFound(_)
                | Self::MetaRoleNotFound(_)
                | Self::MetaRoleCriteriaNotFound(_)
                | Self::MetaRoleEntitlementNotFound(_)
                | Self::MetaRoleConstraintNotFound(_)
                | Self::MetaRoleInheritanceNotFound(_)
                | Self::MetaRoleConflictNotFound(_)
                | Self::RoleParameterNotFound(_)
                | Self::AssignmentParameterNotFound(_)
                | Self::ParameterAuditEventNotFound(_)
                | Self::ObjectTemplateNotFound(_)
                | Self::ObjectTemplateParentNotFound(_)
                | Self::TemplateRuleNotFound(_)
                | Self::TemplateScopeNotFound(_)
                | Self::TemplateVersionNotFound(_)
                | Self::TemplateMergePolicyNotFound(_)
                | Self::TemplateExclusionNotFound(_)
                | Self::TemplateApplicationEventNotFound(_)
                | Self::TemplateEventNotFound(_)
                | Self::OutlierConfigNotFound(_)
                | Self::OutlierAnalysisNotFound(_)
                | Self::OutlierResultNotFound(_)
                | Self::OutlierDispositionNotFound(_)
                | Self::OutlierAlertNotFound(_)
                | Self::PolicySimulationNotFound(_)
                | Self::BatchSimulationNotFound(_)
                | Self::SimulationComparisonNotFound(_)
                | Self::NhiNotFound(_)
                | Self::NhiCredentialNotFound(_)
                | Self::NhiRequestNotFound(_)
                | Self::NhiOwnerNotFound(_)
                | Self::NhiAuditEventNotFound(_)
                | Self::IdentityNotFound(_)
                | Self::DuplicateNotFound(_)
                | Self::MergeOperationNotFound(_)
                | Self::CorrelationRuleNotFound(_)
                | Self::MergeAuditNotFound(_)
                | Self::ArchivedIdentityNotFound(_)
                | Self::BatchMergeJobNotFound(_)
                | Self::PersonaArchetypeNotFound(_)
                | Self::PersonaNotFound(_)
                | Self::PersonaSessionNotFound(_)
                | Self::PersonaLinkNotFound(_)
                | Self::PersonaAuditEventNotFound(_)
                // Power of Attorney (F-061)
                | Self::PoaNotFound(_)
                | Self::PoaAssumedSessionNotFound(_)
                | Self::PoaDonorNotFound(_)
                | Self::PoaAttorneyNotFound(_)
                | Self::PoaAuditEventNotFound(_)
                // Semi-manual Resources (F064)
                | Self::SlaPolicyNotFound(_)
                | Self::TicketingConfigurationNotFound(_)
                | Self::ManualProvisioningTaskNotFound(_)
                | Self::ExternalTicketNotFound(_)
                // License Management (F065)
                | Self::LicensePoolNotFound(_)
                | Self::LicenseAssignmentNotFound(_)
                | Self::LicenseIncompatibilityNotFound(_)
                | Self::LicenseEntitlementLinkNotFound(_)
                | Self::LicenseReclamationRuleNotFound(_)
                // Provisioning Scripts (F066)
                | Self::ProvisioningScriptNotFound(_)
                | Self::ScriptVersionNotFound(_, _)
                | Self::ScriptHookBindingNotFound(_)
                | Self::ScriptTemplateNotFound(_)
                // Correlation Engine (F067)
                | Self::CorrelationThresholdNotFound(_)
                | Self::CorrelationCaseNotFound(_)
                | Self::CorrelationCandidateNotFound(_)
                | Self::CorrelationAuditEventNotFound(_)
                | Self::CorrelationJobNotFound(_)
                // SIEM Integration (F078)
                | Self::SiemDestinationNotFound(_)
                | Self::SiemBatchExportNotFound(_)
                // Business Role Hierarchy (F088)
                | Self::GovRoleNotFound(_)
                | Self::GovRoleParentNotFound(_)
                | Self::GovRoleInheritanceBlockNotFound(_)
                // Self-Service Request Catalog (F-062)
                | Self::CatalogCategoryNotFound(_)
                | Self::CatalogItemNotFound(_)
                | Self::RequestCartNotFound(_)
                | Self::RequestCartItemNotFound(_)
                // Role Inducements & Constructions (F-063)
                | Self::RoleConstructionNotFound(_)
                | Self::RoleInducementNotFound(_)
                | Self::ConnectorNotFound(_)
                // Power of Attorney (F-PoA)
                | Self::PoaNotFound(_)
                | Self::PoaAssumedSessionNotFound(_)
                | Self::PoaDonorNotFound(_)
                | Self::PoaAttorneyNotFound(_)
                | Self::PoaAuditEventNotFound(_)
        )
    }

    /// Returns true if this is a conflict/duplicate error.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::ApplicationNameExists(_)
                | Self::EntitlementNameExists(_)
                | Self::AssignmentAlreadyExists
                | Self::RoleEntitlementExists(_)
                | Self::SodRuleNameExists(_)
                | Self::SodRuleDuplicate
                | Self::SodRulePairExists { .. }
                | Self::SodExemptionAlreadyExists
                | Self::WorkflowNameExists(_)
                | Self::AccessRequestAlreadyExists
                | Self::EntitlementAlreadyAssigned
                | Self::DelegationAlreadyExists
                | Self::DuplicateDelegation
                | Self::CampaignNameExists(_)
                | Self::DuplicatePendingItem
                | Self::ItemAlreadyDecided(_)
                | Self::BirthrightPolicyNameExists(_)
                | Self::LifecycleEventAlreadyProcessed(_)
                | Self::LifecycleActionAlreadyExecuted(_)
                | Self::LifecycleActionAlreadyCancelled(_)
                | Self::RiskFactorNameExists(_)
                | Self::RiskThresholdNameExists(_)
                | Self::RiskAlertAlreadyAcknowledged(_)
                | Self::PeerGroupAttributeExists(_)
                | Self::DetectionRuleNameExists(_)
                | Self::ServiceAccountUserExists
                | Self::ReconciliationAlreadyRunning
                | Self::OrphanAlreadyRemediated(_)
                | Self::OrphanAlreadyDismissed(_)
                | Self::ReportTemplateNameExists(_)
                | Self::ReportScheduleNameExists(_)
                | Self::ReportTemplateAlreadyArchived(_)
                | Self::ReportScheduleAlreadyPaused(_)
                | Self::ReportScheduleAlreadyActive(_)
                | Self::MiningJobAlreadyRunning
                | Self::MiningJobAlreadyCompleted(_)
                | Self::RoleCandidateAlreadyPromoted(_)
                | Self::RoleCandidateAlreadyDismissed(_)
                | Self::ExcessivePrivilegeFlagAlreadyReviewed(_)
                | Self::ConsolidationSuggestionAlreadyProcessed(_)
                | Self::RoleSimulationAlreadyApplied(_)
                | Self::LifecycleConfigAlreadyExists(_)
                | Self::LifecycleStateNameExists(_)
                | Self::LifecycleTransitionNameExists(_)
                | Self::LifecycleTransitionStatePairExists(_, _)
                | Self::ScheduledTransitionAlreadyExists
                | Self::ScheduledTransitionAlreadyExecuted(_)
                | Self::BulkOperationAlreadyRunning(_)
                | Self::BulkOperationAlreadyCompleted(_)
                | Self::EscalationPolicyNameExists(_)
                | Self::ApprovalGroupNameExists(_)
                | Self::MicroCertTriggerNameExists(_)
                | Self::MicroCertificationAlreadyDecided(_)
                | Self::DuplicatePendingMicroCertification
                | Self::MetaRoleNameExists(_)
                | Self::MetaRoleEntitlementAlreadyExists
                | Self::MetaRoleConstraintAlreadyExists(_)
                | Self::MetaRoleConflictAlreadyResolved(_)
                | Self::MetaRoleAlreadyActive(_)
                | Self::MetaRoleAlreadyDisabled(_)
                | Self::RoleParameterNameExists(_)
                | Self::ParametricAssignmentAlreadyExists
                | Self::ObjectTemplateNameExists(_)
                | Self::ObjectTemplateAlreadyActive(_)
                | Self::ObjectTemplateAlreadyDisabled(_)
                | Self::TemplateMergePolicyExists(_)
                | Self::TemplateExclusionAlreadyExists(_)
                | Self::OutlierAnalysisAlreadyRunning
                | Self::OutlierDispositionAlreadyExists
                | Self::OutlierAlertAlreadyDismissed(_)
                | Self::PolicySimulationAlreadyExecuted(_)
                | Self::BatchSimulationAlreadyExecuted(_)
                | Self::BatchSimulationAlreadyApplied(_)
                | Self::NhiNameExists(_)
                | Self::NhiUserAlreadyRegistered(_)
                | Self::NhiRequestAlreadyExists
                | Self::NhiAlreadySuspended(_)
                | Self::NhiCredentialAlreadyRevoked(_)
                | Self::CorrelationRuleNameExists(_)
                | Self::CircularMergeDetected { .. }
                | Self::MergeAlreadyInProgress { .. }
                | Self::DuplicateAlreadyDismissed(_)
                | Self::DuplicateAlreadyMerged(_)
                | Self::BatchMergeJobAlreadyRunning
                | Self::PersonaArchetypeNameExists(_)
                | Self::PersonaNameExists(_)
                | Self::PersonaArchetypeDuplicate
                | Self::PersonaAlreadyArchived(_)
                | Self::PersonaAlreadyActive(_)
                | Self::PersonaLinkAlreadyExists
                // Semi-manual Resources (F064)
                | Self::SlaPolicyInUse(_)
                | Self::TicketingConfigurationInUse(_)
                // License Management (F065)
                | Self::LicensePoolNameExists(_)
                | Self::LicenseAlreadyAssigned
                | Self::LicensePoolHasAssignments(_)
                // Provisioning Scripts (F066)
                | Self::ProvisioningScriptNameExists(_)
                | Self::ScriptTemplateNameExists(_)
                | Self::ScriptHasActiveBindings(_)
                | Self::BindingOrderConflict(_)
                | Self::MaxBindingsExceeded(_)
                // Correlation Engine (F067)
                | Self::CorrelationCaseAlreadyResolved(_)
                // SIEM Integration (F078)
                | Self::SiemDestinationNameExists(_)
                // Business Role Hierarchy (F088)
                | Self::GovRoleNameExists(_)
                | Self::GovRoleVersionConflict
                | Self::GovRoleInheritanceBlockExists
                // Self-Service Request Catalog (F-062)
                | Self::CatalogCategoryNameExists(_)
                | Self::CatalogCategoryHasChildren(_)
                | Self::CatalogCategoryHasItems(_)
                | Self::CatalogItemNameExists(_)
                | Self::CatalogItemInCarts(_)
                | Self::RequestCartItemDuplicate
                // Role Inducements & Constructions (F-063)
                | Self::RoleConstructionVersionConflict
                | Self::RoleConstructionExists
                | Self::RoleInducementExists
                | Self::RoleInducementCycleDetected(_)
                // Power of Attorney (F-PoA)
                | Self::PoaAlreadyRevoked(_)
                | Self::PoaAlreadyAssuming
        )
    }

    /// Returns true if this is an escalation error.
    #[must_use]
    pub fn is_escalation_error(&self) -> bool {
        matches!(
            self,
            Self::EscalationPolicyNotFound(_)
                | Self::EscalationPolicyNameExists(_)
                | Self::EscalationRuleNotFound(_)
                | Self::EscalationLevelNotFound(_)
                | Self::EscalationEventNotFound(_)
                | Self::ApprovalGroupNotFound(_)
                | Self::ApprovalGroupNameExists(_)
                | Self::ApprovalGroupInUse(_)
                | Self::NoEscalationTargetAvailable { .. }
                | Self::EscalationExhausted(_)
                | Self::CannotEscalateNonPendingRequest(_)
                | Self::CannotResetNonEscalatedRequest(_)
                | Self::ManagerNotFoundForEscalation(_)
                | Self::CircularManagerChain(_)
        )
    }

    /// Returns true if this is an `SoD` violation error.
    #[must_use]
    pub fn is_sod_violation(&self) -> bool {
        matches!(self, Self::SodViolationBlocked { .. })
    }

    /// Returns true if this is a precondition failure.
    #[must_use]
    pub fn is_precondition_failed(&self) -> bool {
        matches!(
            self,
            Self::ApplicationHasEntitlements(_)
                | Self::EntitlementHasAssignments(_)
                | Self::ApplicationInactive(_)
                | Self::SodRuleHasViolations(_)
                | Self::SodViolationAlreadyRemediated(_)
                | Self::SodExemptionAlreadyInactive(_)
                | Self::WorkflowHasPendingRequests(_)
                | Self::RequestNotPending
                | Self::StepAlreadyDecided
                | Self::CannotCancelNonPendingRequest
                | Self::DelegationNotActive(_)
                | Self::DelegationScopeViolation { .. }
                | Self::CannotExtendExpiredDelegation(_)
                | Self::CannotExtendRevokedDelegation(_)
                | Self::InvalidDelegationExtension
                | Self::CampaignNotDraft(_)
                | Self::CampaignNotActive(_)
                | Self::CampaignNoItems
                | Self::CannotDeleteNonDraftCampaign
                | Self::CannotCancelCampaign(_)
                | Self::ItemNotPending(_)
                | Self::CannotDeleteActivePolicy
                | Self::CannotCancelNonScheduledAction
                | Self::MoverEventRequiresAttributesBefore
                | Self::EventRequiresAttributesAfter
                | Self::CannotCancelNonRunningReconciliation
                | Self::ServiceAccountExpired(_)
                | Self::ServiceAccountSuspended(_)
                | Self::CannotModifySystemTemplate(_)
                | Self::CannotArchiveSystemTemplate(_)
                | Self::CannotModifyCompletedReport(_)
                | Self::ReportStillGenerating(_)
                | Self::MiningJobNotPending(_)
                | Self::MiningJobNotRunning(_)
                | Self::CannotCancelMiningJob(_)
                | Self::InsufficientMiningData(_)
                | Self::RoleCandidateNotPending(_)
                | Self::RoleSimulationNotDraft(_)
                | Self::RoleSimulationNotExecuted(_)
                | Self::MiningJobTimeout(_)
                | Self::MicroCertificationNotPending(_)
                | Self::MicroCertificationAlreadyExpired(_)
                | Self::CannotSkipNonPendingMicroCert(_)
                | Self::MicroCertTriggerNotActive(_)
                | Self::ParameterHasAssignments(_)
                | Self::RoleNotParametric(_)
                | Self::AssignmentNotTemporallyActive
                | Self::MergeIdentitiesMustBeDifferent
                | Self::SodOverrideReasonRequired
                // Provisioning Scripts (F066)
                | Self::CannotModifySystemScript(_)
                | Self::ScriptNotActive(_)
                | Self::ScriptAlreadyInStatus(_, _)
                | Self::ScriptBodyTooLarge(_)
                | Self::InvalidRollbackVersion(_, _)
                // Correlation Engine (F067)
                | Self::CorrelationWeightExceedsLimit { .. }
                | Self::CorrelationExpressionInvalid(_)
                | Self::InvalidThresholdOrdering { .. }
                | Self::InvalidCorrelationBatchSize(_)
                // SIEM Integration (F078)
                | Self::SiemBatchExportNotReady(_, _)
                // Lifecycle State Machine Extensions (F-193)
                | Self::TransitionConditionsNotSatisfied { .. }
                // Power of Attorney (F-PoA)
                | Self::PoaNotActive(_)
                | Self::PoaTerminalState(_)
                | Self::PoaNotAssuming
                | Self::PoaCannotExtendExpired(_)
                | Self::PoaCannotExtendRevoked(_)
                | Self::PoaInvalidExtension
        )
    }

    /// Returns true if this is a forbidden action.
    #[must_use]
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            Self::SelfApprovalNotAllowed
                | Self::NotAuthorizedApprover
                | Self::SelfDelegationNotAllowed
                | Self::NotAuthorizedReviewer
                | Self::NoMatchingDelegation { .. }
                | Self::NotAuthorizedMicroCertReviewer
                | Self::MicroCertCannotDecide(_, _)
                // Power of Attorney (F-PoA)
                | Self::PoaScopeViolation(_)
        )
    }

    /// Returns true if this is a certification campaign error.
    #[must_use]
    pub fn is_certification_error(&self) -> bool {
        matches!(
            self,
            Self::CampaignNotFound(_)
                | Self::CampaignNameExists(_)
                | Self::CampaignNotDraft(_)
                | Self::CampaignNotActive(_)
                | Self::CampaignNoItems
                | Self::CannotDeleteNonDraftCampaign
                | Self::CannotCancelCampaign(_)
                | Self::CertificationItemNotFound(_)
                | Self::ItemAlreadyDecided(_)
                | Self::ItemNotPending(_)
                | Self::DuplicatePendingItem
                | Self::NotAuthorizedReviewer
                | Self::RevocationJustificationRequired
                | Self::DeadlineInPast
                | Self::SpecificReviewersRequired
                | Self::ReviewerNotFound(_)
        )
    }

    /// Returns true if this is a lifecycle workflow error.
    #[must_use]
    pub fn is_lifecycle_error(&self) -> bool {
        matches!(
            self,
            Self::BirthrightPolicyNotFound(_)
                | Self::BirthrightPolicyNameExists(_)
                | Self::CannotDeleteActivePolicy
                | Self::InvalidPolicyConditions(_)
                | Self::InvalidConditionOperator(_)
                | Self::InvalidConditionAttribute(_)
                | Self::PolicyEntitlementsNotFound(_)
                | Self::LifecycleEventNotFound(_)
                | Self::LifecycleEventAlreadyProcessed(_)
                | Self::InvalidLifecycleEventType(_)
                | Self::LifecycleActionNotFound(_)
                | Self::LifecycleActionAlreadyExecuted(_)
                | Self::LifecycleActionAlreadyCancelled(_)
                | Self::CannotCancelNonScheduledAction
                | Self::MoverEventRequiresAttributesBefore
                | Self::EventRequiresAttributesAfter
                | Self::AccessSnapshotNotFound(_)
        )
    }

    /// Returns true if this is a risk scoring error.
    #[must_use]
    pub fn is_risk_scoring_error(&self) -> bool {
        matches!(
            self,
            Self::RiskFactorNotFound(_)
                | Self::RiskFactorNameExists(_)
                | Self::RiskScoreNotFound(_)
                | Self::RiskThresholdNotFound(_)
                | Self::RiskThresholdNameExists(_)
                | Self::RiskAlertNotFound(_)
                | Self::RiskAlertAlreadyAcknowledged(_)
                | Self::PeerGroupNotFound(_)
                | Self::PeerGroupAttributeExists(_)
                | Self::InvalidWeight(_)
                | Self::InvalidThresholdScore(_)
                | Self::InvalidCooldownHours(_)
                | Self::PeerGroupTooSmall(_)
                | Self::RiskEventNotFound(_)
        )
    }

    /// Returns true if this is an orphan detection error.
    #[must_use]
    pub fn is_orphan_detection_error(&self) -> bool {
        matches!(
            self,
            Self::OrphanDetectionNotFound(_)
                | Self::ReconciliationRunNotFound(_)
                | Self::DetectionRuleNotFound(_)
                | Self::DetectionRuleNameExists(_)
                | Self::ServiceAccountNotFound(_)
                | Self::ServiceAccountUserExists
                | Self::ReconciliationAlreadyRunning
                | Self::InvalidRemediationAction { .. }
                | Self::OrphanAlreadyRemediated(_)
                | Self::OrphanAlreadyDismissed(_)
                | Self::CannotCancelNonRunningReconciliation
                | Self::NewOwnerRequiredForReassignment
                | Self::ServiceAccountExpired(_)
                | Self::ServiceAccountSuspended(_)
        )
    }

    /// Returns true if this is a compliance reporting error.
    #[must_use]
    pub fn is_compliance_reporting_error(&self) -> bool {
        matches!(
            self,
            Self::ReportTemplateNotFound(_)
                | Self::ReportTemplateNameExists(_)
                | Self::CannotModifySystemTemplate(_)
                | Self::CannotArchiveSystemTemplate(_)
                | Self::ReportTemplateAlreadyArchived(_)
                | Self::GeneratedReportNotFound(_)
                | Self::ReportStillGenerating(_)
                | Self::ReportGenerationFailed(_)
                | Self::CannotModifyCompletedReport(_)
                | Self::ReportScheduleNotFound(_)
                | Self::ReportScheduleNameExists(_)
                | Self::ReportScheduleAlreadyPaused(_)
                | Self::ReportScheduleAlreadyActive(_)
                | Self::InvalidScheduleHour(_)
                | Self::InvalidScheduleDayOfWeek(_)
                | Self::InvalidScheduleDayOfMonth(_)
                | Self::MissingScheduleDayOfWeek
                | Self::MissingScheduleDayOfMonth
                | Self::NoRecipientsSpecified
                | Self::InvalidRecipientEmail(_)
        )
    }

    /// Returns true if this is an object lifecycle states error.
    #[must_use]
    pub fn is_lifecycle_states_error(&self) -> bool {
        matches!(
            self,
            Self::LifecycleConfigNotFound(_)
                | Self::LifecycleConfigAlreadyExists(_)
                | Self::LifecycleStateNotFound(_)
                | Self::LifecycleStateNameExists(_)
                | Self::LifecycleStateHasObjects(_, _)
                | Self::LifecycleTransitionNotFound(_)
                | Self::LifecycleTransitionNameExists(_)
                | Self::LifecycleTransitionStatePairExists(_, _)
                | Self::InvalidLifecycleTransition(_, _, _)
                | Self::InvalidTransition(_)
                | Self::TransitionConditionsNotSatisfied { .. }
                | Self::TransitionAuditNotFound(_)
                | Self::StateTransitionRequestNotFound(_)
                | Self::InvalidTransitionRequestStatus(_)
                | Self::RollbackNotAvailable(_)
                | Self::GracePeriodExpired(_)
                | Self::ScheduledTransitionNotFound(_)
                | Self::ScheduledTransitionAlreadyExists
                | Self::ScheduledTransitionAlreadyExecuted(_)
                | Self::ScheduledTimeInPast
                | Self::BulkStateOperationNotFound(_)
                | Self::BulkOperationTooLarge(_)
                | Self::BulkOperationAlreadyRunning(_)
                | Self::BulkOperationAlreadyCompleted(_)
                | Self::LifecycleObjectNotFound { .. }
                | Self::NoLifecycleConfigForObjectType(_)
                | Self::ObjectNotInExpectedState(_, _)
                | Self::InvalidGracePeriodHours(_)
                | Self::TerminalStateCannotHaveTransitions(_)
                | Self::MultipleInitialStatesNotAllowed(_)
        )
    }

    /// Returns true if this is a delegation error.
    #[must_use]
    pub fn is_delegation_error(&self) -> bool {
        matches!(
            self,
            Self::DelegationNotFound(_)
                | Self::DelegationAlreadyExists
                | Self::InvalidDelegationPeriod
                | Self::SelfDelegationNotAllowed
                | Self::DelegationNotActive(_)
                | Self::DelegationScopeViolation { .. }
                | Self::DuplicateDelegation
                | Self::InvalidDelegationPeriodDates { .. }
                | Self::DelegationPeriodTooLong { .. }
                | Self::InvalidDelegationScopeReferences(_)
                | Self::CannotExtendExpiredDelegation(_)
                | Self::CannotExtendRevokedDelegation(_)
                | Self::InvalidDelegationExtension
                | Self::NoMatchingDelegation { .. }
        )
    }

    /// Returns true if this is a micro-certification error.
    #[must_use]
    pub fn is_micro_certification_error(&self) -> bool {
        matches!(
            self,
            Self::MicroCertTriggerNotFound(_)
                | Self::MicroCertTriggerNameExists(_)
                | Self::MicroCertificationNotFound(_)
                | Self::MicroCertificationAlreadyDecided(_)
                | Self::MicroCertificationNotPending(_)
                | Self::MicroCertificationAlreadyExpired(_)
                | Self::NotAuthorizedMicroCertReviewer
                | Self::MicroCertRevocationJustificationRequired
                | Self::MicroCertEventNotFound(_)
                | Self::NoMatchingTriggerRule
                | Self::DuplicatePendingMicroCertification
                | Self::InvalidTriggerScope(_)
                | Self::MicroCertSkipReasonRequired
                | Self::CannotSkipNonPendingMicroCert(_)
                | Self::MicroCertTriggerNotActive(_)
                | Self::MicroCertReviewerNotResolved(_)
                | Self::MicroCertCannotDecide(_, _)
                | Self::MicroCertDelegationError(_)
                | Self::MicroCertSelfDelegationNotAllowed
                | Self::MicroCertDelegateRequiresDedicatedEndpoint
        )
    }

    /// Returns true if this is a role mining error.
    #[must_use]
    pub fn is_role_mining_error(&self) -> bool {
        matches!(
            self,
            Self::MiningJobNotFound(_)
                | Self::MiningJobAlreadyRunning
                | Self::MiningJobNotPending(_)
                | Self::MiningJobNotRunning(_)
                | Self::MiningJobAlreadyCompleted(_)
                | Self::CannotCancelMiningJob(_)
                | Self::InsufficientMiningData(_)
                | Self::RoleCandidateNotFound(_)
                | Self::RoleCandidateAlreadyPromoted(_)
                | Self::RoleCandidateAlreadyDismissed(_)
                | Self::RoleCandidateNotPending(_)
                | Self::ExcessivePrivilegeFlagNotFound(_)
                | Self::ExcessivePrivilegeFlagAlreadyReviewed(_)
                | Self::ConsolidationSuggestionNotFound(_)
                | Self::ConsolidationSuggestionAlreadyProcessed(_)
                | Self::RoleSimulationNotFound(_)
                | Self::RoleSimulationNotDraft(_)
                | Self::RoleSimulationNotExecuted(_)
                | Self::RoleSimulationAlreadyApplied(_)
                | Self::RoleMetricsNotFound(_)
                | Self::RoleNotFoundForMining(_)
                | Self::InvalidMiningParameters(_)
                | Self::MiningJobTimeout(_)
        )
    }

    /// Returns true if this is a meta-role error.
    #[must_use]
    pub fn is_meta_role_error(&self) -> bool {
        matches!(
            self,
            Self::MetaRoleNotFound(_)
                | Self::MetaRoleNameExists(_)
                | Self::MetaRoleCriteriaNotFound(_)
                | Self::MetaRoleEntitlementNotFound(_)
                | Self::MetaRoleEntitlementAlreadyExists
                | Self::MetaRoleConstraintNotFound(_)
                | Self::MetaRoleConstraintAlreadyExists(_)
                | Self::MetaRoleInheritanceNotFound(_)
                | Self::MetaRoleConflictNotFound(_)
                | Self::MetaRoleConflictAlreadyResolved(_)
                | Self::MetaRoleDisabled(_)
                | Self::MetaRoleAlreadyActive(_)
                | Self::MetaRoleAlreadyDisabled(_)
                | Self::MetaRoleHasActiveInheritances(_)
                | Self::InvalidMetaRoleCriteriaField(_)
                | Self::InvalidMetaRoleCriteriaValue { .. }
                | Self::InvalidMetaRoleConstraintType(_)
                | Self::InvalidMetaRolePriority(_)
                | Self::MetaRoleCircularReference
                | Self::MetaRoleCascadeFailed(_)
                | Self::MetaRoleSimulationFailed(_)
        )
    }

    /// Returns true if this is an NHI (Non-Human Identity) lifecycle error.
    #[must_use]
    pub fn is_nhi_error(&self) -> bool {
        matches!(
            self,
            Self::NhiNotFound(_)
                | Self::NhiNameExists(_)
                | Self::NhiUserAlreadyRegistered(_)
                | Self::NhiSuspended(_)
                | Self::NhiExpired(_)
                | Self::NhiInactive(_, _)
                | Self::NhiCredentialNotFound(_)
                | Self::NhiCredentialAlreadyRevoked(_)
                | Self::NhiCredentialInvalid
                | Self::NhiCredentialExpired(_)
                | Self::NhiRotationRequired(_)
                | Self::NhiRequestNotFound(_)
                | Self::NhiRequestAlreadyExists
                | Self::NhiRequestNotPending(_)
                | Self::NhiRequestExpired(_)
                | Self::CannotCancelNhiRequest
                | Self::NhiSelfApprovalNotAllowed
                | Self::NhiAlreadySuspended(_)
                | Self::NhiNotSuspended(_)
                | Self::NhiCannotReactivate { .. }
                | Self::NhiOwnerNotFound(_)
                | Self::NhiBackupOwnerSameAsPrimary
                | Self::NhiOwnershipTransferToSelf
                | Self::NhiRiskCalculationFailed(_)
                | Self::NhiCertificationNotFound
                | Self::NhiAuditEventNotFound(_)
                | Self::NhiUsageTrackingFailed(_)
                | Self::NhiInvalidRotationInterval(_)
                | Self::NhiInvalidInactivityThreshold(_)
                | Self::NhiInGracePeriod(_)
        )
    }

    /// Returns true if this is a parametric role error.
    #[must_use]
    pub fn is_parametric_role_error(&self) -> bool {
        matches!(
            self,
            Self::RoleParameterNotFound(_)
                | Self::RoleParameterNameExists(_)
                | Self::AssignmentParameterNotFound(_)
                | Self::ParametricAssignmentAlreadyExists
                | Self::RequiredParameterMissing(_)
                | Self::ParameterValidationFailed { .. }
                | Self::InvalidParameterType { .. }
                | Self::IntegerParameterOutOfRange { .. }
                | Self::StringParameterLengthInvalid { .. }
                | Self::StringParameterPatternMismatch { .. }
                | Self::EnumParameterValueNotAllowed { .. }
                | Self::DateParameterOutOfRange { .. }
                | Self::ParameterHasAssignments(_)
                | Self::InvalidParameterNameFormat(_)
                | Self::ParameterAuditEventNotFound(_)
                | Self::RoleNotParametric(_)
                | Self::InvalidTemporalValidity
                | Self::AssignmentNotTemporallyActive
                | Self::ParameterSchemaViolation(_)
        )
    }

    /// Returns true if this is an outlier detection error.
    #[must_use]
    pub fn is_outlier_detection_error(&self) -> bool {
        matches!(
            self,
            Self::OutlierConfigNotFound(_)
                | Self::OutlierAnalysisNotFound(_)
                | Self::OutlierAnalysisAlreadyRunning
                | Self::OutlierAnalysisCannotCancel(_)
                | Self::OutlierResultNotFound(_)
                | Self::OutlierDispositionNotFound(_)
                | Self::OutlierDispositionAlreadyExists
                | Self::OutlierDispositionInvalidTransition(_, _)
                | Self::OutlierAlertNotFound(_)
                | Self::OutlierAlertAlreadyDismissed(_)
                | Self::InvalidConfidenceThreshold(_)
                | Self::InvalidScoringWeight { .. }
                | Self::ScoringWeightsSumInvalid(_)
                | Self::InvalidCronExpression(_)
                | Self::NoPeerGroupsForAnalysis
        )
    }

    /// Returns true if this is a provisioning scripts error.
    #[must_use]
    pub fn is_provisioning_script_error(&self) -> bool {
        matches!(
            self,
            Self::ProvisioningScriptNotFound(_)
                | Self::ProvisioningScriptNameExists(_)
                | Self::ScriptVersionNotFound(_, _)
                | Self::ScriptHookBindingNotFound(_)
                | Self::ScriptTemplateNotFound(_)
                | Self::ScriptTemplateNameExists(_)
                | Self::CannotModifySystemScript(_)
                | Self::ScriptNotActive(_)
                | Self::ScriptAlreadyInStatus(_, _)
                | Self::ScriptHasActiveBindings(_)
                | Self::MaxBindingsExceeded(_)
                | Self::ScriptBodyTooLarge(_)
                | Self::ScriptSyntaxError(_)
                | Self::ScriptExecutionFailed(_)
                | Self::ScriptExecutionTimeout(_)
                | Self::InvalidRollbackVersion(_, _)
                | Self::BindingOrderConflict(_)
        )
    }

    /// Returns true if this is an object template error.
    #[must_use]
    pub fn is_object_template_error(&self) -> bool {
        matches!(
            self,
            Self::ObjectTemplateNotFound(_)
                | Self::ObjectTemplateNameExists(_)
                | Self::ObjectTemplateNotDraft(_)
                | Self::ObjectTemplateNotActive(_)
                | Self::ObjectTemplateAlreadyActive(_)
                | Self::ObjectTemplateAlreadyDisabled(_)
                | Self::ObjectTemplateParentNotFound(_)
                | Self::ObjectTemplateParentTypeMismatch
                | Self::ObjectTemplateCircularInheritance
                | Self::ObjectTemplateNoScopes
                | Self::ObjectTemplateHasActiveChildren(_)
                | Self::TemplateRuleNotFound(_)
                | Self::TemplateRuleCircularDependency(_)
                | Self::TemplateRuleExpressionError { .. }
                | Self::TemplateRuleEvaluationError { .. }
                | Self::TemplateRuleInvalidAttribute { .. }
                | Self::TemplateScopeNotFound(_)
                | Self::TemplateScopeInvalidOrganization(_)
                | Self::TemplateScopeConditionError(_)
                | Self::TemplateScopeInvalid(_)
                | Self::TemplateVersionNotFound(_)
                | Self::TemplateMergePolicyNotFound(_)
                | Self::TemplateMergePolicyExists(_)
                | Self::TemplateExclusionNotFound(_)
                | Self::TemplateExclusionAlreadyExists(_)
                | Self::TemplateExclusionInvalidRule(_)
                | Self::TemplateValidationFailed { .. }
                | Self::TemplateApplicationEventNotFound(_)
                | Self::TemplateEventNotFound(_)
                | Self::InvalidTemplatePriority
                | Self::InvalidTemplateRulePriority
        )
    }

    /// Returns true if this is an enhanced simulation error.
    #[must_use]
    pub fn is_simulation_error(&self) -> bool {
        matches!(
            self,
            Self::PolicySimulationNotFound(_)
                | Self::BatchSimulationNotFound(_)
                | Self::SimulationComparisonNotFound(_)
                | Self::ScopeWarningRequired { .. }
                | Self::PolicySimulationAlreadyExecuted(_)
                | Self::BatchSimulationAlreadyExecuted(_)
                | Self::BatchSimulationAlreadyApplied(_)
                | Self::SimulationStale(_)
                | Self::SimulationComparisonStale(_)
                | Self::InvalidSimulationType(_)
                | Self::SimulationTenantMismatch
                | Self::SimulationTooLarge { .. }
                | Self::SimulationPartialFailure { .. }
                | Self::UserDeletedDuringSimulation { .. }
                | Self::PolicyCascadeDetected { .. }
        )
    }

    /// Returns true if this is a role hierarchy error (F088).
    #[must_use]
    pub fn is_role_hierarchy_error(&self) -> bool {
        matches!(
            self,
            Self::GovRoleNotFound(_)
                | Self::GovRoleNameExists(_)
                | Self::GovRoleIsAbstract(_)
                | Self::GovRoleCircularReference
                | Self::GovRoleDepthExceeded(_)
                | Self::GovRoleVersionConflict
                | Self::GovRoleParentNotFound(_)
                | Self::GovRoleInheritanceBlockNotFound(_)
                | Self::GovRoleInheritanceBlockExists
                | Self::GovRoleHasChildren(_)
                | Self::GovRoleMoveExceedsDepth(_)
        )
    }

    /// Returns true if this is a Power of Attorney error (F-061).
    #[must_use]
    pub fn is_poa_error(&self) -> bool {
        matches!(
            self,
            Self::PoaNotFound(_)
                | Self::PoaSelfDelegationNotAllowed
                | Self::PoaDurationExceedsMaximum
                | Self::PoaStartDateInPast
                | Self::PoaInvalidPeriod
                | Self::PoaNotActive(_)
                | Self::PoaTerminalState(_)
                | Self::PoaAlreadyRevoked(_)
                | Self::PoaAssumedSessionNotFound(_)
                | Self::PoaNotAssuming
                | Self::PoaAlreadyAssuming
                | Self::PoaDonorNotFound(_)
                | Self::PoaAttorneyNotFound(_)
                | Self::PoaDonorNotActive(_)
                | Self::PoaAttorneyNotActive(_)
                | Self::PoaScopeViolation(_)
                | Self::PoaAuditEventNotFound(_)
                | Self::PoaExtensionExceedsMaximum
                | Self::PoaCannotExtendExpired(_)
                | Self::PoaCannotExtendRevoked(_)
                | Self::PoaInvalidExtension
        )
    }
}

/// Result type alias for governance operations.
pub type Result<T> = std::result::Result<T, GovernanceError>;
