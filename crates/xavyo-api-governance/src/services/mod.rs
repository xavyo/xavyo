//! Business logic services for governance API.

pub mod application_service;
pub mod assignment_service;
pub mod effective_access_service;
pub mod entitlement_service;
pub mod role_entitlement_service;
pub mod sod_enforcement_service;
pub mod sod_exemption_service;
pub mod sod_rule_service;
pub mod sod_violation_service;

// Access Request Workflow services (F035)
pub mod access_request_service;
pub mod approval_service;
pub mod approval_workflow_service;
pub mod delegation_service;

// Deputy & Power of Attorney services (F053)
pub mod delegation_audit_service;
pub mod delegation_lifecycle_service;

// Certification Campaign services (F036)
pub mod certification_campaign_service;
pub mod certification_item_service;
pub mod certification_remediation_service;

// Lifecycle Workflow services (F037)
pub mod birthright_policy_service;
pub mod lifecycle_event_service;

// Risk Scoring services (F039)
pub mod peer_group_service;
pub mod risk_alert_service;
pub mod risk_event_service;
pub mod risk_factor_service;
pub mod risk_score_service;
pub mod risk_threshold_service;

// Orphan Account Detection services (F040)
pub mod detection_rule_service;
pub mod orphan_detection_service;
pub mod reconciliation_service;
pub mod service_account_service;

// Compliance Reporting services (F042)
pub mod report_data_service;
pub mod report_export_service;
pub mod report_generator_service;
pub mod report_schedule_service;
pub mod report_service;
pub mod report_template_service;

// Role Mining & Analytics services (F041)
pub mod consolidation_analyzer;
pub mod metrics_service;
pub mod mining_service;
pub mod pattern_analyzer;
pub mod privilege_detector;
pub mod simulation_service;

// Object Lifecycle States services (F052)
pub mod action_executor;
pub mod archetype_lifecycle_service;
pub mod bulk_operation_service;
pub mod condition_evaluator;
pub mod failed_operation_service;
pub mod lifecycle_config_service;
pub mod scheduled_transition_service;
pub mod state_access_rule_service;
pub mod state_transition_service;

// Workflow Escalation services (F054)
pub mod approval_group_service;
pub mod escalation_policy_service;
pub mod escalation_service;

// Micro-certification services (F055)
pub mod micro_cert_trigger_service;
pub mod micro_certification_service;

// Meta-role services (F056)
pub mod meta_role_cascade_service;
pub mod meta_role_conflict_service;
pub mod meta_role_matching_service;
pub mod meta_role_service;
pub mod meta_role_simulation_service;

// Parametric role services (F057)
pub mod parameter_service;
pub mod parameter_validation_service;

// Object template services (F058)
pub mod object_template_service;
pub mod template_application_service;
pub mod template_expression_service;
pub mod template_merge_service;
pub mod template_rule_service;
pub mod template_scope_service;
pub mod template_simulation_service;

// Outlier detection services (F059)
pub mod outlier_config_service;
pub mod outlier_scoring_service;

// Enhanced Simulation services (F060)
pub mod batch_simulation_service;
pub mod policy_simulation_service;
pub mod simulation_comparison_service;

// NHI Lifecycle services (F061)
pub mod nhi_certification_service;
pub mod nhi_credential_service;
pub mod nhi_request_service;
pub mod nhi_risk_service;
pub mod nhi_service;
pub mod nhi_usage_service;

// Identity Merge services (F062)
pub mod batch_merge_service;
pub mod duplicate_detection_service;
pub mod fuzzy_matching_service;
pub mod identity_correlation_rule_service;
pub mod identity_merge_service;
pub mod merge_audit_service;

// Persona Management services (F063)
pub mod persona_archetype_service;
pub mod persona_audit_service;
pub mod persona_authorization_service;
pub mod persona_entitlement_service;
pub mod persona_expiration_service;
pub mod persona_service;
pub mod persona_session_service;
pub mod persona_validation_service;

// Power of Attorney services (F-061)
pub mod poa_service;

// Semi-manual Resources services (F064)
pub mod manual_task_service;
pub mod semi_manual_provisioning_service;
pub mod semi_manual_resource_service;
pub mod sla_monitoring_service;
pub mod sla_notification_service;
pub mod sla_policy_service;
pub mod ticket_sync_service;
pub mod ticketing;
pub mod ticketing_config_service;

pub use application_service::ApplicationService;
pub use assignment_service::AssignmentService;
pub use effective_access_service::EffectiveAccessService;
pub use entitlement_service::EntitlementService;
pub use role_entitlement_service::RoleEntitlementService;
pub use sod_enforcement_service::{SodCheckResult, SodEnforcementService, SodViolationInfo};
pub use sod_exemption_service::SodExemptionService;
pub use sod_rule_service::SodRuleService;
pub use sod_violation_service::SodViolationService;

// Access Request Workflow exports (F035)
pub use access_request_service::AccessRequestService;
pub use approval_service::{ApprovalResult, ApprovalService, PendingApprovalInfo};
pub use approval_workflow_service::{ApprovalWorkflowService, CreateStepInput, WorkflowWithSteps};
pub use delegation_service::DelegationService;

// Deputy & Power of Attorney exports (F053)
pub use delegation_audit_service::{DelegationAuditService, ListAuditParams, RecordActionParams};
pub use delegation_lifecycle_service::{DelegationLifecycleService, LifecycleProcessingResult};

// Certification Campaign exports (F036)
pub use certification_campaign_service::CertificationCampaignService;
pub use certification_item_service::CertificationItemService;
pub use certification_remediation_service::CertificationRemediationService;

// Lifecycle Workflow exports (F037)
pub use birthright_policy_service::BirthrightPolicyService;
pub use lifecycle_event_service::LifecycleEventService;

// Risk Scoring exports (F039)
pub use peer_group_service::PeerGroupService;
pub use risk_alert_service::RiskAlertService;
pub use risk_event_service::RiskEventService;
pub use risk_factor_service::RiskFactorService;
pub use risk_score_service::RiskScoreService;
pub use risk_threshold_service::RiskThresholdService;

// Orphan Account Detection exports (F040)
pub use detection_rule_service::DetectionRuleService;
pub use orphan_detection_service::OrphanDetectionService;
pub use reconciliation_service::ReconciliationService;
pub use service_account_service::ServiceAccountService;

// Compliance Reporting exports (F042)
pub use report_data_service::{ReportData, ReportDataService};
pub use report_export_service::{ExportResult, ReportExportService};
pub use report_generator_service::ReportGeneratorService;
pub use report_schedule_service::ReportScheduleService;
pub use report_service::ReportService;
pub use report_template_service::ReportTemplateService;

// Role Mining & Analytics exports (F041)
pub use consolidation_analyzer::{ConsolidationAnalyzer, ConsolidationSuggestionData, RoleData};
pub use metrics_service::MetricsService;
pub use mining_service::MiningService;
pub use pattern_analyzer::{
    AnalyzedPattern, DiscoveredCandidate, PatternAnalyzer, UserEntitlements,
};
pub use privilege_detector::{
    DetectedExcessivePrivilege, PeerAverage, PeerGroupData, PrivilegeDetector,
};
pub use simulation_service::SimulationService;

// Object Lifecycle States exports (F052)
pub use action_executor::{
    ActionBatchResult, ActionExecutionContext, ActionExecutionResult, ActionExecutor,
};
pub use archetype_lifecycle_service::{ArchetypeLifecycleService, EffectiveLifecycleModel};
pub use bulk_operation_service::BulkOperationService;
pub use failed_operation_service::{
    AuditRecordPayload, EntitlementActionPayload, FailedOperationService, RetryResult, RetryStats,
    StateUpdatePayload,
};
pub use lifecycle_config_service::LifecycleConfigService;
pub use scheduled_transition_service::ScheduledTransitionService;
pub use state_access_rule_service::{
    AffectedEntitlement, EntitlementActionResult, EntitlementSnapshot, StateAccessRuleService,
    StateAffectedEntitlements,
};
pub use state_transition_service::StateTransitionService;

// Workflow Escalation exports (F054)
pub use approval_group_service::ApprovalGroupService;
pub use escalation_policy_service::EscalationPolicyService;
pub use escalation_service::{EscalationResult, EscalationService, ResolvedEscalationTarget};

// Micro-certification exports (F055)
pub use micro_cert_trigger_service::MicroCertTriggerService;
pub use micro_certification_service::{
    BulkDecisionResult, MicroCertCreationResult, MicroCertDecisionResult, MicroCertificationService,
};

// Meta-role exports (F056)
pub use meta_role_cascade_service::{CascadeStatus, MetaRoleCascadeService};
pub use meta_role_conflict_service::{ConflictInfo, MetaRoleConflictService};
pub use meta_role_matching_service::{MatchingMetaRole, MetaRoleMatchingService, RoleMatchResult};
pub use meta_role_service::MetaRoleService;
pub use meta_role_simulation_service::{MetaRoleSimulationService, SimulationResult};

// Parametric role exports (F057)
pub use parameter_service::ParameterService;
pub use parameter_validation_service::{
    ParameterValidationResult, ParameterValidationService, SchemaViolation, SchemaViolationType,
    ValidationResult,
};

// Object template exports (F058)
pub use object_template_service::ObjectTemplateService;
pub use template_application_service::{
    ApplicationResult, TemplateApplicationService, ValidationError,
};
pub use template_expression_service::{
    BinaryOperator, Expression, ExpressionError, ExpressionResult, TemplateExpressionService, Token,
};
pub use template_merge_service::{MergeError, MergeResolution, MergeValue, TemplateMergeService};
pub use template_rule_service::TemplateRuleService;
pub use template_scope_service::TemplateScopeService;
pub use template_simulation_service::{
    RuleSimResult, SimValidationError, SimulationResult as TemplateSimulationResult,
    TemplateSimulationService,
};

// Outlier detection exports (F059)
pub use outlier_config_service::OutlierConfigService;
pub use outlier_scoring_service::{
    AlertSummary, DispositionSummary, OutlierScoringService, OutlierSummary, PeerGroupStats,
    UserAccessProfile, UserScoringResult,
};

// Enhanced Simulation exports (F060)
pub use batch_simulation_service::{BatchSimulationService, BATCH_CHUNK_SIZE};
pub use policy_simulation_service::PolicySimulationService;
pub use simulation_comparison_service::SimulationComparisonService;

// NHI Lifecycle exports (F061)
pub use nhi_certification_service::NhiCertificationService;
pub use nhi_credential_service::NhiCredentialService;
pub use nhi_request_service::{NhiRequestService, NhiRequestSummary};
pub use nhi_risk_service::{NhiRiskService, RiskFactorConfig};
pub use nhi_service::NhiService;
pub use nhi_usage_service::NhiUsageService;

// Identity Merge exports (F062)
pub use batch_merge_service::{
    BatchMergeCandidatePreview, BatchMergeItemResult, BatchMergePreview, BatchMergeService,
};
pub use duplicate_detection_service::{
    CorrelationRuleConfig, DetectionScanResult, DuplicateDetectionService, DuplicatePair,
    DuplicateStatistics,
};
// Re-export RuleMatch and RuleMatches from xavyo_db for convenience
pub use fuzzy_matching_service::{FuzzyMatchConfig, FuzzyMatchResult, FuzzyMatchingService};
pub use identity_correlation_rule_service::IdentityCorrelationRuleService;
pub use identity_merge_service::{IdentityMergeService, MergeResult};
pub use merge_audit_service::MergeAuditService;
pub use xavyo_db::models::{RuleMatch, RuleMatches};

// Persona Management exports (F063)
pub use persona_archetype_service::{
    validate_attribute_mappings, validate_lifecycle_policy, validate_naming_pattern,
    PersonaArchetypeService,
};
pub use persona_audit_service::PersonaAuditService;
pub use persona_authorization_service::{
    AuthorizationResult, PersonaAuthorizationService, PersonaPermission,
};
pub use persona_entitlement_service::{
    EntitlementComparison, PersonaContext, PersonaEntitlementResult, PersonaEntitlementService,
};
pub use persona_expiration_service::{
    BatchExpirationResult, ExpiringPersonaSummary, ExpiringPersonasReport, ExtensionResult,
    PersonaExpirationCheckResult, PersonaExpirationService,
};
pub use persona_service::{render_persona_template, PersonaService};
pub use persona_session_service::{ContextInfo, PersonaClaims, PersonaSessionService};
pub use persona_validation_service::{
    ConflictCheckResult, MultiPersonaOperationResult, PersonaValidationService,
};

// Power of Attorney exports (F-061)
pub use poa_service::PoaService;

// Semi-manual Resources exports (F064)
pub use manual_task_service::ManualTaskService;
pub use semi_manual_provisioning_service::SemiManualProvisioningService;
pub use semi_manual_resource_service::SemiManualResourceService;
pub use sla_monitoring_service::{
    SlaCheckResult, SlaComplianceSummary, SlaMonitoringService, SlaStatusLevel, TaskSlaStatus,
};
pub use sla_notification_service::{
    SlaBreachNotification, SlaNotificationConfig, SlaNotificationService, SlaWarningNotification,
};
pub use sla_policy_service::SlaPolicyService;
pub use ticket_sync_service::{
    TicketSyncResult, TicketSyncService, TicketSyncStatus, WebhookCallbackPayload,
    WebhookCallbackResult,
};
pub use ticketing::TicketingService;
pub use ticketing_config_service::{ConnectivityTestResult, TicketingConfigService};

// License Management services (F065)
pub mod license_analytics_service;
pub mod license_assignment_service;
pub mod license_audit_service;
pub mod license_entitlement_service;
pub mod license_expiration_service;
pub mod license_incompatibility_service;
pub mod license_pool_service;
pub mod license_reclamation_service;
pub mod license_report_service;

// License Management exports (F065)
pub use license_analytics_service::{LicenseAnalyticsService, PoolTrendPoint};
pub use license_assignment_service::LicenseAssignmentService;
pub use license_audit_service::{
    LicenseAuditEntry, LicenseAuditService, ListAuditParams as LicenseListAuditParams,
    RecordAssignmentEventParams, RecordBulkEventParams, RecordPoolEventParams,
};
pub use license_entitlement_service::LicenseEntitlementService;
pub use license_expiration_service::{
    ExpirationCheckResult, LicenseExpirationService, PolicyApplicationResult,
    PolicyApplicationSummary, RenewalAlertInfo, RenewalAlertResult,
};
pub use license_incompatibility_service::LicenseIncompatibilityService;
pub use license_pool_service::{CreatePoolResult, LicensePoolService, UpdatePoolResult};
pub use license_reclamation_service::{
    LicenseReclamationService, ReclaimCandidate, ReclamationExecutionResult,
};
pub use license_report_service::{
    AuditTrailEntry, AuditTrailParams, ComplianceReport, ComplianceReportFilters,
    ComplianceReportParams, LicenseReportService, PoolComplianceSummary,
};

// Provisioning Scripts services (F066)
pub mod script_analytics_service;
pub mod script_audit_service;
pub mod script_binding_service;
pub mod script_execution_service;
pub mod script_service;
pub mod script_template_service;

// Provisioning Scripts exports (F066)
pub use script_analytics_service::{
    DailyTrendData, DashboardData, ErrorSummaryData, ScriptAnalyticsData, ScriptAnalyticsService,
    ScriptSummaryData,
};
pub use script_audit_service::{
    ListScriptAuditParams, RecordScriptAuditParams, ScriptAuditService,
};
pub use script_binding_service::ScriptBindingService;
pub use script_execution_service::{
    DryRunExecutionResult, ScriptExecutionService, ValidationResult as ScriptValidationResult,
};
pub use script_service::ScriptService;
pub use script_template_service::ScriptTemplateService;

// Correlation Engine services (F067)
pub mod correlation_audit_service;
pub mod correlation_case_service;
pub mod correlation_engine_service;
pub mod correlation_rule_service;
pub mod correlation_stats_service;
pub mod correlation_threshold_service;

// Correlation Engine exports (F067)
pub use correlation_audit_service::{
    build_audit_filter, parse_event_type, parse_outcome, CorrelationAuditService,
};
pub use correlation_case_service::{CorrelationCaseListResponse, CorrelationCaseService};
pub use correlation_engine_service::{
    CorrelationEngineService, CorrelationJobStatus, CorrelationOutcome, EvaluationResult,
};
pub use correlation_rule_service::CorrelationRuleService;
pub use correlation_stats_service::CorrelationStatsService;
pub use correlation_threshold_service::CorrelationThresholdService;

// SIEM Integration services (F078)
pub mod siem_batch_export_service;
pub mod siem_destination_service;
pub mod siem_health_service;

// SIEM Integration exports (F078)
pub use siem_batch_export_service::SiemBatchExportService;
pub use siem_destination_service::SiemDestinationService;
pub use siem_health_service::{HealthSummaryData, SiemHealthService};

// Business Role Hierarchy services (F088)
pub mod role_hierarchy_service;

// Business Role Hierarchy exports (F088)
pub use role_hierarchy_service::RoleHierarchyService;

// Self-Service Request Catalog services (F-062)
pub mod catalog_service;

// Role Inducements & Constructions services (F-063)
pub mod inducement_trigger_service;
pub mod role_assignment_service;
pub mod role_construction_service;
pub mod role_inducement_service;

// Self-Service Request Catalog exports (F-062)
pub use catalog_service::{
    CartSodViolation, CartSubmissionResult, CartValidationIssue, CartValidationResult,
    CatalogService, RequestContext, RequestabilityResult, SubmittedItemResult,
};

// Role Inducements & Constructions exports (F-063)
pub use inducement_trigger_service::InducementTriggerService;
pub use role_assignment_service::{
    RoleAssignmentResult, RoleAssignmentService, RoleRevocationResult,
};
pub use role_construction_service::RoleConstructionService;
pub use role_inducement_service::RoleInducementService;

// Bulk Action Engine services (F-064 Bulk Actions)
pub mod action_executors;
pub mod bulk_action_service;

// Bulk Action Engine exports (F-064 Bulk Actions)
pub use action_executors::{
    ActionExecutor as BulkActionExecutor, AssignRoleExecutor, DisableUserExecutor,
    EnableUserExecutor, ExecutionContext as BulkExecutionContext,
    ExecutionResult as BulkExecutionResult, ModifyAttributeExecutor, RevokeRoleExecutor,
};
pub use bulk_action_service::BulkActionService;

// GDPR Report services (F-067 Data Protection)
pub mod gdpr_report_service;

// GDPR Report exports (F-067 Data Protection)
pub use gdpr_report_service::GdprReportService;
