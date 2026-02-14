//! Router configuration for governance API.

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::handlers::{
    // Access Request Workflow handlers (F035)
    access_requests,
    // Lifecycle Workflow handlers (F037)
    access_snapshots,
    applications,
    // Workflow Escalation handlers (F054)
    approval_groups,
    approval_workflows,
    approvals,
    // Identity Archetype handlers (F-058)
    archetypes,
    assignments,
    // Enhanced Simulation handlers (F060)
    batch_simulations,
    birthright_policies,
    // Bulk Action Engine handlers (F-064 Bulk Actions)
    bulk_actions,
    // Object Lifecycle States handlers (F052)
    bulk_state_operation,
    // Self-Service Request Catalog handlers (F-062)
    catalog,
    // Certification Campaign handlers (F036)
    certification_campaigns,
    certification_items,
    // Correlation Engine handlers (F067)
    correlation_audit,
    correlation_cases,
    correlation_engine,
    correlation_rules,
    correlation_stats,
    correlation_thresholds,
    delegations,
    // Orphan Account Detection handlers (F040)
    detection_rules,
    effective_access,
    entitlements,
    escalation_events,
    escalation_policies,
    failed_operations,
    // Identity Merge handlers (F062)
    identity_correlation_rules,
    identity_merge,
    // License Management handlers (F065)
    license_analytics,
    license_assignments,
    license_entitlement_links,
    license_incompatibilities,
    license_pools,
    license_reclamation,
    license_reports,
    lifecycle_actions,
    lifecycle_config,
    lifecycle_events,
    // Semi-manual Resources handlers (F064)
    manual_tasks,
    // Meta-role handlers (F056)
    meta_roles,
    // Micro-certification handlers (F055)
    micro_cert_triggers,
    micro_certifications,
    // NHI Lifecycle handlers (F061)
    nhis,
    // Object template handlers (F058)
    object_templates,
    orphan_detections,
    // Outlier detection handlers (F059)
    outliers,
    owners,
    // Parametric role handlers (F057)
    parametric_roles,
    // Risk Scoring handlers (F039)
    peer_groups,
    // Persona Management handlers (F063)
    personas,
    policy_simulations,
    // Power of Attorney handlers (F-061)
    power_of_attorney,
    // Provisioning Scripts handlers (F066)
    provisioning_scripts,
    reconciliation_runs,
    // Compliance Reporting handlers (F042)
    report_schedules,
    report_templates,
    reports,
    risk_alerts,
    risk_events,
    risk_factors,
    risk_scores,
    risk_thresholds,
    // Role Inducements & Constructions handlers (F-063)
    role_assignments,
    role_constructions,
    // Business Role Hierarchy handlers (F088)
    role_entitlements,
    role_hierarchy,
    role_inducements,
    role_inheritance_blocks,
    role_mappings,
    // Role Mining & Analytics handlers (F041)
    role_mining,
    scheduled_transition,
    script_analytics,
    script_hook_bindings,
    script_templates,
    script_testing,
    semi_manual,
    service_accounts,
    // SIEM Integration handlers (F078)
    siem,
    simulation_comparisons,
    sla_policies,
    sod_exemptions,
    sod_rules,
    sod_violations,
    state_transition,
    ticketing_config,
    ticketing_webhook,
};
use crate::services::{
    // Access Request Workflow services (F035)
    AccessRequestService,
    ApplicationService,
    // Workflow Escalation services (F054)
    ApprovalGroupService,
    ApprovalService,
    ApprovalWorkflowService,
    AssignmentService,
    // Identity Merge services (F062)
    BatchMergeService,
    // Enhanced Simulation services (F060)
    BatchSimulationService,
    // Lifecycle Workflow services (F037)
    BirthrightPolicyService,
    // Bulk Action Engine services (F-064 Bulk Actions)
    BulkActionService,
    // Object Lifecycle States services (F052)
    BulkOperationService,
    // Self-Service Request Catalog services (F-062)
    CatalogService,
    // Certification Campaign services (F036)
    CertificationCampaignService,
    CertificationItemService,
    // Correlation Engine services (F067)
    CorrelationAuditService,
    CorrelationCaseService,
    CorrelationEngineService,
    CorrelationRuleService,
    CorrelationStatsService,
    CorrelationThresholdService,
    // Deputy & Power of Attorney services (F053)
    DelegationAuditService,
    DelegationLifecycleService,
    DelegationService,
    // Orphan Account Detection services (F040)
    DetectionRuleService,
    DuplicateDetectionService,
    EffectiveAccessService,
    EntitlementService,
    EscalationPolicyService,
    EscalationService,
    FailedOperationService,
    // GDPR Report services (F-067)
    GdprReportService,
    IdentityCorrelationRuleService,
    IdentityMergeService,
    // Role Inducements & Constructions services (F-063)
    InducementTriggerService,
    // License Management services (F065)
    LicenseAnalyticsService,
    LicenseAssignmentService,
    LicenseEntitlementService,
    LicenseExpirationService,
    LicenseIncompatibilityService,
    LicensePoolService,
    LicenseReclamationService,
    LicenseReportService,
    LifecycleConfigService,
    LifecycleEventService,
    // Semi-manual Resources services (F064)
    ManualTaskService,
    MergeAuditService,
    // Meta-role services (F056)
    MetaRoleCascadeService,
    MetaRoleConflictService,
    MetaRoleMatchingService,
    MetaRoleService,
    MetaRoleSimulationService,
    // Role Mining & Analytics services (F041)
    MetricsService,
    // Micro-certification services (F055)
    MicroCertTriggerService,
    MicroCertificationService,
    MiningService,
    // NHI Lifecycle services (F061)
    NhiCertificationService,
    NhiCredentialService,
    NhiRequestService,
    NhiRiskService,
    NhiService,
    NhiUsageService,
    // Object template services (F058)
    ObjectTemplateService,
    OrphanDetectionService,
    // Outlier detection services (F059)
    OutlierConfigService,
    OutlierScoringService,
    // Parametric role services (F057)
    ParameterService,
    // Risk Scoring services (F039)
    PeerGroupService,
    // Persona Management services (F063)
    PersonaArchetypeService,
    PersonaAuditService,
    PersonaEntitlementService,
    PersonaExpirationService,
    PersonaService,
    PersonaSessionService,
    // Power of Attorney services (F-061)
    PoaService,
    PolicySimulationService,
    ReconciliationService,
    // Compliance Reporting services (F042)
    ReportGeneratorService,
    ReportScheduleService,
    ReportService,
    ReportTemplateService,
    RiskAlertService,
    RiskEventService,
    RiskFactorService,
    RiskScoreService,
    RiskThresholdService,
    RoleAssignmentService,
    RoleConstructionService,
    RoleEntitlementService,
    // Business Role Hierarchy services (F088)
    RoleHierarchyService,
    RoleInducementService,
    ScheduledTransitionService,
    // Provisioning Scripts services (F066)
    ScriptAnalyticsService,
    ScriptAuditService,
    ScriptBindingService,
    ScriptExecutionService,
    ScriptService,
    ScriptTemplateService,
    SemiManualResourceService,
    ServiceAccountService,
    // SIEM Integration services (F078)
    SiemBatchExportService,
    SiemDestinationService,
    SiemHealthService,
    SimulationComparisonService,
    SimulationService,
    SlaMonitoringService,
    SlaPolicyService,
    SodEnforcementService,
    SodExemptionService,
    SodRuleService,
    SodViolationService,
    StateAccessRuleService,
    StateTransitionService,
    TemplateApplicationService,
    TemplateMergeService,
    TemplateRuleService,
    TemplateScopeService,
    TemplateSimulationService,
    TicketSyncService,
    TicketingConfigService,
};

/// Shared state for governance API.
#[derive(Clone)]
pub struct GovernanceState {
    pub(crate) pool: PgPool,
    pub application_service: Arc<ApplicationService>,
    pub entitlement_service: Arc<EntitlementService>,
    pub assignment_service: Arc<AssignmentService>,
    pub role_entitlement_service: Arc<RoleEntitlementService>,
    pub effective_access_service: Arc<EffectiveAccessService>,
    pub sod_rule_service: Arc<SodRuleService>,
    pub sod_enforcement_service: Arc<SodEnforcementService>,
    pub sod_violation_service: Arc<SodViolationService>,
    pub sod_exemption_service: Arc<SodExemptionService>,
    // Access Request Workflow services (F035)
    pub access_request_service: Arc<AccessRequestService>,
    pub approval_service: Arc<ApprovalService>,
    pub approval_workflow_service: Arc<ApprovalWorkflowService>,
    pub delegation_service: Arc<DelegationService>,
    // Deputy & Power of Attorney services (F053)
    pub delegation_audit_service: Arc<DelegationAuditService>,
    pub delegation_lifecycle_service: Arc<DelegationLifecycleService>,
    // Certification Campaign services (F036)
    pub certification_campaign_service: Arc<CertificationCampaignService>,
    pub certification_item_service: Arc<CertificationItemService>,
    // Lifecycle Workflow services (F037)
    pub birthright_policy_service: Arc<BirthrightPolicyService>,
    pub lifecycle_event_service: Arc<LifecycleEventService>,
    // Risk Scoring services (F039)
    pub peer_group_service: Arc<PeerGroupService>,
    pub risk_alert_service: Arc<RiskAlertService>,
    pub risk_event_service: Arc<RiskEventService>,
    pub risk_factor_service: Arc<RiskFactorService>,
    pub risk_score_service: Arc<RiskScoreService>,
    pub risk_threshold_service: Arc<RiskThresholdService>,
    // Orphan Account Detection services (F040)
    pub detection_rule_service: Arc<DetectionRuleService>,
    pub orphan_detection_service: Arc<OrphanDetectionService>,
    pub reconciliation_service: Arc<ReconciliationService>,
    pub service_account_service: Arc<ServiceAccountService>,
    // Compliance Reporting services (F042)
    pub report_template_service: Arc<ReportTemplateService>,
    pub report_service: Arc<ReportService>,
    pub report_schedule_service: Arc<ReportScheduleService>,
    pub report_generator_service: Arc<ReportGeneratorService>,
    // Role Mining & Analytics services (F041)
    pub mining_service: Arc<MiningService>,
    pub simulation_service: Arc<SimulationService>,
    pub metrics_service: Arc<MetricsService>,
    // Object Lifecycle States services (F052)
    pub lifecycle_config_service: Arc<LifecycleConfigService>,
    pub state_access_rule_service: Arc<StateAccessRuleService>,
    pub state_transition_service: Arc<StateTransitionService>,
    pub scheduled_transition_service: Arc<ScheduledTransitionService>,
    pub bulk_operation_service: Arc<BulkOperationService>,
    pub failed_operation_service: Option<Arc<FailedOperationService>>,
    // Workflow Escalation services (F054)
    pub escalation_policy_service: Arc<EscalationPolicyService>,
    pub escalation_service: Arc<EscalationService>,
    pub approval_group_service: Arc<ApprovalGroupService>,
    // Micro-certification services (F055)
    pub micro_certification_service: Arc<MicroCertificationService>,
    pub micro_cert_trigger_service: Arc<MicroCertTriggerService>,
    // Meta-role services (F056)
    pub meta_role_service: Arc<MetaRoleService>,
    pub meta_role_matching_service: Arc<MetaRoleMatchingService>,
    pub meta_role_cascade_service: Arc<MetaRoleCascadeService>,
    pub meta_role_conflict_service: Arc<MetaRoleConflictService>,
    pub meta_role_simulation_service: Arc<MetaRoleSimulationService>,
    // Parametric role services (F057)
    pub parameter_service: Arc<ParameterService>,
    // Object template services (F058)
    pub object_template_service: Arc<ObjectTemplateService>,
    pub template_rule_service: Arc<TemplateRuleService>,
    pub template_scope_service: Arc<TemplateScopeService>,
    pub template_application_service: Arc<TemplateApplicationService>,
    pub template_merge_service: Arc<TemplateMergeService>,
    pub template_simulation_service: Arc<TemplateSimulationService>,
    // Outlier detection services (F059)
    pub outlier_config_service: Arc<OutlierConfigService>,
    pub outlier_scoring_service: Arc<OutlierScoringService>,
    // Enhanced Simulation services (F060)
    pub policy_simulation_service: Arc<PolicySimulationService>,
    pub batch_simulation_service: Arc<BatchSimulationService>,
    pub simulation_comparison_service: Arc<SimulationComparisonService>,
    // NHI Lifecycle services (F061)
    pub nhi_service: Arc<NhiService>,
    pub nhi_credential_service: Arc<NhiCredentialService>,
    pub nhi_usage_service: Arc<NhiUsageService>,
    pub nhi_risk_service: Arc<NhiRiskService>,
    pub nhi_certification_service: Arc<NhiCertificationService>,
    pub nhi_request_service: Arc<NhiRequestService>,
    // Identity Merge services (F062)
    pub batch_merge_service: Arc<BatchMergeService>,
    pub duplicate_detection_service: Arc<DuplicateDetectionService>,
    pub identity_correlation_rule_service: Arc<IdentityCorrelationRuleService>,
    pub identity_merge_service: Arc<IdentityMergeService>,
    pub merge_audit_service: Arc<MergeAuditService>,
    // Persona Management services (F063)
    pub persona_archetype_service: Arc<PersonaArchetypeService>,
    pub persona_service: Arc<PersonaService>,
    pub persona_audit_service: Arc<PersonaAuditService>,
    pub persona_session_service: Arc<PersonaSessionService>,
    pub persona_entitlement_service: Arc<PersonaEntitlementService>,
    pub persona_expiration_service: Arc<PersonaExpirationService>,
    // Power of Attorney services (F-061)
    pub poa_service: Arc<PoaService>,
    // Semi-manual Resources services (F064)
    pub manual_task_service: Arc<ManualTaskService>,
    pub semi_manual_resource_service: Arc<SemiManualResourceService>,
    pub sla_policy_service: Arc<SlaPolicyService>,
    pub sla_monitoring_service: Arc<SlaMonitoringService>,
    pub ticketing_config_service: Arc<TicketingConfigService>,
    pub ticket_sync_service: Arc<TicketSyncService>,
    // License Management services (F065)
    pub license_pool_service: Arc<LicensePoolService>,
    pub license_assignment_service: Arc<LicenseAssignmentService>,
    pub license_entitlement_service: Arc<LicenseEntitlementService>,
    pub license_incompatibility_service: Arc<LicenseIncompatibilityService>,
    pub license_reclamation_service: Arc<LicenseReclamationService>,
    pub license_analytics_service: Arc<LicenseAnalyticsService>,
    pub license_report_service: Arc<LicenseReportService>,
    pub license_expiration_service: Arc<LicenseExpirationService>,
    // Provisioning Scripts services (F066)
    pub script_service: Arc<ScriptService>,
    pub script_binding_service: Arc<ScriptBindingService>,
    pub script_template_service: Arc<ScriptTemplateService>,
    pub script_execution_service: Arc<ScriptExecutionService>,
    pub script_analytics_service: Arc<ScriptAnalyticsService>,
    pub script_audit_service: Arc<ScriptAuditService>,
    // Correlation Engine services (F067)
    pub correlation_audit_service: Arc<CorrelationAuditService>,
    pub correlation_case_service: Arc<CorrelationCaseService>,
    pub correlation_engine_service: Arc<CorrelationEngineService>,
    pub correlation_rule_service: Arc<CorrelationRuleService>,
    pub correlation_stats_service: Arc<CorrelationStatsService>,
    pub correlation_threshold_service: Arc<CorrelationThresholdService>,
    // SIEM Integration services (F078)
    pub siem_destination_service: Arc<SiemDestinationService>,
    pub siem_batch_export_service: Arc<SiemBatchExportService>,
    pub siem_health_service: Arc<SiemHealthService>,
    siem_encryption_key: [u8; 32],
    // Business Role Hierarchy services (F088)
    pub role_hierarchy_service: Arc<RoleHierarchyService>,
    // Self-Service Request Catalog services (F-062)
    pub catalog_service: Arc<CatalogService>,
    // Role Inducements & Constructions services (F-063)
    pub role_construction_service: Arc<RoleConstructionService>,
    pub role_inducement_service: Arc<RoleInducementService>,
    pub inducement_trigger_service: Arc<InducementTriggerService>,
    pub role_assignment_service: Arc<RoleAssignmentService>,
    // Bulk Action Engine services (F-064 Bulk Actions)
    pub bulk_action_service: Arc<BulkActionService>,
    // GDPR Report services (F-067)
    pub gdpr_report_service: Arc<GdprReportService>,
}

impl GovernanceState {
    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the SIEM encryption key for `auth_config` encryption.
    #[must_use]
    pub fn siem_encryption_key(&self) -> &[u8] {
        &self.siem_encryption_key
    }

    /// Load the SIEM encryption key from the environment.
    ///
    /// SECURITY: This function requires the `XAVYO_SIEM_ENCRYPTION_KEY` environment
    /// variable to be set. There is no fallback to a hardcoded key to prevent
    /// accidental use of weak encryption in production.
    ///
    /// To generate a key: `openssl rand -base64 32`
    fn load_siem_encryption_key() -> Result<[u8; 32], String> {
        use base64::Engine;
        let key_b64 = std::env::var("XAVYO_SIEM_ENCRYPTION_KEY").map_err(|_| {
            "XAVYO_SIEM_ENCRYPTION_KEY environment variable not set. \
             Generate a key with: openssl rand -base64 32"
                .to_string()
        })?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .map_err(|e| format!("XAVYO_SIEM_ENCRYPTION_KEY must be valid base64: {e}"))?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "XAVYO_SIEM_ENCRYPTION_KEY must decode to 32 bytes, got {}",
                key_bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Create a new governance state with all services.
    ///
    /// # Errors
    ///
    /// Returns an error if the SIEM encryption key environment variable is not set or invalid.
    pub fn new(pool: PgPool) -> Result<Self, String> {
        let sod_enforcement_service = Arc::new(SodEnforcementService::new(pool.clone()));
        let matching_service = Arc::new(MetaRoleMatchingService::new(pool.clone()));
        // NHI services need to be created first as NhiRequestService depends on them
        let nhi_service = Arc::new(NhiService::new(pool.clone()));
        let nhi_credential_service = Arc::new(NhiCredentialService::new(pool.clone()));

        // Identity Merge service needs to be created first as BatchMergeService depends on it
        let identity_merge_service = Arc::new(IdentityMergeService::new(pool.clone()));

        Ok(Self {
            pool: pool.clone(),
            application_service: Arc::new(ApplicationService::new(pool.clone())),
            entitlement_service: Arc::new(EntitlementService::new(pool.clone())),
            assignment_service: Arc::new(AssignmentService::new(pool.clone())),
            role_entitlement_service: Arc::new(RoleEntitlementService::new(pool.clone())),
            effective_access_service: Arc::new(EffectiveAccessService::new(pool.clone())),
            sod_rule_service: Arc::new(SodRuleService::new(pool.clone())),
            sod_enforcement_service: sod_enforcement_service.clone(),
            sod_violation_service: Arc::new(SodViolationService::new(pool.clone())),
            sod_exemption_service: Arc::new(SodExemptionService::new(pool.clone())),
            // Access Request Workflow services (F035)
            access_request_service: Arc::new(AccessRequestService::new(pool.clone())),
            approval_service: Arc::new(ApprovalService::new(pool.clone())),
            approval_workflow_service: Arc::new(ApprovalWorkflowService::new(pool.clone())),
            delegation_service: Arc::new(DelegationService::new(pool.clone())),
            // Deputy & Power of Attorney services (F053)
            delegation_audit_service: Arc::new(DelegationAuditService::new(pool.clone())),
            delegation_lifecycle_service: Arc::new(DelegationLifecycleService::new(pool.clone())),
            // Certification Campaign services (F036)
            certification_campaign_service: Arc::new(CertificationCampaignService::new(
                pool.clone(),
            )),
            certification_item_service: Arc::new(CertificationItemService::new(pool.clone())),
            // Lifecycle Workflow services (F037)
            birthright_policy_service: Arc::new(BirthrightPolicyService::new(pool.clone())),
            lifecycle_event_service: Arc::new(LifecycleEventService::new(
                pool.clone(),
                Arc::new(BirthrightPolicyService::new(pool.clone())),
                Arc::new(AssignmentService::new(pool.clone())),
            )),
            // Risk Scoring services (F039)
            peer_group_service: Arc::new(PeerGroupService::new(pool.clone())),
            risk_alert_service: Arc::new(RiskAlertService::new(pool.clone())),
            risk_event_service: Arc::new(RiskEventService::new(pool.clone())),
            risk_factor_service: Arc::new(RiskFactorService::new(pool.clone())),
            risk_score_service: Arc::new(RiskScoreService::new(pool.clone())),
            risk_threshold_service: Arc::new(RiskThresholdService::new(pool.clone())),
            // Orphan Account Detection services (F040)
            detection_rule_service: Arc::new(DetectionRuleService::new(pool.clone())),
            orphan_detection_service: Arc::new(OrphanDetectionService::new(pool.clone())),
            reconciliation_service: Arc::new(ReconciliationService::new(pool.clone())),
            service_account_service: Arc::new(ServiceAccountService::new(pool.clone())),
            // Compliance Reporting services (F042)
            report_template_service: Arc::new(ReportTemplateService::new(pool.clone())),
            report_service: Arc::new(ReportService::new(pool.clone())),
            report_schedule_service: Arc::new(ReportScheduleService::new(pool.clone())),
            report_generator_service: Arc::new(ReportGeneratorService::new(pool.clone())),
            // Role Mining & Analytics services (F041)
            mining_service: Arc::new(MiningService::new(pool.clone())),
            simulation_service: Arc::new(SimulationService::new(pool.clone())),
            metrics_service: Arc::new(MetricsService::new(pool.clone())),
            // Object Lifecycle States services (F052)
            lifecycle_config_service: Arc::new(LifecycleConfigService::new(pool.clone())),
            state_access_rule_service: Arc::new(StateAccessRuleService::new(pool.clone())),
            state_transition_service: {
                let access_rule_service = Arc::new(StateAccessRuleService::new(pool.clone()));
                let failed_op_service = Arc::new(FailedOperationService::new(
                    pool.clone(),
                    access_rule_service.clone(),
                ));
                Arc::new(StateTransitionService::with_retry_support(
                    pool.clone(),
                    access_rule_service,
                    failed_op_service,
                ))
            },
            scheduled_transition_service: Arc::new(ScheduledTransitionService::new(pool.clone())),
            bulk_operation_service: {
                let access_rule_service = Arc::new(StateAccessRuleService::new(pool.clone()));
                let failed_op_service = Arc::new(FailedOperationService::new(
                    pool.clone(),
                    access_rule_service.clone(),
                ));
                let transition_service = Arc::new(StateTransitionService::with_retry_support(
                    pool.clone(),
                    access_rule_service,
                    failed_op_service,
                ));
                Arc::new(BulkOperationService::new(pool.clone(), transition_service))
            },
            failed_operation_service: {
                let access_rule_service = Arc::new(StateAccessRuleService::new(pool.clone()));
                Some(Arc::new(FailedOperationService::new(
                    pool.clone(),
                    access_rule_service,
                )))
            },
            // Workflow Escalation services (F054)
            escalation_policy_service: Arc::new(EscalationPolicyService::new(pool.clone())),
            escalation_service: Arc::new(EscalationService::new(pool.clone())),
            approval_group_service: Arc::new(ApprovalGroupService::new(pool.clone())),
            // Micro-certification services (F055)
            micro_certification_service: Arc::new(MicroCertificationService::new(pool.clone())),
            micro_cert_trigger_service: Arc::new(MicroCertTriggerService::new(pool.clone())),
            // Meta-role services (F056)
            meta_role_service: Arc::new(MetaRoleService::new(pool.clone())),
            meta_role_matching_service: matching_service.clone(),
            meta_role_cascade_service: Arc::new(MetaRoleCascadeService::new(pool.clone())),
            meta_role_conflict_service: Arc::new(MetaRoleConflictService::new(pool.clone())),
            meta_role_simulation_service: Arc::new(MetaRoleSimulationService::new(
                Arc::new(pool.clone()),
                matching_service,
            )),
            // Parametric role services (F057)
            parameter_service: Arc::new(ParameterService::new(pool.clone())),
            // Object template services (F058)
            object_template_service: Arc::new(ObjectTemplateService::new(pool.clone())),
            template_rule_service: Arc::new(TemplateRuleService::new(pool.clone())),
            template_scope_service: Arc::new(TemplateScopeService::new(pool.clone())),
            template_application_service: Arc::new(TemplateApplicationService::new(pool.clone())),
            template_merge_service: Arc::new(TemplateMergeService::new(pool.clone())),
            template_simulation_service: Arc::new(TemplateSimulationService::new(pool.clone())),
            // Outlier detection services (F059)
            outlier_config_service: Arc::new(OutlierConfigService::new(pool.clone())),
            outlier_scoring_service: Arc::new(OutlierScoringService::new(pool.clone())),
            // Enhanced Simulation services (F060)
            policy_simulation_service: Arc::new(PolicySimulationService::new(pool.clone())),
            batch_simulation_service: Arc::new(BatchSimulationService::new(pool.clone())),
            simulation_comparison_service: Arc::new(SimulationComparisonService::new(pool.clone())),
            // NHI Lifecycle services (F061)
            nhi_service: nhi_service.clone(),
            nhi_credential_service: nhi_credential_service.clone(),
            nhi_usage_service: Arc::new(NhiUsageService::new(pool.clone())),
            nhi_risk_service: Arc::new(NhiRiskService::new(pool.clone())),
            nhi_certification_service: Arc::new(NhiCertificationService::new(pool.clone())),
            nhi_request_service: Arc::new(NhiRequestService::new(
                pool.clone(),
                nhi_service,
                nhi_credential_service,
            )),
            // Identity Merge services (F062)
            duplicate_detection_service: Arc::new(DuplicateDetectionService::new(pool.clone())),
            identity_correlation_rule_service: Arc::new(IdentityCorrelationRuleService::new(
                pool.clone(),
            )),
            identity_merge_service: identity_merge_service.clone(),
            batch_merge_service: Arc::new(BatchMergeService::new(
                pool.clone(),
                identity_merge_service,
            )),
            merge_audit_service: Arc::new(MergeAuditService::new(pool.clone())),
            // Persona Management services (F063)
            persona_archetype_service: Arc::new(PersonaArchetypeService::new(pool.clone())),
            persona_service: Arc::new(PersonaService::new(pool.clone())),
            persona_audit_service: Arc::new(PersonaAuditService::new(pool.clone())),
            persona_session_service: Arc::new(PersonaSessionService::new(pool.clone())),
            persona_entitlement_service: Arc::new(PersonaEntitlementService::new(pool.clone())),
            persona_expiration_service: Arc::new(PersonaExpirationService::new(pool.clone())),
            // Power of Attorney services (F-061)
            poa_service: Arc::new(PoaService::new(pool.clone())),
            // Semi-manual Resources services (F064)
            manual_task_service: Arc::new(ManualTaskService::new(pool.clone())),
            semi_manual_resource_service: Arc::new(SemiManualResourceService::new(pool.clone())),
            sla_policy_service: Arc::new(SlaPolicyService::new(pool.clone())),
            sla_monitoring_service: Arc::new(SlaMonitoringService::new(pool.clone())),
            ticketing_config_service: Arc::new(TicketingConfigService::new(pool.clone())),
            ticket_sync_service: Arc::new(TicketSyncService::new(pool.clone())),
            // License Management services (F065)
            license_pool_service: Arc::new(LicensePoolService::new(pool.clone())),
            license_assignment_service: Arc::new(LicenseAssignmentService::new(pool.clone())),
            license_entitlement_service: Arc::new(LicenseEntitlementService::new(pool.clone())),
            license_incompatibility_service: Arc::new(LicenseIncompatibilityService::new(
                pool.clone(),
            )),
            license_reclamation_service: Arc::new(LicenseReclamationService::new(pool.clone())),
            license_analytics_service: Arc::new(LicenseAnalyticsService::new(pool.clone())),
            license_report_service: Arc::new(LicenseReportService::new(pool.clone())),
            license_expiration_service: Arc::new(LicenseExpirationService::new(pool.clone())),
            // Provisioning Scripts services (F066)
            script_service: Arc::new(ScriptService::new(pool.clone())),
            script_binding_service: Arc::new(ScriptBindingService::new(pool.clone())),
            script_template_service: Arc::new(ScriptTemplateService::new(pool.clone())),
            script_execution_service: Arc::new(ScriptExecutionService::new(pool.clone())),
            script_analytics_service: Arc::new(ScriptAnalyticsService::new(pool.clone())),
            script_audit_service: Arc::new(ScriptAuditService::new(pool.clone())),
            // Correlation Engine services (F067)
            correlation_audit_service: Arc::new(CorrelationAuditService::new(pool.clone())),
            correlation_case_service: Arc::new(CorrelationCaseService::new(pool.clone())),
            correlation_engine_service: Arc::new(CorrelationEngineService::new(pool.clone())),
            correlation_rule_service: Arc::new(CorrelationRuleService::new(pool.clone())),
            correlation_stats_service: Arc::new(CorrelationStatsService::new(pool.clone())),
            correlation_threshold_service: Arc::new(CorrelationThresholdService::new(pool.clone())),
            // SIEM Integration services (F078)
            siem_destination_service: Arc::new(SiemDestinationService::new(pool.clone())),
            siem_batch_export_service: Arc::new(SiemBatchExportService::new(pool.clone())),
            siem_health_service: Arc::new(SiemHealthService::new(pool.clone())),
            siem_encryption_key: Self::load_siem_encryption_key()?,
            // Business Role Hierarchy services (F088)
            role_hierarchy_service: Arc::new(RoleHierarchyService::new(pool.clone())),
            // Self-Service Request Catalog services (F-062)
            catalog_service: Arc::new(CatalogService::new(pool.clone())),
            // Role Inducements & Constructions services (F-063)
            role_construction_service: Arc::new(RoleConstructionService::new(pool.clone())),
            role_inducement_service: Arc::new(RoleInducementService::new(pool.clone())),
            inducement_trigger_service: Arc::new(InducementTriggerService::new(pool.clone())),
            role_assignment_service: Arc::new(RoleAssignmentService::new(pool.clone())),
            // Bulk Action Engine services (F-064 Bulk Actions)
            bulk_action_service: Arc::new(BulkActionService::new(pool.clone())),
            // GDPR Report services (F-067)
            gdpr_report_service: Arc::new(GdprReportService::new(pool)),
        })
    }
}

/// Create the governance API router.
///
/// All routes are prefixed with `/governance` and require authentication.
pub fn governance_router(pool: PgPool) -> Router {
    let state = GovernanceState::new(pool)
        .expect("Failed to initialize GovernanceState (check XAVYO_SIEM_ENCRYPTION_KEY)");

    Router::new()
        // Applications
        .route("/applications", get(applications::list_applications))
        .route("/applications", post(applications::create_application))
        .route("/applications/:id", get(applications::get_application))
        .route("/applications/:id", put(applications::update_application))
        .route(
            "/applications/:id",
            delete(applications::delete_application),
        )
        // Entitlements
        .route("/entitlements", get(entitlements::list_entitlements))
        .route("/entitlements", post(entitlements::create_entitlement))
        .route("/entitlements/:id", get(entitlements::get_entitlement))
        .route("/entitlements/:id", put(entitlements::update_entitlement))
        .route(
            "/entitlements/:id",
            delete(entitlements::delete_entitlement),
        )
        // Entitlement Owners
        .route("/entitlements/:id/owner", put(owners::set_owner))
        .route("/entitlements/:id/owner", delete(owners::remove_owner))
        // GDPR Data Protection (F-067)
        .route("/gdpr/report", get(entitlements::gdpr_report))
        .route(
            "/gdpr/users/:user_id/data-protection",
            get(entitlements::user_data_protection),
        )
        // Assignments
        .route("/assignments", get(assignments::list_assignments))
        .route("/assignments", post(assignments::create_assignment))
        .route(
            "/assignments/bulk",
            post(assignments::bulk_create_assignments),
        )
        .route("/assignments/:id", get(assignments::get_assignment))
        .route("/assignments/:id", delete(assignments::revoke_assignment))
        // Role Entitlements
        .route(
            "/role-entitlements",
            get(role_mappings::list_role_entitlements),
        )
        .route(
            "/role-entitlements",
            post(role_mappings::create_role_entitlement),
        )
        .route(
            "/role-entitlements/:id",
            delete(role_mappings::delete_role_entitlement),
        )
        // Effective Access
        .route(
            "/users/:user_id/effective-access",
            get(effective_access::get_effective_access),
        )
        // Persona-aware Effective Access (F063 integration)
        .route(
            "/users/:user_id/persona-effective-access",
            get(effective_access::get_persona_effective_access),
        )
        .route(
            "/users/:user_id/entitlements/:entitlement_id/check",
            get(effective_access::check_entitlement_access),
        )
        // SoD Rules
        .route("/sod-rules", get(sod_rules::list_sod_rules))
        .route("/sod-rules", post(sod_rules::create_sod_rule))
        .route("/sod-rules/:id", get(sod_rules::get_sod_rule))
        .route("/sod-rules/:id", put(sod_rules::update_sod_rule))
        .route("/sod-rules/:id", delete(sod_rules::delete_sod_rule))
        .route("/sod-rules/:id/enable", post(sod_rules::enable_sod_rule))
        .route("/sod-rules/:id/disable", post(sod_rules::disable_sod_rule))
        // SoD Check (pre-flight validation)
        .route("/sod-check", post(sod_rules::sod_check))
        // SoD Violations
        .route("/sod-violations", get(sod_violations::list_violations))
        .route("/sod-violations/:id", get(sod_violations::get_violation))
        .route(
            "/sod-violations/:id/remediate",
            post(sod_violations::remediate_violation),
        )
        // SoD Rule Scan
        .route("/sod-rules/:id/scan", post(sod_violations::scan_rule))
        // SoD Exemptions
        .route("/sod-exemptions", get(sod_exemptions::list_exemptions))
        .route("/sod-exemptions", post(sod_exemptions::create_exemption))
        .route("/sod-exemptions/:id", get(sod_exemptions::get_exemption))
        .route(
            "/sod-exemptions/:id/revoke",
            post(sod_exemptions::revoke_exemption),
        )
        // Access Requests (F035)
        .route("/access-requests", get(access_requests::list_my_requests))
        .route("/access-requests", post(access_requests::create_request))
        .route("/access-requests/:id", get(access_requests::get_request))
        .route(
            "/access-requests/:id/cancel",
            post(access_requests::cancel_request),
        )
        // Approvals (F035)
        .route("/my-approvals", get(approvals::list_pending_approvals))
        .route(
            "/access-requests/:id/approve",
            post(approvals::approve_request),
        )
        .route(
            "/access-requests/:id/reject",
            post(approvals::reject_request),
        )
        // Approval Workflows (F035)
        .route(
            "/approval-workflows",
            get(approval_workflows::list_workflows),
        )
        .route(
            "/approval-workflows",
            post(approval_workflows::create_workflow),
        )
        .route(
            "/approval-workflows/:id",
            get(approval_workflows::get_workflow),
        )
        .route(
            "/approval-workflows/:id",
            put(approval_workflows::update_workflow),
        )
        .route(
            "/approval-workflows/:id",
            delete(approval_workflows::delete_workflow),
        )
        .route(
            "/approval-workflows/:id/set-default",
            post(approval_workflows::set_default_workflow),
        )
        // Delegations (F035 + F053)
        .route("/delegations", get(delegations::list_my_delegations))
        .route("/delegations", post(delegations::create_delegation))
        // Deputy delegations (F053)
        .route(
            "/delegations/as-deputy",
            get(delegations::list_delegations_as_deputy),
        )
        .route("/delegations/:id", get(delegations::get_delegation))
        .route(
            "/delegations/:id/revoke",
            post(delegations::revoke_delegation),
        )
        // Delegation lifecycle (F053)
        .route(
            "/delegations/:id/extend",
            patch(delegations::extend_delegation),
        )
        .route(
            "/delegations/:id/scope",
            get(delegations::get_delegation_scope),
        )
        // Delegated work items (F053)
        .route(
            "/work-items/delegated",
            get(delegations::list_delegated_work_items),
        )
        // Delegation lifecycle processing (F053)
        .route(
            "/delegations/process-lifecycle",
            post(delegations::process_delegation_lifecycle),
        )
        // Delegation audit trail (F053)
        .route(
            "/delegations/audit",
            get(delegations::list_delegation_audit),
        )
        // Certification Campaigns (F036)
        .route(
            "/certification-campaigns",
            get(certification_campaigns::list_campaigns),
        )
        .route(
            "/certification-campaigns",
            post(certification_campaigns::create_campaign),
        )
        .route(
            "/certification-campaigns/:id",
            get(certification_campaigns::get_campaign),
        )
        .route(
            "/certification-campaigns/:id",
            put(certification_campaigns::update_campaign),
        )
        .route(
            "/certification-campaigns/:id",
            delete(certification_campaigns::delete_campaign),
        )
        .route(
            "/certification-campaigns/:id/launch",
            post(certification_campaigns::launch_campaign),
        )
        .route(
            "/certification-campaigns/:id/cancel",
            post(certification_campaigns::cancel_campaign),
        )
        .route(
            "/certification-campaigns/:id/progress",
            get(certification_campaigns::get_campaign_progress),
        )
        .route(
            "/certification-campaigns/:campaign_id/items",
            get(certification_items::list_campaign_items),
        )
        // Certification Items (F036)
        .route(
            "/certification-items/:id",
            get(certification_items::get_item),
        )
        .route(
            "/certification-items/:id/decide",
            post(certification_items::decide_item),
        )
        .route(
            "/certification-items/:id/reassign",
            post(certification_items::reassign_item),
        )
        // My Certifications (F036)
        .route(
            "/my-certifications",
            get(certification_items::get_my_certifications),
        )
        .route(
            "/my-certifications/summary",
            get(certification_items::get_my_certifications_summary),
        )
        // Birthright Policies (F037)
        .route(
            "/birthright-policies",
            get(birthright_policies::list_policies),
        )
        .route(
            "/birthright-policies",
            post(birthright_policies::create_policy),
        )
        .route(
            "/birthright-policies/simulate",
            post(birthright_policies::simulate_all_policies),
        )
        .route(
            "/birthright-policies/:id",
            get(birthright_policies::get_policy),
        )
        .route(
            "/birthright-policies/:id",
            put(birthright_policies::update_policy),
        )
        .route(
            "/birthright-policies/:id",
            delete(birthright_policies::archive_policy),
        )
        .route(
            "/birthright-policies/:id/enable",
            post(birthright_policies::enable_policy),
        )
        .route(
            "/birthright-policies/:id/disable",
            post(birthright_policies::disable_policy),
        )
        .route(
            "/birthright-policies/:id/simulate",
            post(birthright_policies::simulate_policy),
        )
        .route(
            "/birthright-policies/:id/impact",
            post(birthright_policies::analyze_policy_impact),
        )
        // Lifecycle Events (F037)
        .route("/lifecycle-events", get(lifecycle_events::list_events))
        .route("/lifecycle-events", post(lifecycle_events::create_event))
        .route(
            "/lifecycle-events/trigger",
            post(lifecycle_events::trigger_event),
        )
        .route("/lifecycle-events/:id", get(lifecycle_events::get_event))
        .route(
            "/lifecycle-events/:id/process",
            post(lifecycle_events::process_event),
        )
        // Lifecycle Actions (F037)
        .route("/lifecycle-actions", get(lifecycle_actions::list_actions))
        .route(
            "/lifecycle-actions/execute-due",
            post(lifecycle_actions::execute_due_actions),
        )
        .route(
            "/lifecycle-actions/:id/cancel",
            post(lifecycle_actions::cancel_action),
        )
        // Access Snapshots (F037)
        .route("/access-snapshots", get(access_snapshots::list_snapshots))
        .route("/access-snapshots/:id", get(access_snapshots::get_snapshot))
        .route(
            "/users/:user_id/access-snapshots",
            get(access_snapshots::list_user_snapshots),
        )
        // Risk Events (F039)
        .route("/risk-events", post(risk_events::create_risk_event))
        .route(
            "/risk-events/cleanup",
            post(risk_events::cleanup_expired_events),
        )
        .route("/risk-events/:event_id", get(risk_events::get_risk_event))
        .route(
            "/risk-events/:event_id",
            delete(risk_events::delete_risk_event),
        )
        .route(
            "/users/:user_id/risk-events",
            get(risk_events::list_user_risk_events),
        )
        // Risk Factors (F039)
        .route("/risk-factors", get(risk_factors::list_risk_factors))
        .route("/risk-factors", post(risk_factors::create_risk_factor))
        .route(
            "/risk-factors/:factor_id",
            get(risk_factors::get_risk_factor),
        )
        .route(
            "/risk-factors/:factor_id",
            put(risk_factors::update_risk_factor),
        )
        .route(
            "/risk-factors/:factor_id",
            delete(risk_factors::delete_risk_factor),
        )
        .route(
            "/risk-factors/:factor_id/enable",
            post(risk_factors::enable_risk_factor),
        )
        .route(
            "/risk-factors/:factor_id/disable",
            post(risk_factors::disable_risk_factor),
        )
        // Risk Scoring (F039)
        .route("/risk-scores", get(risk_scores::list_risk_scores))
        .route(
            "/risk-scores/summary",
            get(risk_scores::get_risk_score_summary),
        )
        .route(
            "/risk-scores/calculate-all",
            post(risk_scores::calculate_all_risk_scores),
        )
        .route(
            "/users/:user_id/risk-score",
            get(risk_scores::get_user_risk_score),
        )
        .route(
            "/users/:user_id/risk-score/calculate",
            post(risk_scores::calculate_user_risk_score),
        )
        .route(
            "/users/:user_id/risk-score/history",
            get(risk_scores::get_user_risk_score_history),
        )
        .route(
            "/users/:user_id/risk-score/snapshot",
            post(risk_scores::save_risk_score_snapshot),
        )
        .route(
            "/users/:user_id/risk-enforcement",
            get(risk_scores::get_user_risk_enforcement),
        )
        // Risk Enforcement Policy (F073)
        .route(
            "/risk/enforcement-policy",
            get(risk_scores::get_enforcement_policy).put(risk_scores::upsert_enforcement_policy),
        )
        // Peer Groups (F039)
        .route("/peer-groups", get(peer_groups::list_peer_groups))
        .route("/peer-groups", post(peer_groups::create_peer_group))
        .route(
            "/peer-groups/refresh-all",
            post(peer_groups::refresh_all_peer_groups),
        )
        .route("/peer-groups/:group_id", get(peer_groups::get_peer_group))
        .route(
            "/peer-groups/:group_id",
            delete(peer_groups::delete_peer_group),
        )
        .route(
            "/peer-groups/:group_id/refresh",
            post(peer_groups::refresh_peer_group_stats),
        )
        .route(
            "/users/:user_id/peer-comparison",
            get(peer_groups::get_user_peer_comparison),
        )
        // Risk Thresholds (F039)
        .route(
            "/risk-thresholds",
            get(risk_thresholds::list_risk_thresholds),
        )
        .route(
            "/risk-thresholds",
            post(risk_thresholds::create_risk_threshold),
        )
        .route(
            "/risk-thresholds/:threshold_id",
            get(risk_thresholds::get_risk_threshold),
        )
        .route(
            "/risk-thresholds/:threshold_id",
            put(risk_thresholds::update_risk_threshold),
        )
        .route(
            "/risk-thresholds/:threshold_id",
            delete(risk_thresholds::delete_risk_threshold),
        )
        .route(
            "/risk-thresholds/:threshold_id/enable",
            post(risk_thresholds::enable_risk_threshold),
        )
        .route(
            "/risk-thresholds/:threshold_id/disable",
            post(risk_thresholds::disable_risk_threshold),
        )
        // Risk Alerts (F039)
        .route("/risk-alerts", get(risk_alerts::list_risk_alerts))
        .route("/risk-alerts/summary", get(risk_alerts::get_alert_summary))
        .route("/risk-alerts/:alert_id", get(risk_alerts::get_risk_alert))
        .route(
            "/risk-alerts/:alert_id",
            delete(risk_alerts::delete_risk_alert),
        )
        .route(
            "/risk-alerts/:alert_id/acknowledge",
            post(risk_alerts::acknowledge_risk_alert),
        )
        .route(
            "/users/:user_id/risk-alerts/latest",
            get(risk_alerts::get_user_latest_alert),
        )
        .route(
            "/users/:user_id/risk-alerts/acknowledge-all",
            post(risk_alerts::acknowledge_user_alerts),
        )
        // Reconciliation Runs (F040)
        .route(
            "/reconciliation-runs",
            get(reconciliation_runs::list_reconciliation_runs),
        )
        .route(
            "/reconciliation-runs",
            post(reconciliation_runs::trigger_reconciliation),
        )
        .route(
            "/reconciliation-runs/:id",
            get(reconciliation_runs::get_reconciliation_run),
        )
        .route(
            "/reconciliation-runs/:id/cancel",
            post(reconciliation_runs::cancel_reconciliation),
        )
        // Reconciliation Schedule (F040)
        .route(
            "/reconciliation-schedule",
            get(reconciliation_runs::get_schedule),
        )
        .route(
            "/reconciliation-schedule",
            put(reconciliation_runs::upsert_schedule),
        )
        .route(
            "/reconciliation-schedule",
            delete(reconciliation_runs::delete_schedule),
        )
        .route(
            "/reconciliation-schedule/trigger",
            post(reconciliation_runs::trigger_scheduled_runs),
        )
        // Orphan Detections (F040)
        .route(
            "/orphan-detections",
            get(orphan_detections::list_orphan_detections),
        )
        .route(
            "/orphan-detections/summary",
            get(orphan_detections::get_orphan_summary),
        )
        .route(
            "/orphan-detections/age-analysis",
            get(orphan_detections::get_age_analysis),
        )
        .route(
            "/orphan-detections/risk-report",
            get(orphan_detections::get_risk_report),
        )
        .route(
            "/orphan-detections/export",
            get(orphan_detections::export_orphans_csv),
        )
        .route(
            "/orphan-detections/bulk-remediate",
            post(orphan_detections::bulk_remediate),
        )
        .route(
            "/orphan-detections/:id",
            get(orphan_detections::get_orphan_detection),
        )
        .route(
            "/orphan-detections/:id/review",
            post(orphan_detections::start_review),
        )
        .route(
            "/orphan-detections/:id/reassign",
            post(orphan_detections::reassign_orphan),
        )
        .route(
            "/orphan-detections/:id/disable",
            post(orphan_detections::disable_orphan),
        )
        .route(
            "/orphan-detections/:id/delete",
            post(orphan_detections::delete_orphan),
        )
        .route(
            "/orphan-detections/:id/dismiss",
            post(orphan_detections::dismiss_orphan),
        )
        // Detection Rules (F040)
        .route(
            "/detection-rules",
            get(detection_rules::list_detection_rules),
        )
        .route(
            "/detection-rules",
            post(detection_rules::create_detection_rule),
        )
        .route(
            "/detection-rules/seed-defaults",
            post(detection_rules::seed_default_rules),
        )
        .route(
            "/detection-rules/:id",
            get(detection_rules::get_detection_rule),
        )
        .route(
            "/detection-rules/:id",
            put(detection_rules::update_detection_rule),
        )
        .route(
            "/detection-rules/:id",
            delete(detection_rules::delete_detection_rule),
        )
        .route(
            "/detection-rules/:id/enable",
            post(detection_rules::enable_detection_rule),
        )
        .route(
            "/detection-rules/:id/disable",
            post(detection_rules::disable_detection_rule),
        )
        // Service Accounts (F040)
        .route(
            "/service-accounts",
            get(service_accounts::list_service_accounts),
        )
        .route(
            "/service-accounts",
            post(service_accounts::register_service_account),
        )
        .route(
            "/service-accounts/summary",
            get(service_accounts::get_service_account_summary),
        )
        .route(
            "/service-accounts/mark-expired",
            post(service_accounts::mark_expired_accounts),
        )
        .route(
            "/service-accounts/:id",
            get(service_accounts::get_service_account),
        )
        .route(
            "/service-accounts/:id",
            put(service_accounts::update_service_account),
        )
        .route(
            "/service-accounts/:id",
            delete(service_accounts::unregister_service_account),
        )
        .route(
            "/service-accounts/:id/certify",
            post(service_accounts::certify_service_account),
        )
        .route(
            "/service-accounts/:id/suspend",
            post(service_accounts::suspend_service_account),
        )
        .route(
            "/service-accounts/:id/reactivate",
            post(service_accounts::reactivate_service_account),
        )
        // Report Templates (F042)
        .route("/reports/templates", get(report_templates::list_templates))
        .route(
            "/reports/templates",
            post(report_templates::create_template),
        )
        .route(
            "/reports/templates/:id",
            get(report_templates::get_template),
        )
        .route(
            "/reports/templates/:id",
            put(report_templates::update_template),
        )
        .route(
            "/reports/templates/:id",
            delete(report_templates::archive_template),
        )
        .route(
            "/reports/templates/:id/clone",
            post(report_templates::clone_template),
        )
        // Generated Reports (F042)
        .route("/reports", get(reports::list_reports))
        .route("/reports/generate", post(reports::generate_report))
        .route("/reports/cleanup", post(reports::cleanup_expired_reports))
        .route("/reports/:id", get(reports::get_report))
        .route("/reports/:id", delete(reports::delete_report))
        .route("/reports/:id/data", get(reports::get_report_data))
        // Report Schedules (F042)
        .route("/reports/schedules", get(report_schedules::list_schedules))
        .route(
            "/reports/schedules",
            post(report_schedules::create_schedule),
        )
        .route(
            "/reports/schedules/trigger-due",
            post(report_schedules::trigger_due_schedules),
        )
        .route(
            "/reports/schedules/:id",
            get(report_schedules::get_schedule),
        )
        .route(
            "/reports/schedules/:id",
            put(report_schedules::update_schedule),
        )
        .route(
            "/reports/schedules/:id",
            delete(report_schedules::delete_schedule),
        )
        .route(
            "/reports/schedules/:id/pause",
            post(report_schedules::pause_schedule),
        )
        .route(
            "/reports/schedules/:id/resume",
            post(report_schedules::resume_schedule),
        )
        // Role Mining Jobs (F041)
        .route("/role-mining/jobs", get(role_mining::list_mining_jobs))
        .route("/role-mining/jobs", post(role_mining::create_mining_job))
        .route(
            "/role-mining/jobs/:job_id",
            get(role_mining::get_mining_job),
        )
        .route(
            "/role-mining/jobs/:job_id",
            delete(role_mining::cancel_mining_job),
        )
        .route(
            "/role-mining/jobs/:job_id/run",
            post(role_mining::run_mining_job),
        )
        // Role Candidates (F041)
        .route(
            "/role-mining/jobs/:job_id/candidates",
            get(role_mining::list_candidates),
        )
        .route(
            "/role-mining/candidates/:candidate_id",
            get(role_mining::get_candidate),
        )
        .route(
            "/role-mining/candidates/:candidate_id/promote",
            post(role_mining::promote_candidate),
        )
        .route(
            "/role-mining/candidates/:candidate_id/dismiss",
            post(role_mining::dismiss_candidate),
        )
        // Access Patterns (F041)
        .route(
            "/role-mining/jobs/:job_id/patterns",
            get(role_mining::list_access_patterns),
        )
        .route(
            "/role-mining/patterns/:pattern_id",
            get(role_mining::get_access_pattern),
        )
        // Excessive Privileges (F041)
        .route(
            "/role-mining/jobs/:job_id/excessive-privileges",
            get(role_mining::list_excessive_privileges),
        )
        .route(
            "/role-mining/excessive-privileges/:flag_id",
            get(role_mining::get_excessive_privilege),
        )
        .route(
            "/role-mining/excessive-privileges/:flag_id/review",
            post(role_mining::review_excessive_privilege),
        )
        // Consolidation Suggestions (F041)
        .route(
            "/role-mining/jobs/:job_id/consolidation-suggestions",
            get(role_mining::list_consolidation_suggestions),
        )
        .route(
            "/role-mining/consolidation-suggestions/:suggestion_id",
            get(role_mining::get_consolidation_suggestion),
        )
        .route(
            "/role-mining/consolidation-suggestions/:suggestion_id/dismiss",
            post(role_mining::dismiss_consolidation_suggestion),
        )
        // Simulations (F041)
        .route(
            "/role-mining/simulations",
            get(role_mining::list_simulations),
        )
        .route(
            "/role-mining/simulations",
            post(role_mining::create_simulation),
        )
        .route(
            "/role-mining/simulations/:simulation_id",
            get(role_mining::get_simulation),
        )
        .route(
            "/role-mining/simulations/:simulation_id",
            delete(role_mining::cancel_simulation),
        )
        .route(
            "/role-mining/simulations/:simulation_id/execute",
            post(role_mining::execute_simulation),
        )
        .route(
            "/role-mining/simulations/:simulation_id/apply",
            post(role_mining::apply_simulation),
        )
        // Role Metrics (F041)
        .route("/role-mining/metrics", get(role_mining::list_metrics))
        .route(
            "/role-mining/metrics/calculate",
            post(role_mining::calculate_metrics),
        )
        .route(
            "/role-mining/metrics/:role_id",
            get(role_mining::get_role_metrics),
        )
        // Lifecycle Configurations (F052)
        .route("/lifecycle/configs", get(lifecycle_config::list_configs))
        .route("/lifecycle/configs", post(lifecycle_config::create_config))
        .route(
            "/lifecycle/configs/:config_id",
            get(lifecycle_config::get_config),
        )
        .route(
            "/lifecycle/configs/:config_id",
            put(lifecycle_config::update_config),
        )
        .route(
            "/lifecycle/configs/:config_id",
            delete(lifecycle_config::delete_config),
        )
        // Lifecycle States (F052)
        .route(
            "/lifecycle/configs/:config_id/states",
            post(lifecycle_config::add_state),
        )
        .route(
            "/lifecycle/configs/:config_id/states/:state_id",
            put(lifecycle_config::update_state),
        )
        .route(
            "/lifecycle/configs/:config_id/states/:state_id",
            delete(lifecycle_config::delete_state),
        )
        // Lifecycle Transitions (F052)
        .route(
            "/lifecycle/configs/:config_id/transitions",
            post(lifecycle_config::add_transition),
        )
        .route(
            "/lifecycle/configs/:config_id/transitions/:transition_id",
            delete(lifecycle_config::delete_transition),
        )
        // Transition Conditions (F-193)
        .route(
            "/lifecycle/configs/:config_id/transitions/:transition_id/conditions",
            get(lifecycle_config::get_transition_conditions),
        )
        .route(
            "/lifecycle/configs/:config_id/transitions/:transition_id/conditions",
            put(lifecycle_config::update_transition_conditions),
        )
        .route(
            "/lifecycle/configs/:config_id/transitions/:transition_id/conditions/evaluate",
            post(lifecycle_config::evaluate_transition_conditions),
        )
        // State Actions (F-193)
        .route(
            "/lifecycle/configs/:config_id/states/:state_id/actions",
            get(lifecycle_config::get_state_actions),
        )
        .route(
            "/lifecycle/configs/:config_id/states/:state_id/actions",
            put(lifecycle_config::update_state_actions),
        )
        // User Lifecycle Status (F-193)
        .route(
            "/users/:user_id/lifecycle/status",
            get(lifecycle_config::get_user_lifecycle_status),
        )
        // State Transitions (F052)
        .route(
            "/lifecycle/transitions",
            post(state_transition::execute_transition),
        )
        .route(
            "/lifecycle/transitions",
            get(state_transition::list_transition_requests),
        )
        .route(
            "/lifecycle/transitions/:request_id",
            get(state_transition::get_transition_request),
        )
        .route(
            "/lifecycle/objects/:object_type/:object_id/state",
            get(state_transition::get_object_state),
        )
        // Transition Rollback (F052)
        .route(
            "/lifecycle/transitions/:request_id/rollback",
            post(state_transition::rollback_transition),
        )
        // Affected Entitlements Preview (F052)
        .route(
            "/lifecycle/transitions/:transition_id/affected-entitlements/:object_id",
            get(state_transition::get_affected_entitlements),
        )
        // Transition Audit (F052)
        .route(
            "/lifecycle/audit",
            get(state_transition::list_transition_audit),
        )
        .route(
            "/lifecycle/audit/export",
            get(state_transition::export_transition_audit),
        )
        .route(
            "/lifecycle/audit/:audit_id",
            get(state_transition::get_transition_audit),
        )
        // Scheduled Transitions (F052)
        .route(
            "/lifecycle/scheduled",
            get(scheduled_transition::list_scheduled_transitions),
        )
        .route(
            "/lifecycle/scheduled/trigger-due",
            post(scheduled_transition::trigger_due_transitions),
        )
        .route(
            "/lifecycle/scheduled/:schedule_id",
            get(scheduled_transition::get_scheduled_transition),
        )
        .route(
            "/lifecycle/scheduled/:schedule_id/cancel",
            post(scheduled_transition::cancel_scheduled_transition),
        )
        // Bulk State Operations (F052)
        .route(
            "/lifecycle/bulk-operations",
            post(bulk_state_operation::create_bulk_operation),
        )
        .route(
            "/lifecycle/bulk-operations",
            get(bulk_state_operation::list_bulk_operations),
        )
        .route(
            "/lifecycle/bulk-operations/process",
            post(bulk_state_operation::process_bulk_operations),
        )
        .route(
            "/lifecycle/bulk-operations/:operation_id",
            get(bulk_state_operation::get_bulk_operation),
        )
        .route(
            "/lifecycle/bulk-operations/:operation_id/cancel",
            post(bulk_state_operation::cancel_bulk_operation),
        )
        // Failed Operations / Retry Queue (F052)
        .route(
            "/lifecycle/failed-operations/dead-letter",
            get(failed_operations::list_dead_letter_operations),
        )
        .route(
            "/lifecycle/failed-operations/dead-letter/count",
            get(failed_operations::count_dead_letter_operations),
        )
        .route(
            "/lifecycle/failed-operations/process-retries",
            post(failed_operations::process_retries),
        )
        .route(
            "/lifecycle/failed-operations/process-all-retries",
            post(failed_operations::process_all_retries),
        )
        // Escalation Policies (F054)
        .route(
            "/escalation-policies",
            get(escalation_policies::list_policies),
        )
        .route(
            "/escalation-policies",
            post(escalation_policies::create_policy),
        )
        .route(
            "/escalation-policies/:id",
            get(escalation_policies::get_policy),
        )
        .route(
            "/escalation-policies/:id",
            put(escalation_policies::update_policy),
        )
        .route(
            "/escalation-policies/:id",
            delete(escalation_policies::delete_policy),
        )
        .route(
            "/escalation-policies/:id/set-default",
            post(escalation_policies::set_default_policy),
        )
        .route(
            "/escalation-policies/:policy_id/levels",
            post(escalation_policies::add_level),
        )
        .route(
            "/escalation-policies/:policy_id/levels/:level_id",
            delete(escalation_policies::remove_level),
        )
        // Approval Groups (F054)
        .route("/approval-groups", get(approval_groups::list_groups))
        .route("/approval-groups", post(approval_groups::create_group))
        .route("/approval-groups/:id", get(approval_groups::get_group))
        .route("/approval-groups/:id", put(approval_groups::update_group))
        .route(
            "/approval-groups/:id",
            delete(approval_groups::delete_group),
        )
        .route(
            "/approval-groups/:id/members",
            post(approval_groups::add_members),
        )
        .route(
            "/approval-groups/:id/members",
            delete(approval_groups::remove_members),
        )
        .route(
            "/approval-groups/:id/enable",
            post(approval_groups::enable_group),
        )
        .route(
            "/approval-groups/:id/disable",
            post(approval_groups::disable_group),
        )
        .route(
            "/users/:user_id/approval-groups",
            get(approval_groups::get_user_groups),
        )
        // Step Escalation Configuration (F054)
        .route(
            "/approval-steps/:step_id/escalation",
            get(escalation_policies::get_step_escalation),
        )
        .route(
            "/approval-steps/:step_id/escalation",
            put(escalation_policies::configure_step_escalation),
        )
        .route(
            "/approval-steps/:step_id/escalation",
            delete(escalation_policies::remove_step_escalation),
        )
        .route(
            "/approval-steps/:step_id/escalation/enable",
            post(escalation_policies::enable_step_escalation),
        )
        .route(
            "/approval-steps/:step_id/escalation/disable",
            post(escalation_policies::disable_step_escalation),
        )
        // Escalation Events / Audit Trail (F054)
        .route(
            "/escalation-events",
            get(escalation_events::list_escalation_events),
        )
        .route(
            "/access-requests/:request_id/escalation-history",
            get(escalation_events::get_request_escalation_history),
        )
        // Cancel/Reset Escalation Actions (F054 T067-T070)
        .route(
            "/access-requests/:request_id/cancel-escalation",
            post(escalation_events::cancel_escalation),
        )
        .route(
            "/access-requests/:request_id/reset-escalation",
            post(escalation_events::reset_escalation),
        )
        // Micro-certification Trigger Rules (F055)
        .route(
            "/micro-cert-triggers",
            get(micro_cert_triggers::list_triggers),
        )
        .route(
            "/micro-cert-triggers",
            post(micro_cert_triggers::create_trigger),
        )
        .route(
            "/micro-cert-triggers/:id",
            get(micro_cert_triggers::get_trigger),
        )
        .route(
            "/micro-cert-triggers/:id",
            put(micro_cert_triggers::update_trigger),
        )
        .route(
            "/micro-cert-triggers/:id",
            delete(micro_cert_triggers::delete_trigger),
        )
        .route(
            "/micro-cert-triggers/:id/set-default",
            post(micro_cert_triggers::set_default),
        )
        .route(
            "/micro-cert-triggers/:id/enable",
            post(micro_cert_triggers::enable_trigger),
        )
        .route(
            "/micro-cert-triggers/:id/disable",
            post(micro_cert_triggers::disable_trigger),
        )
        // Micro-certifications (F055)
        .route(
            "/micro-certifications",
            get(micro_certifications::list_certifications),
        )
        .route(
            "/micro-certifications/my-pending",
            get(micro_certifications::my_pending),
        )
        .route(
            "/micro-certifications/stats",
            get(micro_certifications::get_stats),
        )
        .route(
            "/micro-certifications/bulk-decide",
            post(micro_certifications::bulk_decide),
        )
        .route(
            "/micro-certifications/trigger",
            post(micro_certifications::manual_trigger),
        )
        .route(
            "/micro-certifications/:id",
            get(micro_certifications::get_certification),
        )
        .route(
            "/micro-certifications/:id/decide",
            post(micro_certifications::decide),
        )
        .route(
            "/micro-certifications/:id/delegate",
            post(micro_certifications::delegate),
        )
        .route(
            "/micro-certifications/:id/events",
            get(micro_certifications::get_events),
        )
        .route(
            "/micro-certifications/:id/skip",
            post(micro_certifications::skip_certification),
        )
        // Micro-certification events (audit trail search)
        .route(
            "/micro-cert-events",
            get(micro_certifications::search_events),
        )
        // Meta-roles (F056)
        .route("/meta-roles", get(meta_roles::list_meta_roles))
        .route("/meta-roles", post(meta_roles::create_meta_role))
        .route("/meta-roles/conflicts", get(meta_roles::list_conflicts))
        .route("/meta-roles/events", get(meta_roles::list_events))
        .route("/meta-roles/events/stats", get(meta_roles::get_event_stats))
        .route("/meta-roles/:id", get(meta_roles::get_meta_role))
        .route("/meta-roles/:id", put(meta_roles::update_meta_role))
        .route("/meta-roles/:id", delete(meta_roles::delete_meta_role))
        .route("/meta-roles/:id/enable", post(meta_roles::enable_meta_role))
        .route(
            "/meta-roles/:id/disable",
            post(meta_roles::disable_meta_role),
        )
        .route("/meta-roles/:id/criteria", post(meta_roles::add_criteria))
        .route(
            "/meta-roles/:id/criteria/:criteria_id",
            delete(meta_roles::remove_criteria),
        )
        .route(
            "/meta-roles/:id/entitlements",
            post(meta_roles::add_entitlement),
        )
        .route(
            "/meta-roles/:id/entitlements/:entitlement_id",
            delete(meta_roles::remove_entitlement),
        )
        .route(
            "/meta-roles/:id/constraints",
            post(meta_roles::add_constraint),
        )
        .route(
            "/meta-roles/:id/constraints/:constraint_id",
            delete(meta_roles::remove_constraint),
        )
        .route(
            "/meta-roles/:id/inheritances",
            get(meta_roles::list_inheritances),
        )
        .route(
            "/meta-roles/:id/reevaluate",
            post(meta_roles::reevaluate_meta_role),
        )
        .route(
            "/meta-roles/:id/simulate",
            post(meta_roles::simulate_changes),
        )
        .route("/meta-roles/:id/cascade", post(meta_roles::trigger_cascade))
        .route(
            "/meta-roles/conflicts/:conflict_id/resolve",
            post(meta_roles::resolve_conflict),
        )
        // Meta-role for specific role
        .route(
            "/roles/:role_id/meta-roles",
            get(meta_roles::get_role_meta_roles),
        )
        // Parametric Roles (F057)
        // Role parameter CRUD
        .route(
            "/roles/:role_id/parameters",
            get(parametric_roles::list_role_parameters),
        )
        .route(
            "/roles/:role_id/parameters",
            post(parametric_roles::add_role_parameter),
        )
        .route(
            "/roles/:role_id/parameters/validate",
            post(parametric_roles::validate_parameters),
        )
        .route(
            "/roles/:role_id/parameters/:parameter_id",
            get(parametric_roles::get_role_parameter),
        )
        .route(
            "/roles/:role_id/parameters/:parameter_id",
            put(parametric_roles::update_role_parameter),
        )
        .route(
            "/roles/:role_id/parameters/:parameter_id",
            delete(parametric_roles::delete_role_parameter),
        )
        // Parametric assignment CRUD
        .route(
            "/roles/:role_id/parametric-assignments",
            post(parametric_roles::create_parametric_assignment),
        )
        .route(
            "/parametric-assignments/:assignment_id",
            get(parametric_roles::get_parametric_assignment),
        )
        .route(
            "/users/:user_id/parametric-assignments",
            get(parametric_roles::list_user_parametric_assignments),
        )
        // Assignment parameter operations
        .route(
            "/parametric-assignments/:assignment_id/parameters",
            get(parametric_roles::get_assignment_parameters),
        )
        .route(
            "/parametric-assignments/:assignment_id/parameters",
            put(parametric_roles::update_assignment_parameters),
        )
        .route(
            "/parametric-assignments/:assignment_id/parameters/audit",
            get(parametric_roles::get_assignment_parameter_audit),
        )
        // Parameter audit trail
        .route(
            "/parameters/audit",
            get(parametric_roles::list_parameter_audit),
        )
        // Object Templates (F058)
        .route("/object-templates", get(object_templates::list_templates))
        .route("/object-templates", post(object_templates::create_template))
        .route("/object-templates/:id", get(object_templates::get_template))
        .route(
            "/object-templates/:id",
            put(object_templates::update_template),
        )
        .route(
            "/object-templates/:id",
            delete(object_templates::delete_template),
        )
        .route(
            "/object-templates/:id/activate",
            post(object_templates::activate_template),
        )
        .route(
            "/object-templates/:id/disable",
            post(object_templates::disable_template),
        )
        // Template Rules (F058)
        .route(
            "/object-templates/:template_id/rules",
            get(object_templates::list_rules),
        )
        .route(
            "/object-templates/:template_id/rules",
            post(object_templates::add_rule),
        )
        .route(
            "/object-templates/:template_id/rules/:rule_id",
            get(object_templates::get_rule),
        )
        .route(
            "/object-templates/:template_id/rules/:rule_id",
            put(object_templates::update_rule),
        )
        .route(
            "/object-templates/:template_id/rules/:rule_id",
            delete(object_templates::remove_rule),
        )
        // Template Versions (F058)
        .route(
            "/object-templates/:template_id/versions",
            get(object_templates::list_versions),
        )
        .route(
            "/object-templates/:template_id/versions/:version_id",
            get(object_templates::get_version),
        )
        // Template Events (F058)
        .route(
            "/object-templates/:template_id/events",
            get(object_templates::list_events),
        )
        // Template Scopes (F058)
        .route(
            "/object-templates/:template_id/scopes",
            get(object_templates::list_scopes).post(object_templates::add_scope),
        )
        .route(
            "/object-templates/:template_id/scopes/:scope_id",
            delete(object_templates::remove_scope),
        )
        // Template Application Events (F058)
        .route(
            "/object-templates/:template_id/application-events",
            get(object_templates::list_application_events_by_template),
        )
        .route(
            "/object-templates/application-events/:object_type/:object_id",
            get(object_templates::list_application_events_by_object),
        )
        // Template Merge Policies (F058)
        .route(
            "/object-templates/:template_id/merge-policies",
            get(object_templates::list_merge_policies).post(object_templates::create_merge_policy),
        )
        .route(
            "/object-templates/:template_id/merge-policies/:policy_id",
            get(object_templates::get_merge_policy),
        )
        .route(
            "/object-templates/:template_id/merge-policies/:policy_id",
            put(object_templates::update_merge_policy),
        )
        .route(
            "/object-templates/:template_id/merge-policies/:policy_id",
            delete(object_templates::delete_merge_policy),
        )
        // Template Exclusions (F058)
        .route(
            "/object-templates/:template_id/exclusions",
            get(object_templates::list_exclusions).post(object_templates::create_exclusion),
        )
        .route(
            "/object-templates/:template_id/exclusions/:exclusion_id",
            delete(object_templates::delete_exclusion),
        )
        // Template Simulation (F058)
        .route(
            "/object-templates/:template_id/simulate",
            post(object_templates::simulate_template),
        )
        // Outlier Detection (F059)
        // Configuration
        .route("/outliers/config", get(outliers::get_config))
        .route("/outliers/config", put(outliers::update_config))
        .route("/outliers/config/enable", post(outliers::enable_detection))
        .route(
            "/outliers/config/disable",
            post(outliers::disable_detection),
        )
        // Analyses
        .route("/outliers/analyses", get(outliers::list_analyses))
        .route("/outliers/analyses", post(outliers::trigger_analysis))
        .route(
            "/outliers/analyses/:analysis_id",
            get(outliers::get_analysis),
        )
        .route(
            "/outliers/analyses/:analysis_id/cancel",
            post(outliers::cancel_analysis),
        )
        // Results
        .route("/outliers/results", get(outliers::list_results))
        .route("/outliers/results/:result_id", get(outliers::get_result))
        .route("/outliers/summary", get(outliers::get_summary))
        .route("/outliers/users/:user_id", get(outliers::get_user_history))
        // Dispositions
        .route(
            "/outliers/results/:result_id/disposition",
            post(outliers::create_disposition),
        )
        .route("/outliers/dispositions", get(outliers::list_dispositions))
        .route(
            "/outliers/dispositions/summary",
            get(outliers::get_disposition_summary),
        )
        .route(
            "/outliers/dispositions/:disposition_id",
            get(outliers::get_disposition),
        )
        .route(
            "/outliers/dispositions/:disposition_id",
            put(outliers::update_disposition),
        )
        // Alerts
        .route("/outliers/alerts", get(outliers::list_alerts))
        .route("/outliers/alerts/summary", get(outliers::get_alert_summary))
        .route(
            "/outliers/alerts/:alert_id/read",
            post(outliers::mark_alert_read),
        )
        .route(
            "/outliers/alerts/:alert_id/dismiss",
            post(outliers::dismiss_alert),
        )
        // Reports
        .route("/outliers/reports", post(outliers::generate_report))
        // Enhanced Simulation (F060)
        // Policy Simulations
        .route(
            "/simulations/policy",
            get(policy_simulations::list_policy_simulations)
                .post(policy_simulations::create_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id",
            get(policy_simulations::get_policy_simulation)
                .delete(policy_simulations::delete_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id/execute",
            post(policy_simulations::execute_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id/cancel",
            post(policy_simulations::cancel_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id/archive",
            post(policy_simulations::archive_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id/restore",
            post(policy_simulations::restore_policy_simulation),
        )
        .route(
            "/simulations/policy/:simulation_id/notes",
            patch(policy_simulations::update_policy_simulation_notes),
        )
        .route(
            "/simulations/policy/:simulation_id/results",
            get(policy_simulations::get_policy_simulation_results),
        )
        .route(
            "/simulations/policy/:simulation_id/staleness",
            get(policy_simulations::check_policy_simulation_staleness),
        )
        .route(
            "/simulations/policy/:simulation_id/export",
            get(policy_simulations::export_policy_simulation),
        )
        // Batch Simulations
        .route(
            "/simulations/batch",
            get(batch_simulations::list_batch_simulations)
                .post(batch_simulations::create_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id",
            get(batch_simulations::get_batch_simulation)
                .delete(batch_simulations::delete_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/execute",
            post(batch_simulations::execute_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/apply",
            post(batch_simulations::apply_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/cancel",
            post(batch_simulations::cancel_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/archive",
            post(batch_simulations::archive_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/restore",
            post(batch_simulations::restore_batch_simulation),
        )
        .route(
            "/simulations/batch/:simulation_id/notes",
            patch(batch_simulations::update_batch_simulation_notes),
        )
        .route(
            "/simulations/batch/:simulation_id/results",
            get(batch_simulations::get_batch_simulation_results),
        )
        .route(
            "/simulations/batch/:simulation_id/export",
            get(batch_simulations::export_batch_simulation),
        )
        // Simulation Comparisons
        .route(
            "/simulations/comparisons",
            get(simulation_comparisons::list_simulation_comparisons)
                .post(simulation_comparisons::create_simulation_comparison),
        )
        .route(
            "/simulations/comparisons/:comparison_id",
            get(simulation_comparisons::get_simulation_comparison)
                .delete(simulation_comparisons::delete_simulation_comparison),
        )
        .route(
            "/simulations/comparisons/:comparison_id/export",
            get(simulation_comparisons::export_simulation_comparison),
        )
        // NHIs (F061)
        .route("/nhis", get(nhis::list_nhis).post(nhis::create_nhi))
        .route("/nhis/summary", get(nhis::get_nhi_summary))
        .route(
            "/nhis/:id",
            get(nhis::get_nhi)
                .put(nhis::update_nhi)
                .delete(nhis::delete_nhi),
        )
        .route("/nhis/:id/suspend", post(nhis::suspend_nhi))
        .route("/nhis/:id/reactivate", post(nhis::reactivate_nhi))
        .route(
            "/nhis/:id/transfer-ownership",
            post(nhis::transfer_nhi_ownership),
        )
        .route("/nhis/:id/certify", post(nhis::certify_nhi))
        // NHI Credentials (F061)
        .route("/nhis/:id/credentials", get(nhis::list_nhi_credentials))
        .route(
            "/nhis/:nhi_id/credentials/:credential_id",
            get(nhis::get_nhi_credential),
        )
        .route(
            "/nhis/:id/credentials/rotate",
            post(nhis::rotate_nhi_credentials),
        )
        .route(
            "/nhis/:nhi_id/credentials/:credential_id/revoke",
            post(nhis::revoke_nhi_credential),
        )
        // NHI Usage Tracking (F061)
        .route("/nhis/:id/usage", post(nhis::record_nhi_usage))
        .route("/nhis/:id/usage", get(nhis::list_nhi_usage))
        .route("/nhis/:id/usage/summary", get(nhis::get_nhi_usage_summary))
        .route(
            "/nhis/staleness-report",
            get(nhis::get_nhi_staleness_report),
        )
        // NHI Risk Scoring (F061)
        .route("/nhis/:id/risk", get(nhis::get_nhi_risk_score))
        .route(
            "/nhis/:id/risk/calculate",
            post(nhis::calculate_nhi_risk_score),
        )
        .route("/nhis/risk/summary", get(nhis::get_nhi_risk_summary))
        .route(
            "/nhis/risk/batch-calculate",
            post(nhis::batch_calculate_nhi_risk),
        )
        // NHI Certification Campaigns (F061)
        .route(
            "/nhis/certification/campaigns",
            get(nhis::list_nhi_certification_campaigns)
                .post(nhis::create_nhi_certification_campaign),
        )
        .route(
            "/nhis/certification/campaigns/:campaign_id",
            get(nhis::get_nhi_certification_campaign),
        )
        .route(
            "/nhis/certification/campaigns/:campaign_id/launch",
            post(nhis::launch_nhi_certification_campaign),
        )
        .route(
            "/nhis/certification/campaigns/:campaign_id/cancel",
            post(nhis::cancel_nhi_certification_campaign),
        )
        .route(
            "/nhis/certification/campaigns/:campaign_id/summary",
            get(nhis::get_nhi_certification_campaign_summary),
        )
        .route(
            "/nhis/certification/campaigns/:campaign_id/items",
            get(nhis::list_nhi_certification_items),
        )
        // NHI Certification Items (F061)
        .route(
            "/nhis/certification/items/:item_id",
            get(nhis::get_nhi_certification_item),
        )
        .route(
            "/nhis/certification/items/:item_id/decide",
            post(nhis::decide_nhi_certification),
        )
        .route(
            "/nhis/certification/items/bulk-decide",
            post(nhis::bulk_decide_nhi_certification),
        )
        // My NHI Certifications (F061)
        .route(
            "/nhis/certification/my-pending",
            get(nhis::get_my_pending_nhi_certifications),
        )
        // NHI Requests (F061 - US6: Self-Service)
        .route(
            "/nhis/requests",
            get(nhis::list_nhi_requests).post(nhis::submit_nhi_request),
        )
        .route("/nhis/requests/summary", get(nhis::get_nhi_request_summary))
        .route(
            "/nhis/requests/my-pending",
            get(nhis::get_my_pending_nhi_requests),
        )
        .route("/nhis/requests/:request_id", get(nhis::get_nhi_request))
        .route(
            "/nhis/requests/:request_id/approve",
            post(nhis::approve_nhi_request),
        )
        .route(
            "/nhis/requests/:request_id/reject",
            post(nhis::reject_nhi_request),
        )
        .route(
            "/nhis/requests/:request_id/cancel",
            post(nhis::cancel_nhi_request),
        )
        // Identity Merge (F062)
        .route("/duplicates", get(identity_merge::list_duplicates))
        .route("/duplicates/:id", get(identity_merge::get_duplicate))
        .route(
            "/duplicates/:id/dismiss",
            post(identity_merge::dismiss_duplicate),
        )
        .route(
            "/duplicates/detect",
            post(identity_merge::detect_duplicates),
        )
        .route("/merges", get(identity_merge::list_merge_operations))
        .route("/merges/preview", post(identity_merge::preview_merge))
        .route("/merges/execute", post(identity_merge::execute_merge))
        .route("/merges/:id", get(identity_merge::get_merge_operation))
        // Batch Merge (F062 - US3)
        .route(
            "/merges/batch/preview",
            post(identity_merge::preview_batch_merge),
        )
        .route("/merges/batch", post(identity_merge::execute_batch_merge))
        .route("/merges/batch/:job_id", get(identity_merge::get_batch_job))
        // Merge Audit (F062 - US5)
        .route("/merges/audit", get(identity_merge::list_merge_audits))
        .route("/merges/audit/:id", get(identity_merge::get_merge_audit))
        // Identity Correlation Rules (F062)
        .route(
            "/identity-correlation-rules",
            get(identity_correlation_rules::list_identity_correlation_rules)
                .post(identity_correlation_rules::create_identity_correlation_rule),
        )
        .route(
            "/identity-correlation-rules/:id",
            get(identity_correlation_rules::get_identity_correlation_rule)
                .put(identity_correlation_rules::update_identity_correlation_rule)
                .delete(identity_correlation_rules::delete_identity_correlation_rule),
        )
        // Persona Archetypes (F063)
        .route(
            "/persona-archetypes",
            get(personas::list_archetypes).post(personas::create_archetype),
        )
        .route(
            "/persona-archetypes/:id",
            get(personas::get_archetype)
                .put(personas::update_archetype)
                .delete(personas::delete_archetype),
        )
        .route(
            "/persona-archetypes/:id/activate",
            post(personas::activate_archetype),
        )
        .route(
            "/persona-archetypes/:id/deactivate",
            post(personas::deactivate_archetype),
        )
        // Personas (F063)
        .route(
            "/personas",
            get(personas::list_personas).post(personas::create_persona),
        )
        .route(
            "/personas/:id",
            get(personas::get_persona).put(personas::update_persona),
        )
        .route("/personas/:id/activate", post(personas::activate_persona))
        .route(
            "/personas/:id/deactivate",
            post(personas::deactivate_persona),
        )
        .route("/personas/:id/archive", post(personas::archive_persona))
        .route(
            "/personas/:id/propagate-attributes",
            post(personas::propagate_attributes),
        )
        .route("/personas/:id/audit", get(personas::get_persona_audit))
        // User Personas (F063)
        .route("/users/:user_id/personas", get(personas::get_user_personas))
        // Persona Audit (F063)
        .route("/persona-audit", get(personas::list_audit_events))
        // Context Switching (F063)
        .route("/context/switch", post(personas::switch_context))
        .route("/context/switch-back", post(personas::switch_back))
        .route("/context/current", get(personas::get_current_context))
        .route("/context/sessions", get(personas::list_context_sessions))
        // Persona Expiration (F063)
        .route("/personas/:id/extend", post(personas::extend_persona))
        .route("/personas/expiring", get(personas::get_expiring_personas))
        // Power of Attorney (F-061)
        .route(
            "/power-of-attorney",
            get(power_of_attorney::list_poa).post(power_of_attorney::grant_poa),
        )
        .route("/power-of-attorney/:id", get(power_of_attorney::get_poa))
        .route(
            "/power-of-attorney/:id/revoke",
            post(power_of_attorney::revoke_poa),
        )
        .route(
            "/power-of-attorney/:id/extend",
            post(power_of_attorney::extend_poa),
        )
        .route(
            "/power-of-attorney/:id/assume",
            post(power_of_attorney::assume_identity),
        )
        .route(
            "/power-of-attorney/drop",
            post(power_of_attorney::drop_identity),
        )
        .route(
            "/power-of-attorney/current-assumption",
            get(power_of_attorney::get_current_assumption),
        )
        .route(
            "/power-of-attorney/:id/audit",
            get(power_of_attorney::get_poa_audit_trail),
        )
        // Power of Attorney Admin (F-061)
        .route(
            "/admin/power-of-attorney",
            get(power_of_attorney::admin_list_poa),
        )
        .route(
            "/admin/power-of-attorney/:id/revoke",
            post(power_of_attorney::admin_revoke_poa),
        )
        // SLA Policies (F064)
        .route(
            "/sla-policies",
            get(sla_policies::list_sla_policies).post(sla_policies::create_sla_policy),
        )
        .route(
            "/sla-policies/:id",
            get(sla_policies::get_sla_policy)
                .put(sla_policies::update_sla_policy)
                .delete(sla_policies::delete_sla_policy),
        )
        // Ticketing Configurations (F064)
        .route(
            "/ticketing-configurations",
            get(ticketing_config::list_ticketing_configurations)
                .post(ticketing_config::create_ticketing_configuration),
        )
        .route(
            "/ticketing-configurations/:id",
            get(ticketing_config::get_ticketing_configuration)
                .put(ticketing_config::update_ticketing_configuration)
                .delete(ticketing_config::delete_ticketing_configuration),
        )
        .route(
            "/ticketing-configurations/:id/test",
            post(ticketing_config::test_ticketing_configuration),
        )
        // Manual Provisioning Tasks (F064)
        .route("/manual-tasks", get(manual_tasks::list_manual_tasks))
        .route(
            "/manual-tasks/dashboard",
            get(manual_tasks::get_manual_task_dashboard),
        )
        .route("/manual-tasks/:id", get(manual_tasks::get_manual_task))
        .route(
            "/manual-tasks/:id/claim",
            post(manual_tasks::claim_manual_task),
        )
        .route(
            "/manual-tasks/:id/start",
            post(manual_tasks::start_manual_task),
        )
        .route(
            "/manual-tasks/:id/confirm",
            post(manual_tasks::confirm_manual_task),
        )
        .route(
            "/manual-tasks/:id/reject",
            post(manual_tasks::reject_manual_task),
        )
        .route(
            "/manual-tasks/:id/cancel",
            post(manual_tasks::cancel_manual_task),
        )
        // Semi-manual Application Configuration (F064)
        .route(
            "/semi-manual/applications",
            get(semi_manual::list_semi_manual_applications),
        )
        .route(
            "/semi-manual/applications/:id",
            get(semi_manual::get_semi_manual_config)
                .put(semi_manual::configure_semi_manual)
                .delete(semi_manual::remove_semi_manual_config),
        )
        // Ticketing Webhooks (F064) - no auth required, uses secret
        .route(
            "/webhooks/ticketing/:configuration_id",
            post(ticketing_webhook::handle_webhook_callback),
        )
        // Ticket Sync Admin (F064)
        .route(
            "/admin/tickets/sync",
            post(ticketing_webhook::trigger_ticket_sync),
        )
        .route(
            "/admin/tickets/:ticket_id/sync",
            post(ticketing_webhook::sync_single_ticket),
        )
        // License Pools (F065)
        .route(
            "/license-pools",
            get(license_pools::list_license_pools).post(license_pools::create_license_pool),
        )
        .route(
            "/license-pools/:id",
            get(license_pools::get_license_pool)
                .put(license_pools::update_license_pool)
                .delete(license_pools::delete_license_pool),
        )
        .route(
            "/license-pools/:id/archive",
            post(license_pools::archive_license_pool),
        )
        // License Assignments (F065)
        .route(
            "/license-assignments",
            get(license_assignments::list_assignments).post(license_assignments::create_assignment),
        )
        .route(
            "/license-assignments/bulk",
            post(license_assignments::bulk_assign),
        )
        .route(
            "/license-assignments/bulk-reclaim",
            post(license_assignments::bulk_reclaim),
        )
        .route(
            "/license-assignments/:id",
            get(license_assignments::get_assignment)
                .delete(license_assignments::deallocate_assignment),
        )
        // License Entitlement Links (F065)
        .route(
            "/license-entitlement-links",
            get(license_entitlement_links::list_links).post(license_entitlement_links::create_link),
        )
        .route(
            "/license-entitlement-links/:id",
            get(license_entitlement_links::get_link).delete(license_entitlement_links::delete_link),
        )
        .route(
            "/license-entitlement-links/:id/enabled",
            put(license_entitlement_links::set_link_enabled),
        )
        // License Incompatibilities (F065)
        .route(
            "/license-incompatibilities",
            get(license_incompatibilities::list_incompatibilities)
                .post(license_incompatibilities::create_incompatibility),
        )
        .route(
            "/license-incompatibilities/:id",
            get(license_incompatibilities::get_incompatibility)
                .delete(license_incompatibilities::delete_incompatibility),
        )
        // License Reclamation Rules (F065)
        .route(
            "/license-reclamation-rules",
            get(license_reclamation::list_rules).post(license_reclamation::create_rule),
        )
        .route(
            "/license-reclamation-rules/:id",
            get(license_reclamation::get_rule)
                .put(license_reclamation::update_rule)
                .delete(license_reclamation::delete_rule),
        )
        // License Analytics (F065)
        .route(
            "/license-analytics/dashboard",
            get(license_analytics::get_dashboard),
        )
        .route(
            "/license-analytics/recommendations",
            get(license_analytics::get_recommendations),
        )
        .route(
            "/license-analytics/expiring",
            get(license_analytics::get_expiring_pools),
        )
        // License Reports (F065)
        .route(
            "/license-reports/compliance",
            post(license_reports::generate_compliance_report),
        )
        .route(
            "/license-reports/audit-trail",
            get(license_reports::get_audit_trail),
        )
        // Provisioning Scripts (F066)
        .route(
            "/scripts",
            get(provisioning_scripts::list_scripts).post(provisioning_scripts::create_script),
        )
        .route("/scripts/validate", post(script_testing::validate_script))
        .route("/scripts/dry-run", post(script_testing::dry_run_raw))
        .route(
            "/scripts/:id",
            get(provisioning_scripts::get_script)
                .put(provisioning_scripts::update_script)
                .delete(provisioning_scripts::delete_script),
        )
        .route(
            "/scripts/:id/activate",
            post(provisioning_scripts::activate_script),
        )
        .route(
            "/scripts/:id/deactivate",
            post(provisioning_scripts::deactivate_script),
        )
        .route(
            "/scripts/:id/versions",
            get(provisioning_scripts::list_script_versions)
                .post(provisioning_scripts::create_script_version),
        )
        .route(
            "/scripts/:script_id/versions/compare",
            get(provisioning_scripts::compare_versions),
        )
        .route(
            "/scripts/:script_id/versions/:version_number",
            get(provisioning_scripts::get_script_version),
        )
        .route(
            "/scripts/:script_id/versions/:version_number/dry-run",
            post(script_testing::dry_run_version),
        )
        .route(
            "/scripts/:id/rollback",
            post(provisioning_scripts::rollback_script),
        )
        // Script Hook Bindings (F066)
        .route(
            "/script-bindings",
            get(script_hook_bindings::list_bindings).post(script_hook_bindings::create_binding),
        )
        .route(
            "/script-bindings/:id",
            get(script_hook_bindings::get_binding)
                .put(script_hook_bindings::update_binding)
                .delete(script_hook_bindings::delete_binding),
        )
        .route(
            "/connectors/:connector_id/script-bindings",
            get(script_hook_bindings::list_bindings_by_connector),
        )
        // Script Templates (F066)
        .route(
            "/script-templates",
            get(script_templates::list_templates).post(script_templates::create_template),
        )
        .route(
            "/script-templates/:id",
            get(script_templates::get_template)
                .put(script_templates::update_template)
                .delete(script_templates::delete_template),
        )
        .route(
            "/script-templates/:id/instantiate",
            post(script_templates::instantiate_template),
        )
        // Script Analytics (F066)
        .route(
            "/script-analytics/dashboard",
            get(script_analytics::get_dashboard),
        )
        .route(
            "/script-analytics/scripts/:script_id",
            get(script_analytics::get_script_analytics),
        )
        // Script Execution Logs (F066)
        .route(
            "/script-execution-logs",
            get(script_analytics::list_execution_logs),
        )
        .route(
            "/script-execution-logs/:id",
            get(script_analytics::get_execution_log),
        )
        // Script Audit Events (F066)
        .route(
            "/script-audit-events",
            get(script_analytics::list_script_audit_events),
        )
        // Correlation Rules (F067)
        .route(
            "/connectors/:connector_id/correlation/rules",
            get(correlation_rules::list_correlation_rules)
                .post(correlation_rules::create_correlation_rule),
        )
        .route(
            "/connectors/:connector_id/correlation/rules/validate-expression",
            post(correlation_rules::validate_expression),
        )
        .route(
            "/connectors/:connector_id/correlation/rules/:id",
            get(correlation_rules::get_correlation_rule)
                .patch(correlation_rules::update_correlation_rule)
                .delete(correlation_rules::delete_correlation_rule),
        )
        // Correlation Thresholds (F067)
        .route(
            "/connectors/:connector_id/correlation/thresholds",
            get(correlation_thresholds::get_correlation_thresholds)
                .put(correlation_thresholds::upsert_correlation_thresholds),
        )
        // Correlation Engine Evaluation (F067)
        .route(
            "/connectors/:connector_id/correlation/evaluate",
            post(correlation_engine::trigger_correlation),
        )
        .route(
            "/connectors/:connector_id/correlation/jobs/:job_id",
            get(correlation_engine::get_correlation_job_status),
        )
        // Correlation Cases - Review Queue (F067)
        .route(
            "/correlation/cases",
            get(correlation_cases::list_correlation_cases),
        )
        .route(
            "/correlation/cases/:case_id",
            get(correlation_cases::get_correlation_case),
        )
        .route(
            "/correlation/cases/:case_id/confirm",
            post(correlation_cases::confirm_correlation_case),
        )
        .route(
            "/correlation/cases/:case_id/reject",
            post(correlation_cases::reject_correlation_case),
        )
        .route(
            "/correlation/cases/:case_id/create-identity",
            post(correlation_cases::create_identity_from_case),
        )
        .route(
            "/correlation/cases/:case_id/reassign",
            post(correlation_cases::reassign_correlation_case),
        )
        // Correlation Audit Trail (F067)
        .route(
            "/correlation/audit",
            get(correlation_audit::list_correlation_audit_events),
        )
        .route(
            "/correlation/audit/:event_id",
            get(correlation_audit::get_correlation_audit_event),
        )
        // Correlation Statistics (F067)
        .route(
            "/connectors/:connector_id/correlation/statistics",
            get(correlation_stats::get_correlation_statistics),
        )
        .route(
            "/connectors/:connector_id/correlation/statistics/trends",
            get(correlation_stats::get_correlation_trends),
        )
        // SIEM Destinations (F078)
        .route(
            "/siem/destinations",
            get(siem::list_destinations).post(siem::create_destination),
        )
        .route(
            "/siem/destinations/:id",
            get(siem::get_destination)
                .put(siem::update_destination)
                .delete(siem::delete_destination),
        )
        .route("/siem/destinations/:id/test", post(siem::test_destination))
        // SIEM Batch Exports (F078)
        .route(
            "/siem/exports",
            get(siem::list_batch_exports).post(siem::create_batch_export),
        )
        .route("/siem/exports/:id", get(siem::get_batch_export))
        .route(
            "/siem/exports/:id/download",
            get(siem::download_batch_export),
        )
        // SIEM Health & Dead Letter (F078)
        .route(
            "/siem/destinations/:id/health",
            get(siem::get_destination_health),
        )
        .route(
            "/siem/destinations/:id/health/history",
            get(siem::get_delivery_history),
        )
        .route(
            "/siem/destinations/:id/dead-letter",
            get(siem::list_dead_letter),
        )
        .route(
            "/siem/destinations/:id/dead-letter/redeliver",
            post(siem::redeliver_dead_letter),
        )
        // Business Role Hierarchy (F088)
        .route("/roles", get(role_hierarchy::list_roles))
        .route("/roles", post(role_hierarchy::create_role))
        .route("/roles/tree", get(role_hierarchy::get_tree))
        .route("/roles/:role_id", get(role_hierarchy::get_role))
        .route("/roles/:role_id", put(role_hierarchy::update_role))
        .route("/roles/:role_id", delete(role_hierarchy::delete_role))
        .route(
            "/roles/:role_id/ancestors",
            get(role_hierarchy::get_ancestors),
        )
        .route(
            "/roles/:role_id/descendants",
            get(role_hierarchy::get_descendants),
        )
        .route(
            "/roles/:role_id/children",
            get(role_hierarchy::get_children),
        )
        .route("/roles/:role_id/move", post(role_hierarchy::move_role))
        .route("/roles/:role_id/impact", get(role_hierarchy::get_impact))
        // Role Entitlements (F088)
        .route(
            "/roles/:role_id/entitlements",
            get(role_entitlements::list_role_entitlements),
        )
        .route(
            "/roles/:role_id/entitlements",
            post(role_entitlements::add_role_entitlement),
        )
        .route(
            "/roles/:role_id/entitlements/:entitlement_id",
            delete(role_entitlements::remove_role_entitlement),
        )
        .route(
            "/roles/:role_id/effective-entitlements",
            get(role_entitlements::get_effective_entitlements),
        )
        .route(
            "/roles/:role_id/effective-entitlements/recompute",
            post(role_entitlements::recompute_effective_entitlements),
        )
        // Role Inheritance Blocks (F088)
        .route(
            "/roles/:role_id/inheritance-blocks",
            get(role_inheritance_blocks::list_inheritance_blocks),
        )
        .route(
            "/roles/:role_id/inheritance-blocks",
            post(role_inheritance_blocks::add_inheritance_block),
        )
        .route(
            "/roles/:role_id/inheritance-blocks/:block_id",
            delete(role_inheritance_blocks::remove_inheritance_block),
        )
        // Identity Archetypes (F-058)
        .route("/archetypes", get(archetypes::list_archetypes))
        .route("/archetypes", post(archetypes::create_archetype))
        .route("/archetypes/:id", get(archetypes::get_archetype))
        .route("/archetypes/:id", put(archetypes::update_archetype))
        .route("/archetypes/:id", delete(archetypes::delete_archetype))
        .route(
            "/archetypes/:id/ancestry",
            get(archetypes::get_archetype_ancestry),
        )
        .route(
            "/archetypes/:id/policies",
            get(archetypes::list_archetype_policies),
        )
        .route(
            "/archetypes/:id/policies",
            post(archetypes::bind_archetype_policy),
        )
        .route(
            "/archetypes/:id/policies/:policy_type",
            delete(archetypes::unbind_archetype_policy),
        )
        .route(
            "/archetypes/:id/effective-policies",
            get(archetypes::get_effective_policies),
        )
        // Archetype Lifecycle Assignment (F-193)
        .route(
            "/archetypes/:archetype_id/lifecycle",
            get(archetypes::get_archetype_lifecycle),
        )
        .route(
            "/archetypes/:archetype_id/lifecycle",
            put(archetypes::assign_archetype_lifecycle),
        )
        .route(
            "/archetypes/:archetype_id/lifecycle",
            delete(archetypes::remove_archetype_lifecycle),
        )
        // User Archetype Assignment (F-058)
        .route(
            "/users/:user_id/archetype",
            get(archetypes::get_user_archetype),
        )
        .route(
            "/users/:user_id/archetype",
            put(archetypes::assign_user_archetype),
        )
        .route(
            "/users/:user_id/archetype",
            delete(archetypes::remove_user_archetype),
        )
        // Self-Service Request Catalog routes (F-062)
        // Browse routes (US1)
        .route("/catalog/categories", get(catalog::list_catalog_categories))
        .route(
            "/catalog/categories/:id",
            get(catalog::get_catalog_category),
        )
        .route("/catalog/items", get(catalog::list_catalog_items))
        .route("/catalog/items/:id", get(catalog::get_catalog_item))
        // Admin catalog routes (US5)
        .route(
            "/admin/catalog/categories",
            get(catalog::admin_list_catalog_categories),
        )
        .route(
            "/admin/catalog/categories",
            post(catalog::create_catalog_category),
        )
        .route(
            "/admin/catalog/categories/:id",
            put(catalog::update_catalog_category),
        )
        .route(
            "/admin/catalog/categories/:id",
            delete(catalog::delete_catalog_category),
        )
        .route(
            "/admin/catalog/items",
            get(catalog::admin_list_catalog_items),
        )
        .route("/admin/catalog/items", post(catalog::create_catalog_item))
        .route(
            "/admin/catalog/items/:id",
            put(catalog::update_catalog_item),
        )
        .route(
            "/admin/catalog/items/:id",
            delete(catalog::delete_catalog_item),
        )
        .route(
            "/admin/catalog/items/:id/enable",
            post(catalog::enable_catalog_item),
        )
        .route(
            "/admin/catalog/items/:id/disable",
            post(catalog::disable_catalog_item),
        )
        // Cart routes (US2)
        .route(
            "/catalog/cart",
            get(catalog::get_cart).delete(catalog::clear_cart),
        )
        .route("/catalog/cart/items", post(catalog::add_to_cart))
        .route(
            "/catalog/cart/items/:item_id",
            put(catalog::update_cart_item).delete(catalog::remove_from_cart),
        )
        // Cart validation & submission routes (US3)
        .route("/catalog/cart/validate", post(catalog::validate_cart))
        .route("/catalog/cart/submit", post(catalog::submit_cart))
        // Role Constructions (F-063)
        .route(
            "/roles/:role_id/constructions",
            get(role_constructions::list_role_constructions)
                .post(role_constructions::create_role_construction),
        )
        .route(
            "/roles/:role_id/constructions/:construction_id",
            get(role_constructions::get_role_construction)
                .put(role_constructions::update_role_construction)
                .delete(role_constructions::delete_role_construction),
        )
        .route(
            "/roles/:role_id/constructions/:construction_id/enable",
            post(role_constructions::enable_role_construction),
        )
        .route(
            "/roles/:role_id/constructions/:construction_id/disable",
            post(role_constructions::disable_role_construction),
        )
        // Role Inducements (F-063)
        .route(
            "/roles/:role_id/inducements",
            get(role_inducements::list_role_inducements)
                .post(role_inducements::create_role_inducement),
        )
        .route(
            "/roles/:role_id/inducements/:inducement_id",
            get(role_inducements::get_role_inducement)
                .delete(role_inducements::delete_role_inducement),
        )
        .route(
            "/roles/:role_id/inducements/:inducement_id/enable",
            post(role_inducements::enable_role_inducement),
        )
        .route(
            "/roles/:role_id/inducements/:inducement_id/disable",
            post(role_inducements::disable_role_inducement),
        )
        .route(
            "/roles/:role_id/induced-roles",
            get(role_inducements::get_induced_roles),
        )
        // Role Effective Constructions (F-063)
        .route(
            "/roles/:role_id/effective-constructions",
            get(role_constructions::get_role_effective_constructions),
        )
        // User Effective Constructions (F-063)
        .route(
            "/users/:user_id/effective-constructions",
            get(role_constructions::get_user_effective_constructions),
        )
        // Role Assignments with Construction Triggering (F-063)
        .route(
            "/roles/:role_id/assignments/:user_id",
            get(role_assignments::check_user_has_role)
                .post(role_assignments::assign_role)
                .delete(role_assignments::revoke_role),
        )
        .route(
            "/users/:user_id/roles",
            get(role_assignments::list_user_roles),
        )
        // Bulk Action Engine routes (F-064 Bulk Actions)
        .route(
            "/admin/bulk-actions",
            get(bulk_actions::list_bulk_actions).post(bulk_actions::create_bulk_action),
        )
        .route(
            "/admin/bulk-actions/validate-expression",
            post(bulk_actions::validate_expression),
        )
        .route(
            "/admin/bulk-actions/:id",
            get(bulk_actions::get_bulk_action).delete(bulk_actions::delete_bulk_action),
        )
        .route(
            "/admin/bulk-actions/:id/preview",
            post(bulk_actions::preview_bulk_action),
        )
        .route(
            "/admin/bulk-actions/:id/execute",
            post(bulk_actions::execute_bulk_action),
        )
        .route(
            "/admin/bulk-actions/:id/cancel",
            post(bulk_actions::cancel_bulk_action),
        )
        .with_state(state)
}
