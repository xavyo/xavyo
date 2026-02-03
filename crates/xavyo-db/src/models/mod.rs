//! Database entity models for xavyo-db.
//!
//! These models represent the database tables and provide
//! type-safe interactions with PostgreSQL.

pub mod admin_audit_log;

// Core tenant model (F095)
pub mod admin_permission;
pub mod admin_role_template;
pub mod admin_role_template_permission;
pub mod authorization_code;
pub mod branding_asset;
pub mod email_change_request;
pub mod email_template;
pub mod email_verification_token;
pub mod failed_login_attempt;
pub mod federated_auth_session;
pub mod group;
pub mod group_membership;
pub mod identity_provider_domain;
pub mod ip_restriction_rule;
pub mod lockout_policy;
pub mod login_attempt;
pub mod mfa_audit_log;
pub mod mfa_policy;
pub mod mfa_secret;
pub mod oauth_client;
pub mod oauth_refresh_token;
pub mod password_history;
pub mod password_policy;
pub mod password_reset_token;
pub mod processed_event;
pub mod recovery_code;
pub mod refresh_token;
pub mod saml_service_provider;
pub mod scim_attribute_mapping;
pub mod scim_audit_log;
pub mod scim_token;
pub mod security_alert;
pub mod session;
pub mod session_policy;
pub mod social_connection;
pub mod tenant;
pub mod tenant_branding;
pub mod tenant_identity_provider;
pub mod tenant_idp_certificate;
pub mod tenant_ip_settings;
pub mod tenant_social_provider;
pub mod user;
pub mod user_admin_assignment;
pub mod user_device;
pub mod user_identity_link;
pub mod user_location;
pub mod user_role;
pub mod webauthn_audit;
pub mod webauthn_challenge;
pub mod webauthn_credential;
pub mod webauthn_policy;

// Plan Management models (F-PLAN-MGMT)
pub mod plan;

// Governance models (F033)
pub mod gov_application;
pub mod gov_entitlement;
pub mod gov_entitlement_assignment;
pub mod gov_role_entitlement;

// SoD models (F034)
pub mod gov_sod_exemption;
pub mod gov_sod_rule;
pub mod gov_sod_violation;

// Access Request Workflow models (F035)
pub mod gov_access_request;
pub mod gov_approval_decision;
pub mod gov_approval_delegation;
pub mod gov_approval_step;
pub mod gov_approval_workflow;

// Certification Campaign models (F036)
pub mod gov_certification_campaign;
pub mod gov_certification_decision;
pub mod gov_certification_item;

// Lifecycle Workflow models (F037)
pub mod gov_access_snapshot;
pub mod gov_birthright_policy;
pub mod gov_lifecycle_action;
pub mod gov_lifecycle_event;

// Risk Scoring models (F039)
pub mod gov_peer_group;
pub mod gov_risk_alert;
pub mod gov_risk_enforcement_policy;
pub mod gov_risk_event;
pub mod gov_risk_factor;
pub mod gov_risk_score;
pub mod gov_risk_score_history;
pub mod gov_risk_threshold;

// Orphan Account Detection models (F040)
pub mod gov_detection_rule;
pub mod gov_orphan_detection;
pub mod gov_reconciliation_run;
pub mod gov_remediation_log;
pub mod gov_service_account;

// Compliance Reporting models (F042)
pub mod gov_generated_report;
pub mod gov_report_schedule;
pub mod gov_report_template;

// Role Mining and Analytics models (F041)
pub mod gov_access_pattern;
pub mod gov_consolidation_suggestion;
pub mod gov_excessive_privilege;
pub mod gov_role_candidate;
pub mod gov_role_metrics;
pub mod gov_role_mining_job;
pub mod gov_role_simulation;

pub use admin_audit_log::{
    AdminAction, AdminAuditLog, AdminResourceType, AuditLogFilter, CreateAuditLogEntry,
};
pub use admin_permission::{AdminPermission, CategorySummary, PermissionCategory};
pub use admin_role_template::{AdminRoleTemplate, CreateRoleTemplate, UpdateRoleTemplate};
pub use admin_role_template_permission::AdminRoleTemplatePermission;
pub use authorization_code::{
    AuthorizationCode, AuthorizationCodeBuilder, NewAuthorizationCode, AUTH_CODE_EXPIRY_MINUTES,
};
pub use branding_asset::{AssetListFilter, AssetType, BrandingAsset, CreateBrandingAsset};
pub use email_change_request::EmailChangeRequest;
pub use email_template::{
    EmailTemplate, EmailTemplateSummary, TemplateType, TemplateVariable, UpsertEmailTemplate,
};
pub use email_verification_token::{EmailVerificationToken, EmailVerificationTokenBuilder};
pub use failed_login_attempt::{FailedLoginAttempt, FailureReason};
pub use federated_auth_session::{
    CreateFederatedAuthSession, FederatedAuthSession, SESSION_EXPIRY_MINUTES,
};
pub use group::{CreateGroup, Group, UpdateGroup};
pub use group_membership::{GroupMemberInfo, GroupMembership, UserGroupInfo};
pub use identity_provider_domain::{CreateDomain, IdentityProviderDomain};
pub use ip_restriction_rule::{
    CreateIpRule, IpRestrictionRule, IpRuleType, ListRulesFilter, UpdateIpRule,
};
pub use lockout_policy::{TenantLockoutPolicy, UpsertLockoutPolicy};
pub use login_attempt::{AuthMethod, CreateLoginAttempt, LoginAttempt};
pub use mfa_audit_log::{CreateMfaAuditLog, MfaAuditAction, MfaAuditLog};
pub use mfa_policy::TenantMfaPolicy;
pub use mfa_secret::{CreateTotpSecret, MfaPolicy, UserTotpSecret};
pub use oauth_client::{ClientType, NewOAuth2Client, OAuth2Client, OAuth2ClientBuilder};
pub use oauth_refresh_token::{
    NewOAuthRefreshToken, OAuthRefreshToken, OAuthRefreshTokenBuilder, REFRESH_TOKEN_EXPIRY_DAYS,
};
pub use password_history::PasswordHistory;
pub use password_policy::{TenantPasswordPolicy, UpsertPasswordPolicy};
pub use password_reset_token::{PasswordResetToken, PasswordResetTokenBuilder};
pub use processed_event::{CreateProcessedEvent, ProcessedEvent};
pub use recovery_code::UserRecoveryCode;
pub use refresh_token::{RefreshToken, RefreshTokenBuilder};
pub use saml_service_provider::{
    AttributeMap, AttributeMapping, CreateServiceProviderRequest, SamlServiceProvider,
    UpdateServiceProviderRequest,
};
pub use scim_attribute_mapping::{
    AttributeTransform, MappingRequest, ScimAttributeMapping, UpdateMappingsRequest,
};
pub use scim_audit_log::{CreateAuditLog, ScimAuditLog, ScimOperation, ScimResourceType};
pub use scim_token::{CreateScimToken, ScimToken, ScimTokenCreated, ScimTokenInfo};
pub use security_alert::{AlertType, CreateSecurityAlert, SecurityAlert, Severity};
pub use session::{CreateSession, RevokeReason, Session, SessionInfo};
pub use session_policy::{TenantSessionPolicy, UpsertSessionPolicy};
pub use social_connection::{CreateSocialConnection, SocialConnection, UpdateSocialConnection};
pub use tenant_branding::{PublicBranding, TenantBranding, UpdateBranding};
pub use tenant_identity_provider::{
    CreateIdentityProvider, ProviderType, TenantIdentityProvider, UpdateIdentityProvider,
    ValidationStatus,
};
pub use tenant_idp_certificate::{CertificateInfo, TenantIdpCertificate, UploadCertificateRequest};
pub use tenant_ip_settings::{IpEnforcementMode, TenantIpSettings, UpdateIpSettings};
pub use tenant_social_provider::{TenantSocialProvider, UpsertTenantSocialProvider};
pub use user::User;
pub use user_admin_assignment::{
    AssignmentFilter, CreateAssignment, ScopeType, UserAdminAssignment,
};
pub use user_device::{DeviceType, UserDevice};
pub use user_identity_link::{CreateUserIdentityLink, UpdateUserIdentityLink, UserIdentityLink};
pub use user_location::UserLocation;
pub use user_role::UserRole;
pub use webauthn_audit::{
    CreateWebAuthnAuditLog, WebAuthnAuditAction, WebAuthnAuditLog, WebAuthnAuditLogFilter,
};
pub use webauthn_challenge::{
    CeremonyType, CreateWebAuthnChallenge, WebAuthnChallenge, CHALLENGE_EXPIRY_MINUTES,
};
pub use webauthn_credential::{
    AuthenticatorType, CreateWebAuthnCredential, CredentialInfo, UserWebAuthnCredential,
};
pub use webauthn_policy::{
    TenantWebAuthnPolicy, UpsertWebAuthnPolicy, UserVerification, DEFAULT_MAX_CREDENTIALS,
};

// Plan Management exports (F-PLAN-MGMT)
pub use plan::{
    next_billing_cycle_date, PlanChangeStatus, PlanChangeType, PlanDefinition, PlanTier,
    TenantPlanChange,
};

// Governance exports (F033)
pub use gov_application::{
    CreateGovApplication, GovAppStatus, GovAppType, GovApplication, UpdateGovApplication,
};
pub use gov_entitlement::{
    CreateGovEntitlement, EntitlementFilter, GovEntitlement, GovEntitlementStatus, GovRiskLevel,
    UpdateGovEntitlement,
};
pub use gov_entitlement_assignment::{
    BulkAssignmentFailure, BulkAssignmentRequest, BulkAssignmentResult, CreateGovAssignment,
    GovAssignmentFilter, GovAssignmentStatus, GovAssignmentTargetType, GovEntitlementAssignment,
};
pub use gov_role_entitlement::{
    CreateGovRoleEntitlement, GovRoleEntitlement, RoleEntitlementFilter,
};

// SoD exports (F034)
pub use gov_sod_exemption::{
    CreateGovSodExemption, GovExemptionStatus, GovSodExemption, SodExemptionFilter,
};
pub use gov_sod_rule::{
    CreateGovSodRule, GovSodRule, GovSodRuleStatus, GovSodSeverity, SodRuleFilter, UpdateGovSodRule,
};
pub use gov_sod_violation::{
    CreateGovSodViolation, GovSodViolation, GovViolationStatus, SodViolationFilter,
};

// Access Request Workflow exports (F035)
pub use gov_access_request::{
    AccessRequestFilter, CreateGovAccessRequest, GovAccessRequest, GovRequestStatus,
};
pub use gov_approval_decision::{CreateGovApprovalDecision, GovApprovalDecision, GovDecisionType};
pub use gov_approval_delegation::{
    CreateGovApprovalDelegation, DelegationFilter, GovApprovalDelegation,
};
pub use gov_approval_step::{CreateGovApprovalStep, GovApprovalStep, GovApproverType};
pub use gov_approval_workflow::{
    CreateGovApprovalWorkflow, GovApprovalWorkflow, UpdateGovApprovalWorkflow, WorkflowFilter,
};

// Certification Campaign exports (F036)
pub use gov_certification_campaign::{
    CampaignFilter, CertCampaignStatus, CertReviewerType, CertScopeType,
    CreateCertificationCampaign, GovCertificationCampaign, UpdateCertificationCampaign,
};
pub use gov_certification_decision::{
    CertDecisionType, CreateCertificationDecision, GovCertificationDecision,
};
pub use gov_certification_item::{
    CertItemFilter, CertItemStatus, CertItemSummary, CreateCertificationItem, GovCertificationItem,
};

// Lifecycle Workflow exports (F037)
pub use gov_access_snapshot::{
    AccessSnapshotFilter, AccessSnapshotType, CreateAccessSnapshot, GovAccessSnapshot,
    SnapshotAssignment, SnapshotContent,
};
pub use gov_birthright_policy::{
    BirthrightPolicyFilter, BirthrightPolicyStatus, ConditionOperator, CreateBirthrightPolicy,
    EvaluationMode, GovBirthrightPolicy, PolicyCondition, UpdateBirthrightPolicy,
};
pub use gov_lifecycle_action::{
    CreateLifecycleAction, GovLifecycleAction, LifecycleActionFilter, LifecycleActionType,
};
pub use gov_lifecycle_event::{
    CreateLifecycleEvent, GovLifecycleEvent, LifecycleEventFilter, LifecycleEventType,
};

// Risk Enforcement Policy exports (F073)
pub use gov_risk_enforcement_policy::{
    EnforcementMode, GovRiskEnforcementPolicy, UpsertEnforcementPolicy,
};

// Risk Scoring exports (F039)
pub use gov_peer_group::{
    CreateGovPeerGroup, GovPeerGroup, GovPeerGroupMember, OutlierSeverity, PeerComparison,
    PeerGroupFilter, PeerGroupType, UpdateGovPeerGroupStats,
};
pub use gov_risk_alert::{CreateGovRiskAlert, GovRiskAlert, RiskAlertFilter, RiskAlertSortBy};
pub use gov_risk_event::{CreateGovRiskEvent, GovRiskEvent, RiskEventFilter};
pub use gov_risk_factor::{
    CreateGovRiskFactor, GovRiskFactor, RiskFactorCategory, RiskFactorFilter, UpdateGovRiskFactor,
};
pub use gov_risk_score::{
    GovRiskScore, RiskLevel, RiskScoreFilter, RiskScoreSortBy, UpsertGovRiskScore,
};
pub use gov_risk_score_history::{
    CreateGovRiskScoreHistory, GovRiskScoreHistory, RiskScoreTrend, TrendDirection,
};
pub use gov_risk_threshold::{
    AlertSeverity, CreateGovRiskThreshold, GovRiskThreshold, RiskThresholdFilter, ThresholdAction,
    UpdateGovRiskThreshold,
};

// Orphan Account Detection exports (F040)
pub use gov_detection_rule::{
    CreateGovDetectionRule, DetectionRuleFilter, DetectionRuleType, GovDetectionRule,
    UpdateGovDetectionRule,
};
pub use gov_orphan_detection::{
    CreateGovOrphanDetection, DetectionReason, GovOrphanDetection, OrphanDetectionFilter,
    OrphanStatus, RemediateGovOrphanDetection, RemediationAction,
};
pub use gov_reconciliation_run::{
    CreateGovReconciliationRun, GovReconciliationRun, ReconciliationRunFilter,
    ReconciliationStatus, UpdateGovReconciliationRun,
};
pub use gov_remediation_log::{CreateGovRemediationLog, GovRemediationLog, RemediationLogFilter};
pub use gov_service_account::{
    CreateGovServiceAccount, GovServiceAccount, ServiceAccountFilter, ServiceAccountStatus,
    UpdateGovServiceAccount,
};

// Compliance Reporting exports (F042)
pub use gov_generated_report::{
    GenerateReportRequest, GeneratedReportFilter, GovGeneratedReport, OutputFormat, ReportStatus,
    DEFAULT_RETENTION_YEARS,
};
pub use gov_report_schedule::{
    CreateReportSchedule, GovReportSchedule, ReportScheduleFilter, ScheduleFrequency,
    ScheduleStatus, UpdateReportSchedule, MAX_CONSECUTIVE_FAILURES,
};
pub use gov_report_template::{
    CloneReportTemplate, ColumnDefinition, ComplianceStandard, CreateReportTemplate,
    FilterDefinition, GovReportTemplate, ReportTemplateFilter, ReportTemplateType, SortDefinition,
    TemplateDefinition, TemplateStatus, UpdateReportTemplate,
};

// Role Mining and Analytics exports (F041)
pub use gov_access_pattern::{AccessPatternFilter, CreateAccessPattern, GovAccessPattern};
pub use gov_consolidation_suggestion::{
    ConsolidationStatus, ConsolidationSuggestionFilter, CreateConsolidationSuggestion,
    GovConsolidationSuggestion,
};
pub use gov_excessive_privilege::{
    CreateExcessivePrivilege, ExcessivePrivilegeFilter, GovExcessivePrivilege, PrivilegeFlagStatus,
    UpdateExcessivePrivilegeStatus,
};
pub use gov_role_candidate::{
    CandidatePromotionStatus, CreateRoleCandidate, GovRoleCandidate, RoleCandidateFilter,
};
pub use gov_role_metrics::{
    CreateRoleMetrics, EntitlementUsage, GovRoleMetrics, RoleMetricsFilter,
    TrendDirection as MetricsTrendDirection,
};
pub use gov_role_mining_job::{
    CreateMiningJob, GovRoleMiningJob, MiningJobFilter, MiningJobParameters, MiningJobStatus,
    UpdateJobProgress,
};
pub use gov_role_simulation::{
    AccessChange, CreateRoleSimulation, GovRoleSimulation, RoleSimulationFilter, ScenarioType,
    SimulationChanges, SimulationStatus,
};

// Connector Framework models (F045)
pub mod attribute_mapping;
pub mod connector_configuration;
pub mod connector_health;
pub mod connector_schema;
pub mod operation_log;
pub mod provisioning_operation;

// Schema Discovery models (F046)
pub mod connector_schema_version;
pub mod schema_refresh_schedule;

// Provisioning Consistency models (F047)
pub mod conflict_record;
pub mod operation_attempt;

// Live Synchronization models (F048)
pub mod inbound_change;
pub mod sync_configuration;
pub mod sync_conflict;
pub mod sync_status;
pub mod sync_token;

// Reconciliation Engine models (F049)
pub mod connector_reconciliation_run;
pub mod reconciliation_action;
pub mod reconciliation_discrepancy;
pub mod reconciliation_schedule;

// Connector Framework exports (F045)
pub use attribute_mapping::{
    AttributeMapping as ConnectorAttributeMapping,
    CreateAttributeMapping as CreateConnectorAttributeMapping, DeprovisionAction,
    MappingFilter as ConnectorMappingFilter,
    UpdateAttributeMapping as UpdateConnectorAttributeMapping,
};
pub use connector_configuration::{
    ConnectorConfiguration, ConnectorFilter, ConnectorStatus, ConnectorSummary, ConnectorType,
    CreateConnectorConfiguration, UpdateConnectorConfiguration,
};
pub use connector_health::{
    CircuitBreakerConfig, CircuitState, ConnectorHealth, HealthStatus, UpdateConnectorHealth,
};
pub use connector_schema::{
    ConnectorSchema, SchemaFilter, SchemaValidationError, UpsertConnectorSchema, VALID_DATA_TYPES,
};
pub use operation_log::{CreateOperationLog, LogStatus, OperationLog, OperationLogFilter};
pub use provisioning_operation::{
    CreateProvisioningOperation, OperationFilter, OperationStatus, OperationType,
    ProvisioningOperation, DEFAULT_MAX_RETRIES, DEFAULT_PRIORITY,
};

// Schema Discovery exports (F046)
pub use connector_schema_version::{
    ConnectorSchemaVersion, CreateSchemaVersion, SchemaVersionSummary, TriggeredBy,
};
pub use schema_refresh_schedule::{ScheduleType, SchemaRefreshSchedule, UpsertSchedule};

// Provisioning Consistency exports (F047)
pub use conflict_record::{
    ConflictFilter, ConflictRecord, ConflictType, CreateConflictRecord, ResolutionOutcome,
    ResolutionStrategy, ResolveConflict,
};
pub use operation_attempt::{CompleteOperationAttempt, CreateOperationAttempt, OperationAttempt};

// Live Synchronization exports (F048)
pub use inbound_change::{
    CreateInboundChange, InboundChange, InboundChangeFilter, InboundChangeType,
    InboundProcessingStatus, SyncSituation,
};
pub use sync_configuration::{
    CreateSyncConfiguration, SyncConfiguration, SyncConflictResolution, SyncMode,
    UpdateSyncConfiguration,
};
pub use sync_conflict::{
    CreateSyncConflict, ResolveSyncConflict, SyncConflict, SyncConflictFilter, SyncConflictType,
    SyncResolutionStrategy,
};
pub use sync_status::{SyncState, SyncStatus, UpsertSyncStatus};
pub use sync_token::{CreateSyncToken, SyncToken, SyncTokenType};

// Reconciliation Engine exports (F049)
pub use connector_reconciliation_run::{
    ConnectorReconciliationMode, ConnectorReconciliationRun, ConnectorReconciliationRunFilter,
    ConnectorReconciliationStatus, CreateConnectorReconciliationRun,
};
pub use reconciliation_action::{
    CreateReconciliationAction, ReconciliationAction, ReconciliationActionFilter,
    ReconciliationActionResult,
};
pub use reconciliation_discrepancy::{
    CreateReconciliationDiscrepancy, ReconciliationActionType, ReconciliationDiscrepancy,
    ReconciliationDiscrepancyFilter, ReconciliationDiscrepancyType, ReconciliationResolutionStatus,
};
pub use reconciliation_schedule::{
    ReconciliationSchedule, ReconciliationScheduleFrequency, UpsertReconciliationSchedule,
};

// Object Lifecycle States models (F052)
pub mod gov_bulk_state_operation;
pub mod gov_lifecycle_config;
pub mod gov_lifecycle_failed_operation;
pub mod gov_lifecycle_state;
pub mod gov_lifecycle_transition;
pub mod gov_scheduled_transition;
pub mod gov_state_transition_audit;
pub mod gov_state_transition_request;

// Deputy & Power of Attorney models (F053)
pub mod gov_delegation_audit;
pub mod gov_delegation_scope;

// Workflow Escalation models (F054)
pub mod gov_approval_group;
pub mod gov_escalation_event;
pub mod gov_escalation_level;
pub mod gov_escalation_policy;
pub mod gov_escalation_rule;
pub mod gov_escalation_types;

// Micro-certification models (F055)
pub mod gov_micro_cert_event;
pub mod gov_micro_cert_trigger;
pub mod gov_micro_cert_types;
pub mod gov_micro_certification;

// Object Lifecycle States exports (F052)
pub use gov_bulk_state_operation::{
    BulkOperationFilter, BulkOperationProgress, BulkOperationResult, BulkOperationStatus,
    CreateGovBulkStateOperation, GovBulkStateOperation, UpdateGovBulkStateOperation,
    MAX_BULK_OPERATION_SIZE,
};
pub use gov_lifecycle_config::{
    CreateGovLifecycleConfig, GovLifecycleConfig, LifecycleConfigFilter, LifecycleObjectType,
    UpdateGovLifecycleConfig,
};
pub use gov_lifecycle_failed_operation::{
    CreateFailedOperation, FailedOperationStatus, FailedOperationType, GovLifecycleFailedOperation,
};
pub use gov_lifecycle_state::{
    CreateGovLifecycleState, EntitlementAction, GovLifecycleState, LifecycleStateFilter,
    UpdateGovLifecycleState,
};
pub use gov_lifecycle_transition::{
    CreateGovLifecycleTransition, GovLifecycleTransition, GovLifecycleTransitionWithStates,
    LifecycleTransitionFilter, UpdateGovLifecycleTransition,
};
pub use gov_scheduled_transition::{
    CreateGovScheduledTransition, GovScheduleStatus, GovScheduledTransition,
    ScheduledTransitionFilter, UpdateGovScheduledTransition,
};
pub use gov_state_transition_audit::{
    ApprovalDetails, AuditActionType, CreateGovStateTransitionAudit, EntitlementSnapshot,
    GovStateTransitionAudit, TransitionAuditFilter, UpdateGovStateTransitionAudit,
};
pub use gov_state_transition_request::{
    CreateGovStateTransitionRequest, GovStateTransitionRequest,
    GovStateTransitionRequestWithStates, TransitionRequestFilter, TransitionRequestStatus,
    UpdateGovStateTransitionRequest,
};

// Deputy & Power of Attorney exports (F053)
pub use gov_approval_delegation::DelegationStatus;
pub use gov_delegation_audit::{
    CreateGovDelegationAudit, DelegationActionType, DelegationAuditFilter, GovDelegationAudit,
    WorkItemType,
};
pub use gov_delegation_scope::{CreateGovDelegationScope, GovDelegationScope};

// Workflow Escalation exports (F054)
pub use gov_approval_group::{
    ApprovalGroupFilter, CreateApprovalGroup, GovApprovalGroup, UpdateApprovalGroup,
};
pub use gov_escalation_event::{
    CreateEscalationEvent, EscalationEventFilter, EscalationStats, GovEscalationEvent,
};
pub use gov_escalation_level::{CreateEscalationLevel, GovEscalationLevel, UpdateEscalationLevel};
pub use gov_escalation_policy::{
    CreateEscalationPolicy, EscalationPolicyFilter, EscalationPolicyWithLevels,
    GovEscalationPolicy, UpdateEscalationPolicy,
};
pub use gov_escalation_rule::{
    CreateEscalationRule, EscalationRuleWithLevels, GovEscalationRule, UpdateEscalationRule,
};
pub use gov_escalation_types::{EscalationReason, EscalationTargetType, FinalFallbackAction};

// Micro-certification exports (F055)
pub use gov_micro_cert_event::{
    CreateMicroCertEvent, GovMicroCertEvent, MicroCertEventFilter, MicroCertEventStats,
};
pub use gov_micro_cert_trigger::{
    CreateMicroCertTrigger, GovMicroCertTrigger, MicroCertTriggerFilter, UpdateMicroCertTrigger,
    DEFAULT_REMINDER_THRESHOLD, DEFAULT_TIMEOUT_SECS,
};
pub use gov_micro_cert_types::{
    MicroCertDecision, MicroCertEventType, MicroCertReviewerType, MicroCertScopeType,
    MicroCertStatus, MicroCertTriggerType,
};
pub use gov_micro_certification::{
    CreateMicroCertification, DecideMicroCertification, GovMicroCertification,
    MicroCertificationFilter, MicroCertificationStats,
};

// Meta-role models (F056)
pub mod gov_meta_role;
pub mod gov_meta_role_conflict;
pub mod gov_meta_role_constraint;
pub mod gov_meta_role_criteria;
pub mod gov_meta_role_entitlement;
pub mod gov_meta_role_event;
pub mod gov_meta_role_inheritance;
pub mod gov_meta_role_types;

// Meta-role exports (F056)
pub use gov_meta_role::{CreateGovMetaRole, GovMetaRole, MetaRoleFilter, UpdateGovMetaRole};
pub use gov_meta_role_conflict::{
    CreateGovMetaRoleConflict, GovMetaRoleConflict, MetaRoleConflictFilter,
    ResolveGovMetaRoleConflict,
};
pub use gov_meta_role_constraint::{CreateGovMetaRoleConstraint, GovMetaRoleConstraint};
pub use gov_meta_role_criteria::{CreateGovMetaRoleCriteria, GovMetaRoleCriteria};
pub use gov_meta_role_entitlement::{CreateGovMetaRoleEntitlement, GovMetaRoleEntitlement};
pub use gov_meta_role_event::{
    CreateGovMetaRoleEvent, GovMetaRoleEvent, MetaRoleEventFilter, MetaRoleEventStats,
};
pub use gov_meta_role_inheritance::{
    CreateGovMetaRoleInheritance, GovMetaRoleInheritance, InheritanceFilter,
};
pub use gov_meta_role_types::{
    CriteriaLogic, CriteriaOperator, InheritanceStatus, MetaRoleConflictType, MetaRoleEventType,
    MetaRoleStatus, PermissionType, ResolutionStatus, SUPPORTED_CONSTRAINT_TYPES,
    SUPPORTED_CRITERIA_FIELDS,
};

// Parametric Role models (F057)
pub mod gov_assignment_parameter;
pub mod gov_parameter_audit_event;
pub mod gov_role_parameter;
pub mod gov_role_parameter_types;

// Parametric Role exports (F057)
pub use gov_assignment_parameter::{
    AssignmentParameterWithDefinition, BulkParameterValues, GovRoleAssignmentParameter,
    SetGovAssignmentParameter,
};
pub use gov_parameter_audit_event::{GovParameterAuditEvent, ParameterAuditFilter};
pub use gov_role_parameter::{
    CreateGovRoleParameter, GovRoleParameter, RoleParameterFilter, UpdateGovRoleParameter,
};
pub use gov_role_parameter_types::{ParameterConstraints, ParameterEventType, ParameterType};

// Object Template models (F058)
pub mod gov_object_template;
pub mod gov_template_application_event;
pub mod gov_template_event;
pub mod gov_template_exclusion;
pub mod gov_template_merge_policy;
pub mod gov_template_rule;
pub mod gov_template_scope;
pub mod gov_template_types;
pub mod gov_template_version;

// Object Template exports (F058)
pub use gov_object_template::{
    CreateGovObjectTemplate, GovObjectTemplate, ObjectTemplateFilter, UpdateGovObjectTemplate,
    DEFAULT_TEMPLATE_PRIORITY, MAX_TEMPLATE_PRIORITY, MIN_TEMPLATE_PRIORITY,
};
pub use gov_template_application_event::{
    ApplicationEventFilter, CreateGovTemplateApplicationEvent, GovTemplateApplicationEvent,
};
pub use gov_template_event::{CreateGovTemplateEvent, GovTemplateEvent, TemplateChangeEventFilter};
pub use gov_template_exclusion::{CreateGovTemplateExclusion, GovTemplateExclusion};
pub use gov_template_merge_policy::{
    CreateGovTemplateMergePolicy, GovTemplateMergePolicy, UpdateGovTemplateMergePolicy,
};
pub use gov_template_rule::{
    CreateGovTemplateRule, GovTemplateRule, TemplateRuleFilter, UpdateGovTemplateRule,
    DEFAULT_RULE_PRIORITY, MAX_RULE_PRIORITY, MIN_RULE_PRIORITY,
};
pub use gov_template_scope::{CreateGovTemplateScope, GovTemplateScope};
pub use gov_template_types::{
    ObjectTemplateStatus, TemplateEventType, TemplateMergeStrategy, TemplateNullHandling,
    TemplateObjectType, TemplateOperation, TemplateRuleType, TemplateScopeType, TemplateStrength,
    TemplateTimeReference, APPLICATION_ATTRIBUTES, ENTITLEMENT_ATTRIBUTES, ROLE_ATTRIBUTES,
    SUPPORTED_FUNCTIONS, USER_ATTRIBUTES,
};
pub use gov_template_version::{CreateGovTemplateVersion, GovTemplateVersion};

// Outlier Detection models (F059)
pub mod gov_outlier_alert;
pub mod gov_outlier_analysis;
pub mod gov_outlier_configuration;
pub mod gov_outlier_disposition;
pub mod gov_outlier_result;
pub mod gov_outlier_types;

// Outlier Detection exports (F059)
pub use gov_outlier_alert::{
    AlertFilter as OutlierAlertFilter, AlertSummary as OutlierAlertSummary, CreateAlert,
    GovOutlierAlert,
};
pub use gov_outlier_analysis::{
    ConfigSnapshot, CreateOutlierAnalysis, GovOutlierAnalysis, OutlierAnalysisFilter,
};
pub use gov_outlier_configuration::{GovOutlierConfiguration, UpsertOutlierConfiguration};
pub use gov_outlier_disposition::{
    CreateDisposition, DispositionFilter, DispositionSummary, GovOutlierDisposition,
    UpdateDisposition,
};
pub use gov_outlier_result::{
    CreateOutlierResult, GovOutlierResult, OutlierResultFilter, OutlierResultSummary,
};
pub use gov_outlier_types::{
    FactorBreakdown, FactorScore, OutlierAlertSeverity, OutlierAlertType, OutlierAnalysisStatus,
    OutlierClassification, OutlierDispositionStatus, OutlierTriggerType, PeerGroupScore,
    ScoringWeights,
};

// Enhanced Simulation models (F060)
pub mod gov_batch_simulation;
pub mod gov_batch_simulation_result;
pub mod gov_policy_simulation;
pub mod gov_policy_simulation_result;
pub mod gov_simulation_comparison;
pub mod gov_simulation_types;

// Enhanced Simulation exports (F060)
pub use gov_batch_simulation::{
    BatchSimulationFilter, CreateBatchSimulation, GovBatchSimulation, SCOPE_WARNING_THRESHOLD,
};
pub use gov_batch_simulation_result::{
    AccessItem, BatchSimulationResultFilter, CreateBatchSimulationResult, GovBatchSimulationResult,
};
pub use gov_policy_simulation::{
    CreatePolicySimulation, GovPolicySimulation, PolicySimulationFilter,
};
pub use gov_policy_simulation_result::{
    BirthrightChangeDetails, ConditionMatch, CreatePolicySimulationResult, EntitlementChange,
    EntitlementInfo, GovPolicySimulationResult, PolicySimulationResultFilter, SodViolationDetails,
};
pub use gov_simulation_comparison::{
    CreateSimulationComparison, DeltaEntry, DeltaResults, GovSimulationComparison, ModifiedEntry,
    SimulationComparisonFilter,
};
pub use gov_simulation_types::{
    BatchImpactSummary, BatchSimulationType, ChangeSpec, ComparisonSummary, ComparisonType,
    FilterCriteria, ImpactSummary, ImpactType, ImpactTypeCounts, PolicySimulationType,
    SelectionMode, SeverityCounts,
};

// NHI Lifecycle models (F061)
pub mod gov_nhi_audit_event;
pub mod gov_nhi_credential;
pub mod gov_nhi_request;
pub mod gov_nhi_risk_score;
pub mod gov_nhi_usage_event;

// NHI Lifecycle exports (F061)
pub use gov_nhi_audit_event::{
    CreateGovNhiAuditEvent, GovNhiAuditEvent, NhiAuditEventFilter, NhiAuditEventType,
    NhiSuspensionReason,
};
pub use gov_nhi_credential::{
    CreateGovNhiCredential, GovNhiCredential, NhiCredentialFilter, NhiCredentialType, NhiEntityType,
};
pub use gov_nhi_request::{
    ApproveGovNhiRequest, CreateGovNhiRequest, GovNhiRequest, NhiRequestFilter, NhiRequestStatus,
    RejectGovNhiRequest,
};
pub use gov_nhi_risk_score::{GovNhiRiskScore, NhiRiskScoreFilter, UpsertGovNhiRiskScore};
pub use gov_nhi_usage_event::{
    CreateGovNhiUsageEvent, GovNhiUsageEvent, NhiUsageEventFilter, NhiUsageOutcome,
    NhiUsageSummary, ResourceAccessCount,
};

// Identity Merge models (F062)
pub mod gov_archived_identity;
pub mod gov_correlation_rule;
pub mod gov_duplicate_candidate;
pub mod gov_merge_audit;
pub mod gov_merge_operation;

// Persona Management models (F063)
pub mod gov_persona;
pub mod gov_persona_archetype;
pub mod gov_persona_audit_event;
pub mod gov_persona_link;
pub mod gov_persona_session;
pub mod gov_persona_types;

// Identity Merge exports (F062)
pub use gov_archived_identity::{
    ArchivedIdentityFilter, CreateGovArchivedIdentity, ExternalReferences, GovArchivedIdentity,
};
pub use gov_correlation_rule::{
    CorrelationRuleFilter, CreateGovCorrelationRule, GovCorrelationRule, GovFuzzyAlgorithm,
    GovMatchType, UpdateGovCorrelationRule,
};
pub use gov_duplicate_candidate::{
    CreateGovDuplicateCandidate, DismissGovDuplicateCandidate, DuplicateCandidateFilter,
    GovDuplicateCandidate, GovDuplicateStatus, RuleMatch, RuleMatches,
};
pub use gov_merge_audit::{
    AttributeDecision, AuditSodViolation, CreateGovMergeAudit, EntitlementDecision,
    EntitlementSnapshot as MergeEntitlementSnapshot, GovMergeAudit, IdentitySnapshot,
    MergeAuditFilter,
};
pub use gov_merge_operation::{
    AttributeSelection, CreateGovMergeOperation, EntitlementInfo as MergeEntitlementInfo,
    GovEntitlementStrategy, GovMergeOperation, GovMergeOperationStatus, MergeOperationFilter,
    SodCheckResult, SodViolationDetail,
};

// Persona Management exports (F063)
pub use gov_persona::{CreatePersona, GovPersona, PersonaAttributes, PersonaFilter, UpdatePersona};
pub use gov_persona_archetype::{
    AttributeMappings, ComputedMapping, CreatePersonaArchetype, GovPersonaArchetype,
    LifecyclePolicy, PersonaArchetypeFilter, PropagateMapping, UpdatePersonaArchetype,
};
pub use gov_persona_audit_event::{
    ArchetypeEventData, AttributesPropagatedEventData, ContextSwitchedEventData,
    CreatePersonaAuditEvent, GovPersonaAuditEvent, PersonaAuditEventFilter,
    PersonaCreatedEventData,
};
pub use gov_persona_link::{CreatePersonaLink, GovPersonaLink};
pub use gov_persona_session::{GovPersonaSession, UpsertPersonaSession};
pub use gov_persona_types::{PersonaAuditEventType, PersonaLinkType, PersonaStatus};

// Semi-manual Resources models (F064)
pub mod gov_external_ticket;
pub mod gov_manual_provisioning_task;
pub mod gov_manual_task_audit_event;
pub mod gov_semi_manual_types;
pub mod gov_sla_policy;
pub mod gov_ticketing_configuration;

// Semi-manual Resources exports (F064)
pub use gov_external_ticket::{CreateExternalTicket, GovExternalTicket};
pub use gov_manual_provisioning_task::{
    CreateManualTask, DashboardMetrics, GovManualProvisioningTask, ManualTaskFilter, RetryQueueItem,
};
pub use gov_manual_task_audit_event::{
    CreateManualTaskAuditEvent, GovManualTaskAuditEvent, ManualTaskEventType,
};
pub use gov_semi_manual_types::{
    ManualTaskOperation, ManualTaskStatus, TicketStatusCategory, TicketingType,
};
pub use gov_sla_policy::{CreateSlaPolicy, GovSlaPolicy, SlaPolicyFilter, UpdateSlaPolicy};
pub use gov_ticketing_configuration::{
    CreateTicketingConfiguration, GovTicketingConfiguration, TicketingConfigFilter,
    UpdateTicketingConfiguration,
};

// License Management models (F065)
pub mod gov_license_assignment;
pub mod gov_license_audit_event;
pub mod gov_license_entitlement_link;
pub mod gov_license_incompatibility;
pub mod gov_license_pool;
pub mod gov_license_reclamation_rule;
pub mod gov_license_types;

// License Management exports (F065)
pub use gov_license_assignment::{
    CreateGovLicenseAssignment, GovLicenseAssignment, LicenseAssignmentFilter,
    LicenseAssignmentWithDetails,
};
pub use gov_license_audit_event::{
    CreateGovLicenseAuditEvent, GovLicenseAuditEvent, LicenseAuditEventFilter,
    LicenseAuditEventWithDetails,
};
pub use gov_license_entitlement_link::{
    CreateGovLicenseEntitlementLink, GovLicenseEntitlementLink, LicenseEntitlementLinkFilter,
    LicenseEntitlementLinkWithDetails,
};
pub use gov_license_incompatibility::{
    CreateGovLicenseIncompatibility, GovLicenseIncompatibility, IncompatibilityViolation,
    LicenseIncompatibilityFilter, LicenseIncompatibilityWithDetails,
};
pub use gov_license_pool::{
    CreateGovLicensePool, GovLicensePool, LicensePoolFilter, UpdateGovLicensePool,
};
pub use gov_license_reclamation_rule::{
    CreateGovLicenseReclamationRule, GovLicenseReclamationRule, LicenseReclamationRuleFilter,
    LicenseReclamationRuleWithDetails, ReclamationCandidate, UpdateGovLicenseReclamationRule,
};
pub use gov_license_types::{
    LicenseAssignmentId, LicenseAssignmentSource, LicenseAssignmentStatus, LicenseAuditAction,
    LicenseAuditEventId, LicenseBillingPeriod, LicenseEntitlementLinkId, LicenseExpirationPolicy,
    LicenseIncompatibilityId, LicensePoolId, LicensePoolStatus, LicenseReclaimReason,
    LicenseReclamationRuleId, LicenseReclamationTrigger, LicenseType,
    DEFAULT_NOTIFICATION_DAYS_BEFORE, DEFAULT_WARNING_DAYS, HIGH_UTILIZATION_THRESHOLD,
    LICENSE_MAX_BULK_OPERATION_SIZE, UNDERUTILIZATION_DAYS, UNDERUTILIZATION_THRESHOLD,
};

// Provisioning Scripts models (F066)
pub mod gov_provisioning_script;
pub mod gov_script_audit_event;
pub mod gov_script_execution_log;
pub mod gov_script_hook_binding;
pub mod gov_script_template;
pub mod gov_script_types;
pub mod gov_script_version;

// Provisioning Scripts exports (F066)
pub use gov_provisioning_script::{
    CreateProvisioningScript, GovProvisioningScript, ScriptFilter, UpdateProvisioningScript,
};
pub use gov_script_audit_event::{CreateScriptAuditEvent, GovScriptAuditEvent, ScriptAuditFilter};
pub use gov_script_execution_log::{
    CreateExecutionLog, DailyTrendRow, DashboardStats, ExecutionLogFilter as DbExecutionLogFilter,
    GovScriptExecutionLog, ScriptStats,
};
pub use gov_script_hook_binding::{
    BindingFilter, CreateScriptHookBinding, GovScriptHookBinding, UpdateScriptHookBinding,
};
pub use gov_script_template::{
    CreateScriptTemplate, GovScriptTemplate, TemplateFilter, UpdateScriptTemplate,
};
pub use gov_script_types::{
    ExecutionStatus, FailurePolicy, GovHookPhase, GovScriptStatus, ProvisioningScriptId,
    ScriptAuditAction, ScriptAuditEventId, ScriptExecutionLogId, ScriptHookBindingId,
    ScriptOperationType, ScriptTemplateId, ScriptVersionId, TemplateCategory,
    DEFAULT_MAX_RETRIES as ScriptDefaultMaxRetries, DEFAULT_TIMEOUT_SECONDS, MAX_BINDINGS_PER_HOOK,
    MAX_RETRIES, MAX_SCRIPT_BODY_SIZE, MAX_TIMEOUT_SECONDS,
};
pub use gov_script_version::{CreateScriptVersion, GovScriptVersion};

// Custom User Attributes models (F070)
pub mod tenant_attribute_definition;

// Security Hardening models (F069)
pub mod revoked_token;

// Security Hardening models (F082)
pub mod signing_key;

// Correlation Engine models (F067)
pub mod gov_correlation_audit_event;
pub mod gov_correlation_candidate;
pub mod gov_correlation_case;
pub mod gov_correlation_threshold;

// Correlation Engine exports (F067)
pub use gov_correlation_audit_event::{
    CorrelationAuditFilter, CreateGovCorrelationAuditEvent, GovCorrelationAuditEvent,
    GovCorrelationEventType, GovCorrelationOutcome,
};
pub use gov_correlation_candidate::{
    CreateGovCorrelationCandidate, GovCorrelationCandidate, PerAttributeScore, PerAttributeScores,
};
pub use gov_correlation_case::{
    CorrelationCaseFilter, CreateGovCorrelationCase, GovCorrelationCase, GovCorrelationCaseStatus,
    GovCorrelationTrigger,
};
pub use gov_correlation_threshold::{GovCorrelationThreshold, UpsertGovCorrelationThreshold};

// Custom User Attributes exports (F070)
pub use tenant_attribute_definition::TenantAttributeDefinition;

// Security Hardening exports (F069)
pub use revoked_token::{CreateRevokedToken, RevokedToken};

// Security Hardening exports (F082)
pub use signing_key::{CreateSigningKey, SigningKey};

// Webhook models (F085)
pub mod webhook_circuit_breaker;
pub mod webhook_delivery;
pub mod webhook_dlq;
pub mod webhook_subscription;

// Webhook exports (F085)
// Note: CircuitState is already exported from connector_health
pub use webhook_circuit_breaker::{UpsertCircuitBreakerState, WebhookCircuitBreakerState};
pub use webhook_delivery::{CreateWebhookDelivery, WebhookDelivery};
pub use webhook_dlq::{CreateWebhookDlqEntry, DlqFilter, WebhookDlqEntry};
pub use webhook_subscription::{
    CreateWebhookSubscription, UpdateWebhookSubscription, WebhookSubscription,
};

// SIEM Integration models (F078)
pub mod siem_batch_export;
pub mod siem_delivery_health;
pub mod siem_destination;
pub mod siem_export_event;

// Passwordless Authentication models (F079)
pub mod passwordless_policy;
pub mod passwordless_token;

// SIEM Integration exports (F078)
pub use siem_batch_export::{CreateSiemBatchExport, SiemBatchExport};
pub use siem_delivery_health::{HealthSummary, SiemDeliveryHealth};
pub use siem_destination::{CreateSiemDestination, SiemDestination, UpdateSiemDestination};
pub use siem_export_event::{CreateSiemExportEvent, SiemExportEvent};

// Passwordless Authentication exports (F079)
pub use passwordless_policy::{EnabledMethods, PasswordlessPolicy};
pub use passwordless_token::{PasswordlessToken, PasswordlessTokenType};

// Authorization Engine models (F083)
pub mod authorization_policy;
pub mod entitlement_action_mapping;
pub mod policy_condition;

// Authorization Engine exports (F083)
pub use authorization_policy::{
    AuthorizationPolicy, CreateAuthorizationPolicy, UpdateAuthorizationPolicy,
};
pub use entitlement_action_mapping::{CreateEntitlementActionMapping, EntitlementActionMapping};
pub use policy_condition::{
    CreatePolicyCondition as CreateAuthPolicyCondition, PolicyConditionRecord,
};

// Bulk User Import models (F086)
pub mod user_import_error;
pub mod user_import_job;
pub mod user_invitation;

// Bulk User Import exports (F086)
pub use user_import_error::{CreateImportError, UserImportError};
pub use user_import_job::{CreateImportJob, UserImportJob};
pub use user_invitation::{CreateAdminInvitation, CreateInvitation, UserInvitation};

// SCIM Outbound Provisioning Client models (F087)
pub mod scim_provisioning_log;
pub mod scim_provisioning_state;
pub mod scim_sync_run;
pub mod scim_target;
pub mod scim_target_attribute_mapping;

// SCIM Outbound Provisioning Client exports (F087)
pub use scim_provisioning_log::{CreateScimProvisioningLog, ScimProvisioningLog};
pub use scim_provisioning_state::{CreateScimProvisioningState, ScimProvisioningState};
pub use scim_sync_run::{CreateScimSyncRun, ScimSyncRun};
pub use scim_target::{CreateScimTarget, ScimTarget, UpdateScimTarget};
pub use scim_target_attribute_mapping::{
    CreateScimTargetAttributeMapping, ScimTargetAttributeMapping,
};

// Business Role Hierarchy models (F088)
pub mod gov_role;
pub mod gov_role_effective_entitlement;
pub mod gov_role_inheritance_block;

// Business Role Hierarchy exports (F088)
pub use gov_role::{
    CreateGovRole, GovRole, GovRoleDescendant, GovRoleFilter, GovRoleImpactAnalysis,
    GovRoleMoveResult, GovRoleTreeNode, UpdateGovRole, DEFAULT_MAX_HIERARCHY_DEPTH,
};
pub use gov_role_effective_entitlement::{
    EffectiveEntitlementDetails, GovRoleEffectiveEntitlement,
};
pub use gov_role_inheritance_block::{
    CreateGovRoleInheritanceBlock, GovRoleInheritanceBlock, InheritanceBlockDetails,
};

// AI Agent Security models (F089)
pub mod ai_agent;
pub mod ai_agent_audit_event;
pub mod ai_agent_tool_permission;
pub mod ai_tool;

// AI Agent Security exports (F089)
pub use ai_agent::{
    AiAgent, AiAgentFilter, AiAgentStatus, AiAgentType, CreateAiAgent, UpdateAiAgent,
};
pub use ai_agent_audit_event::{
    AiAgentAuditEvent, AiAgentAuditEventFilter, AiAuditDecision, AiAuditEventType, AiAuditOutcome,
    LogAuditEvent,
};
pub use ai_agent_tool_permission::{
    AiAgentToolPermission, AiAgentToolPermissionDetails, GrantToolPermission, UpdateToolPermission,
};
pub use ai_tool::{AiRiskLevel, AiTool, AiToolFilter, AiToolStatus, CreateAiTool, UpdateAiTool};

// A2A Protocol models (F091)
pub mod a2a_task;

// A2A Protocol exports (F091)
pub use a2a_task::{A2aTask, A2aTaskFilter, A2aTaskState, CallbackStatus, CreateA2aTask};

// Human-in-the-Loop Approval models (F092)
pub mod ai_agent_approval_request;

// Human-in-the-Loop Approval exports (F092)
pub use ai_agent_approval_request::{
    AiAgentApprovalRequest, ApprovalRequestFilter, ApprovalStatus, CreateApprovalRequest,
};

// Behavioral Anomaly Detection models (F094)
pub mod anomaly_baseline;
pub mod anomaly_threshold;
pub mod detected_anomaly;

// Behavioral Anomaly Detection exports (F094)
pub use anomaly_baseline::{AnomalyBaseline, CreateAnomalyBaseline, DbBaselineType};
pub use anomaly_threshold::{AnomalyThreshold, UpsertAnomalyThreshold};
pub use detected_anomaly::{
    CreateDetectedAnomaly, DbAnomalySeverity, DbAnomalyType, DetectedAnomaly, DetectedAnomalyFilter,
};

// Core tenant exports (F095)
pub use tenant::{Tenant, TenantType};

// Device Code OAuth models (F096)
pub mod device_code;

// Device Code OAuth exports (F096)
pub use device_code::{
    DeviceCode, DeviceCodeStatus, NewDeviceCode, DEFAULT_POLLING_INTERVAL,
    DEVICE_CODE_EXPIRY_SECONDS,
};

// Device Code Confirmation models (F117 Storm-2372)
pub mod device_code_confirmation;

// Device Code Confirmation exports (F117 Storm-2372)
pub use device_code_confirmation::{
    DeviceCodeConfirmation, NewDeviceCodeConfirmation, CONFIRMATION_EXPIRY_MINUTES,
    MAX_RESEND_COUNT, RESEND_COOLDOWN_SECONDS,
};

// Known User IPs models (F117 Storm-2372 Risk Scoring)
pub mod known_user_ip;

// Known User IPs exports (F117 Storm-2372 Risk Scoring)
pub use known_user_ip::KnownUserIp;

// Tenant Provisioning API models (F097)
pub mod api_key;
pub mod tenant_mfa_config;

// Tenant Provisioning API exports (F097)
pub use api_key::{ApiKey, CreateApiKey};
pub use tenant_mfa_config::{TenantMfaConfig, UpsertMfaConfig};

// Unified NHI View models (F108)
pub mod nhi_view;

// Unified NHI trait implementations (F108)
pub mod nhi_impl;

// Unified NHI View exports (F108)
pub use nhi_view::{
    NhiCountByRiskLevel, NhiCountByType, NhiRiskSummary, NhiViewFilter, NonHumanIdentityView,
};

// Tenant Usage Tracking models (F-USAGE-TRACK)
pub mod usage;

// Tenant Usage Tracking exports (F-USAGE-TRACK)
pub use usage::{TenantActiveUser, TenantUsageMetrics};

// Idempotency models (F-IDEMPOTENCY)
pub mod idempotent_request;

// Idempotency exports (F-IDEMPOTENCY)
pub use idempotent_request::{
    CreateIdempotentRequest, IdempotentRequest, IdempotentState, InsertResult,
    IDEMPOTENCY_TTL_HOURS, PROCESSING_TIMEOUT_SECONDS,
};

// Dynamic Secrets Provisioning models (F120)
pub mod agent_secret_permission;
pub mod credential_request_audit;
pub mod dynamic_credential;
pub mod secret_provider_config;
pub mod secret_type_config;

// Workload Identity Federation models (F121)
pub mod iam_role_mapping;
pub mod identity_audit_event;
pub mod identity_credential_request;
pub mod identity_provider_config;

// Dynamic Secrets Provisioning exports (F120)
pub use agent_secret_permission::{
    AgentSecretPermission, AgentSecretPermissionFilter, GrantSecretPermission,
    UpdateSecretPermission,
};
pub use credential_request_audit::{
    AuditStats, CreateCredentialRequestAudit, CredentialErrorCode, CredentialRequestAudit,
    CredentialRequestAuditFilter, CredentialRequestContext, CredentialRequestOutcome,
};
pub use dynamic_credential::{
    CreateDynamicCredential, CredentialStatus, DynamicCredential, DynamicCredentialFilter,
    SecretProviderType,
};
pub use secret_provider_config::{
    AwsSettings, CreateSecretProviderConfig, InfisicalSettings, OpenBaoSettings,
    ProviderHealthResult, ProviderHealthStatus, ProviderStatus, SecretProviderConfig,
    SecretProviderConfigFilter, UpdateSecretProviderConfig,
};
pub use secret_type_config::{
    CreateSecretTypeConfiguration, SecretTypeConfigFilter, SecretTypeConfiguration,
    UpdateSecretTypeConfiguration, DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
};

// Workload Identity Federation exports (F121)
pub use iam_role_mapping::{
    CreateIamRoleMapping, IamRoleMapping, IamRoleMappingFilter, UpdateIamRoleMapping,
    DEFAULT_TTL_SECONDS as IAM_DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS as IAM_MAX_TTL_SECONDS,
    MIN_TTL_SECONDS as IAM_MIN_TTL_SECONDS,
};
pub use identity_audit_event::{
    CreateIdentityAuditEvent, IdentityAuditEvent, IdentityAuditEventFilter, IdentityAuditEventType,
    IdentityAuditOutcome,
};
pub use identity_credential_request::{
    CreateIdentityCredentialRequest, IdentityCredentialOutcome, IdentityCredentialRequest,
    IdentityCredentialRequestFilter, IdentityCredentialStats,
};
pub use identity_provider_config::{
    CloudProviderType, CreateIdentityProviderConfig, IdentityProviderConfig,
    IdentityProviderConfigFilter, IdpHealthStatus, UpdateIdentityProviderConfig,
};

// Agent PKI & Certificate Issuance models (F127)
pub mod agent_certificate;
pub mod certificate_authority;
pub mod certificate_revocation;

// Agent PKI & Certificate Issuance exports (F127)
pub use agent_certificate::{
    AgentCertificate, AgentCertificateFilter, CertificateStatus, IssueCertificateRequest,
    IssueCertificateResponse,
};
pub use certificate_authority::{
    CaType, CertificateAuthority, CertificateAuthorityFilter, CreateExternalCa, CreateInternalCa,
    UpdateCertificateAuthority,
};
pub use certificate_revocation::{
    CertificateRevocation, CertificateRevocationFilter, RevocationReasonCode,
    RevokeCertificateRequest,
};
