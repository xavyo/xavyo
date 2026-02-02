//! HTTP request handlers for governance API.

pub mod applications;
pub mod assignments;
pub mod effective_access;
pub mod entitlements;
pub mod owners;
pub mod role_mappings;
pub mod sod_exemptions;
pub mod sod_rules;
pub mod sod_violations;

// Access Request Workflow handlers (F035)
pub mod access_requests;
pub mod approval_workflows;
pub mod approvals;
pub mod delegations;

// Certification Campaign handlers (F036)
pub mod certification_campaigns;
pub mod certification_items;

// Lifecycle Workflow handlers (F037)
pub mod access_snapshots;
pub mod birthright_policies;
pub mod lifecycle_actions;
pub mod lifecycle_events;

// Risk Scoring handlers (F039)
pub mod peer_groups;
pub mod risk_alerts;
pub mod risk_events;
pub mod risk_factors;
pub mod risk_scores;
pub mod risk_thresholds;

// Orphan Account Detection handlers (F040)
pub mod detection_rules;
pub mod orphan_detections;
pub mod reconciliation_runs;
pub mod service_accounts;

// Compliance Reporting handlers (F042)
pub mod report_schedules;
pub mod report_templates;
pub mod reports;

// Role Mining & Analytics handlers (F041)
pub mod role_mining;

// Object Lifecycle States handlers (F052)
pub mod bulk_state_operation;
pub mod failed_operations;
pub mod lifecycle_config;
pub mod scheduled_transition;
pub mod state_transition;

// Workflow Escalation handlers (F054)
pub mod approval_groups;
pub mod escalation_events;
pub mod escalation_policies;

// Micro-certification handlers (F055)
pub mod micro_cert_triggers;
pub mod micro_certifications;

// Meta-role handlers (F056)
pub mod meta_roles;

// Parametric role handlers (F057)
pub mod parametric_roles;

// Object template handlers (F058)
pub mod object_templates;

// Outlier detection handlers (F059)
pub mod outliers;

// Enhanced Simulation handlers (F060)
pub mod batch_simulations;
pub mod policy_simulations;
pub mod simulation_comparisons;

// NHI Lifecycle handlers (F061)
pub mod nhis;

// Identity Merge handlers (F062)
pub mod identity_correlation_rules;
pub mod identity_merge;

// Persona Management handlers (F063)
pub mod personas;

// Semi-manual Resources handlers (F064)
pub mod manual_tasks;
pub mod semi_manual;
pub mod sla_policies;
pub mod ticketing_config;
pub mod ticketing_webhook;

// License Management handlers (F065)
pub mod license_analytics;
pub mod license_assignments;
pub mod license_entitlement_links;
pub mod license_incompatibilities;
pub mod license_pools;
pub mod license_reclamation;
pub mod license_reports;

// Provisioning Scripts handlers (F066)
pub mod provisioning_scripts;
pub mod script_analytics;
pub mod script_hook_bindings;
pub mod script_templates;
pub mod script_testing;

// Correlation Engine handlers (F067)
pub mod correlation_audit;
pub mod correlation_cases;
pub mod correlation_engine;
pub mod correlation_rules;
pub mod correlation_stats;
pub mod correlation_thresholds;

// SIEM Integration handlers (F078)
pub mod siem;

// Business Role Hierarchy handlers (F088)
pub mod role_entitlements;
pub mod role_hierarchy;
pub mod role_inheritance_blocks;
