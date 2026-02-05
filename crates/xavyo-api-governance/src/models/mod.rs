//! Request and response models for governance API.

pub mod application;
pub mod assignment;
pub mod effective_access;
pub mod entitlement;
pub mod role_entitlement;

// SoD models (F034)
pub mod sod_exemption;
pub mod sod_rule;
pub mod sod_violation;

// Access Request Workflow models (F035)
pub mod access_request;
pub mod approval;
pub mod approval_workflow;
pub mod delegation;

// Certification Campaign models (F036)
pub mod certification;

// Lifecycle Workflow models (F037)
pub mod birthright_policy;
pub mod lifecycle_event;

// Risk Scoring models (F039)
pub mod peer_group;
pub mod risk_alert;
pub mod risk_event;
pub mod risk_factor;
pub mod risk_score;
pub mod risk_threshold;

// Orphan Account Detection models (F040)
pub mod detection_rule;
pub mod orphan_detection;
pub mod reconciliation_run;
pub mod service_account;

// Compliance Reporting models (F042)
pub mod report;

// Role Mining & Analytics models (F041)
pub mod role_mining;

// Object Lifecycle States models (F052)
pub mod lifecycle;

// Workflow Escalation models (F054)
pub mod escalation;

// Micro-certification models (F055)
pub mod micro_certification;

// Meta-role models (F056)
pub mod meta_role;

// Parametric role models (F057)
pub mod parametric_role;

// Object Template models (F058)
pub mod object_template;

// Outlier Detection models (F059)
pub mod outlier;

// Enhanced Simulation models (F060)
pub mod batch_simulation;
pub mod policy_simulation;
pub mod simulation_comparison;

// NHI Lifecycle models (F061)
pub mod nhi;

// Identity Merge models (F062)
pub mod identity_merge;

// Persona Management models (F063)
pub mod persona;

// Semi-manual Resources models (F064)
pub mod semi_manual;

pub use application::*;
pub use assignment::*;
pub use effective_access::*;
pub use entitlement::*;
pub use role_entitlement::*;

// SoD exports (F034)
pub use sod_exemption::*;
pub use sod_rule::*;
pub use sod_violation::*;

// Access Request Workflow exports (F035)
pub use access_request::*;
pub use approval::*;
pub use approval_workflow::*;
pub use delegation::*;

// Certification Campaign exports (F036)
pub use certification::*;

// Lifecycle Workflow exports (F037)
pub use birthright_policy::*;
pub use lifecycle_event::*;

// Risk Scoring exports (F039)
pub use peer_group::*;
pub use risk_alert::*;
pub use risk_event::*;
pub use risk_factor::*;
pub use risk_score::*;
pub use risk_threshold::*;

// Orphan Account Detection exports (F040)
pub use detection_rule::*;
pub use orphan_detection::*;
pub use reconciliation_run::*;
pub use service_account::*;

// Compliance Reporting exports (F042)
pub use report::*;

// Role Mining & Analytics exports (F041)
pub use role_mining::*;

// Object Lifecycle States exports (F052)
pub use lifecycle::*;

// Workflow Escalation exports (F054)
pub use escalation::*;

// Micro-certification exports (F055)
pub use micro_certification::*;

// Meta-role exports (F056)
pub use meta_role::*;

// Parametric role exports (F057)
pub use parametric_role::*;

// Object Template exports (F058)
pub use object_template::*;

// Outlier Detection exports (F059)
pub use outlier::*;

// Enhanced Simulation exports (F060)
pub use batch_simulation::*;
pub use policy_simulation::*;
pub use simulation_comparison::*;

// NHI Lifecycle exports (F061)
pub use nhi::*;

// Identity Merge exports (F062)
pub use identity_merge::*;

// Persona Management exports (F063)
pub use persona::*;

// Semi-manual Resources exports (F064)
pub use semi_manual::*;

// License Management models (F065)
pub mod license;

// Provisioning Scripts models (F066)
pub mod script;

// License Management exports (F065)
pub use license::*;

// Provisioning Scripts exports (F066)
// Note: script types are NOT glob-exported to avoid name collisions with
// object_template (TemplateResponse, CreateTemplateRequest, etc.).
// Use `crate::models::script::` qualified paths instead.

// Correlation Engine models (F067)
pub mod correlation;

// Correlation Engine exports (F067)
// Note: correlation types are NOT glob-exported to avoid name collisions with
// identity_merge (CreateCorrelationRuleRequest, UpdateCorrelationRuleRequest,
// CorrelationRuleResponse). Use `crate::models::correlation::` qualified paths instead.

// SIEM Integration models (F078)
pub mod siem;
// Note: siem types are NOT glob-exported. Use `crate::models::siem::` qualified paths.

// Identity Archetype models (F-058)
pub mod archetype;
pub mod identity_archetype;

// Power of Attorney models (F-061)
pub mod power_of_attorney;

// Self-Service Request Catalog models (F-062)
pub mod catalog;

// Identity Archetype exports (F-058)
pub use archetype::*;
pub use identity_archetype::*;

// Power of Attorney exports (F-061)
pub use power_of_attorney::*;

// Self-Service Request Catalog exports (F-062)
pub use catalog::*;

// Role Inducements & Constructions models (F-063)
pub mod role_construction;
pub mod role_inducement;

// Role Inducements & Constructions exports (F-063)
pub use role_construction::*;
pub use role_inducement::*;

// Bulk Action Engine models (F-064)
pub mod bulk_action;

// Bulk Action Engine exports (F-064)
pub use bulk_action::*;
