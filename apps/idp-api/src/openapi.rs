//! `OpenAPI` documentation and Swagger UI configuration.
//!
//! This module sets up utoipa for `OpenAPI` spec generation and
//! configures Swagger UI for interactive API documentation.

use axum::Router;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::health::{
    DependencyCheck, HealthResponse, HealthState, LivenessResponse, ReadinessResponse,
    StartupResponse,
};
use crate::state::AppState;

/// Security scheme modifier for Bearer authentication.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// `OpenAPI` documentation for the IDP API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "xavyo API",
        version = "0.1.0",
        description = "Identity Provider API for xavyo",
        contact(name = "xavyo Team"),
        license(name = "BSL-1.1", url = "https://github.com/xavyo/xavyo/blob/master/LICENSE")
    ),
    servers(
        (url = "http://localhost:8080", description = "Development server"),
        (url = "https://idp.xavyo.net", description = "Production server")
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Service health and status"),
        (name = "Authentication", description = "Login, logout, password operations"),
        (name = "MFA", description = "Multi-factor authentication (TOTP, WebAuthn)"),
        (name = "WebAuthn MFA", description = "WebAuthn/FIDO2 registration and authentication"),
        (name = "Admin - WebAuthn Policy", description = "Tenant WebAuthn policy management"),
        (name = "Admin - WebAuthn Credentials", description = "Admin WebAuthn credential management"),
        (name = "IP Restrictions", description = "IP-based access control"),
        (name = "Delegated Admin", description = "Role-based permission management"),
        (name = "Branding", description = "Tenant branding configuration"),
        (name = "Branding Assets", description = "Logo and asset management"),
        (name = "Email Templates", description = "Email template customization"),
        (name = "Public", description = "Public endpoints (no authentication)"),
        (name = "OAuth2", description = "OAuth2/OIDC provider endpoints"),
        (name = "OAuth2 Device Code", description = "RFC 8628 Device Authorization Grant"),
        (name = "OAuth2 Admin", description = "OAuth2 client management"),
        (name = "OIDC Discovery", description = "OpenID Connect discovery"),
        (name = "Users", description = "User management"),
        (name = "SAML", description = "SAML SSO operations"),
        (name = "SAML Admin", description = "SAML service provider management"),
        (name = "SCIM", description = "SCIM user provisioning"),
        (name = "OIDC Federation", description = "External IdP federation"),
        (name = "Social Login", description = "Social identity provider authentication"),
        // User self-service
        (name = "User Profile", description = "User profile management"),
        (name = "User Security", description = "User security overview and MFA status"),
        (name = "User Sessions", description = "User session management"),
        (name = "User Devices", description = "User device management and trust"),
        (name = "Audit", description = "User audit and login history"),
        (name = "Security Alerts", description = "User security alerts"),
        // Governance
        (name = "Governance - Applications", description = "IGA application registry management"),
        (name = "Governance - Entitlements", description = "IGA entitlement definitions"),
        (name = "Governance - Assignments", description = "IGA entitlement assignments to users/groups"),
        (name = "Governance - Role Entitlements", description = "IGA role-to-entitlement mappings"),
        (name = "Governance - Entitlement Owners", description = "IGA entitlement ownership management"),
        (name = "Governance - Effective Access", description = "IGA effective user access query"),
        (name = "Governance - SoD Rules", description = "Separation of Duties rule management"),
        (name = "Governance - SoD Violations", description = "SoD violation detection and management"),
        (name = "Governance - SoD Exemptions", description = "SoD exemption management for approved exceptions"),
        (name = "Governance - Access Requests", description = "Self-service access request submission and management"),
        (name = "Governance - Approvals", description = "Access request approval workflow"),
        (name = "Governance - Approval Workflows", description = "Multi-level approval workflow configuration"),
        (name = "Governance - Delegations", description = "Approval authority delegation management"),
        (name = "Governance - Certification Campaigns", description = "Access certification campaign management"),
        (name = "Governance - Certification Items", description = "Certification item review and decisions"),
        (name = "Governance - Lifecycle", description = "Joiner-Mover-Leaver lifecycle events and actions"),
        (name = "Governance - Risk Factors", description = "Risk factor configuration and management"),
        (name = "Governance - Risk Scoring", description = "User risk score calculation and tracking"),
        (name = "Governance - Peer Groups", description = "Peer group management for outlier detection"),
        (name = "Governance - Risk Alerts", description = "Risk-based alert management"),
        (name = "Governance - Orphan Detection", description = "Orphan account detection and remediation"),
        (name = "Governance - Detection Rules", description = "Detection rule configuration"),
        (name = "Governance - Compliance Reporting", description = "Report templates, generation, and scheduling for compliance audits"),
        (name = "Governance - Role Mining", description = "Role mining jobs, candidate discovery, pattern analysis, and role optimization"),
        // Business Role Hierarchy (F088)
        (name = "Governance - Role Hierarchy", description = "Business role hierarchy with parent-child relationships, entitlement inheritance, and impact analysis"),
        // Object Lifecycle States (F052)
        (name = "Governance - Lifecycle Config", description = "Lifecycle configuration management for object state machines"),
        (name = "Governance - State Transitions", description = "Object state transition execution, rollback, and audit"),
        (name = "Governance - Scheduled Transitions", description = "Scheduled state transition management"),
        (name = "Governance - Bulk Operations", description = "Bulk state transition operations for organizational changes"),
        // Connectors (F045, F048, F049)
        (name = "Connectors", description = "Connector configuration and management for external system provisioning"),
        (name = "Connector Operations", description = "Provisioning operation queue, retries, dead letter queue, and conflict resolution"),
        (name = "Connector Sync", description = "Live synchronization configuration, delta sync, change tracking, and conflict management"),
        (name = "Connector Reconciliation", description = "Full reconciliation runs, discrepancy detection, remediation, and scheduling"),
        // Workflow Escalation (F054)
        (name = "Governance - Workflow Escalation", description = "Escalation policies, approval groups, and step escalation configuration"),
        // Micro-certification (F055)
        (name = "Governance - Micro-certification", description = "Event-triggered micro-certifications, trigger rules, and just-in-time access review"),
        // Meta-roles (F056)
        (name = "Governance - Meta-roles", description = "Meta-role management, criteria matching, inheritance, and conflict resolution"),
        // Parametric Roles (F057)
        (name = "Governance - Parametric Roles", description = "Role parameter definitions, parametric assignments, and parameter audit"),
        // Object Templates (F058)
        (name = "Governance - Object Templates", description = "Object template management, rules, scopes, versions, and application events"),
        // Outlier Detection (F059)
        (name = "Governance - Outlier Detection", description = "Outlier detection configuration, analyses, results, dispositions, and alerts"),
        // Enhanced Simulation (F060)
        (name = "Governance - Enhanced Simulation", description = "Batch simulation management for policy and role change impact analysis"),
        // NHI Lifecycle (F061)
        (name = "Governance - NHIs", description = "Non-human identity lifecycle, credentials, usage, risk scoring, certification, and access requests"),
        // Identity Merge (F062)
        (name = "Governance - Identity Merge", description = "Duplicate identity detection, merge preview, and merge execution"),
        // Persona Management (F063)
        (name = "Governance - Persona Management", description = "Persona archetypes, persona lifecycle, context switching, and audit"),
        // Semi-manual Resources (F064)
        (name = "Governance - Semi-manual Resources", description = "Semi-manual provisioning, manual tasks, ticketing integration, and SLA policies"),
        // License Management (F065)
        (name = "Governance - License Management", description = "License pool management, assignments, entitlement links, incompatibilities, reclamation, and analytics"),
        // Provisioning Scripts (F066)
        (name = "Governance - Provisioning Scripts", description = "Provisioning script management, templates, hook bindings, testing, and analytics"),
        // Correlation Engine (F067)
        (name = "Governance - Correlation Engine", description = "Identity-to-account correlation rules, thresholds, cases, audit, and statistics"),
        // SIEM Integration / Audit Export (F078)
        (name = "Governance - Audit Export", description = "SIEM destination management, connectivity testing, and audit log export"),
        // Adaptive Authentication (F073)
        (name = "Governance - Risk Management", description = "Risk enforcement policy configuration for adaptive authentication"),
        // Token Revocation (F069)
        (name = "Token Revocation", description = "JWT access token revocation for security hardening"),
        // Key Management (F082)
        (name = "Key Management", description = "Admin endpoints for JWT signing key rotation and revocation"),
        // Custom User Attributes (F070)
        (name = "Attribute Definitions", description = "Custom attribute schema definition management per tenant"),
        (name = "User Custom Attributes", description = "User custom attribute storage, retrieval, and patching"),
        (name = "Bulk Operations", description = "Bulk custom attribute update operations"),
        (name = "Attribute Audit", description = "Audit custom attribute compliance across users"),
        // Organization & Department Hierarchy (F071)
        (name = "Group Hierarchy", description = "Manage group parent-child relationships, tree traversal, and subtree membership"),
        // Observability (F072)
        (name = "Observability", description = "OpenTelemetry tracing, Prometheus metrics, and Kubernetes health probes"),
        // Passwordless Authentication (F079)
        (name = "Passwordless Authentication", description = "Magic link and email OTP passwordless login"),
        (name = "Passwordless Policy", description = "Tenant passwordless authentication policy management"),
        // Fine-Grained Authorization (F083)
        (name = "Authorization - Policies", description = "Authorization policy CRUD for PDP configuration"),
        (name = "Authorization - Mappings", description = "Entitlement-to-action mapping management"),
        (name = "Authorization - Query", description = "Authorization decision queries (can-i, admin check, bulk check)"),
        // Webhooks & Event Subscriptions (F085)
        (name = "Webhooks", description = "Webhook subscription management and delivery tracking"),
        // Bulk User Import & Invitations (F086)
        (name = "Import", description = "Bulk user CSV import, job tracking, and invitation management"),
        // SCIM Outbound Provisioning (F087)
        (name = "SCIM Targets", description = "SCIM 2.0 outbound provisioning target management, health checks, and configuration"),
        (name = "SCIM Target Mappings", description = "SCIM 2.0 outbound attribute mapping configuration"),
        (name = "SCIM Target Sync", description = "SCIM 2.0 outbound sync triggering and run history"),
        (name = "SCIM Target Provisioning", description = "SCIM 2.0 outbound provisioning state and retry management"),
        (name = "SCIM Target Logs", description = "SCIM 2.0 outbound provisioning operation logs"),
        // AI Agent Security (F089)
        (name = "AI Agents", description = "AI agent registry and lifecycle management"),
        (name = "AI Agent Tools", description = "AI tool registry and schema management"),
        (name = "AI Agent Permissions", description = "Agent-tool permission grants and revocation"),
        (name = "AI Agent Authorization", description = "Real-time authorization decisions for agent tool invocations"),
        (name = "AI Agent Audit", description = "Agent activity audit trail queries"),
        (name = "AI Agent Discovery", description = "A2A Protocol AgentCard discovery"),
        // MCP & A2A Protocol (F091)
        (name = "MCP Tools", description = "Model Context Protocol tool discovery and invocation"),
        (name = "A2A Tasks", description = "Agent-to-Agent Protocol task management"),
        // Human-in-the-Loop Approval (F092)
        (name = "AI Agent Approvals", description = "Human-in-the-loop approval workflow for AI agent tool invocations"),
        // Tenant Provisioning (F097)
        (name = "Tenant Provisioning", description = "Self-service tenant creation for authenticated users"),
        // Unified NHI (F108, F109)
        (name = "Unified NHI", description = "Unified Non-Human Identity view spanning service accounts and AI agents"),
        (name = "Unified NHI Certification", description = "Cross-type certification campaigns for unified NHI governance"),
        // NHI API Consolidation (F109)
        (name = "NHI - Service Accounts", description = "Service account lifecycle, credentials, usage, risk, and self-service requests"),
        (name = "NHI - Agents", description = "AI agent management, permissions, authorization, audit, and anomaly detection"),
        (name = "NHI - Tools", description = "Tool registry for AI agent capabilities"),
        (name = "NHI - Approvals", description = "Human-in-the-loop approval workflow for agent tool invocations"),
        // Unified NHI Data Model (201-tool-nhi-promotion)
        (name = "NHI", description = "Unified Non-Human Identity list and detail endpoints"),
        (name = "NHI Lifecycle", description = "NHI lifecycle state transitions (suspend, reactivate, deprecate, archive, deactivate, activate)"),
        (name = "NHI Credentials", description = "NHI credential issuance, rotation, and revocation"),
        (name = "NHI Certifications", description = "NHI certification campaign management"),
        (name = "NHI Permissions", description = "Agent-to-tool permission grants and queries"),
        (name = "NHI Risk", description = "NHI risk scoring and summary"),
        (name = "NHI SoD", description = "NHI Separation of Duties rule management and validation"),
        (name = "NHI Inactivity", description = "NHI inactivity detection, auto-suspend, and orphan management"),
        (name = "NHI Agents", description = "NHI AI agent type-specific CRUD"),
        (name = "NHI Service Accounts", description = "NHI service account type-specific CRUD"),
        (name = "NHI Tools", description = "NHI tool type-specific CRUD")
    ),
    paths(
        // Health
        crate::health::health_handler,
        // Observability (F072, F074)
        crate::health::livez_handler,
        crate::health::readyz_handler,
        crate::health::healthz_handler,
        crate::health::startupz_handler,
        // Auth - Core
        xavyo_api_auth::handlers::login::login_handler,
        xavyo_api_auth::handlers::register::register_handler,
        xavyo_api_auth::handlers::logout::logout_handler,
        xavyo_api_auth::handlers::refresh::refresh_handler,
        xavyo_api_auth::handlers::forgot_password::forgot_password_handler,
        xavyo_api_auth::handlers::reset_password::reset_password_handler,
        xavyo_api_auth::handlers::verify_email::verify_email_handler,
        xavyo_api_auth::handlers::resend_verification::resend_verification_handler,
        xavyo_api_auth::handlers::password_change::password_change_handler,
        // Auth - Token Revocation (F069)
        xavyo_api_auth::handlers::revocation::revoke_token_handler,
        xavyo_api_auth::handlers::revocation::revoke_user_tokens_handler,
        // Auth - Key Management (F082)
        xavyo_api_auth::handlers::key_management::rotate_key_handler,
        xavyo_api_auth::handlers::key_management::revoke_key_handler,
        xavyo_api_auth::handlers::key_management::list_keys_handler,
        // Auth - Passwordless Authentication (F079)
        xavyo_api_auth::handlers::passwordless::request_magic_link_handler,
        xavyo_api_auth::handlers::passwordless::verify_magic_link_handler,
        xavyo_api_auth::handlers::passwordless::request_email_otp_handler,
        xavyo_api_auth::handlers::passwordless::verify_email_otp_handler,
        xavyo_api_auth::handlers::passwordless_policy::get_passwordless_policy_handler,
        xavyo_api_auth::handlers::passwordless_policy::update_passwordless_policy_handler,
        xavyo_api_auth::handlers::passwordless_policy::get_available_methods_handler,
        // Auth - IP Restrictions
        xavyo_api_auth::handlers::ip_restrictions::get_ip_settings,
        xavyo_api_auth::handlers::ip_restrictions::update_ip_settings,
        xavyo_api_auth::handlers::ip_restrictions::list_ip_rules,
        xavyo_api_auth::handlers::ip_restrictions::create_ip_rule,
        xavyo_api_auth::handlers::ip_restrictions::get_ip_rule,
        xavyo_api_auth::handlers::ip_restrictions::update_ip_rule,
        xavyo_api_auth::handlers::ip_restrictions::delete_ip_rule,
        xavyo_api_auth::handlers::ip_restrictions::validate_ip,
        // Auth - Delegated Admin
        xavyo_api_auth::handlers::delegated_admin::list_permissions,
        xavyo_api_auth::handlers::delegated_admin::get_permissions_by_category,
        xavyo_api_auth::handlers::delegated_admin::list_role_templates,
        xavyo_api_auth::handlers::delegated_admin::create_role_template,
        xavyo_api_auth::handlers::delegated_admin::get_role_template,
        xavyo_api_auth::handlers::delegated_admin::update_role_template,
        xavyo_api_auth::handlers::delegated_admin::delete_role_template,
        xavyo_api_auth::handlers::delegated_admin::list_assignments,
        xavyo_api_auth::handlers::delegated_admin::create_assignment,
        xavyo_api_auth::handlers::delegated_admin::get_assignment,
        xavyo_api_auth::handlers::delegated_admin::revoke_assignment,
        xavyo_api_auth::handlers::delegated_admin::get_user_permissions,
        xavyo_api_auth::handlers::delegated_admin::get_audit_log,
        xavyo_api_auth::handlers::delegated_admin::check_permission,
        // Auth - Branding
        xavyo_api_auth::handlers::branding::get_branding,
        xavyo_api_auth::handlers::branding::update_branding,
        xavyo_api_auth::handlers::branding_assets::upload_asset,
        xavyo_api_auth::handlers::branding_assets::list_assets,
        xavyo_api_auth::handlers::branding_assets::get_asset,
        xavyo_api_auth::handlers::branding_assets::delete_asset,
        xavyo_api_auth::handlers::email_templates::list_templates,
        xavyo_api_auth::handlers::email_templates::get_template,
        xavyo_api_auth::handlers::email_templates::update_template,
        xavyo_api_auth::handlers::email_templates::preview_template,
        xavyo_api_auth::handlers::email_templates::reset_template,
        xavyo_api_auth::handlers::public_branding::get_public_branding,
        // Auth - MFA WebAuthn (F032)
        xavyo_api_auth::handlers::mfa::webauthn::register::start_webauthn_registration,
        xavyo_api_auth::handlers::mfa::webauthn::register::finish_webauthn_registration,
        xavyo_api_auth::handlers::mfa::webauthn::authenticate::start_webauthn_authentication,
        xavyo_api_auth::handlers::mfa::webauthn::authenticate::finish_webauthn_authentication,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::list_webauthn_credentials,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::update_webauthn_credential,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::delete_webauthn_credential,
        // Auth - Admin WebAuthn (F032)
        xavyo_api_auth::handlers::admin::webauthn_policy::get_webauthn_policy,
        xavyo_api_auth::handlers::admin::webauthn_policy::update_webauthn_policy,
        xavyo_api_auth::handlers::admin::webauthn_policy::admin_list_user_credentials,
        xavyo_api_auth::handlers::admin::webauthn_policy::admin_revoke_credential,
        // OAuth2
        xavyo_api_oauth::handlers::authorize::authorize_handler,
        xavyo_api_oauth::handlers::authorize::consent_handler,
        xavyo_api_oauth::handlers::token::token_handler,
        xavyo_api_oauth::handlers::discovery::discovery_handler,
        xavyo_api_oauth::handlers::discovery::jwks_handler,
        xavyo_api_oauth::handlers::userinfo::userinfo_handler,
        // OAuth2 Device Code (RFC 8628)
        xavyo_api_oauth::handlers::device::device_authorization_handler,
        // OAuth2 Admin
        xavyo_api_oauth::handlers::client_admin::list_clients_handler,
        xavyo_api_oauth::handlers::client_admin::get_client_handler,
        xavyo_api_oauth::handlers::client_admin::create_client_handler,
        xavyo_api_oauth::handlers::client_admin::update_client_handler,
        xavyo_api_oauth::handlers::client_admin::delete_client_handler,
        xavyo_api_oauth::handlers::client_admin::regenerate_secret_handler,
        // Users
        xavyo_api_users::handlers::create::create_user_handler,
        xavyo_api_users::handlers::list::list_users_handler,
        xavyo_api_users::handlers::get::get_user_handler,
        xavyo_api_users::handlers::update::update_user_handler,
        xavyo_api_users::handlers::delete::delete_user_handler,
        // Attribute Definitions (F070)
        xavyo_api_users::handlers::attribute_definitions::create_attribute_definition,
        xavyo_api_users::handlers::attribute_definitions::list_attribute_definitions,
        xavyo_api_users::handlers::attribute_definitions::get_attribute_definition,
        xavyo_api_users::handlers::attribute_definitions::update_attribute_definition,
        xavyo_api_users::handlers::attribute_definitions::delete_attribute_definition,
        // Well-Known Attribute Seeding (F081)
        xavyo_api_users::handlers::attribute_definitions::seed_wellknown,
        // User Custom Attributes (F070)
        xavyo_api_users::handlers::user_custom_attributes::get_user_custom_attributes,
        xavyo_api_users::handlers::user_custom_attributes::set_user_custom_attributes,
        xavyo_api_users::handlers::user_custom_attributes::patch_user_custom_attributes,
        // Bulk Operations (F070 - US4)
        xavyo_api_users::handlers::user_custom_attributes::bulk_update_custom_attribute,
        // Attribute Audit (F070 - FR-017)
        xavyo_api_users::handlers::attribute_audit::audit_missing_required_attributes,
        // Group Hierarchy (F071)
        xavyo_api_users::handlers::group_hierarchy::list_groups,
        xavyo_api_users::handlers::group_hierarchy::move_group,
        xavyo_api_users::handlers::group_hierarchy::get_children,
        xavyo_api_users::handlers::group_hierarchy::get_ancestors,
        xavyo_api_users::handlers::group_hierarchy::get_subtree,
        xavyo_api_users::handlers::group_hierarchy::list_root_groups,
        xavyo_api_users::handlers::group_hierarchy::get_subtree_members,
        // SAML
        xavyo_api_saml::handlers::sso::sso_redirect,
        xavyo_api_saml::handlers::sso::sso_post,
        xavyo_api_saml::handlers::metadata::get_metadata,
        xavyo_api_saml::handlers::initiate::initiate_sso,
        xavyo_api_saml::handlers::admin::service_providers::list_service_providers,
        xavyo_api_saml::handlers::admin::service_providers::create_service_provider,
        xavyo_api_saml::handlers::admin::service_providers::get_service_provider,
        xavyo_api_saml::handlers::admin::service_providers::update_service_provider,
        xavyo_api_saml::handlers::admin::service_providers::delete_service_provider,
        xavyo_api_saml::handlers::admin::certificates::list_certificates,
        xavyo_api_saml::handlers::admin::certificates::upload_certificate,
        xavyo_api_saml::handlers::admin::certificates::activate_certificate,
        // SCIM
        xavyo_api_scim::handlers::users::list_users,
        xavyo_api_scim::handlers::users::create_user,
        xavyo_api_scim::handlers::users::get_user,
        xavyo_api_scim::handlers::users::replace_user,
        xavyo_api_scim::handlers::users::update_user,
        xavyo_api_scim::handlers::users::delete_user,
        // OIDC Federation
        xavyo_api_oidc_federation::handlers::admin::list_identity_providers,
        xavyo_api_oidc_federation::handlers::admin::create_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::get_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::update_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::delete_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::validate_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::toggle_identity_provider,
        xavyo_api_oidc_federation::handlers::admin::list_domains,
        xavyo_api_oidc_federation::handlers::admin::add_domain,
        xavyo_api_oidc_federation::handlers::admin::remove_domain,
        // Social Login
        xavyo_api_social::handlers::admin::list_providers,
        xavyo_api_social::handlers::admin::update_provider,
        xavyo_api_social::handlers::admin::disable_provider,
        // Governance - Applications (F033)
        xavyo_api_governance::handlers::applications::list_applications,
        xavyo_api_governance::handlers::applications::get_application,
        xavyo_api_governance::handlers::applications::create_application,
        xavyo_api_governance::handlers::applications::update_application,
        xavyo_api_governance::handlers::applications::delete_application,
        // Governance - Entitlements (F033)
        xavyo_api_governance::handlers::entitlements::list_entitlements,
        xavyo_api_governance::handlers::entitlements::get_entitlement,
        xavyo_api_governance::handlers::entitlements::create_entitlement,
        xavyo_api_governance::handlers::entitlements::update_entitlement,
        xavyo_api_governance::handlers::entitlements::delete_entitlement,
        // Governance - Assignments (F033)
        xavyo_api_governance::handlers::assignments::list_assignments,
        xavyo_api_governance::handlers::assignments::get_assignment,
        xavyo_api_governance::handlers::assignments::create_assignment,
        xavyo_api_governance::handlers::assignments::bulk_create_assignments,
        xavyo_api_governance::handlers::assignments::revoke_assignment,
        // Governance - Role Entitlements (F033)
        xavyo_api_governance::handlers::role_mappings::list_role_entitlements,
        xavyo_api_governance::handlers::role_mappings::create_role_entitlement,
        xavyo_api_governance::handlers::role_mappings::delete_role_entitlement,
        // Governance - Entitlement Owners (F033)
        xavyo_api_governance::handlers::owners::set_owner,
        xavyo_api_governance::handlers::owners::remove_owner,
        // Governance - Effective Access (F033)
        xavyo_api_governance::handlers::effective_access::get_effective_access,
        // Governance - SoD Rules (F034)
        xavyo_api_governance::handlers::sod_rules::list_sod_rules,
        xavyo_api_governance::handlers::sod_rules::get_sod_rule,
        xavyo_api_governance::handlers::sod_rules::create_sod_rule,
        xavyo_api_governance::handlers::sod_rules::update_sod_rule,
        xavyo_api_governance::handlers::sod_rules::delete_sod_rule,
        xavyo_api_governance::handlers::sod_rules::enable_sod_rule,
        xavyo_api_governance::handlers::sod_rules::disable_sod_rule,
        xavyo_api_governance::handlers::sod_rules::sod_check,
        // Governance - SoD Violations (F034)
        xavyo_api_governance::handlers::sod_violations::list_violations,
        xavyo_api_governance::handlers::sod_violations::get_violation,
        xavyo_api_governance::handlers::sod_violations::scan_rule,
        xavyo_api_governance::handlers::sod_violations::remediate_violation,
        // Governance - SoD Exemptions (F034)
        xavyo_api_governance::handlers::sod_exemptions::list_exemptions,
        xavyo_api_governance::handlers::sod_exemptions::get_exemption,
        xavyo_api_governance::handlers::sod_exemptions::create_exemption,
        xavyo_api_governance::handlers::sod_exemptions::revoke_exemption,
        // Governance - Access Requests (F035)
        xavyo_api_governance::handlers::access_requests::list_my_requests,
        xavyo_api_governance::handlers::access_requests::get_request,
        xavyo_api_governance::handlers::access_requests::create_request,
        xavyo_api_governance::handlers::access_requests::cancel_request,
        // Governance - Approvals (F035)
        xavyo_api_governance::handlers::approvals::list_pending_approvals,
        xavyo_api_governance::handlers::approvals::approve_request,
        xavyo_api_governance::handlers::approvals::reject_request,
        // Governance - Approval Workflows (F035)
        xavyo_api_governance::handlers::approval_workflows::list_workflows,
        xavyo_api_governance::handlers::approval_workflows::get_workflow,
        xavyo_api_governance::handlers::approval_workflows::create_workflow,
        xavyo_api_governance::handlers::approval_workflows::update_workflow,
        xavyo_api_governance::handlers::approval_workflows::delete_workflow,
        xavyo_api_governance::handlers::approval_workflows::set_default_workflow,
        // Governance - Delegations (F035)
        xavyo_api_governance::handlers::delegations::list_my_delegations,
        xavyo_api_governance::handlers::delegations::get_delegation,
        xavyo_api_governance::handlers::delegations::create_delegation,
        xavyo_api_governance::handlers::delegations::revoke_delegation,
        // Governance - Certification Campaigns (F036)
        xavyo_api_governance::handlers::certification_campaigns::list_campaigns,
        xavyo_api_governance::handlers::certification_campaigns::get_campaign,
        xavyo_api_governance::handlers::certification_campaigns::create_campaign,
        xavyo_api_governance::handlers::certification_campaigns::update_campaign,
        xavyo_api_governance::handlers::certification_campaigns::delete_campaign,
        xavyo_api_governance::handlers::certification_campaigns::launch_campaign,
        xavyo_api_governance::handlers::certification_campaigns::cancel_campaign,
        xavyo_api_governance::handlers::certification_campaigns::get_campaign_progress,
        // Governance - Certification Items (F036)
        xavyo_api_governance::handlers::certification_items::list_campaign_items,
        xavyo_api_governance::handlers::certification_items::get_item,
        xavyo_api_governance::handlers::certification_items::decide_item,
        xavyo_api_governance::handlers::certification_items::reassign_item,
        xavyo_api_governance::handlers::certification_items::get_my_certifications,
        xavyo_api_governance::handlers::certification_items::get_my_certifications_summary,
        // Governance - Compliance Reporting: Report Templates (F042)
        xavyo_api_governance::handlers::report_templates::list_templates,
        xavyo_api_governance::handlers::report_templates::get_template,
        xavyo_api_governance::handlers::report_templates::create_template,
        xavyo_api_governance::handlers::report_templates::clone_template,
        xavyo_api_governance::handlers::report_templates::update_template,
        xavyo_api_governance::handlers::report_templates::archive_template,
        // Governance - Compliance Reporting: Generated Reports (F042)
        xavyo_api_governance::handlers::reports::list_reports,
        xavyo_api_governance::handlers::reports::get_report,
        xavyo_api_governance::handlers::reports::generate_report,
        xavyo_api_governance::handlers::reports::get_report_data,
        xavyo_api_governance::handlers::reports::delete_report,
        xavyo_api_governance::handlers::reports::cleanup_expired_reports,
        // Governance - Compliance Reporting: Report Schedules (F042)
        xavyo_api_governance::handlers::report_schedules::list_schedules,
        xavyo_api_governance::handlers::report_schedules::get_schedule,
        xavyo_api_governance::handlers::report_schedules::create_schedule,
        xavyo_api_governance::handlers::report_schedules::update_schedule,
        xavyo_api_governance::handlers::report_schedules::delete_schedule,
        xavyo_api_governance::handlers::report_schedules::pause_schedule,
        xavyo_api_governance::handlers::report_schedules::resume_schedule,
        // Governance - Role Mining: Jobs (F041)
        xavyo_api_governance::handlers::role_mining::list_mining_jobs,
        xavyo_api_governance::handlers::role_mining::get_mining_job,
        xavyo_api_governance::handlers::role_mining::create_mining_job,
        xavyo_api_governance::handlers::role_mining::run_mining_job,
        xavyo_api_governance::handlers::role_mining::cancel_mining_job,
        // Governance - Role Mining: Candidates (F041)
        xavyo_api_governance::handlers::role_mining::list_candidates,
        xavyo_api_governance::handlers::role_mining::get_candidate,
        xavyo_api_governance::handlers::role_mining::promote_candidate,
        xavyo_api_governance::handlers::role_mining::dismiss_candidate,
        // Governance - Role Mining: Access Patterns (F041)
        xavyo_api_governance::handlers::role_mining::list_access_patterns,
        xavyo_api_governance::handlers::role_mining::get_access_pattern,
        // Governance - Role Mining: Excessive Privileges (F041)
        xavyo_api_governance::handlers::role_mining::list_excessive_privileges,
        xavyo_api_governance::handlers::role_mining::get_excessive_privilege,
        xavyo_api_governance::handlers::role_mining::review_excessive_privilege,
        // Governance - Role Mining: Consolidation Suggestions (F041)
        xavyo_api_governance::handlers::role_mining::list_consolidation_suggestions,
        xavyo_api_governance::handlers::role_mining::get_consolidation_suggestion,
        xavyo_api_governance::handlers::role_mining::dismiss_consolidation_suggestion,
        // Governance - Role Mining: Simulations (F041)
        xavyo_api_governance::handlers::role_mining::list_simulations,
        xavyo_api_governance::handlers::role_mining::get_simulation,
        xavyo_api_governance::handlers::role_mining::create_simulation,
        xavyo_api_governance::handlers::role_mining::execute_simulation,
        xavyo_api_governance::handlers::role_mining::apply_simulation,
        xavyo_api_governance::handlers::role_mining::cancel_simulation,
        // Governance - Role Mining: Metrics (F041)
        xavyo_api_governance::handlers::role_mining::list_metrics,
        xavyo_api_governance::handlers::role_mining::get_role_metrics,
        xavyo_api_governance::handlers::role_mining::calculate_metrics,
        // Governance - Role Hierarchy (F088)
        xavyo_api_governance::handlers::role_hierarchy::list_roles,
        xavyo_api_governance::handlers::role_hierarchy::create_role,
        xavyo_api_governance::handlers::role_hierarchy::get_role,
        xavyo_api_governance::handlers::role_hierarchy::update_role,
        xavyo_api_governance::handlers::role_hierarchy::delete_role,
        xavyo_api_governance::handlers::role_hierarchy::get_tree,
        xavyo_api_governance::handlers::role_hierarchy::get_ancestors,
        xavyo_api_governance::handlers::role_hierarchy::get_descendants,
        xavyo_api_governance::handlers::role_hierarchy::get_children,
        xavyo_api_governance::handlers::role_hierarchy::move_role,
        xavyo_api_governance::handlers::role_hierarchy::get_impact,
        // Governance - Role Entitlements (F088)
        xavyo_api_governance::handlers::role_entitlements::list_role_entitlements,
        xavyo_api_governance::handlers::role_entitlements::add_role_entitlement,
        xavyo_api_governance::handlers::role_entitlements::remove_role_entitlement,
        xavyo_api_governance::handlers::role_entitlements::get_effective_entitlements,
        xavyo_api_governance::handlers::role_entitlements::recompute_effective_entitlements,
        // Governance - Role Inheritance Blocks (F088)
        xavyo_api_governance::handlers::role_inheritance_blocks::list_inheritance_blocks,
        xavyo_api_governance::handlers::role_inheritance_blocks::add_inheritance_block,
        xavyo_api_governance::handlers::role_inheritance_blocks::remove_inheritance_block,
        // Governance - Lifecycle Events (F037)
        xavyo_api_governance::handlers::lifecycle_events::list_events,
        xavyo_api_governance::handlers::lifecycle_events::get_event,
        xavyo_api_governance::handlers::lifecycle_events::create_event,
        xavyo_api_governance::handlers::lifecycle_events::process_event,
        xavyo_api_governance::handlers::lifecycle_events::trigger_event,
        // Governance - Lifecycle Actions (F037)
        xavyo_api_governance::handlers::lifecycle_actions::list_actions,
        xavyo_api_governance::handlers::lifecycle_actions::cancel_action,
        xavyo_api_governance::handlers::lifecycle_actions::execute_due_actions,
        // Governance - Access Snapshots (F037)
        xavyo_api_governance::handlers::access_snapshots::list_snapshots,
        xavyo_api_governance::handlers::access_snapshots::get_snapshot,
        xavyo_api_governance::handlers::access_snapshots::list_user_snapshots,
        // Governance - Birthright Policies (F038)
        xavyo_api_governance::handlers::birthright_policies::list_policies,
        xavyo_api_governance::handlers::birthright_policies::get_policy,
        xavyo_api_governance::handlers::birthright_policies::create_policy,
        xavyo_api_governance::handlers::birthright_policies::update_policy,
        xavyo_api_governance::handlers::birthright_policies::archive_policy,
        xavyo_api_governance::handlers::birthright_policies::enable_policy,
        xavyo_api_governance::handlers::birthright_policies::disable_policy,
        xavyo_api_governance::handlers::birthright_policies::simulate_policy,
        xavyo_api_governance::handlers::birthright_policies::simulate_all_policies,
        xavyo_api_governance::handlers::birthright_policies::analyze_policy_impact,
        // Governance - Risk Factors (F039)
        xavyo_api_governance::handlers::risk_factors::list_risk_factors,
        xavyo_api_governance::handlers::risk_factors::create_risk_factor,
        xavyo_api_governance::handlers::risk_factors::get_risk_factor,
        xavyo_api_governance::handlers::risk_factors::update_risk_factor,
        xavyo_api_governance::handlers::risk_factors::delete_risk_factor,
        xavyo_api_governance::handlers::risk_factors::enable_risk_factor,
        xavyo_api_governance::handlers::risk_factors::disable_risk_factor,
        // Governance - Risk Scores (F039)
        xavyo_api_governance::handlers::risk_scores::get_user_risk_score,
        xavyo_api_governance::handlers::risk_scores::calculate_user_risk_score,
        xavyo_api_governance::handlers::risk_scores::get_user_risk_score_history,
        xavyo_api_governance::handlers::risk_scores::list_risk_scores,
        xavyo_api_governance::handlers::risk_scores::get_risk_score_summary,
        xavyo_api_governance::handlers::risk_scores::calculate_all_risk_scores,
        xavyo_api_governance::handlers::risk_scores::save_risk_score_snapshot,
        xavyo_api_governance::handlers::risk_scores::get_user_risk_enforcement,
        // Risk Enforcement Policy (F073)
        xavyo_api_governance::handlers::risk_scores::get_enforcement_policy,
        xavyo_api_governance::handlers::risk_scores::upsert_enforcement_policy,
        // Governance - Peer Groups (F039)
        xavyo_api_governance::handlers::peer_groups::list_peer_groups,
        xavyo_api_governance::handlers::peer_groups::create_peer_group,
        xavyo_api_governance::handlers::peer_groups::get_peer_group,
        xavyo_api_governance::handlers::peer_groups::delete_peer_group,
        xavyo_api_governance::handlers::peer_groups::refresh_peer_group_stats,
        xavyo_api_governance::handlers::peer_groups::refresh_all_peer_groups,
        xavyo_api_governance::handlers::peer_groups::get_user_peer_comparison,
        // Governance - Risk Alerts (F039)
        xavyo_api_governance::handlers::risk_alerts::list_risk_alerts,
        xavyo_api_governance::handlers::risk_alerts::get_risk_alert,
        xavyo_api_governance::handlers::risk_alerts::acknowledge_risk_alert,
        xavyo_api_governance::handlers::risk_alerts::acknowledge_user_alerts,
        xavyo_api_governance::handlers::risk_alerts::get_alert_summary,
        xavyo_api_governance::handlers::risk_alerts::delete_risk_alert,
        xavyo_api_governance::handlers::risk_alerts::get_user_latest_alert,
        // Governance - Orphan Detection (F040)
        xavyo_api_governance::handlers::orphan_detections::list_orphan_detections,
        xavyo_api_governance::handlers::orphan_detections::get_orphan_summary,
        xavyo_api_governance::handlers::orphan_detections::get_orphan_detection,
        xavyo_api_governance::handlers::orphan_detections::start_review,
        xavyo_api_governance::handlers::orphan_detections::reassign_orphan,
        xavyo_api_governance::handlers::orphan_detections::disable_orphan,
        xavyo_api_governance::handlers::orphan_detections::delete_orphan,
        xavyo_api_governance::handlers::orphan_detections::dismiss_orphan,
        xavyo_api_governance::handlers::orphan_detections::bulk_remediate,
        xavyo_api_governance::handlers::orphan_detections::get_age_analysis,
        xavyo_api_governance::handlers::orphan_detections::get_risk_report,
        xavyo_api_governance::handlers::orphan_detections::export_orphans_csv,
        // Governance - Detection Rules (F040)
        xavyo_api_governance::handlers::detection_rules::list_detection_rules,
        xavyo_api_governance::handlers::detection_rules::get_detection_rule,
        xavyo_api_governance::handlers::detection_rules::create_detection_rule,
        xavyo_api_governance::handlers::detection_rules::update_detection_rule,
        xavyo_api_governance::handlers::detection_rules::delete_detection_rule,
        xavyo_api_governance::handlers::detection_rules::enable_detection_rule,
        xavyo_api_governance::handlers::detection_rules::disable_detection_rule,
        xavyo_api_governance::handlers::detection_rules::seed_default_rules,
        // Governance - Reconciliation Runs (F040)
        xavyo_api_governance::handlers::reconciliation_runs::trigger_reconciliation,
        xavyo_api_governance::handlers::reconciliation_runs::get_reconciliation_run,
        xavyo_api_governance::handlers::reconciliation_runs::list_reconciliation_runs,
        xavyo_api_governance::handlers::reconciliation_runs::cancel_reconciliation,
        xavyo_api_governance::handlers::reconciliation_runs::get_schedule,
        xavyo_api_governance::handlers::reconciliation_runs::upsert_schedule,
        xavyo_api_governance::handlers::reconciliation_runs::delete_schedule,
        xavyo_api_governance::handlers::reconciliation_runs::trigger_scheduled_runs,
        // Governance - Object Lifecycle States (F052)
        // Lifecycle Config
        xavyo_api_governance::handlers::lifecycle_config::list_configs,
        xavyo_api_governance::handlers::lifecycle_config::get_config,
        xavyo_api_governance::handlers::lifecycle_config::create_config,
        xavyo_api_governance::handlers::lifecycle_config::update_config,
        xavyo_api_governance::handlers::lifecycle_config::delete_config,
        xavyo_api_governance::handlers::lifecycle_config::add_state,
        xavyo_api_governance::handlers::lifecycle_config::update_state,
        xavyo_api_governance::handlers::lifecycle_config::delete_state,
        xavyo_api_governance::handlers::lifecycle_config::add_transition,
        xavyo_api_governance::handlers::lifecycle_config::delete_transition,
        // State Transitions
        xavyo_api_governance::handlers::state_transition::execute_transition,
        xavyo_api_governance::handlers::state_transition::get_object_state,
        xavyo_api_governance::handlers::state_transition::list_transition_requests,
        xavyo_api_governance::handlers::state_transition::get_transition_request,
        xavyo_api_governance::handlers::state_transition::list_transition_audit,
        xavyo_api_governance::handlers::state_transition::get_transition_audit,
        xavyo_api_governance::handlers::state_transition::export_transition_audit,
        xavyo_api_governance::handlers::state_transition::rollback_transition,
        xavyo_api_governance::handlers::state_transition::get_affected_entitlements,
        // Scheduled Transitions
        xavyo_api_governance::handlers::scheduled_transition::list_scheduled_transitions,
        xavyo_api_governance::handlers::scheduled_transition::get_scheduled_transition,
        xavyo_api_governance::handlers::scheduled_transition::cancel_scheduled_transition,
        xavyo_api_governance::handlers::scheduled_transition::trigger_due_transitions,
        // Bulk State Operations
        xavyo_api_governance::handlers::bulk_state_operation::create_bulk_operation,
        xavyo_api_governance::handlers::bulk_state_operation::list_bulk_operations,
        xavyo_api_governance::handlers::bulk_state_operation::get_bulk_operation,
        xavyo_api_governance::handlers::bulk_state_operation::cancel_bulk_operation,
        xavyo_api_governance::handlers::bulk_state_operation::process_bulk_operations,
        // Connectors (F045)
        xavyo_api_connectors::handlers::list_connectors,
        xavyo_api_connectors::handlers::create_connector,
        xavyo_api_connectors::handlers::get_connector,
        xavyo_api_connectors::handlers::update_connector,
        xavyo_api_connectors::handlers::delete_connector,
        xavyo_api_connectors::handlers::test_connector,
        xavyo_api_connectors::handlers::activate_connector,
        xavyo_api_connectors::handlers::deactivate_connector,
        xavyo_api_connectors::handlers::get_connector_health,
        // Schema Discovery (F046)
        xavyo_api_connectors::handlers::discover_schema,
        xavyo_api_connectors::handlers::get_schema,
        xavyo_api_connectors::handlers::get_object_class,
        xavyo_api_connectors::handlers::clear_schema_cache,
        xavyo_api_connectors::handlers::trigger_schema_discovery,
        xavyo_api_connectors::handlers::get_discovery_status,
        xavyo_api_connectors::handlers::get_cached_schema,
        xavyo_api_connectors::handlers::list_schema_versions,
        xavyo_api_connectors::handlers::diff_schema_versions,
        xavyo_api_connectors::handlers::list_object_classes,
        xavyo_api_connectors::handlers::get_object_class_details,
        xavyo_api_connectors::handlers::list_object_class_attributes,
        xavyo_api_connectors::handlers::get_refresh_schedule,
        xavyo_api_connectors::handlers::set_refresh_schedule,
        xavyo_api_connectors::handlers::delete_refresh_schedule,
        // Attribute Mappings (F046)
        xavyo_api_connectors::handlers::create_mapping,
        xavyo_api_connectors::handlers::list_mappings,
        xavyo_api_connectors::handlers::get_mapping,
        xavyo_api_connectors::handlers::update_mapping,
        xavyo_api_connectors::handlers::delete_mapping,
        xavyo_api_connectors::handlers::preview_mapping,
        // Workflow Escalation: Escalation Policies (F054)
        xavyo_api_governance::handlers::escalation_policies::list_policies,
        xavyo_api_governance::handlers::escalation_policies::get_policy,
        xavyo_api_governance::handlers::escalation_policies::create_policy,
        xavyo_api_governance::handlers::escalation_policies::update_policy,
        xavyo_api_governance::handlers::escalation_policies::delete_policy,
        xavyo_api_governance::handlers::escalation_policies::set_default_policy,
        xavyo_api_governance::handlers::escalation_policies::add_level,
        xavyo_api_governance::handlers::escalation_policies::remove_level,
        // Workflow Escalation: Step Escalation Configuration (F054)
        xavyo_api_governance::handlers::escalation_policies::get_step_escalation,
        xavyo_api_governance::handlers::escalation_policies::configure_step_escalation,
        xavyo_api_governance::handlers::escalation_policies::remove_step_escalation,
        xavyo_api_governance::handlers::escalation_policies::enable_step_escalation,
        xavyo_api_governance::handlers::escalation_policies::disable_step_escalation,
        // Workflow Escalation: Approval Groups (F054)
        xavyo_api_governance::handlers::approval_groups::list_groups,
        xavyo_api_governance::handlers::approval_groups::get_group,
        xavyo_api_governance::handlers::approval_groups::create_group,
        xavyo_api_governance::handlers::approval_groups::update_group,
        xavyo_api_governance::handlers::approval_groups::delete_group,
        xavyo_api_governance::handlers::approval_groups::add_members,
        xavyo_api_governance::handlers::approval_groups::remove_members,
        xavyo_api_governance::handlers::approval_groups::enable_group,
        xavyo_api_governance::handlers::approval_groups::disable_group,
        xavyo_api_governance::handlers::approval_groups::get_user_groups,
        // Workflow Escalation: Escalation Events / Audit Trail (F054)
        xavyo_api_governance::handlers::escalation_events::list_escalation_events,
        xavyo_api_governance::handlers::escalation_events::get_request_escalation_history,
        // Workflow Escalation: Cancel/Reset Escalation Actions (F054 T067-T070)
        xavyo_api_governance::handlers::escalation_events::cancel_escalation,
        xavyo_api_governance::handlers::escalation_events::reset_escalation,
        // Micro-certification Triggers (F055)
        xavyo_api_governance::handlers::micro_cert_triggers::list_triggers,
        xavyo_api_governance::handlers::micro_cert_triggers::get_trigger,
        xavyo_api_governance::handlers::micro_cert_triggers::create_trigger,
        xavyo_api_governance::handlers::micro_cert_triggers::update_trigger,
        xavyo_api_governance::handlers::micro_cert_triggers::delete_trigger,
        xavyo_api_governance::handlers::micro_cert_triggers::set_default,
        xavyo_api_governance::handlers::micro_cert_triggers::enable_trigger,
        xavyo_api_governance::handlers::micro_cert_triggers::disable_trigger,
        // Micro-certifications (F055)
        xavyo_api_governance::handlers::micro_certifications::list_certifications,
        xavyo_api_governance::handlers::micro_certifications::my_pending,
        xavyo_api_governance::handlers::micro_certifications::get_stats,
        xavyo_api_governance::handlers::micro_certifications::bulk_decide,
        xavyo_api_governance::handlers::micro_certifications::manual_trigger,
        xavyo_api_governance::handlers::micro_certifications::get_certification,
        xavyo_api_governance::handlers::micro_certifications::decide,
        xavyo_api_governance::handlers::micro_certifications::delegate,
        xavyo_api_governance::handlers::micro_certifications::get_events,
        xavyo_api_governance::handlers::micro_certifications::search_events,
        xavyo_api_governance::handlers::micro_certifications::skip_certification,
        // Meta-roles (F056)
        xavyo_api_governance::handlers::meta_roles::list_meta_roles,
        xavyo_api_governance::handlers::meta_roles::create_meta_role,
        xavyo_api_governance::handlers::meta_roles::get_meta_role,
        xavyo_api_governance::handlers::meta_roles::update_meta_role,
        xavyo_api_governance::handlers::meta_roles::delete_meta_role,
        xavyo_api_governance::handlers::meta_roles::enable_meta_role,
        xavyo_api_governance::handlers::meta_roles::disable_meta_role,
        xavyo_api_governance::handlers::meta_roles::add_criteria,
        xavyo_api_governance::handlers::meta_roles::remove_criteria,
        xavyo_api_governance::handlers::meta_roles::add_entitlement,
        xavyo_api_governance::handlers::meta_roles::remove_entitlement,
        xavyo_api_governance::handlers::meta_roles::add_constraint,
        xavyo_api_governance::handlers::meta_roles::remove_constraint,
        xavyo_api_governance::handlers::meta_roles::get_role_meta_roles,
        xavyo_api_governance::handlers::meta_roles::list_inheritances,
        xavyo_api_governance::handlers::meta_roles::reevaluate_meta_role,
        xavyo_api_governance::handlers::meta_roles::list_conflicts,
        xavyo_api_governance::handlers::meta_roles::resolve_conflict,
        xavyo_api_governance::handlers::meta_roles::simulate_changes,
        xavyo_api_governance::handlers::meta_roles::trigger_cascade,
        xavyo_api_governance::handlers::meta_roles::list_events,
        xavyo_api_governance::handlers::meta_roles::get_event_stats,
        // Parametric Roles (F057)
        xavyo_api_governance::handlers::parametric_roles::list_role_parameters,
        xavyo_api_governance::handlers::parametric_roles::add_role_parameter,
        xavyo_api_governance::handlers::parametric_roles::get_role_parameter,
        xavyo_api_governance::handlers::parametric_roles::update_role_parameter,
        xavyo_api_governance::handlers::parametric_roles::delete_role_parameter,
        xavyo_api_governance::handlers::parametric_roles::validate_parameters,
        xavyo_api_governance::handlers::parametric_roles::create_parametric_assignment,
        xavyo_api_governance::handlers::parametric_roles::get_parametric_assignment,
        xavyo_api_governance::handlers::parametric_roles::list_user_parametric_assignments,
        xavyo_api_governance::handlers::parametric_roles::get_assignment_parameters,
        xavyo_api_governance::handlers::parametric_roles::update_assignment_parameters,
        xavyo_api_governance::handlers::parametric_roles::list_parameter_audit,
        xavyo_api_governance::handlers::parametric_roles::get_assignment_parameter_audit,
        // Object Templates (F058)
        xavyo_api_governance::handlers::object_templates::list_templates,
        xavyo_api_governance::handlers::object_templates::create_template,
        xavyo_api_governance::handlers::object_templates::get_template,
        xavyo_api_governance::handlers::object_templates::update_template,
        xavyo_api_governance::handlers::object_templates::delete_template,
        xavyo_api_governance::handlers::object_templates::activate_template,
        xavyo_api_governance::handlers::object_templates::disable_template,
        xavyo_api_governance::handlers::object_templates::list_rules,
        xavyo_api_governance::handlers::object_templates::add_rule,
        xavyo_api_governance::handlers::object_templates::get_rule,
        xavyo_api_governance::handlers::object_templates::update_rule,
        xavyo_api_governance::handlers::object_templates::remove_rule,
        xavyo_api_governance::handlers::object_templates::list_versions,
        xavyo_api_governance::handlers::object_templates::get_version,
        xavyo_api_governance::handlers::object_templates::list_events,
        xavyo_api_governance::handlers::object_templates::add_scope,
        xavyo_api_governance::handlers::object_templates::list_scopes,
        xavyo_api_governance::handlers::object_templates::remove_scope,
        xavyo_api_governance::handlers::object_templates::list_application_events_by_template,
        xavyo_api_governance::handlers::object_templates::list_application_events_by_object,
        // Outlier Detection (F059)
        xavyo_api_governance::handlers::outliers::get_config,
        xavyo_api_governance::handlers::outliers::update_config,
        xavyo_api_governance::handlers::outliers::enable_detection,
        xavyo_api_governance::handlers::outliers::disable_detection,
        xavyo_api_governance::handlers::outliers::list_analyses,
        xavyo_api_governance::handlers::outliers::trigger_analysis,
        xavyo_api_governance::handlers::outliers::get_analysis,
        xavyo_api_governance::handlers::outliers::cancel_analysis,
        xavyo_api_governance::handlers::outliers::list_results,
        xavyo_api_governance::handlers::outliers::get_result,
        xavyo_api_governance::handlers::outliers::get_summary,
        xavyo_api_governance::handlers::outliers::get_user_history,
        xavyo_api_governance::handlers::outliers::create_disposition,
        xavyo_api_governance::handlers::outliers::get_disposition,
        xavyo_api_governance::handlers::outliers::update_disposition,
        xavyo_api_governance::handlers::outliers::list_dispositions,
        xavyo_api_governance::handlers::outliers::get_disposition_summary,
        xavyo_api_governance::handlers::outliers::list_alerts,
        xavyo_api_governance::handlers::outliers::get_alert_summary,
        xavyo_api_governance::handlers::outliers::mark_alert_read,
        xavyo_api_governance::handlers::outliers::dismiss_alert,
        xavyo_api_governance::handlers::outliers::generate_report,
        // Enhanced Simulation (F060)
        xavyo_api_governance::handlers::batch_simulations::get_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::list_batch_simulations,
        xavyo_api_governance::handlers::batch_simulations::create_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::execute_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::apply_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::cancel_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::archive_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::restore_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::update_batch_simulation_notes,
        xavyo_api_governance::handlers::batch_simulations::get_batch_simulation_results,
        xavyo_api_governance::handlers::batch_simulations::delete_batch_simulation,
        xavyo_api_governance::handlers::batch_simulations::export_batch_simulation,
        // NHI Lifecycle (F061)
        xavyo_api_governance::handlers::nhis::list_nhis,
        xavyo_api_governance::handlers::nhis::get_nhi_summary,
        xavyo_api_governance::handlers::nhis::get_nhi,
        xavyo_api_governance::handlers::nhis::create_nhi,
        xavyo_api_governance::handlers::nhis::update_nhi,
        xavyo_api_governance::handlers::nhis::delete_nhi,
        xavyo_api_governance::handlers::nhis::suspend_nhi,
        xavyo_api_governance::handlers::nhis::reactivate_nhi,
        xavyo_api_governance::handlers::nhis::transfer_nhi_ownership,
        xavyo_api_governance::handlers::nhis::certify_nhi,
        xavyo_api_governance::handlers::nhis::list_nhi_credentials,
        xavyo_api_governance::handlers::nhis::get_nhi_credential,
        xavyo_api_governance::handlers::nhis::rotate_nhi_credentials,
        xavyo_api_governance::handlers::nhis::revoke_nhi_credential,
        xavyo_api_governance::handlers::nhis::record_nhi_usage,
        xavyo_api_governance::handlers::nhis::list_nhi_usage,
        xavyo_api_governance::handlers::nhis::get_nhi_usage_summary,
        xavyo_api_governance::handlers::nhis::get_nhi_staleness_report,
        xavyo_api_governance::handlers::nhis::get_nhi_risk_score,
        xavyo_api_governance::handlers::nhis::calculate_nhi_risk_score,
        xavyo_api_governance::handlers::nhis::get_nhi_risk_summary,
        xavyo_api_governance::handlers::nhis::batch_calculate_nhi_risk,
        xavyo_api_governance::handlers::nhis::create_nhi_certification_campaign,
        xavyo_api_governance::handlers::nhis::launch_nhi_certification_campaign,
        xavyo_api_governance::handlers::nhis::get_nhi_certification_campaign,
        xavyo_api_governance::handlers::nhis::list_nhi_certification_campaigns,
        xavyo_api_governance::handlers::nhis::cancel_nhi_certification_campaign,
        xavyo_api_governance::handlers::nhis::get_nhi_certification_campaign_summary,
        xavyo_api_governance::handlers::nhis::list_nhi_certification_items,
        xavyo_api_governance::handlers::nhis::get_nhi_certification_item,
        xavyo_api_governance::handlers::nhis::decide_nhi_certification,
        xavyo_api_governance::handlers::nhis::bulk_decide_nhi_certification,
        xavyo_api_governance::handlers::nhis::get_my_pending_nhi_certifications,
        xavyo_api_governance::handlers::nhis::submit_nhi_request,
        xavyo_api_governance::handlers::nhis::list_nhi_requests,
        xavyo_api_governance::handlers::nhis::get_my_pending_nhi_requests,
        xavyo_api_governance::handlers::nhis::get_nhi_request,
        xavyo_api_governance::handlers::nhis::approve_nhi_request,
        xavyo_api_governance::handlers::nhis::reject_nhi_request,
        xavyo_api_governance::handlers::nhis::cancel_nhi_request,
        xavyo_api_governance::handlers::nhis::get_nhi_request_summary,
        // Identity Merge (F062)
        xavyo_api_governance::handlers::identity_merge::list_duplicates,
        xavyo_api_governance::handlers::identity_merge::get_duplicate,
        xavyo_api_governance::handlers::identity_merge::dismiss_duplicate,
        xavyo_api_governance::handlers::identity_merge::preview_merge,
        xavyo_api_governance::handlers::identity_merge::execute_merge,
        xavyo_api_governance::handlers::identity_merge::get_merge_operation,
        xavyo_api_governance::handlers::identity_merge::list_merge_operations,
        // Persona Management (F063)
        xavyo_api_governance::handlers::personas::list_archetypes,
        xavyo_api_governance::handlers::personas::create_archetype,
        xavyo_api_governance::handlers::personas::get_archetype,
        xavyo_api_governance::handlers::personas::update_archetype,
        xavyo_api_governance::handlers::personas::delete_archetype,
        xavyo_api_governance::handlers::personas::activate_archetype,
        xavyo_api_governance::handlers::personas::deactivate_archetype,
        xavyo_api_governance::handlers::personas::list_personas,
        xavyo_api_governance::handlers::personas::create_persona,
        xavyo_api_governance::handlers::personas::get_persona,
        xavyo_api_governance::handlers::personas::update_persona,
        xavyo_api_governance::handlers::personas::activate_persona,
        xavyo_api_governance::handlers::personas::deactivate_persona,
        xavyo_api_governance::handlers::personas::archive_persona,
        xavyo_api_governance::handlers::personas::propagate_attributes,
        xavyo_api_governance::handlers::personas::get_user_personas,
        xavyo_api_governance::handlers::personas::list_audit_events,
        xavyo_api_governance::handlers::personas::get_persona_audit,
        xavyo_api_governance::handlers::personas::switch_context,
        xavyo_api_governance::handlers::personas::switch_back,
        xavyo_api_governance::handlers::personas::get_current_context,
        xavyo_api_governance::handlers::personas::list_context_sessions,
        // Semi-manual Resources: Manual Tasks (F064)
        xavyo_api_governance::handlers::manual_tasks::list_manual_tasks,
        xavyo_api_governance::handlers::manual_tasks::get_manual_task,
        xavyo_api_governance::handlers::manual_tasks::confirm_manual_task,
        xavyo_api_governance::handlers::manual_tasks::reject_manual_task,
        xavyo_api_governance::handlers::manual_tasks::cancel_manual_task,
        xavyo_api_governance::handlers::manual_tasks::get_manual_task_dashboard,
        xavyo_api_governance::handlers::manual_tasks::claim_manual_task,
        xavyo_api_governance::handlers::manual_tasks::start_manual_task,
        // Semi-manual Resources: Semi-manual Config (F064)
        xavyo_api_governance::handlers::semi_manual::list_semi_manual_applications,
        xavyo_api_governance::handlers::semi_manual::get_semi_manual_config,
        xavyo_api_governance::handlers::semi_manual::configure_semi_manual,
        xavyo_api_governance::handlers::semi_manual::remove_semi_manual_config,
        // Semi-manual Resources: SLA Policies (F064)
        xavyo_api_governance::handlers::sla_policies::list_sla_policies,
        xavyo_api_governance::handlers::sla_policies::get_sla_policy,
        xavyo_api_governance::handlers::sla_policies::create_sla_policy,
        xavyo_api_governance::handlers::sla_policies::update_sla_policy,
        xavyo_api_governance::handlers::sla_policies::delete_sla_policy,
        // Semi-manual Resources: Ticketing Config (F064)
        xavyo_api_governance::handlers::ticketing_config::list_ticketing_configurations,
        xavyo_api_governance::handlers::ticketing_config::get_ticketing_configuration,
        xavyo_api_governance::handlers::ticketing_config::create_ticketing_configuration,
        xavyo_api_governance::handlers::ticketing_config::update_ticketing_configuration,
        xavyo_api_governance::handlers::ticketing_config::delete_ticketing_configuration,
        xavyo_api_governance::handlers::ticketing_config::test_ticketing_configuration,
        // Semi-manual Resources: Ticketing Webhooks (F064)
        xavyo_api_governance::handlers::ticketing_webhook::handle_webhook_callback,
        xavyo_api_governance::handlers::ticketing_webhook::trigger_ticket_sync,
        xavyo_api_governance::handlers::ticketing_webhook::sync_single_ticket,
        // License Management: License Pools (F065)
        xavyo_api_governance::handlers::license_pools::list_license_pools,
        xavyo_api_governance::handlers::license_pools::get_license_pool,
        xavyo_api_governance::handlers::license_pools::create_license_pool,
        xavyo_api_governance::handlers::license_pools::update_license_pool,
        xavyo_api_governance::handlers::license_pools::delete_license_pool,
        xavyo_api_governance::handlers::license_pools::archive_license_pool,
        // License Management: Assignments (F065)
        xavyo_api_governance::handlers::license_assignments::create_assignment,
        xavyo_api_governance::handlers::license_assignments::list_assignments,
        xavyo_api_governance::handlers::license_assignments::get_assignment,
        xavyo_api_governance::handlers::license_assignments::deallocate_assignment,
        xavyo_api_governance::handlers::license_assignments::bulk_assign,
        xavyo_api_governance::handlers::license_assignments::bulk_reclaim,
        // License Management: Entitlement Links (F065)
        xavyo_api_governance::handlers::license_entitlement_links::list_links,
        xavyo_api_governance::handlers::license_entitlement_links::get_link,
        xavyo_api_governance::handlers::license_entitlement_links::create_link,
        xavyo_api_governance::handlers::license_entitlement_links::delete_link,
        xavyo_api_governance::handlers::license_entitlement_links::set_link_enabled,
        // License Management: Incompatibilities (F065)
        xavyo_api_governance::handlers::license_incompatibilities::list_incompatibilities,
        xavyo_api_governance::handlers::license_incompatibilities::get_incompatibility,
        xavyo_api_governance::handlers::license_incompatibilities::create_incompatibility,
        xavyo_api_governance::handlers::license_incompatibilities::delete_incompatibility,
        // License Management: Reclamation Rules (F065)
        xavyo_api_governance::handlers::license_reclamation::list_rules,
        xavyo_api_governance::handlers::license_reclamation::get_rule,
        xavyo_api_governance::handlers::license_reclamation::create_rule,
        xavyo_api_governance::handlers::license_reclamation::update_rule,
        xavyo_api_governance::handlers::license_reclamation::delete_rule,
        // License Management: Reports (F065)
        xavyo_api_governance::handlers::license_reports::generate_compliance_report,
        xavyo_api_governance::handlers::license_reports::get_audit_trail,
        // License Management: Analytics (F065)
        xavyo_api_governance::handlers::license_analytics::get_dashboard,
        xavyo_api_governance::handlers::license_analytics::get_recommendations,
        xavyo_api_governance::handlers::license_analytics::get_expiring_pools,
        // Provisioning Scripts: Scripts (F066)
        xavyo_api_governance::handlers::provisioning_scripts::list_scripts,
        xavyo_api_governance::handlers::provisioning_scripts::create_script,
        xavyo_api_governance::handlers::provisioning_scripts::get_script,
        xavyo_api_governance::handlers::provisioning_scripts::update_script,
        xavyo_api_governance::handlers::provisioning_scripts::delete_script,
        xavyo_api_governance::handlers::provisioning_scripts::activate_script,
        xavyo_api_governance::handlers::provisioning_scripts::deactivate_script,
        xavyo_api_governance::handlers::provisioning_scripts::list_script_versions,
        xavyo_api_governance::handlers::provisioning_scripts::get_script_version,
        xavyo_api_governance::handlers::provisioning_scripts::create_script_version,
        xavyo_api_governance::handlers::provisioning_scripts::rollback_script,
        xavyo_api_governance::handlers::provisioning_scripts::compare_versions,
        // Provisioning Scripts: Templates (F066)
        xavyo_api_governance::handlers::script_templates::list_templates,
        xavyo_api_governance::handlers::script_templates::create_template,
        xavyo_api_governance::handlers::script_templates::get_template,
        xavyo_api_governance::handlers::script_templates::update_template,
        xavyo_api_governance::handlers::script_templates::delete_template,
        xavyo_api_governance::handlers::script_templates::instantiate_template,
        // Provisioning Scripts: Hook Bindings (F066)
        xavyo_api_governance::handlers::script_hook_bindings::list_bindings,
        xavyo_api_governance::handlers::script_hook_bindings::create_binding,
        xavyo_api_governance::handlers::script_hook_bindings::get_binding,
        xavyo_api_governance::handlers::script_hook_bindings::update_binding,
        xavyo_api_governance::handlers::script_hook_bindings::delete_binding,
        xavyo_api_governance::handlers::script_hook_bindings::list_bindings_by_connector,
        // Provisioning Scripts: Testing (F066)
        xavyo_api_governance::handlers::script_testing::validate_script,
        xavyo_api_governance::handlers::script_testing::dry_run_version,
        xavyo_api_governance::handlers::script_testing::dry_run_raw,
        // Provisioning Scripts: Analytics (F066)
        xavyo_api_governance::handlers::script_analytics::get_dashboard,
        xavyo_api_governance::handlers::script_analytics::get_script_analytics,
        xavyo_api_governance::handlers::script_analytics::list_execution_logs,
        xavyo_api_governance::handlers::script_analytics::get_execution_log,
        xavyo_api_governance::handlers::script_analytics::list_script_audit_events,
        // Correlation Engine (F067)
        xavyo_api_governance::handlers::correlation_engine::trigger_correlation,
        xavyo_api_governance::handlers::correlation_engine::get_correlation_job_status,
        // Correlation Engine: Rules (F067)
        xavyo_api_governance::handlers::correlation_rules::list_correlation_rules,
        xavyo_api_governance::handlers::correlation_rules::get_correlation_rule,
        xavyo_api_governance::handlers::correlation_rules::create_correlation_rule,
        xavyo_api_governance::handlers::correlation_rules::update_correlation_rule,
        xavyo_api_governance::handlers::correlation_rules::delete_correlation_rule,
        xavyo_api_governance::handlers::correlation_rules::validate_expression,
        // Correlation Engine: Thresholds (F067)
        xavyo_api_governance::handlers::correlation_thresholds::get_correlation_thresholds,
        xavyo_api_governance::handlers::correlation_thresholds::upsert_correlation_thresholds,
        // Correlation Engine: Cases (F067)
        xavyo_api_governance::handlers::correlation_cases::list_correlation_cases,
        xavyo_api_governance::handlers::correlation_cases::get_correlation_case,
        xavyo_api_governance::handlers::correlation_cases::confirm_correlation_case,
        xavyo_api_governance::handlers::correlation_cases::reject_correlation_case,
        xavyo_api_governance::handlers::correlation_cases::create_identity_from_case,
        xavyo_api_governance::handlers::correlation_cases::reassign_correlation_case,
        // Correlation Engine: Audit (F067)
        xavyo_api_governance::handlers::correlation_audit::list_correlation_audit_events,
        xavyo_api_governance::handlers::correlation_audit::get_correlation_audit_event,
        // Correlation Engine: Stats (F067)
        xavyo_api_governance::handlers::correlation_stats::get_correlation_statistics,
        xavyo_api_governance::handlers::correlation_stats::get_correlation_trends,
        // SIEM Integration / Audit Export (F078)
        xavyo_api_governance::handlers::siem::list_destinations,
        xavyo_api_governance::handlers::siem::create_destination,
        xavyo_api_governance::handlers::siem::get_destination,
        xavyo_api_governance::handlers::siem::update_destination,
        xavyo_api_governance::handlers::siem::delete_destination,
        xavyo_api_governance::handlers::siem::test_destination,
        // SIEM Batch Exports (F078)
        xavyo_api_governance::handlers::siem::list_batch_exports,
        xavyo_api_governance::handlers::siem::create_batch_export,
        xavyo_api_governance::handlers::siem::get_batch_export,
        xavyo_api_governance::handlers::siem::download_batch_export,
        // SIEM Health & Dead Letter (F078)
        xavyo_api_governance::handlers::siem::get_destination_health,
        xavyo_api_governance::handlers::siem::get_delivery_history,
        xavyo_api_governance::handlers::siem::list_dead_letter,
        xavyo_api_governance::handlers::siem::redeliver_dead_letter,
        // Webhooks & Event Subscriptions (F085)
        xavyo_webhooks::handlers::subscriptions::create_subscription_handler,
        xavyo_webhooks::handlers::subscriptions::list_subscriptions_handler,
        xavyo_webhooks::handlers::subscriptions::get_subscription_handler,
        xavyo_webhooks::handlers::subscriptions::update_subscription_handler,
        xavyo_webhooks::handlers::subscriptions::delete_subscription_handler,
        xavyo_webhooks::handlers::subscriptions::list_event_types_handler,
        xavyo_webhooks::handlers::deliveries::list_deliveries_handler,
        xavyo_webhooks::handlers::deliveries::get_delivery_handler,
        // Authorization Policies (F083)
        xavyo_api_authorization::handlers::policies::list_policies,
        xavyo_api_authorization::handlers::policies::create_policy,
        xavyo_api_authorization::handlers::policies::get_policy,
        xavyo_api_authorization::handlers::policies::update_policy,
        xavyo_api_authorization::handlers::policies::deactivate_policy,
        // Authorization Mappings (F083)
        xavyo_api_authorization::handlers::mappings::list_mappings,
        xavyo_api_authorization::handlers::mappings::create_mapping,
        xavyo_api_authorization::handlers::mappings::get_mapping,
        xavyo_api_authorization::handlers::mappings::delete_mapping,
        // Authorization Query (F083)
        xavyo_api_authorization::handlers::query::can_i_handler,
        xavyo_api_authorization::handlers::query::admin_check_handler,
        xavyo_api_authorization::handlers::query::bulk_check_handler,
        // Connector Operations (F048)
        xavyo_api_connectors::handlers::operations::list_operations,
        xavyo_api_connectors::handlers::operations::get_operation,
        xavyo_api_connectors::handlers::operations::trigger_operation,
        xavyo_api_connectors::handlers::operations::retry_operation,
        xavyo_api_connectors::handlers::operations::cancel_operation,
        xavyo_api_connectors::handlers::operations::get_operation_logs,
        xavyo_api_connectors::handlers::operations::get_queue_stats,
        xavyo_api_connectors::handlers::operations::list_dead_letter,
        xavyo_api_connectors::handlers::operations::resolve_operation,
        xavyo_api_connectors::handlers::operations::get_operation_attempts,
        xavyo_api_connectors::handlers::operations::list_conflicts,
        xavyo_api_connectors::handlers::operations::get_conflict,
        xavyo_api_connectors::handlers::operations::resolve_conflict,
        // Connector Sync (F048)
        xavyo_api_connectors::handlers::sync::get_sync_config,
        xavyo_api_connectors::handlers::sync::update_sync_config,
        xavyo_api_connectors::handlers::sync::enable_sync,
        xavyo_api_connectors::handlers::sync::disable_sync,
        xavyo_api_connectors::handlers::sync::get_sync_status,
        xavyo_api_connectors::handlers::sync::get_sync_token,
        xavyo_api_connectors::handlers::sync::reset_sync_token,
        xavyo_api_connectors::handlers::sync::trigger_sync,
        xavyo_api_connectors::handlers::sync::list_changes,
        xavyo_api_connectors::handlers::sync::get_change,
        xavyo_api_connectors::handlers::sync::retry_change,
        xavyo_api_connectors::handlers::sync::link_change,
        xavyo_api_connectors::handlers::sync::list_sync_conflicts,
        xavyo_api_connectors::handlers::sync::resolve_sync_conflict,
        xavyo_api_connectors::handlers::sync::get_all_sync_status,
        // Connector Reconciliation (F049)
        xavyo_api_connectors::handlers::reconciliation::trigger_reconciliation,
        xavyo_api_connectors::handlers::reconciliation::get_reconciliation_run,
        xavyo_api_connectors::handlers::reconciliation::list_reconciliation_runs,
        xavyo_api_connectors::handlers::reconciliation::cancel_reconciliation_run,
        xavyo_api_connectors::handlers::reconciliation::resume_reconciliation_run,
        xavyo_api_connectors::handlers::reconciliation::list_discrepancies,
        xavyo_api_connectors::handlers::reconciliation::get_discrepancy,
        xavyo_api_connectors::handlers::reconciliation::remediate_discrepancy,
        xavyo_api_connectors::handlers::reconciliation::bulk_remediate_discrepancies,
        xavyo_api_connectors::handlers::reconciliation::ignore_discrepancy,
        xavyo_api_connectors::handlers::reconciliation::preview_remediation,
        xavyo_api_connectors::handlers::reconciliation::get_schedule,
        xavyo_api_connectors::handlers::reconciliation::update_schedule,
        xavyo_api_connectors::handlers::reconciliation::delete_schedule,
        xavyo_api_connectors::handlers::reconciliation::enable_schedule,
        xavyo_api_connectors::handlers::reconciliation::disable_schedule,
        xavyo_api_connectors::handlers::reconciliation::list_schedules,
        xavyo_api_connectors::handlers::reconciliation::get_report,
        xavyo_api_connectors::handlers::reconciliation::get_trend,
        xavyo_api_connectors::handlers::reconciliation::list_actions,
        // SCIM Outbound Targets (F087)
        xavyo_api_connectors::handlers::scim_targets::create_scim_target,
        xavyo_api_connectors::handlers::scim_targets::list_scim_targets,
        xavyo_api_connectors::handlers::scim_targets::get_scim_target,
        xavyo_api_connectors::handlers::scim_targets::update_scim_target,
        xavyo_api_connectors::handlers::scim_targets::delete_scim_target,
        xavyo_api_connectors::handlers::scim_targets::health_check_scim_target,
        // SCIM Outbound Mappings (F087)
        xavyo_api_connectors::handlers::scim_mappings::list_mappings,
        xavyo_api_connectors::handlers::scim_mappings::replace_mappings,
        xavyo_api_connectors::handlers::scim_mappings::reset_mapping_defaults,
        // SCIM Outbound Sync (F087)
        xavyo_api_connectors::handlers::scim_sync::trigger_sync,
        xavyo_api_connectors::handlers::scim_sync::trigger_reconciliation,
        xavyo_api_connectors::handlers::scim_sync::list_sync_runs,
        xavyo_api_connectors::handlers::scim_sync::get_sync_run,
        // SCIM Outbound Provisioning State (F087)
        xavyo_api_connectors::handlers::scim_provisioning::list_provisioning_state,
        xavyo_api_connectors::handlers::scim_provisioning::retry_provisioning,
        // SCIM Outbound Logs (F087)
        xavyo_api_connectors::handlers::scim_log::list_provisioning_log,
        xavyo_api_connectors::handlers::scim_log::get_log_detail,
        // Human-in-the-Loop Approvals (F092)
        xavyo_api_agents::handlers::approvals::list_approvals,
        xavyo_api_agents::handlers::approvals::get_approval,
        xavyo_api_agents::handlers::approvals::check_approval_status,
        xavyo_api_agents::handlers::approvals::approve_request,
        xavyo_api_agents::handlers::approvals::deny_request,
        // AI Agent Registry (F089)
        xavyo_api_agents::handlers::agents::create_agent,
        xavyo_api_agents::handlers::agents::list_agents,
        xavyo_api_agents::handlers::agents::get_agent,
        xavyo_api_agents::handlers::agents::update_agent,
        xavyo_api_agents::handlers::agents::delete_agent,
        xavyo_api_agents::handlers::agents::suspend_agent,
        xavyo_api_agents::handlers::agents::reactivate_agent,
        // AI Agent Tools (F089)
        xavyo_api_agents::handlers::tools::create_tool,
        xavyo_api_agents::handlers::tools::list_tools,
        xavyo_api_agents::handlers::tools::get_tool,
        xavyo_api_agents::handlers::tools::update_tool,
        xavyo_api_agents::handlers::tools::delete_tool,
        // AI Agent Permissions (F090)
        xavyo_api_agents::handlers::permissions::grant_permission,
        xavyo_api_agents::handlers::permissions::list_permissions,
        xavyo_api_agents::handlers::permissions::revoke_permission,
        // AI Agent Authorization (F090)
        xavyo_api_agents::handlers::authorize::authorize,
        // AI Agent Audit (F090)
        xavyo_api_agents::handlers::audit::query_audit,
        // AI Agent Discovery (F091 - A2A)
        xavyo_api_agents::handlers::discovery::get_agent_card,
        // MCP Tools (F091)
        xavyo_api_agents::handlers::mcp::list_tools,
        xavyo_api_agents::handlers::mcp::call_tool,
        // A2A Tasks (F091)
        xavyo_api_agents::handlers::a2a::create_task,
        xavyo_api_agents::handlers::a2a::list_tasks,
        xavyo_api_agents::handlers::a2a::get_task,
        xavyo_api_agents::handlers::a2a::cancel_task,
        // Security Assessment (F093)
        xavyo_api_agents::handlers::assessment::get_agent_security_assessment,
        // Behavioral Anomaly Detection (F094)
        xavyo_api_agents::handlers::anomaly::list_agent_anomalies,
        xavyo_api_agents::handlers::anomaly::get_agent_baseline,
        xavyo_api_agents::handlers::anomaly::get_agent_thresholds,
        xavyo_api_agents::handlers::anomaly::set_agent_thresholds,
        xavyo_api_agents::handlers::anomaly::reset_agent_thresholds,
        xavyo_api_agents::handlers::anomaly::get_tenant_thresholds,
        xavyo_api_agents::handlers::anomaly::set_tenant_thresholds,
        // Tenant Provisioning (F097)
        xavyo_api_tenants::handlers::provision::provision_handler,
        // Unified NHI (201-tool-nhi-promotion)
        xavyo_api_nhi::handlers::unified::list_nhis,
        xavyo_api_nhi::handlers::unified::get_nhi,
        // NHI Lifecycle
        xavyo_api_nhi::handlers::lifecycle::suspend,
        xavyo_api_nhi::handlers::lifecycle::reactivate,
        xavyo_api_nhi::handlers::lifecycle::deprecate,
        xavyo_api_nhi::handlers::lifecycle::archive,
        xavyo_api_nhi::handlers::lifecycle::deactivate,
        xavyo_api_nhi::handlers::lifecycle::activate,
        // NHI Credentials
        xavyo_api_nhi::handlers::credentials::issue_credential,
        xavyo_api_nhi::handlers::credentials::list_credentials,
        xavyo_api_nhi::handlers::credentials::rotate_credential,
        xavyo_api_nhi::handlers::credentials::revoke_credential,
        // NHI Certifications
        xavyo_api_nhi::handlers::certification::create_campaign,
        xavyo_api_nhi::handlers::certification::list_campaigns,
        xavyo_api_nhi::handlers::certification::certify_nhi,
        xavyo_api_nhi::handlers::certification::revoke_certification,
        // NHI Permissions
        xavyo_api_nhi::handlers::permissions::grant_permission,
        xavyo_api_nhi::handlers::permissions::revoke_permission,
        xavyo_api_nhi::handlers::permissions::list_agent_tools,
        xavyo_api_nhi::handlers::permissions::list_tool_agents,
        // NHI Risk
        xavyo_api_nhi::handlers::risk::get_risk,
        xavyo_api_nhi::handlers::risk::get_risk_summary,
        // NHI SoD
        xavyo_api_nhi::handlers::sod::create_sod_rule,
        xavyo_api_nhi::handlers::sod::list_sod_rules,
        xavyo_api_nhi::handlers::sod::delete_sod_rule,
        xavyo_api_nhi::handlers::sod::check_sod,
        // NHI Inactivity
        xavyo_api_nhi::handlers::inactivity::detect_inactive,
        xavyo_api_nhi::handlers::inactivity::initiate_grace_period,
        xavyo_api_nhi::handlers::inactivity::auto_suspend,
        xavyo_api_nhi::handlers::inactivity::detect_orphans,
        // NHI Agents
        xavyo_api_nhi::handlers::agents::create_agent,
        xavyo_api_nhi::handlers::agents::list_agents,
        xavyo_api_nhi::handlers::agents::get_agent,
        xavyo_api_nhi::handlers::agents::update_agent,
        xavyo_api_nhi::handlers::agents::delete_agent,
        // NHI Service Accounts
        xavyo_api_nhi::handlers::service_accounts::create_service_account,
        xavyo_api_nhi::handlers::service_accounts::list_service_accounts,
        xavyo_api_nhi::handlers::service_accounts::get_service_account,
        xavyo_api_nhi::handlers::service_accounts::update_service_account,
        xavyo_api_nhi::handlers::service_accounts::delete_service_account,
        // NHI Tools
        xavyo_api_nhi::handlers::tools::create_tool,
        xavyo_api_nhi::handlers::tools::list_tools,
        xavyo_api_nhi::handlers::tools::get_tool,
        xavyo_api_nhi::handlers::tools::update_tool,
        xavyo_api_nhi::handlers::tools::delete_tool,
        // NOTE: The following handlers need #[utoipa::path] annotations to be included in OpenAPI:
        // - Bulk Import (F086): import.rs, errors.rs, invitations.rs handlers (9 endpoints)
        // - Prometheus Metrics (F072): metrics.rs handler (1 endpoint)
    ),
    components(schemas(
        // Health
        HealthResponse,
        HealthState,
        // Observability (F072, F074)
        LivenessResponse,
        ReadinessResponse,
        DependencyCheck,
        StartupResponse,
        // Auth models
        xavyo_api_auth::models::LoginRequest,
        xavyo_api_auth::models::TokenResponse,
        xavyo_api_auth::models::MfaRequiredResponse,
        xavyo_api_auth::models::RegisterRequest,
        xavyo_api_auth::models::RegisterResponse,
        xavyo_api_auth::models::LogoutRequest,
        xavyo_api_auth::models::RefreshRequest,
        xavyo_api_auth::models::ForgotPasswordRequest,
        xavyo_api_auth::models::ForgotPasswordResponse,
        xavyo_api_auth::models::ResetPasswordRequest,
        xavyo_api_auth::models::ResetPasswordResponse,
        xavyo_api_auth::models::VerifyEmailRequest,
        xavyo_api_auth::models::VerifyEmailResponse,
        xavyo_api_auth::models::ResendVerificationRequest,
        xavyo_api_auth::models::ResendVerificationResponse,
        xavyo_api_auth::models::PasswordChangeRequest,
        xavyo_api_auth::models::PasswordChangeResponse,
        xavyo_api_auth::models::MfaMethod,
        // Passwordless Authentication models (F079)
        xavyo_api_auth::models::PasswordlessRequest,
        xavyo_api_auth::models::MagicLinkVerifyRequest,
        xavyo_api_auth::models::EmailOtpVerifyRequest,
        xavyo_api_auth::models::UpdatePasswordlessPolicyRequest,
        xavyo_api_auth::models::PasswordlessInitResponse,
        xavyo_api_auth::models::PasswordlessMfaRequiredResponse,
        xavyo_api_auth::models::AvailableMethodsResponse,
        xavyo_api_auth::models::PasswordlessPolicyResponse,
        // Token Revocation models (F069)
        xavyo_api_auth::handlers::revocation::RevokeTokenRequest,
        xavyo_api_auth::handlers::revocation::RevokeUserTokensRequest,
        xavyo_api_auth::handlers::revocation::RevocationResponse,
        xavyo_api_auth::handlers::revocation::UserRevocationResponse,
        xavyo_api_auth::handlers::revocation::RevocationErrorResponse,
        // WebAuthn models (F032)
        xavyo_api_auth::handlers::mfa::webauthn::register::StartRegistrationRequest,
        xavyo_api_auth::handlers::mfa::webauthn::register::RegistrationOptionsResponse,
        xavyo_api_auth::handlers::mfa::webauthn::register::FinishRegistrationRequest,
        xavyo_api_auth::handlers::mfa::webauthn::register::RegistrationResponse,
        xavyo_api_auth::handlers::mfa::webauthn::authenticate::AuthenticationOptionsResponse,
        xavyo_api_auth::handlers::mfa::webauthn::authenticate::FinishAuthenticationRequest,
        xavyo_api_auth::handlers::mfa::webauthn::authenticate::AuthenticationSuccessResponse,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::CredentialListResponse,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::UpdateCredentialRequest,
        xavyo_api_auth::handlers::mfa::webauthn::credentials::UpdateCredentialResponse,
        xavyo_api_auth::handlers::admin::webauthn_policy::WebAuthnPolicyResponse,
        xavyo_api_auth::handlers::admin::webauthn_policy::UpdateWebAuthnPolicyRequest,
        xavyo_api_auth::handlers::admin::webauthn_policy::AdminCredentialListResponse,
        xavyo_api_auth::handlers::admin::webauthn_policy::AdminCredentialInfo,
        // OAuth2 models
        xavyo_api_oauth::models::TokenRequest,
        xavyo_api_oauth::models::TokenResponse,
        xavyo_api_oauth::models::ConsentRequest,
        xavyo_api_oauth::models::OpenIdConfiguration,
        xavyo_api_oauth::models::JwkSet,
        xavyo_api_oauth::models::Jwk,
        xavyo_api_oauth::models::ClientResponse,
        xavyo_api_oauth::models::ClientListResponse,
        xavyo_api_oauth::models::CreateClientRequest,
        xavyo_api_oauth::models::CreateClientResponse,
        xavyo_api_oauth::models::UpdateClientRequest,
        xavyo_api_oauth::handlers::client_admin::RegenerateSecretResponse,
        // OAuth2 Device Code models (RFC 8628)
        xavyo_api_oauth::handlers::device::DeviceAuthorizationRequest,
        xavyo_api_oauth::handlers::device::DeviceAuthorizationResponse,
        xavyo_api_oauth::handlers::device::DeviceCodeErrorResponse,
        // User models
        xavyo_api_users::models::CreateUserRequest,
        xavyo_api_users::models::UpdateUserRequest,
        xavyo_api_users::models::UserResponse,
        xavyo_api_users::models::UserListResponse,
        xavyo_api_users::models::PaginationMeta,
        // Attribute Definition models (F070)
        xavyo_api_users::models::CreateAttributeDefinitionRequest,
        xavyo_api_users::models::UpdateAttributeDefinitionRequest,
        xavyo_api_users::models::AttributeDefinitionResponse,
        xavyo_api_users::models::AttributeDefinitionListResponse,
        xavyo_api_users::models::ValidationRules,
        xavyo_api_users::error::AttributeFieldError,
        xavyo_api_users::error::ProblemDetails,
        xavyo_api_users::models::SetCustomAttributesRequest,
        xavyo_api_users::models::PatchCustomAttributesRequest,
        xavyo_api_users::models::UserCustomAttributesResponse,
        xavyo_api_users::models::BulkUpdateRequest,
        xavyo_api_users::models::BulkUpdateFilter,
        xavyo_api_users::models::BulkUpdateResponse,
        xavyo_api_users::models::BulkUpdateFailure,
        xavyo_api_users::models::MissingAttributeAuditResponse,
        xavyo_api_users::models::UserMissingAttributes,
        // Well-Known Seeding models (F081)
        xavyo_api_users::models::SeedWellKnownResponse,
        xavyo_api_users::models::SeededAttribute,
        xavyo_api_users::models::SkippedAttribute,
        // Group Hierarchy models (F071)
        xavyo_api_users::models::GroupDetail,
        xavyo_api_users::models::GroupListResponse,
        xavyo_api_users::models::MoveGroupRequest,
        xavyo_api_users::models::AncestorEntry,
        xavyo_api_users::models::AncestorPathResponse,
        xavyo_api_users::models::SubtreeEntry,
        xavyo_api_users::models::SubtreeResponse,
        xavyo_api_users::models::SubtreeMember,
        xavyo_api_users::models::SubtreeMembershipResponse,
        xavyo_api_users::models::Pagination,
        xavyo_api_users::models::PaginationWithTotal,
        // SAML models
        xavyo_api_saml::models::SsoPostForm,
        xavyo_api_saml::models::InitiateSsoRequest,
        xavyo_api_saml::models::ServiceProviderResponse,
        xavyo_api_saml::models::ServiceProviderListResponse,
        xavyo_api_saml::models::CertificateListResponse,
        // SCIM models
        xavyo_api_scim::models::ScimUser,
        xavyo_api_scim::models::CreateScimUserRequest,
        xavyo_api_scim::models::ScimPatchRequest,
        // OIDC Federation models
        xavyo_api_oidc_federation::models::CreateIdentityProviderRequest,
        xavyo_api_oidc_federation::models::UpdateIdentityProviderRequest,
        xavyo_api_oidc_federation::models::ToggleIdentityProviderRequest,
        xavyo_api_oidc_federation::models::CreateDomainRequest,
        xavyo_api_oidc_federation::models::IdentityProviderResponse,
        xavyo_api_oidc_federation::models::IdentityProviderListResponse,
        xavyo_api_oidc_federation::models::DomainResponse,
        xavyo_api_oidc_federation::models::DomainListResponse,
        xavyo_api_oidc_federation::models::ValidationResultResponse,
        // Social Login models
        xavyo_api_social::models::UpdateProviderRequest,
        xavyo_api_social::models::TenantProviderResponse,
        xavyo_api_social::models::TenantProvidersListResponse,
        // IP Restrictions models
        xavyo_api_auth::models::IpSettingsResponse,
        xavyo_api_auth::models::UpdateIpSettingsRequest,
        xavyo_api_auth::models::IpRuleResponse,
        xavyo_api_auth::models::ListRulesResponse,
        xavyo_api_auth::models::CreateIpRuleRequest,
        xavyo_api_auth::models::UpdateIpRuleRequest,
        xavyo_api_auth::models::ValidateIpRequest,
        xavyo_api_auth::models::ValidateIpResponse,
        xavyo_api_auth::models::MatchingRuleInfo,
        // IP types from xavyo_db
        xavyo_db::models::IpRuleType,
        xavyo_db::models::IpEnforcementMode,
        // Delegated Admin models
        xavyo_api_auth::models::PermissionResponse,
        xavyo_api_auth::models::PermissionListResponse,
        xavyo_api_auth::models::CategorySummaryResponse,
        xavyo_api_auth::models::RoleTemplateResponse,
        xavyo_api_auth::models::RoleTemplateDetailResponse,
        xavyo_api_auth::models::RoleTemplateListResponse,
        xavyo_api_auth::models::CreateRoleTemplateRequest,
        xavyo_api_auth::models::UpdateRoleTemplateRequest,
        xavyo_api_auth::models::AssignmentResponse,
        xavyo_api_auth::models::AssignmentDetailResponse,
        xavyo_api_auth::models::AssignmentListResponse,
        xavyo_api_auth::models::CreateAssignmentRequest,
        xavyo_api_auth::models::AuditLogEntryResponse,
        xavyo_api_auth::models::AuditLogResponse,
        xavyo_api_auth::models::EffectivePermissions,
        xavyo_api_auth::models::ScopeAssignment,
        xavyo_api_auth::handlers::delegated_admin::CheckPermissionRequest,
        xavyo_api_auth::handlers::delegated_admin::CheckPermissionResponse,
        // Branding models
        xavyo_api_auth::models::BrandingResponse,
        xavyo_api_auth::models::UpdateBrandingRequest,
        xavyo_api_auth::models::PublicBrandingResponse,
        xavyo_api_auth::models::AssetResponse,
        xavyo_api_auth::models::EmailTemplateSummaryResponse,
        xavyo_api_auth::models::EmailTemplateResponse,
        xavyo_api_auth::models::UpdateEmailTemplateRequest,
        xavyo_api_auth::models::PreviewEmailTemplateRequest,
        xavyo_api_auth::models::EmailTemplatePreviewResponse,
        xavyo_api_auth::models::TemplateVariableInfo,
        // WebAuthn credential types
        xavyo_db::models::CredentialInfo,
        // SCIM additional models
        xavyo_api_scim::models::ScimName,
        xavyo_api_scim::models::ScimEmail,
        xavyo_api_scim::models::ScimMeta,
        xavyo_api_scim::models::ScimUserGroup,
        xavyo_api_scim::models::ScimPatchOp,
        // SAML models
        xavyo_db::models::CertificateInfo,
        xavyo_db::models::UploadCertificateRequest,
        xavyo_db::models::CreateServiceProviderRequest,
        xavyo_db::models::UpdateServiceProviderRequest,
        // OAuth2 additional models
        xavyo_api_oauth::models::ClientType,
        // OIDC Federation additional models
        xavyo_api_oidc_federation::models::ClaimMappingConfig,
        xavyo_api_oidc_federation::models::ClaimMappingEntry,
        xavyo_api_oidc_federation::models::NameIdConfig,
        xavyo_api_oidc_federation::models::DiscoveredEndpointsResponse,
        // Governance models (F033)
        xavyo_api_governance::models::ApplicationResponse,
        xavyo_api_governance::models::ApplicationListResponse,
        xavyo_api_governance::models::CreateApplicationRequest,
        xavyo_api_governance::models::UpdateApplicationRequest,
        xavyo_api_governance::models::EntitlementResponse,
        xavyo_api_governance::models::EntitlementListResponse,
        xavyo_api_governance::models::CreateEntitlementRequest,
        xavyo_api_governance::models::UpdateEntitlementRequest,
        xavyo_api_governance::models::SetOwnerRequest,
        xavyo_api_governance::models::AssignmentResponse,
        xavyo_api_governance::models::AssignmentListResponse,
        xavyo_api_governance::models::CreateAssignmentRequest,
        xavyo_api_governance::models::BulkCreateAssignmentsRequest,
        xavyo_api_governance::models::BulkAssignmentResponse,
        xavyo_api_governance::models::BulkAssignmentFailureResponse,
        xavyo_api_governance::models::RoleEntitlementResponse,
        xavyo_api_governance::models::RoleEntitlementListResponse,
        xavyo_api_governance::models::CreateRoleEntitlementRequest,
        xavyo_api_governance::models::EffectiveAccessResponse,
        xavyo_api_governance::models::EffectiveEntitlementResponse,
        xavyo_api_governance::models::EntitlementSourceResponse,
        // Governance DB types (F033)
        xavyo_db::models::GovAppType,
        xavyo_db::models::GovAppStatus,
        xavyo_db::models::GovRiskLevel,
        xavyo_db::models::GovEntitlementStatus,
        xavyo_db::models::GovAssignmentTargetType,
        xavyo_db::models::GovAssignmentStatus,
        // SoD Rule models (F034)
        xavyo_api_governance::models::SodRuleResponse,
        xavyo_api_governance::models::SodRuleListResponse,
        xavyo_api_governance::models::CreateSodRuleRequest,
        xavyo_api_governance::models::UpdateSodRuleRequest,
        // SoD DB types (F034)
        xavyo_db::models::GovSodSeverity,
        xavyo_db::models::GovSodRuleStatus,
        // Access Request models (F035)
        xavyo_api_governance::models::AccessRequestResponse,
        xavyo_api_governance::models::AccessRequestListResponse,
        xavyo_api_governance::models::CreateAccessRequestRequest,
        xavyo_api_governance::models::AccessRequestCreatedResponse,
        xavyo_api_governance::models::SodViolationSummary,
        // Approval models (F035)
        xavyo_api_governance::models::PendingApprovalListResponse,
        xavyo_api_governance::models::PendingApprovalItem,
        xavyo_api_governance::models::DecisionSummary,
        xavyo_api_governance::models::ApproveRequestRequest,
        xavyo_api_governance::models::RejectRequestRequest,
        xavyo_api_governance::models::ApprovalActionResponse,
        // Approval Workflow models (F035)
        xavyo_api_governance::models::ApprovalWorkflowResponse,
        xavyo_api_governance::models::ApprovalWorkflowListResponse,
        xavyo_api_governance::models::ApprovalWorkflowSummary,
        xavyo_api_governance::models::ApprovalStepResponse,
        xavyo_api_governance::models::CreateApprovalWorkflowRequest,
        xavyo_api_governance::models::UpdateApprovalWorkflowRequest,
        xavyo_api_governance::models::CreateApprovalStepRequest,
        // Delegation models (F035)
        xavyo_api_governance::models::DelegationResponse,
        xavyo_api_governance::models::DelegationListResponse,
        xavyo_api_governance::models::CreateDelegationRequest,
        // Access Request DB types (F035)
        xavyo_db::models::GovRequestStatus,
        xavyo_db::models::GovDecisionType,
        xavyo_db::models::GovApproverType,
        // Certification Campaign models (F036)
        xavyo_api_governance::models::CampaignResponse,
        xavyo_api_governance::models::CampaignListResponse,
        xavyo_api_governance::models::CampaignWithProgressResponse,
        xavyo_api_governance::models::CampaignProgressResponse,
        xavyo_api_governance::models::CreateCampaignRequest,
        xavyo_api_governance::models::UpdateCampaignRequest,
        xavyo_api_governance::models::ScopeConfig,
        // Certification Item models (F036)
        xavyo_api_governance::models::ItemResponse,
        xavyo_api_governance::models::ItemListResponse,
        xavyo_api_governance::models::ItemWithDetailsResponse,
        xavyo_api_governance::models::ItemWithDecisionResponse,
        xavyo_api_governance::models::DecisionResponse,
        xavyo_api_governance::models::DecisionRequest,
        xavyo_api_governance::models::ReassignRequest,
        xavyo_api_governance::models::ReviewerSummaryResponse,
        xavyo_api_governance::models::ReviewerCampaignSummary,
        // Certification DB types (F036)
        xavyo_db::models::CertScopeType,
        xavyo_db::models::CertReviewerType,
        xavyo_db::models::CertCampaignStatus,
        xavyo_db::models::CertItemStatus,
        xavyo_db::models::CertDecisionType,
        // Compliance Reporting: Report Template models (F042)
        xavyo_api_governance::models::ReportTemplateResponse,
        xavyo_api_governance::models::ReportTemplateListResponse,
        xavyo_api_governance::models::CreateReportTemplateRequest,
        xavyo_api_governance::models::UpdateReportTemplateRequest,
        xavyo_api_governance::models::CloneReportTemplateRequest,
        // Compliance Reporting: Generated Report models (F042)
        xavyo_api_governance::models::GeneratedReportResponse,
        xavyo_api_governance::models::GeneratedReportListResponse,
        xavyo_api_governance::models::GenerateReportRequest,
        // Compliance Reporting: Report Schedule models (F042)
        xavyo_api_governance::models::ReportScheduleResponse,
        xavyo_api_governance::models::ReportScheduleListResponse,
        xavyo_api_governance::models::CreateReportScheduleRequest,
        xavyo_api_governance::models::UpdateReportScheduleRequest,
        // Compliance Reporting DB types (F042)
        xavyo_db::models::ReportTemplateType,
        xavyo_db::models::ComplianceStandard,
        xavyo_db::models::TemplateStatus,
        xavyo_db::models::TemplateDefinition,
        xavyo_db::models::ColumnDefinition,
        xavyo_db::models::FilterDefinition,
        xavyo_db::models::SortDefinition,
        xavyo_db::models::ReportStatus,
        xavyo_db::models::OutputFormat,
        xavyo_db::models::ScheduleFrequency,
        xavyo_db::models::ScheduleStatus,
        // Compliance Reporting additional types (F042)
        xavyo_api_governance::handlers::reports::CleanupResponse,
        // Role Mining models (F041)
        xavyo_api_governance::models::MiningJobResponse,
        xavyo_api_governance::models::MiningJobListResponse,
        xavyo_api_governance::models::CreateMiningJobRequest,
        xavyo_api_governance::models::MiningJobParametersRequest,
        xavyo_api_governance::models::RoleCandidateResponse,
        xavyo_api_governance::models::RoleCandidateListResponse,
        xavyo_api_governance::models::PromoteCandidateRequest,
        xavyo_api_governance::models::DismissCandidateRequest,
        xavyo_api_governance::models::AccessPatternResponse,
        xavyo_api_governance::models::AccessPatternListResponse,
        xavyo_api_governance::models::ExcessivePrivilegeResponse,
        xavyo_api_governance::models::ExcessivePrivilegeListResponse,
        xavyo_api_governance::models::ReviewPrivilegeRequest,
        xavyo_api_governance::models::PrivilegeReviewAction,
        xavyo_api_governance::models::ConsolidationSuggestionResponse,
        xavyo_api_governance::models::ConsolidationSuggestionListResponse,
        xavyo_api_governance::models::DismissConsolidationRequest,
        xavyo_api_governance::models::SimulationResponse,
        xavyo_api_governance::models::SimulationListResponse,
        xavyo_api_governance::models::CreateSimulationRequest,
        xavyo_api_governance::models::RoleMetricsResponse,
        xavyo_api_governance::models::RoleMetricsListResponse,
        xavyo_api_governance::models::CalculateMetricsRequest,
        // Role Mining DB types (F041)
        xavyo_db::models::MiningJobStatus,
        xavyo_db::models::MiningJobParameters,
        xavyo_db::models::CandidatePromotionStatus,
        xavyo_db::models::ConsolidationStatus,
        xavyo_db::models::PrivilegeFlagStatus,
        xavyo_db::models::ScenarioType,
        xavyo_db::models::SimulationStatus,
        xavyo_db::models::SimulationChanges,
        xavyo_db::models::EntitlementUsage,
        xavyo_db::models::MetricsTrendDirection,
        xavyo_db::models::TrendDirection,
        // Lifecycle models (F037)
        xavyo_api_governance::models::CreateLifecycleEventRequest,
        xavyo_api_governance::models::LifecycleEventResponse,
        xavyo_api_governance::models::LifecycleEventWithActionsResponse,
        xavyo_api_governance::models::LifecycleEventListResponse,
        xavyo_api_governance::models::LifecycleActionResponse,
        xavyo_api_governance::models::LifecycleActionListResponse,
        xavyo_api_governance::models::AccessSnapshotResponse,
        xavyo_api_governance::models::AccessSnapshotListResponse,
        xavyo_api_governance::models::ProcessEventResult,
        // Birthright Policy models (F038)
        xavyo_api_governance::models::CreateBirthrightPolicyRequest,
        xavyo_api_governance::models::UpdateBirthrightPolicyRequest,
        xavyo_api_governance::models::BirthrightPolicyResponse,
        xavyo_api_governance::models::BirthrightPolicyListResponse,
        xavyo_api_governance::models::SimulatePolicyRequest,
        xavyo_api_governance::models::SimulatePolicyResponse,
        xavyo_api_governance::models::SimulateAllPoliciesResponse,
        xavyo_api_governance::models::ImpactAnalysisRequest,
        xavyo_api_governance::models::ImpactAnalysisResponse,
        xavyo_api_governance::models::PolicyConditionRequest,
        xavyo_api_governance::models::PolicyConditionResponse,
        // Risk Factor models (F039)
        xavyo_api_governance::models::CreateRiskFactorRequest,
        xavyo_api_governance::models::UpdateRiskFactorRequest,
        xavyo_api_governance::models::RiskFactorResponse,
        xavyo_api_governance::models::RiskFactorListResponse,
        // Risk Score models (F039)
        xavyo_api_governance::models::RiskScoreResponse,
        xavyo_api_governance::models::RiskScoreListResponse,
        xavyo_api_governance::models::RiskScoreHistoryResponse,
        xavyo_api_governance::models::RiskTrendResponse,
        xavyo_api_governance::models::CalculateScoreRequest,
        xavyo_api_governance::models::BatchCalculateResponse,
        xavyo_api_governance::models::RiskEnforcementResponse,
        xavyo_api_governance::models::RiskScoreSummary,
        xavyo_api_governance::models::RiskScoreSortOption,
        xavyo_api_governance::models::EnforcementAction,
        // Enforcement Policy models (F073)
        xavyo_api_governance::models::EnforcementPolicyResponse,
        xavyo_api_governance::models::UpsertEnforcementPolicyRequest,
        // Peer Group models (F039)
        xavyo_api_governance::models::CreatePeerGroupRequest,
        xavyo_api_governance::models::PeerGroupResponse,
        xavyo_api_governance::models::PeerGroupListResponse,
        xavyo_api_governance::models::UserPeerComparisonResponse,
        xavyo_api_governance::models::RefreshPeerGroupsResponse,
        xavyo_api_governance::models::RefreshStatsResponse,
        // Risk Alert models (F039)
        xavyo_api_governance::models::RiskAlertResponse,
        xavyo_api_governance::models::RiskAlertListResponse,
        xavyo_api_governance::models::AcknowledgeAlertResponse,
        xavyo_api_governance::models::BulkAcknowledgeResponse,
        xavyo_api_governance::models::AlertSummary,
        // Orphan Detection models (F040)
        xavyo_api_governance::models::OrphanDetectionResponse,
        xavyo_api_governance::models::OrphanDetectionListResponse,
        xavyo_api_governance::models::OrphanSummaryResponse,
        xavyo_api_governance::models::ReassignOrphanRequest,
        xavyo_api_governance::models::DisableOrphanRequest,
        xavyo_api_governance::models::DeleteOrphanRequest,
        xavyo_api_governance::models::DeleteOrphanResponse,
        xavyo_api_governance::models::DismissOrphanRequest,
        xavyo_api_governance::models::BulkRemediateRequest,
        xavyo_api_governance::models::BulkRemediateResponse,
        xavyo_api_governance::models::BulkRemediationAction,
        xavyo_api_governance::models::OrphanAgeAnalysis,
        xavyo_api_governance::models::OrphanRiskReport,
        // Detection Rule models (F040)
        xavyo_api_governance::models::CreateDetectionRuleRequest,
        xavyo_api_governance::models::UpdateDetectionRuleRequest,
        xavyo_api_governance::models::DetectionRuleResponse,
        xavyo_api_governance::models::DetectionRuleListResponse,
        // Reconciliation models (F040)
        xavyo_api_governance::models::TriggerReconciliationRequest,
        xavyo_api_governance::models::ReconciliationRunResponse,
        xavyo_api_governance::models::ReconciliationRunListResponse,
        xavyo_api_governance::models::ReconciliationScheduleResponse,
        xavyo_api_governance::models::UpsertScheduleRequest,
        // Lifecycle DB types (F037)
        xavyo_db::models::LifecycleEventType,
        xavyo_db::models::LifecycleActionType,
        xavyo_db::models::AccessSnapshotType,
        // Birthright Policy DB types (F038)
        xavyo_db::models::BirthrightPolicyStatus,
        xavyo_db::models::EvaluationMode,
        // Risk Factor DB types (F039)
        xavyo_db::models::RiskFactorCategory,
        // Risk Score DB types (F039)
        xavyo_db::models::RiskLevel,
        // Orphan Detection DB types (F040)
        xavyo_db::models::OrphanStatus,
        xavyo_db::models::ReconciliationStatus,
        xavyo_db::models::DetectionRuleType,
        // Connector models (F045)
        xavyo_api_connectors::ConnectorResponse,
        xavyo_api_connectors::ConnectorSummaryResponse,
        xavyo_api_connectors::ConnectorListResponse,
        xavyo_api_connectors::CreateConnectorRequest,
        xavyo_api_connectors::UpdateConnectorRequest,
        xavyo_api_connectors::ConnectionTestResponse,
        // Connector DB types (F045)
        xavyo_db::models::ConnectorType,
        xavyo_db::models::ConnectorStatus,
        // Workflow Escalation: Escalation Policy models (F054)
        xavyo_api_governance::models::EscalationPolicyResponse,
        xavyo_api_governance::models::EscalationPolicyListResponse,
        xavyo_api_governance::models::EscalationPolicySummary,
        xavyo_api_governance::models::EscalationLevelResponse,
        xavyo_api_governance::models::CreateEscalationPolicyRequest,
        xavyo_api_governance::models::UpdateEscalationPolicyRequest,
        xavyo_api_governance::models::CreateEscalationLevelRequest,
        // Workflow Escalation: Step Escalation models (F054)
        xavyo_api_governance::models::StepEscalationResponse,
        xavyo_api_governance::models::ConfigureStepEscalationRequest,
        // Workflow Escalation: Approval Group models (F054)
        xavyo_api_governance::models::ApprovalGroupResponse,
        xavyo_api_governance::models::ApprovalGroupListResponse,
        xavyo_api_governance::models::ApprovalGroupSummary,
        xavyo_api_governance::models::CreateApprovalGroupRequest,
        xavyo_api_governance::models::UpdateApprovalGroupRequest,
        xavyo_api_governance::models::ModifyMembersRequest,
        // Workflow Escalation: Escalation Events (F054)
        xavyo_api_governance::models::EscalationEventResponse,
        xavyo_api_governance::models::EscalationEventListResponse,
        xavyo_api_governance::models::EscalationHistoryResponse,
        // Workflow Escalation: Cancel/Reset Escalation (F054 T067-T070)
        xavyo_api_governance::models::CancelEscalationResponse,
        xavyo_api_governance::models::ResetEscalationResponse,
        // Workflow Escalation: DB types (F054)
        xavyo_db::models::EscalationTargetType,
        xavyo_db::models::FinalFallbackAction,
        xavyo_db::models::EscalationReason,
        // Micro-certification (F055)
        xavyo_api_governance::models::TriggerRuleResponse,
        xavyo_api_governance::models::TriggerRuleListResponse,
        xavyo_api_governance::models::CreateTriggerRuleRequest,
        xavyo_api_governance::models::UpdateTriggerRuleRequest,
        xavyo_api_governance::models::MicroCertificationResponse,
        xavyo_api_governance::models::MicroCertificationWithDetailsResponse,
        xavyo_api_governance::models::MicroCertificationListResponse,
        xavyo_api_governance::models::MicroCertificationStatsResponse,
        xavyo_api_governance::models::DecideMicroCertificationRequest,
        xavyo_api_governance::models::DelegateMicroCertificationRequest,
        xavyo_api_governance::models::BulkDecisionRequest,
        xavyo_api_governance::models::BulkDecisionResponse,
        xavyo_api_governance::models::BulkDecisionFailure,
        xavyo_api_governance::models::SkipMicroCertificationRequest,
        xavyo_api_governance::models::ManualTriggerRequest,
        xavyo_api_governance::models::ManualTriggerResponse,
        xavyo_api_governance::models::MicroCertEventResponse,
        xavyo_api_governance::models::MicroCertEventListResponse,
        xavyo_api_governance::models::MicroCertUserSummary,
        xavyo_api_governance::models::MicroCertEntitlementSummary,
        xavyo_api_governance::models::TriggerRuleSummary,
        // Micro-certification DB types (F055)
        xavyo_db::models::MicroCertTriggerType,
        xavyo_db::models::MicroCertScopeType,
        xavyo_db::models::MicroCertReviewerType,
        xavyo_db::models::MicroCertStatus,
        xavyo_db::models::MicroCertDecision,
        xavyo_db::models::MicroCertEventType,
        // Meta-role models (F056)
        xavyo_api_governance::models::CreateMetaRoleRequest,
        xavyo_api_governance::models::UpdateMetaRoleRequest,
        xavyo_api_governance::models::MetaRoleResponse,
        xavyo_api_governance::models::MetaRoleWithDetailsResponse,
        xavyo_api_governance::models::MetaRoleStatsResponse,
        xavyo_api_governance::models::MetaRoleListResponse,
        xavyo_api_governance::models::CreateMetaRoleCriteriaRequest,
        xavyo_api_governance::models::MetaRoleCriteriaResponse,
        xavyo_api_governance::models::CreateMetaRoleEntitlementRequest,
        xavyo_api_governance::models::AddMetaRoleEntitlementRequest,
        xavyo_api_governance::models::MetaRoleEntitlementResponse,
        xavyo_api_governance::models::MetaRoleEntitlementSummary,
        xavyo_api_governance::models::CreateMetaRoleConstraintRequest,
        xavyo_api_governance::models::AddMetaRoleConstraintRequest,
        xavyo_api_governance::models::UpdateMetaRoleConstraintRequest,
        xavyo_api_governance::models::MetaRoleConstraintResponse,
        xavyo_api_governance::models::InheritanceResponse,
        xavyo_api_governance::models::MetaRoleSummary,
        xavyo_api_governance::models::ChildRoleSummary,
        xavyo_api_governance::models::InheritanceListResponse,
        xavyo_api_governance::models::ResolveConflictRequest,
        xavyo_api_governance::models::ConflictResponse,
        xavyo_api_governance::models::ConflictListResponse,
        xavyo_api_governance::models::EventResponse,
        xavyo_api_governance::models::EventListResponse,
        xavyo_api_governance::models::EventStatsResponse,
        xavyo_api_governance::models::SimulateMetaRoleRequest,
        xavyo_api_governance::models::MetaRoleSimulationType,
        xavyo_api_governance::models::SimulationResultResponse,
        xavyo_api_governance::models::SimulationRoleChange,
        xavyo_api_governance::models::SimulationConflict,
        xavyo_api_governance::models::SimulationSummary,
        xavyo_api_governance::models::TriggerCascadeRequest,
        xavyo_api_governance::models::CascadeStatusResponse,
        xavyo_api_governance::models::CascadeFailure,
        xavyo_api_governance::models::EvaluateRoleMatchRequest,
        xavyo_api_governance::models::RoleMatchResponse,
        xavyo_api_governance::models::MatchingMetaRole,
        // Meta-role DB types (F056)
        xavyo_db::models::MetaRoleStatus,
        xavyo_db::models::CriteriaLogic,
        xavyo_db::models::CriteriaOperator,
        xavyo_db::models::PermissionType,
        xavyo_db::models::InheritanceStatus,
        xavyo_db::models::MetaRoleConflictType,
        xavyo_db::models::ResolutionStatus,
        xavyo_db::models::MetaRoleEventType,
        // Parametric Role models (F057)
        xavyo_api_governance::models::CreateRoleParameterRequest,
        xavyo_api_governance::models::UpdateRoleParameterRequest,
        xavyo_api_governance::models::ParameterConstraintsRequest,
        xavyo_api_governance::models::RoleParameterResponse,
        xavyo_api_governance::models::RoleParameterListResponse,
        xavyo_api_governance::models::CreateParametricAssignmentRequest,
        xavyo_api_governance::models::ParameterValueRequest,
        xavyo_api_governance::models::UpdateAssignmentParametersRequest,
        xavyo_api_governance::models::AssignmentParameterResponse,
        xavyo_api_governance::models::ParametricAssignmentResponse,
        xavyo_api_governance::models::ParametricAssignmentListResponse,
        xavyo_api_governance::models::ValidateParametersRequest,
        xavyo_api_governance::models::ValidateParametersResponse,
        xavyo_api_governance::models::ParameterValidationResult,
        xavyo_api_governance::models::ParameterAuditEventResponse,
        xavyo_api_governance::models::ParameterAuditListResponse,
        xavyo_api_governance::models::EffectiveEntitlementWithParams,
        xavyo_api_governance::models::EffectiveParameterValue,
        // Parametric Role DB types (F057)
        xavyo_db::models::ParameterType,
        xavyo_db::models::ParameterEventType,
        // Object Template models (F058)
        xavyo_api_governance::models::CreateTemplateRequest,
        xavyo_api_governance::models::UpdateTemplateRequest,
        xavyo_api_governance::models::TemplateResponse,
        xavyo_api_governance::models::TemplateDetailResponse,
        xavyo_api_governance::models::TemplateListResponse,
        xavyo_api_governance::models::CreateRuleRequest,
        xavyo_api_governance::models::UpdateRuleRequest,
        xavyo_api_governance::models::RuleResponse,
        xavyo_api_governance::models::RuleListResponse,
        xavyo_api_governance::models::CreateScopeRequest,
        xavyo_api_governance::models::ScopeResponse,
        xavyo_api_governance::models::ScopeListResponse,
        xavyo_api_governance::models::VersionResponse,
        xavyo_api_governance::models::VersionListResponse,
        xavyo_api_governance::models::CreateMergePolicyRequest,
        xavyo_api_governance::models::UpdateMergePolicyRequest,
        xavyo_api_governance::models::MergePolicyResponse,
        xavyo_api_governance::models::MergePolicyListResponse,
        xavyo_api_governance::models::SimulationRequest,
        xavyo_api_governance::models::TemplateSimulationResponse,
        xavyo_api_governance::models::RuleApplicationResult,
        xavyo_api_governance::models::ValidationError,
        xavyo_api_governance::models::TemplateEventResponse,
        xavyo_api_governance::models::TemplateEventListResponse,
        xavyo_api_governance::models::ApplicationEventResponse,
        xavyo_api_governance::models::ApplicationEventListResponse,
        xavyo_api_governance::models::ExpressionValidationResult,
        // Object Template DB types (F058)
        xavyo_db::models::TemplateObjectType,
        xavyo_db::models::ObjectTemplateStatus,
        xavyo_db::models::TemplateRuleType,
        xavyo_db::models::TemplateStrength,
        xavyo_db::models::TemplateScopeType,
        xavyo_db::models::TemplateMergeStrategy,
        xavyo_db::models::TemplateNullHandling,
        xavyo_db::models::TemplateTimeReference,
        xavyo_db::models::TemplateEventType,
        // Outlier Detection models (F059)
        xavyo_api_governance::models::UpdateOutlierConfigRequest,
        xavyo_api_governance::models::OutlierConfigResponse,
        xavyo_api_governance::models::TriggerAnalysisRequest,
        xavyo_api_governance::models::OutlierAnalysisResponse,
        xavyo_api_governance::models::OutlierResultResponse,
        xavyo_api_governance::models::OutlierSummaryResponse,
        xavyo_api_governance::models::CreateDispositionRequest,
        xavyo_api_governance::models::DispositionResponse,
        xavyo_api_governance::models::DispositionSummaryResponse,
        xavyo_api_governance::models::AlertResponse,
        xavyo_api_governance::models::AlertSummaryResponse,
        xavyo_api_governance::models::GenerateOutlierReportRequest,
        xavyo_api_governance::models::OutlierTrendPoint,
        xavyo_api_governance::models::PeerGroupBreakdown,
        xavyo_api_governance::models::OutlierReportResponse,
        xavyo_api_governance::models::UserOutlierHistoryResponse,
        xavyo_api_governance::models::DetailedFactorScore,
        // Outlier Detection DB types (F059)
        xavyo_db::models::OutlierAnalysisStatus,
        xavyo_db::models::OutlierTriggerType,
        xavyo_db::models::OutlierClassification,
        xavyo_db::models::OutlierDispositionStatus,
        xavyo_db::models::OutlierAlertType,
        xavyo_db::models::OutlierAlertSeverity,
        // Enhanced Simulation models (F060)
        xavyo_api_governance::models::CreateBatchSimulationRequest,
        xavyo_api_governance::models::ExecuteBatchSimulationRequest,
        xavyo_api_governance::models::ApplyBatchSimulationRequest,
        xavyo_api_governance::models::UpdateBatchSimulationNotesRequest,
        xavyo_api_governance::models::BatchSimulationResponse,
        xavyo_api_governance::models::BatchSimulationResultResponse,
        xavyo_api_governance::models::BatchSimulationListResponse,
        xavyo_api_governance::models::BatchSimulationResultListResponse,
        xavyo_api_governance::models::PolicySimulationResponse,
        xavyo_api_governance::models::PolicySimulationResultResponse,
        xavyo_api_governance::models::SimulationComparisonResponse,
        xavyo_db::models::ComparisonSummary,
        xavyo_db::models::DeltaEntry,
        xavyo_db::models::DeltaResults,
        xavyo_db::models::ModifiedEntry,
        // Enhanced Simulation DB types (F060)
        xavyo_db::models::PolicySimulationType,
        xavyo_db::models::BatchSimulationType,
        xavyo_db::models::SelectionMode,
        xavyo_db::models::ImpactType,
        xavyo_db::models::ComparisonType,
        // NHI Lifecycle models (F061)
        xavyo_api_governance::models::NhiResponse,
        xavyo_api_governance::models::CreateNhiRequest,
        xavyo_api_governance::models::UpdateNhiRequest,
        xavyo_api_governance::models::NhiListResponse,
        xavyo_api_governance::models::NhiSummary,
        xavyo_api_governance::models::NhiRiskBreakdown,
        xavyo_api_governance::models::NhiCredentialResponse,
        xavyo_api_governance::models::NhiCredentialCreatedResponse,
        xavyo_api_governance::models::RotateCredentialsRequest,
        xavyo_api_governance::models::RevokeCredentialRequest,
        xavyo_api_governance::models::NhiCredentialListResponse,
        xavyo_api_governance::models::NhiUsageEventResponse,
        xavyo_api_governance::models::NhiUsageEventListResponse,
        xavyo_api_governance::models::NhiUsageSummaryResponse,
        xavyo_api_governance::models::ResourceAccessSummary,
        xavyo_api_governance::models::NhiRiskScoreResponse,
        xavyo_api_governance::models::NhiRequestResponse,
        xavyo_api_governance::models::SubmitNhiRequestRequest,
        xavyo_api_governance::models::ApproveNhiRequestRequest,
        xavyo_api_governance::models::RejectNhiRequestRequest,
        xavyo_api_governance::models::NhiRequestListResponse,
        xavyo_api_governance::models::NhiAuditEventResponse,
        xavyo_api_governance::models::NhiAuditEventListResponse,
        xavyo_api_governance::models::SuspendNhiRequest,
        xavyo_api_governance::models::ReactivateNhiRequest,
        xavyo_api_governance::models::TransferOwnershipRequest,
        xavyo_api_governance::models::CertifyNhiResponse,
        xavyo_api_governance::models::RecordUsageRequest,
        xavyo_api_governance::models::NhiUsageListResponse,
        xavyo_api_governance::models::ResourceAccessInfo,
        xavyo_api_governance::models::NhiUsageSummaryExtendedResponse,
        xavyo_api_governance::models::StaleNhiInfo,
        xavyo_api_governance::models::StalenessReportResponse,
        xavyo_api_governance::models::NhiRiskScoreListResponse,
        xavyo_api_governance::models::RiskLevelSummary,
        xavyo_api_governance::models::NhiCertificationStatus,
        xavyo_api_governance::models::NhiCertificationDecision,
        xavyo_api_governance::models::NhiCertificationItemResponse,
        xavyo_api_governance::models::NhiCertificationSummary,
        xavyo_api_governance::models::CreateNhiCertificationCampaignRequest,
        xavyo_api_governance::models::NhiCertReviewerType,
        xavyo_api_governance::models::NhiCertificationDecisionRequest,
        xavyo_api_governance::models::BulkNhiCertificationDecisionRequest,
        xavyo_api_governance::models::BulkNhiCertificationResult,
        xavyo_api_governance::models::BulkCertificationError,
        xavyo_api_governance::models::NhiCertificationItemListResponse,
        xavyo_api_governance::models::NhiCertificationCampaignResponse,
        xavyo_api_governance::models::NhiCertCampaignStatus,
        xavyo_api_governance::models::NhiCertificationCampaignListResponse,
        // NHI Lifecycle DB types (F061)
        xavyo_db::models::NhiCredentialType,
        xavyo_db::models::NhiRequestStatus,
        xavyo_db::models::NhiAuditEventType,
        xavyo_db::models::NhiSuspensionReason,
        // Identity Merge models (F062)
        xavyo_api_governance::models::DuplicateCandidateResponse,
        xavyo_api_governance::models::DuplicateDetailResponse,
        xavyo_api_governance::models::IdentitySummary,
        xavyo_api_governance::models::AttributeComparison,
        xavyo_api_governance::models::RuleMatchResponse,
        xavyo_api_governance::models::DismissDuplicateRequest,
        xavyo_api_governance::models::MergePreviewRequest,
        xavyo_api_governance::models::MergePreviewResponse,
        xavyo_api_governance::models::EntitlementsPreview,
        xavyo_api_governance::models::MergeEntitlementSummary,
        xavyo_api_governance::models::MergeSodCheckResponse,
        xavyo_api_governance::models::MergeSodViolationResponse,
        xavyo_api_governance::models::MergeExecuteRequest,
        xavyo_api_governance::models::MergeOperationResponse,
        xavyo_api_governance::models::BatchMergeRequest,
        xavyo_api_governance::models::AttributeResolutionRule,
        xavyo_api_governance::models::BatchMergeResponse,
        xavyo_api_governance::models::BatchMergeStatus,
        xavyo_api_governance::models::MergeAuditSummaryResponse,
        xavyo_api_governance::models::MergeAuditDetailResponse,
        xavyo_api_governance::models::TriggerDetectionRequest,
        xavyo_api_governance::models::DetectionJobResponse,
        xavyo_api_governance::models::DetectionJobStatus,
        xavyo_api_governance::models::MergeErrorResponse,
        // Identity Merge DB types (F062)
        xavyo_db::models::GovDuplicateStatus,
        xavyo_db::models::GovMergeOperationStatus,
        xavyo_db::models::GovEntitlementStrategy,
        // Persona Management models (F063)
        xavyo_api_governance::models::CreateArchetypeRequest,
        xavyo_api_governance::models::UpdateArchetypeRequest,
        xavyo_api_governance::models::AttributeMappingsRequest,
        xavyo_api_governance::models::PropagateMappingRequest,
        xavyo_api_governance::models::ComputedMappingRequest,
        xavyo_api_governance::models::DefaultEntitlementRequest,
        xavyo_api_governance::models::LifecyclePolicyRequest,
        xavyo_api_governance::models::ArchetypeResponse,
        xavyo_api_governance::models::ArchetypeListResponse,
        xavyo_api_governance::models::CreatePersonaRequest,
        xavyo_api_governance::models::UpdatePersonaRequest,
        xavyo_api_governance::models::DeactivatePersonaRequest,
        xavyo_api_governance::models::ArchivePersonaRequest,
        xavyo_api_governance::models::ExtendPersonaRequest,
        xavyo_api_governance::models::ExtendPersonaResponse,
        xavyo_api_governance::models::ExtensionStatus,
        xavyo_api_governance::models::PersonaResponse,
        xavyo_api_governance::models::PersonaDetailResponse,
        xavyo_api_governance::models::PersonaAttributesResponse,
        xavyo_api_governance::models::PersonaListResponse,
        xavyo_api_governance::models::UserPersonasResponse,
        xavyo_api_governance::models::ExpiringPersonasResponse,
        xavyo_api_governance::models::ExpiringPersonaSummary,
        xavyo_api_governance::models::SwitchContextRequest,
        xavyo_api_governance::models::SwitchBackRequest,
        xavyo_api_governance::models::SwitchContextResponse,
        xavyo_api_governance::models::CurrentContextResponse,
        xavyo_api_governance::models::ContextSessionListResponse,
        xavyo_api_governance::models::ContextSessionSummary,
        xavyo_api_governance::models::PersonaAuditEventResponse,
        xavyo_api_governance::models::PersonaAuditListResponse,
        xavyo_api_governance::models::PersonaUserSummary,
        xavyo_api_governance::models::PersonaEntitlementSummary,
        // Persona Management DB types (F063)
        xavyo_db::models::PersonaStatus,
        xavyo_db::models::PersonaLinkType,
        xavyo_db::models::PersonaAuditEventType,
        // Semi-manual Resources models (F064)
        xavyo_api_governance::models::CreateTicketingConfigurationRequest,
        xavyo_api_governance::models::UpdateTicketingConfigurationRequest,
        xavyo_api_governance::models::TicketingConfigurationResponse,
        xavyo_api_governance::models::TicketingConfigurationListResponse,
        xavyo_api_governance::models::TestTicketingConfigurationRequest,
        xavyo_api_governance::models::TestTicketingConfigurationResponse,
        xavyo_api_governance::models::CreateSlaPolicyRequest,
        xavyo_api_governance::models::UpdateSlaPolicyRequest,
        xavyo_api_governance::models::SlaPolicyResponse,
        xavyo_api_governance::models::SlaPolicyListResponse,
        xavyo_api_governance::models::CreateManualProvisioningTaskRequest,
        xavyo_api_governance::models::CompleteManualTaskRequest,
        xavyo_api_governance::models::CancelManualTaskRequest,
        xavyo_api_governance::models::ReassignManualTaskRequest,
        xavyo_api_governance::models::ManualProvisioningTaskResponse,
        xavyo_api_governance::models::ManualProvisioningTaskDetailResponse,
        xavyo_api_governance::models::ManualProvisioningTaskListResponse,
        xavyo_api_governance::models::ManualTaskDashboardResponse,
        xavyo_api_governance::models::ConfirmManualTaskRequest,
        xavyo_api_governance::models::RejectManualTaskRequest,
        xavyo_api_governance::models::DashboardMetricsResponse,
        xavyo_api_governance::models::RetryQueueResponse,
        xavyo_api_governance::models::RetryQueueItemResponse,
        xavyo_api_governance::models::ExternalTicketResponse,
        xavyo_api_governance::models::SyncTicketRequest,
        xavyo_api_governance::models::SyncTicketResponse,
        xavyo_api_governance::models::ManualTaskAuditEventResponse,
        xavyo_api_governance::models::ManualTaskAuditListResponse,
        xavyo_api_governance::models::SemiManualApplicationResponse,
        xavyo_api_governance::models::SemiManualApplicationsListResponse,
        xavyo_api_governance::models::ConfigureSemiManualRequest,
        // Semi-manual Resources DB types (F064)
        xavyo_db::models::TicketingType,
        xavyo_db::models::ManualTaskOperation,
        xavyo_db::models::ManualTaskStatus,
        xavyo_db::models::TicketStatusCategory,
        // License Management models (F065)
        xavyo_api_governance::models::CreateLicensePoolRequest,
        xavyo_api_governance::models::UpdateLicensePoolRequest,
        xavyo_api_governance::models::LicensePoolResponse,
        xavyo_api_governance::models::AssignLicenseRequest,
        xavyo_api_governance::models::BulkAssignLicenseRequest,
        xavyo_api_governance::models::BulkReclaimLicenseRequest,
        xavyo_api_governance::models::LicenseAssignmentResponse,
        xavyo_api_governance::models::BulkOperationResult,
        xavyo_api_governance::models::BulkOperationFailure,
        xavyo_api_governance::models::CreateLicenseEntitlementLinkRequest,
        xavyo_api_governance::models::LicenseEntitlementLinkResponse,
        xavyo_api_governance::models::CreateLicenseIncompatibilityRequest,
        xavyo_api_governance::models::LicenseIncompatibilityResponse,
        xavyo_api_governance::models::CreateReclamationRuleRequest,
        xavyo_api_governance::models::UpdateReclamationRuleRequest,
        xavyo_api_governance::models::ReclamationRuleResponse,
        xavyo_api_governance::models::LicenseDashboardResponse,
        xavyo_api_governance::models::LicenseSummary,
        xavyo_api_governance::models::LicensePoolStats,
        xavyo_api_governance::models::VendorCost,
        xavyo_api_governance::models::LicenseRecommendation,
        xavyo_api_governance::models::RecommendationType,
        xavyo_api_governance::models::LicenseAuditEntry,
        xavyo_api_governance::models::LicensePoolListResponse,
        xavyo_api_governance::models::LicenseAssignmentListResponse,
        xavyo_api_governance::models::EntitlementLinkListResponse,
        xavyo_api_governance::models::IncompatibilityListResponse,
        xavyo_api_governance::models::ReclamationRuleListResponse,
        xavyo_api_governance::models::AuditEventListResponse,
        xavyo_api_governance::models::IncompatibilityCheckResult,
        xavyo_api_governance::models::IncompatibilityViolation,
        xavyo_api_governance::models::ExpiringLicensesResponse,
        xavyo_api_governance::models::ExpiringPoolInfo,
        // License Management DB types (F065)
        xavyo_db::models::LicenseType,
        xavyo_db::models::LicenseBillingPeriod,
        xavyo_db::models::LicenseExpirationPolicy,
        xavyo_db::models::LicensePoolStatus,
        xavyo_db::models::LicenseAssignmentStatus,
        xavyo_db::models::LicenseAssignmentSource,
        xavyo_db::models::LicenseReclamationTrigger,
        xavyo_db::models::LicenseReclaimReason,
        xavyo_db::models::LicenseAuditAction,
        // Provisioning Script models (F066) - qualified paths to avoid name collisions with F058
        xavyo_api_governance::models::script::CreateScriptRequest,
        xavyo_api_governance::models::script::UpdateScriptRequest,
        xavyo_api_governance::models::script::UpdateScriptBodyRequest,
        xavyo_api_governance::models::script::ScriptResponse,
        xavyo_api_governance::models::script::ScriptListResponse,
        xavyo_api_governance::models::script::ScriptVersionResponse,
        xavyo_api_governance::models::script::ScriptVersionListResponse,
        xavyo_api_governance::models::script::RollbackRequest,
        xavyo_api_governance::models::script::VersionComparisonResponse,
        xavyo_api_governance::models::script::DiffLine,
        xavyo_api_governance::models::script::DiffChangeType,
        xavyo_api_governance::models::script::CreateBindingRequest,
        xavyo_api_governance::models::script::UpdateBindingRequest,
        xavyo_api_governance::models::script::BindingResponse,
        xavyo_api_governance::models::script::BindingListResponse,
        xavyo_api_governance::models::script::ValidateScriptRequest,
        xavyo_api_governance::models::script::ValidationResponse,
        xavyo_api_governance::models::script::ScriptError,
        xavyo_api_governance::models::script::DryRunRequest,
        xavyo_api_governance::models::script::DryRunResponse,
        xavyo_api_governance::models::script::CreateTemplateRequest,
        xavyo_api_governance::models::script::UpdateTemplateRequest,
        xavyo_api_governance::models::script::TemplateResponse,
        xavyo_api_governance::models::script::TemplateListResponse,
        xavyo_api_governance::models::script::InstantiateTemplateRequest,
        xavyo_api_governance::models::script::DashboardResponse,
        xavyo_api_governance::models::script::ScriptSummary,
        xavyo_api_governance::models::script::ScriptAnalyticsResponse,
        xavyo_api_governance::models::script::DailyTrend,
        xavyo_api_governance::models::script::ErrorSummary,
        xavyo_api_governance::models::script::ExecutionLogResponse,
        xavyo_api_governance::models::script::ExecutionLogListResponse,
        xavyo_api_governance::models::script::ExecutionLogFilter,
        // Correlation Engine models (F067) - qualified paths to avoid name collisions with F062
        xavyo_api_governance::models::correlation::CreateCorrelationRuleRequest,
        xavyo_api_governance::models::correlation::UpdateCorrelationRuleRequest,
        xavyo_api_governance::models::correlation::CorrelationRuleResponse,
        xavyo_api_governance::models::correlation::CorrelationRuleListResponse,
        xavyo_api_governance::models::correlation::ValidateExpressionRequest,
        xavyo_api_governance::models::correlation::ValidateExpressionResponse,
        xavyo_api_governance::models::correlation::UpsertCorrelationThresholdRequest,
        xavyo_api_governance::models::correlation::CorrelationThresholdResponse,
        xavyo_api_governance::models::correlation::CorrelationCaseSummaryResponse,
        xavyo_api_governance::models::correlation::CorrelationCaseDetailResponse,
        xavyo_api_governance::models::correlation::CorrelationCandidateDetailResponse,
        xavyo_api_governance::models::correlation::ConfirmCaseRequest,
        xavyo_api_governance::models::correlation::RejectCaseRequest,
        xavyo_api_governance::models::correlation::CreateIdentityFromCaseRequest,
        xavyo_api_governance::models::correlation::ReassignCaseRequest,
        xavyo_api_governance::models::correlation::TriggerCorrelationRequest,
        xavyo_api_governance::models::correlation::TriggerCorrelationResponse,
        xavyo_api_governance::models::correlation::CorrelationJobStatusResponse,
        xavyo_api_governance::models::correlation::CorrelationAuditEventResponse,
        xavyo_api_governance::models::correlation::CorrelationAuditListResponse,
        xavyo_api_governance::models::correlation::CorrelationStatisticsResponse,
        xavyo_api_governance::models::correlation::CorrelationTrendsResponse,
        xavyo_api_governance::models::correlation::DailyTrendData,
        // Correlation Engine DB types (F067)
        xavyo_db::models::GovCorrelationCaseStatus,
        xavyo_db::models::GovCorrelationTrigger,
        // SIEM Integration / Audit Export models (F078) - qualified paths
        xavyo_api_governance::models::siem::CreateSiemDestinationRequest,
        xavyo_api_governance::models::siem::UpdateSiemDestinationRequest,
        xavyo_api_governance::models::siem::SiemDestinationResponse,
        xavyo_api_governance::models::siem::SiemDestinationListResponse,
        xavyo_api_governance::models::siem::TestConnectivityResponse,
        // SIEM Batch Export models (F078)
        xavyo_api_governance::models::siem::CreateBatchExportRequest,
        xavyo_api_governance::models::siem::SiemBatchExportResponse,
        xavyo_api_governance::models::siem::SiemBatchExportListResponse,
        // SIEM Health & Dead Letter models (F078)
        xavyo_api_governance::models::siem::SiemHealthSummaryResponse,
        xavyo_api_governance::models::siem::RedeliverResponse,
        // Webhooks & Event Subscriptions (F085)
        xavyo_webhooks::models::CreateWebhookSubscriptionRequest,
        xavyo_webhooks::models::UpdateWebhookSubscriptionRequest,
        xavyo_webhooks::models::WebhookSubscriptionResponse,
        xavyo_webhooks::models::WebhookSubscriptionListResponse,
        xavyo_webhooks::models::WebhookDeliveryResponse,
        xavyo_webhooks::models::WebhookDeliveryDetailResponse,
        xavyo_webhooks::models::WebhookDeliveryListResponse,
        xavyo_webhooks::models::EventTypeInfo,
        xavyo_webhooks::models::EventTypeListResponse,
        xavyo_webhooks::models::WebhookEventType,
        // Connector Reconciliation (F049)
        xavyo_api_connectors::handlers::reconciliation::TriggerReconciliationRequest,
        xavyo_api_connectors::handlers::reconciliation::ReconciliationRunResponse,
        xavyo_api_connectors::handlers::reconciliation::ReconciliationStatistics,
        xavyo_api_connectors::handlers::reconciliation::ListRunsResponse,
        xavyo_api_connectors::handlers::reconciliation::DiscrepancyResponse,
        xavyo_api_connectors::handlers::reconciliation::ListDiscrepanciesResponse,
        xavyo_api_connectors::handlers::reconciliation::RemediateRequest,
        xavyo_api_connectors::handlers::reconciliation::RemediationResponse,
        xavyo_api_connectors::handlers::reconciliation::BulkRemediateRequest,
        xavyo_api_connectors::handlers::reconciliation::BulkRemediateItem,
        xavyo_api_connectors::handlers::reconciliation::BulkRemediationResponse,
        xavyo_api_connectors::handlers::reconciliation::BulkRemediationSummary,
        xavyo_api_connectors::handlers::reconciliation::PreviewRequest,
        xavyo_api_connectors::handlers::reconciliation::PreviewResponse,
        xavyo_api_connectors::handlers::reconciliation::PreviewItem,
        xavyo_api_connectors::handlers::reconciliation::PreviewSummary,
        xavyo_api_connectors::handlers::reconciliation::ScheduleRequest,
        xavyo_api_connectors::handlers::reconciliation::ScheduleResponse,
        xavyo_api_connectors::handlers::reconciliation::ListSchedulesResponse,
        xavyo_api_connectors::handlers::reconciliation::ReportResponse,
        xavyo_api_connectors::handlers::reconciliation::RunInfo,
        xavyo_api_connectors::handlers::reconciliation::DiscrepancySummary,
        xavyo_api_connectors::handlers::reconciliation::ActionSummary,
        xavyo_api_connectors::handlers::reconciliation::AttributeMismatchCount,
        xavyo_api_connectors::handlers::reconciliation::PerformanceMetrics,
        xavyo_api_connectors::handlers::reconciliation::TrendResponse,
        xavyo_api_connectors::handlers::reconciliation::TrendDataPoint,
        xavyo_api_connectors::handlers::reconciliation::ActionResponse,
        xavyo_api_connectors::handlers::reconciliation::ListActionsResponse,
        // Connector Sync (F048)
        xavyo_api_connectors::handlers::sync::SyncConfigResponse,
        xavyo_api_connectors::handlers::sync::UpdateSyncConfigRequest,
        xavyo_api_connectors::handlers::sync::SyncStatusResponse,
        xavyo_api_connectors::handlers::sync::SyncTokenResponse,
        xavyo_api_connectors::handlers::sync::SyncTriggerResponse,
        xavyo_api_connectors::handlers::sync::InboundChangeResponse,
        xavyo_api_connectors::handlers::sync::ListChangesResponse,
        xavyo_api_connectors::handlers::sync::SyncConflictResponse,
        xavyo_api_connectors::handlers::sync::ListConflictsResponse,
        xavyo_api_connectors::handlers::sync::ResolveConflictRequest,
        xavyo_api_connectors::handlers::sync::LinkChangeRequest,
        // Connector Operations (F048)
        xavyo_api_connectors::services::OperationResponse,
        xavyo_api_connectors::services::OperationListResponse,
        xavyo_api_connectors::services::OperationLogResponse,
        xavyo_api_connectors::services::QueueStatsResponse,
        xavyo_api_connectors::services::DlqListResponse,
        xavyo_api_connectors::services::AttemptListResponse,
        xavyo_api_connectors::services::AttemptResponse,
        xavyo_api_connectors::services::ConflictResponse,
        xavyo_api_connectors::services::ConflictListResponse,
        xavyo_api_connectors::services::TriggerOperationRequest,
        xavyo_api_connectors::services::ResolveOperationRequest,
        xavyo_api_connectors::services::ResolveConflictRequest,
        // SCIM Outbound Targets (F087)
        xavyo_api_connectors::services::CreateScimTargetRequest,
        xavyo_api_connectors::services::UpdateScimTargetRequest,
        xavyo_api_connectors::services::ScimTargetResponse,
        xavyo_api_connectors::services::ScimTargetListResponse,
        xavyo_api_connectors::services::HealthCheckResponse,
        // SCIM Outbound Mappings (F087)
        xavyo_api_connectors::handlers::scim_mappings::ReplaceMappingsRequest,
        xavyo_api_connectors::handlers::scim_mappings::MappingEntry,
        xavyo_api_connectors::handlers::scim_mappings::MappingListResponse,
        // SCIM Outbound Sync (F087)
        xavyo_api_connectors::handlers::scim_sync::TriggerSyncResponse,
        xavyo_api_connectors::handlers::scim_sync::SyncRunListResponse,
        // SCIM Outbound Provisioning (F087)
        xavyo_api_connectors::handlers::scim_provisioning::ProvisioningStateListResponse,
        xavyo_api_connectors::handlers::scim_provisioning::RetryResponse,
        // SCIM Outbound Logs (F087)
        xavyo_api_connectors::handlers::scim_log::ProvisioningLogListResponse,
        // Human-in-the-Loop Approvals (F092)
        xavyo_api_agents::models::ApprovalListResponse,
        xavyo_api_agents::models::ApprovalResponse,
        xavyo_api_agents::models::ApprovalStatusResponse,
        xavyo_api_agents::models::ApprovalSummary,
        xavyo_api_agents::models::ApproveRequest,
        xavyo_api_agents::models::DenyRequest,
        // AI Agent Registry (F089)
        xavyo_api_agents::models::CreateAgentRequest,
        xavyo_api_agents::models::UpdateAgentRequest,
        xavyo_api_agents::models::AgentResponse,
        xavyo_api_agents::models::AgentListResponse,
        // AI Agent Tools (F089)
        xavyo_api_agents::models::CreateToolRequest,
        xavyo_api_agents::models::UpdateToolRequest,
        xavyo_api_agents::models::ToolResponse,
        xavyo_api_agents::models::ToolListResponse,
        // AI Agent Permissions (F090)
        xavyo_api_agents::models::GrantPermissionRequest,
        xavyo_api_agents::models::PermissionResponse,
        xavyo_api_agents::models::PermissionListResponse,
        // AI Agent Authorization (F090)
        xavyo_api_agents::models::AuthorizeRequest,
        xavyo_api_agents::models::AuthorizationContext,
        xavyo_api_agents::models::AuthorizeResponse,
        // AI Agent Audit (F090)
        xavyo_api_agents::models::AuditEventResponse,
        xavyo_api_agents::models::AuditListResponse,
        // AI Agent Discovery (F091 - A2A)
        xavyo_api_agents::models::AgentCard,
        xavyo_api_agents::models::AgentCapabilities,
        xavyo_api_agents::models::AgentAuthentication,
        xavyo_api_agents::models::AgentSkill,
        // MCP Tools (F091)
        xavyo_api_agents::models::McpTool,
        xavyo_api_agents::models::McpToolsResponse,
        xavyo_api_agents::models::McpCallRequest,
        xavyo_api_agents::models::McpCallResponse,
        xavyo_api_agents::models::McpContext,
        xavyo_api_agents::models::McpErrorResponse,
        // A2A Tasks (F091)
        xavyo_api_agents::models::CreateA2aTaskRequest,
        xavyo_api_agents::models::CreateA2aTaskResponse,
        xavyo_api_agents::models::A2aTaskResponse,
        xavyo_api_agents::models::A2aTaskListResponse,
        xavyo_api_agents::models::CancelA2aTaskResponse,
        xavyo_api_agents::models::A2aErrorResponse,
        // Security Assessment (F093)
        xavyo_api_agents::models::SecurityAssessment,
        xavyo_api_agents::models::VulnerabilityCheck,
        xavyo_api_agents::models::Recommendation,
        xavyo_api_agents::models::ComplianceStatus,
        xavyo_api_agents::models::OwaspAgenticCompliance,
        // Behavioral Anomaly Detection (F094)
        xavyo_api_agents::models::DetectedAnomaly,
        xavyo_api_agents::models::AnomalyListResponse,
        xavyo_api_agents::models::Baseline,
        xavyo_api_agents::models::BaselineResponse,
        xavyo_api_agents::models::Threshold,
        xavyo_api_agents::models::ThresholdsResponse,
        xavyo_api_agents::models::SetThresholdsRequest,
        xavyo_api_agents::models::AnomalyThresholdInput,
        // Tenant Provisioning models (F097)
        xavyo_api_tenants::models::ProvisionTenantRequest,
        xavyo_api_tenants::models::ProvisionTenantResponse,
        xavyo_api_tenants::models::TenantInfo,
        xavyo_api_tenants::models::AdminInfo,
        xavyo_api_tenants::models::OAuthClientInfo,
        xavyo_api_tenants::models::EndpointInfo,
        // Unified NHI models (201-tool-nhi-promotion)
        // Unified handler types
        xavyo_api_nhi::handlers::unified::NhiIdentityDetail,
        xavyo_api_nhi::handlers::unified::ToolExtension,
        xavyo_api_nhi::handlers::unified::AgentExtension,
        xavyo_api_nhi::handlers::unified::ServiceAccountExtension,
        // Lifecycle handler types
        xavyo_api_nhi::handlers::lifecycle::SuspendRequest,
        // Credential handler types
        xavyo_api_nhi::handlers::credentials::IssueCredentialRequest,
        xavyo_api_nhi::handlers::credentials::RotateCredentialRequest,
        xavyo_api_nhi::handlers::credentials::CredentialIssuedResponse,
        // Certification handler types
        xavyo_api_nhi::handlers::certification::CreateCampaignRequest,
        xavyo_api_nhi::handlers::certification::CertifyResponse,
        xavyo_api_nhi::handlers::certification::RevokeResponse,
        // Permission handler types
        xavyo_api_nhi::handlers::permissions::GrantPermissionRequest,
        // Risk service types
        xavyo_api_nhi::services::nhi_risk_service::RiskBreakdown,
        xavyo_api_nhi::services::nhi_risk_service::RiskSummary,
        xavyo_api_nhi::services::nhi_risk_service::RiskFactor,
        xavyo_api_nhi::services::nhi_risk_service::TypeRiskSummary,
        xavyo_api_nhi::services::nhi_risk_service::LevelRiskSummary,
        // SoD handler types
        xavyo_api_nhi::handlers::sod::SodEnforcement,
        xavyo_api_nhi::handlers::sod::SodRule,
        xavyo_api_nhi::handlers::sod::CreateSodRuleRequest,
        xavyo_api_nhi::handlers::sod::SodCheckRequest,
        xavyo_api_nhi::handlers::sod::SodViolation,
        xavyo_api_nhi::handlers::sod::SodCheckResult,
        // Inactivity service types
        xavyo_api_nhi::services::nhi_inactivity_service::InactiveEntity,
        xavyo_api_nhi::services::nhi_inactivity_service::OrphanEntity,
        xavyo_api_nhi::services::nhi_inactivity_service::AutoSuspendResult,
        xavyo_api_nhi::services::nhi_inactivity_service::AutoSuspendFailure,
        // Inactivity handler types
        xavyo_api_nhi::handlers::inactivity::GracePeriodRequest,
        // Agent handler types
        xavyo_api_nhi::handlers::agents::CreateAgentRequest,
        xavyo_api_nhi::handlers::agents::UpdateAgentRequest,
        // Service Account handler types
        xavyo_api_nhi::handlers::service_accounts::CreateServiceAccountRequest,
        xavyo_api_nhi::handlers::service_accounts::UpdateServiceAccountRequest,
        // Tool handler types
        xavyo_api_nhi::handlers::tools::CreateToolRequest,
        xavyo_api_nhi::handlers::tools::UpdateToolRequest,

        // ====================================================================
        // Previously unregistered schemas (fixing 172 stub schemas)
        // ====================================================================

        // --- xavyo-db model types ---
        xavyo_db::models::AccessItem,
        xavyo_db::models::AlertSeverity,
        xavyo_db::models::AuditActionType,
        xavyo_db::models::BatchImpactSummary,
        xavyo_db::models::BulkOperationStatus,
        xavyo_db::models::ChangeSpec,
        xavyo_db::models::ConditionOperator,
        xavyo_db::models::DataProtectionClassification,
        xavyo_db::models::DelegationStatus,
        xavyo_db::models::DetectionReason,
        xavyo_db::models::FilterCriteria,
        xavyo_db::models::GdprLegalBasis,
        xavyo_db::models::GovExemptionStatus,
        xavyo_db::models::GovScheduleStatus,
        xavyo_db::models::GovViolationStatus,
        xavyo_db::models::LifecycleObjectType,
        xavyo_db::models::NhiAgentWithIdentity,
        xavyo_db::models::NhiCredential,
        xavyo_db::models::NhiIdentity,
        xavyo_db::models::NhiServiceAccountWithIdentity,
        xavyo_db::models::NhiToolPermission,
        xavyo_db::models::NhiToolWithIdentity,
        xavyo_db::models::NhiUsageOutcome,
        xavyo_db::models::OperationType,
        xavyo_db::models::PeerGroupScore,
        xavyo_db::models::PeerGroupType,
        xavyo_db::models::RemediationAction,
        // RiskAlertSortOption is in governance, not db
        xavyo_db::models::ScoringWeights,
        xavyo_db::models::ServiceAccountStatus,
        xavyo_db::models::Severity,
        xavyo_db::models::TransitionRequestStatus,
        // SCIM-related DB models
        xavyo_db::models::ScimProvisioningLog,
        xavyo_db::models::ScimProvisioningState,
        xavyo_db::models::ScimSyncRun,
        xavyo_db::models::ScimTargetAttributeMapping,
        // NHI certification campaign (DB model)
        xavyo_db::models::NhiCertificationCampaign,

        // --- xavyo-nhi foundation types ---
        xavyo_nhi::types::NhiType,
        xavyo_nhi::types::NhiLifecycleState,

        // --- xavyo-api-governance handler types ---
        xavyo_api_governance::handlers::license_reports::AuditTrailResponse,
        xavyo_api_governance::handlers::license_reports::ComplianceReportRequest,
        xavyo_api_governance::handlers::license_entitlement_links::SetLinkEnabledRequest,
        xavyo_api_governance::handlers::nhis::NhiRequestApprovalResponse,
        xavyo_api_governance::handlers::role_entitlements::AddRoleEntitlementRequest,
        xavyo_api_governance::handlers::role_entitlements::EffectiveEntitlementsResponse,
        xavyo_api_governance::handlers::role_entitlements::RecomputeResponse,
        xavyo_api_governance::handlers::role_hierarchy::CreateRoleRequest,
        xavyo_api_governance::handlers::role_hierarchy::MoveRoleRequest,
        xavyo_api_governance::handlers::role_hierarchy::RoleListResponse,
        xavyo_api_governance::handlers::role_hierarchy::RoleMoveResponse,
        xavyo_api_governance::handlers::role_hierarchy::RoleResponse,
        xavyo_api_governance::handlers::role_hierarchy::RoleTreeResponse,
        xavyo_api_governance::handlers::role_hierarchy::UpdateRoleRequest,
        xavyo_api_governance::handlers::role_inheritance_blocks::AddInheritanceBlockRequest,
        xavyo_api_governance::handlers::role_inheritance_blocks::InheritanceBlockDetailsResponse,
        xavyo_api_governance::handlers::role_inheritance_blocks::InheritanceBlockResponse,
        xavyo_api_governance::handlers::script_testing::RawDryRunRequest,
        xavyo_api_governance::handlers::ticketing_webhook::SingleTicketSyncResponse,
        xavyo_api_governance::handlers::ticketing_webhook::TicketSyncResponse,
        xavyo_api_governance::handlers::ticketing_webhook::WebhookCallbackRequest,
        xavyo_api_governance::handlers::ticketing_webhook::WebhookCallbackResponse,

        // --- xavyo-api-governance model types ---
        xavyo_api_governance::models::AccessSnapshotSummary,
        xavyo_api_governance::models::AffectedUser,
        xavyo_api_governance::models::BulkOperationDetailResponse,
        xavyo_api_governance::models::BulkOperationListResponse,
        xavyo_api_governance::models::BulkOperationResponse,
        xavyo_api_governance::models::BulkRemediationError,
        xavyo_api_governance::models::CampaignSummary,
        xavyo_api_governance::models::ConditionEvaluationResult,
        xavyo_api_governance::models::CreateBulkOperationRequest,
        xavyo_api_governance::models::CreateDelegationScopeRequest,
        xavyo_api_governance::models::CreateLifecycleConfigRequest,
        xavyo_api_governance::models::CreateLifecycleStateRequest,
        xavyo_api_governance::models::CreateLifecycleTransitionRequest,
        xavyo_api_governance::models::CreateParametricAssignmentRequest,
        xavyo_api_governance::models::CreateSodExemptionRequest,
        xavyo_api_governance::models::DepartmentImpact,
        xavyo_api_governance::models::EntitlementImpact,
        xavyo_api_governance::models::EntitlementSummary,
        xavyo_api_governance::models::ExecuteTransitionRequest,
        xavyo_api_governance::models::FactorBreakdown,
        xavyo_api_governance::models::HighRiskOrphan,
        xavyo_api_governance::models::ImpactSummary,
        xavyo_api_governance::models::LevelCount,
        xavyo_api_governance::models::LifecycleConfigDetailResponse,
        xavyo_api_governance::models::LifecycleConfigListResponse,
        xavyo_api_governance::models::LifecycleConfigResponse,
        xavyo_api_governance::models::LifecycleStateResponse,
        xavyo_api_governance::models::LifecycleTransitionResponse,
        xavyo_api_governance::models::LocationImpact,
        xavyo_api_governance::models::ManualProvisioningTaskResponse,
        xavyo_api_governance::models::ManualProvisioningTaskListResponse,
        xavyo_api_governance::models::MatchingPolicyResult,
        xavyo_api_governance::models::ObjectLifecycleStatusResponse,
        xavyo_api_governance::models::ParametricAssignmentListResponse,
        xavyo_api_governance::models::ParametricAssignmentResponse,
        xavyo_api_governance::models::PeerComparisonData,
        xavyo_api_governance::models::PeerGroupComparison,
        xavyo_api_governance::models::ProcessingSummary,
        xavyo_api_governance::models::ReasonBreakdown,
        xavyo_api_governance::models::ReviewerProgressResponse,
        xavyo_api_governance::models::RiskAlertSortOption,
        xavyo_api_governance::models::RiskScoreHistoryEntry,
        xavyo_api_governance::models::ScanRuleResponse,
        xavyo_api_governance::models::ScheduledTransitionResponse,
        xavyo_api_governance::models::SeverityCount,
        xavyo_api_governance::models::SnapshotContentResponse,
        xavyo_api_governance::models::SodCheckResponse,
        xavyo_api_governance::models::SodExemptionListResponse,
        xavyo_api_governance::models::SodExemptionResponse,
        xavyo_api_governance::models::SodViolationListResponse,
        xavyo_api_governance::models::SodViolationResponse,
        xavyo_api_governance::models::SodWarningSummary,
        xavyo_api_governance::models::TransitionAuditListResponse,
        xavyo_api_governance::models::TransitionAuditResponse,
        xavyo_api_governance::models::TransitionRequestListResponse,
        xavyo_api_governance::models::TransitionRequestResponse,
        xavyo_api_governance::models::TriggerTypeStats,
        xavyo_api_governance::models::UpdateLifecycleConfigRequest,
        xavyo_api_governance::models::UpdateLifecycleStateRequest,
        xavyo_api_governance::models::UpdateNotesRequest,
        xavyo_api_governance::models::UserSummary,
        // Governance - remediation violation
        xavyo_api_governance::models::RemediateViolationRequest,

        // --- xavyo-api-governance service types ---
        xavyo_api_governance::services::correlation_case_service::CorrelationCaseListResponse,
        xavyo_api_governance::services::license_report_service::ComplianceReport,
        xavyo_api_governance::services::nhi_request_service::NhiRequestSummary,
        xavyo_api_governance::services::state_access_rule_service::StateAffectedEntitlements,

        // --- xavyo-api-agents types ---
        xavyo_api_agents::models::AnomalyType,
        xavyo_api_agents::models::AnomalyWarning,
        xavyo_api_agents::models::BaselineStatus,
        xavyo_api_agents::models::BaselineType,
        xavyo_api_agents::models::Category,
        xavyo_api_agents::models::CheckName,
        xavyo_api_agents::models::McpErrorCode,
        xavyo_api_agents::models::Priority,
        xavyo_api_agents::models::Status,
        xavyo_api_agents::models::ThresholdSource,
        xavyo_api_agents::models::UserContext,

        // --- xavyo-api-authorization types ---
        xavyo_api_authorization::models::AuthorizationDecisionResponse,
        xavyo_api_authorization::models::BulkCheckRequest,
        xavyo_api_authorization::models::BulkCheckResponse,
        xavyo_api_authorization::models::CreateMappingRequest,
        xavyo_api_authorization::models::CreatePolicyRequest,
        xavyo_api_authorization::models::MappingResponse,
        xavyo_api_authorization::models::PolicyListResponse,
        xavyo_api_authorization::models::PolicyResponse,
        xavyo_api_authorization::models::UpdatePolicyRequest,

        // --- xavyo-api-connectors types ---
        xavyo_api_connectors::handlers::schemas::AttributeListResponse,
        xavyo_api_connectors::handlers::schemas::DiscoverSchemaRequest,
        xavyo_api_connectors::handlers::schemas::DiscoveryStatusResponse,
        xavyo_api_connectors::handlers::schemas::ObjectClassListResponse,
        xavyo_api_connectors::handlers::schemas::RefreshScheduleRequest,
        xavyo_api_connectors::handlers::schemas::RefreshScheduleResponse,
        xavyo_api_connectors::handlers::schemas::SchemaDiffResponse,
        xavyo_api_connectors::handlers::schemas::SchemaVersionListResponse,
        xavyo_api_connectors::models::ConnectorHealthResponse,
        xavyo_api_connectors::services::mapping_service::PreviewMappingRequest,
        xavyo_api_connectors::services::mapping_service::PreviewMappingResponse,
        xavyo_api_connectors::services::mapping_service::UpdateMappingRequest,
        xavyo_api_connectors::services::schema_service::ObjectClassResponse,
        xavyo_api_connectors::services::schema_service::SchemaResponse,

        // --- xavyo-api-auth types ---
        xavyo_api_auth::handlers::key_management::KeyErrorResponse,
        xavyo_api_auth::handlers::key_management::ListKeysResponse,
        xavyo_api_auth::handlers::key_management::RotateKeyResponse,

        // --- xavyo-api-users types ---
        xavyo_api_users::models::LifecycleStateInfo,

        // --- xavyo-scim-client types ---
        xavyo_scim_client::auth::ScimCredentials,
        xavyo_scim_client::client::ServiceProviderConfig,

        // --- xavyo-api-tenants types ---
        xavyo_api_tenants::error::ErrorResponse,

        // ====================================================================
        // Nested types (fields of the above types that also need registration)
        // ====================================================================

        // --- xavyo-db nested types ---
        xavyo_db::models::EntitlementAction,
        xavyo_db::models::OutlierSeverity,
        xavyo_db::models::ScheduleType,
        xavyo_db::models::SchemaVersionSummary,

        // --- xavyo-connector nested types ---
        xavyo_connector::schema::DiffSummary,
        xavyo_connector::schema::ObjectClassChanges,
        xavyo_connector::schema::AttributeChanges,
        xavyo_connector::schema::AttributeAddition,
        xavyo_connector::schema::AttributeModification,
        xavyo_connector::schema::PropertyChange,
        xavyo_connector::schema::AttributeDataType,

        // --- xavyo-api-governance nested types ---
        xavyo_api_governance::services::state_access_rule_service::AffectedEntitlement,
        xavyo_api_governance::services::license_report_service::AuditTrailEntry,
        xavyo_api_governance::services::license_report_service::ComplianceReportFilters,
        xavyo_api_governance::services::license_report_service::PoolComplianceSummary,
        xavyo_api_governance::handlers::role_hierarchy::RoleTreeNodeResponse,
        xavyo_api_governance::handlers::ticketing_webhook::TicketSyncErrorResponse,
        xavyo_api_governance::models::RollbackInfo,
        xavyo_api_governance::models::SnapshotAssignmentResponse,
        xavyo_api_governance::models::SodCheckViolation,
        xavyo_api_governance::models::EntitlementSourceInfo,
        xavyo_api_governance::models::TransitionStateInfo,
        xavyo_api_governance::models::UserImpactType,

        // --- xavyo-api-authorization nested types ---
        xavyo_api_authorization::models::CheckItem,
        xavyo_api_authorization::models::ConditionResponse,
        xavyo_api_authorization::models::CreateConditionRequest,

        // --- xavyo-api-connectors nested types ---
        xavyo_api_connectors::handlers::schemas::AttributeWithSource,
        xavyo_api_connectors::handlers::schemas::ObjectClassSummary,
        xavyo_api_connectors::services::schema_service::AttributeResponse,
        xavyo_api_connectors::services::mapping_service::TransformError,

        // --- xavyo-api-auth nested types ---
        xavyo_api_auth::handlers::key_management::KeyInfo,

        // --- xavyo-scim-client nested types ---
        xavyo_scim_client::client::BulkSupport,
        xavyo_scim_client::client::FeatureSupport,
        xavyo_scim_client::client::FilterSupport,

        // --- Generic paginated response aliases (governance) ---
        xavyo_api_governance::models::outlier::PaginatedOutlierAnalysisResponse,
        xavyo_api_governance::models::identity_merge::MergePaginatedDuplicateCandidateResponse,

        // --- Generic paginated response aliases (NHI) ---
        xavyo_api_nhi::handlers::unified::PaginatedNhiIdentityResponse,
        xavyo_api_nhi::handlers::agents::PaginatedNhiAgentWithIdentityResponse,
        xavyo_api_nhi::handlers::tools::PaginatedNhiToolWithIdentityResponse,
        xavyo_api_nhi::handlers::service_accounts::PaginatedNhiServiceAccountWithIdentityResponse,
        xavyo_api_nhi::handlers::permissions::PaginatedNhiToolPermissionResponse,
        xavyo_api_nhi::handlers::sod::PaginatedSodRuleResponse,
    ))
)]
pub struct ApiDoc;

/// Create Swagger UI routes.
pub fn swagger_routes() -> Router<AppState> {
    Router::new().merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_generation() {
        let doc = ApiDoc::openapi();
        let json = doc.to_json().expect("Should serialize to JSON");
        assert!(json.contains("xavyo API"));
        assert!(json.contains("/health"));
    }

    #[test]
    fn test_openapi_contains_health_endpoint() {
        let doc = ApiDoc::openapi();
        assert!(doc.paths.paths.contains_key("/health"));
    }

    #[test]
    fn test_openapi_has_components() {
        let doc = ApiDoc::openapi();
        let schemas = &doc.components.as_ref().unwrap().schemas;
        assert!(schemas.contains_key("HealthResponse"));
        assert!(schemas.contains_key("HealthState"));
    }

    #[test]
    fn test_openapi_contains_all_endpoint_groups() {
        let doc = ApiDoc::openapi();
        let paths = &doc.paths.paths;

        // Health
        assert!(paths.contains_key("/health"), "Missing /health endpoint");

        // Auth - Core
        assert!(
            paths.contains_key("/auth/login"),
            "Missing /auth/login endpoint"
        );
        assert!(
            paths.contains_key("/auth/register"),
            "Missing /auth/register endpoint"
        );
        assert!(
            paths.contains_key("/auth/logout"),
            "Missing /auth/logout endpoint"
        );
        assert!(
            paths.contains_key("/auth/refresh"),
            "Missing /auth/refresh endpoint"
        );
        assert!(
            paths.contains_key("/auth/forgot-password"),
            "Missing /auth/forgot-password endpoint"
        );
        assert!(
            paths.contains_key("/auth/reset-password"),
            "Missing /auth/reset-password endpoint"
        );

        // OAuth2
        assert!(
            paths.contains_key("/oauth/authorize"),
            "Missing /oauth/authorize endpoint"
        );
        assert!(
            paths.contains_key("/oauth/token"),
            "Missing /oauth/token endpoint"
        );
        assert!(
            paths.contains_key("/.well-known/openid-configuration"),
            "Missing OIDC discovery endpoint"
        );
        assert!(
            paths.contains_key("/.well-known/jwks.json"),
            "Missing JWKS endpoint"
        );

        // Users
        assert!(paths.contains_key("/users"), "Missing /users endpoint");

        // SAML
        assert!(
            paths.contains_key("/saml/sso"),
            "Missing /saml/sso endpoint"
        );
        assert!(
            paths.contains_key("/saml/metadata"),
            "Missing /saml/metadata endpoint"
        );

        // SCIM
        assert!(
            paths.contains_key("/scim/v2/Users"),
            "Missing SCIM users endpoint"
        );

        // OIDC Federation
        assert!(
            paths.contains_key("/admin/federation/identity-providers"),
            "Missing federation endpoint"
        );

        // Social Login
        assert!(
            paths.contains_key("/admin/social-providers"),
            "Missing social providers endpoint"
        );
    }

    #[test]
    fn test_openapi_tags_defined() {
        let doc = ApiDoc::openapi();
        let tags = doc.tags.as_ref().expect("Tags should be defined");

        let expected_tags = [
            "Health",
            "Authentication",
            "IP Restrictions",
            "Delegated Admin",
            "Branding",
            "Email Templates",
            "Public",
            "OAuth2",
            "OAuth2 Admin",
            "OIDC Discovery",
            "Users",
            "SAML",
            "SAML Admin",
            "SCIM",
            "OIDC Federation",
            "Social Login",
        ];

        for tag_name in expected_tags {
            assert!(
                tags.iter().any(|t| t.name == tag_name),
                "Missing tag: {tag_name}"
            );
        }
    }

    #[test]
    fn test_openapi_schemas_registered() {
        let doc = ApiDoc::openapi();
        let schemas = &doc.components.as_ref().unwrap().schemas;

        // Auth models
        assert!(
            schemas.contains_key("LoginRequest"),
            "Missing LoginRequest schema"
        );
        assert!(
            schemas.contains_key("TokenResponse"),
            "Missing TokenResponse schema"
        );
        assert!(
            schemas.contains_key("RegisterRequest"),
            "Missing RegisterRequest schema"
        );

        // OAuth2 models
        assert!(
            schemas.contains_key("TokenRequest"),
            "Missing TokenRequest schema"
        );
        assert!(
            schemas.contains_key("OpenIdConfiguration"),
            "Missing OpenIdConfiguration schema"
        );

        // User models
        assert!(
            schemas.contains_key("CreateUserRequest"),
            "Missing CreateUserRequest schema"
        );
        assert!(
            schemas.contains_key("UserResponse"),
            "Missing UserResponse schema"
        );

        // SCIM models
        assert!(schemas.contains_key("ScimUser"), "Missing ScimUser schema");

        // OIDC Federation models
        assert!(
            schemas.contains_key("IdentityProviderResponse"),
            "Missing IdentityProviderResponse schema"
        );

        // Social Login models
        assert!(
            schemas.contains_key("UpdateProviderRequest"),
            "Missing UpdateProviderRequest schema"
        );
        assert!(
            schemas.contains_key("TenantProviderResponse"),
            "Missing TenantProviderResponse schema"
        );
        assert!(
            schemas.contains_key("TenantProvidersListResponse"),
            "Missing TenantProvidersListResponse schema"
        );
    }

    #[test]
    fn test_openapi_security_scheme_defined() {
        let doc = ApiDoc::openapi();
        let security_schemes = &doc.components.as_ref().unwrap().security_schemes;

        assert!(
            security_schemes.contains_key("bearerAuth"),
            "Missing bearerAuth security scheme"
        );
    }

    #[test]
    fn test_openapi_endpoint_count() {
        let doc = ApiDoc::openapi();
        let path_count = doc.paths.paths.len();

        // We should have at least 300 endpoints documented (includes all governance features F033-F067)
        assert!(
            path_count >= 300,
            "Expected at least 300 endpoints, got {path_count}"
        );
    }

    #[test]
    fn test_openapi_governance_tags_defined() {
        let doc = ApiDoc::openapi();
        let tags = doc.tags.as_ref().expect("Tags should be defined");

        let governance_tags = [
            "Governance - Applications",
            "Governance - Entitlements",
            "Governance - SoD Rules",
            "Governance - Access Requests",
            "Governance - Certification Campaigns",
            "Governance - Lifecycle",
            "Governance - Risk Factors",
            "Governance - Risk Scoring",
            "Governance - Peer Groups",
            "Governance - Risk Alerts",
            "Governance - Orphan Detection",
            "Governance - Detection Rules",
            "Governance - Compliance Reporting",
            "Governance - Role Mining",
            "Governance - Role Hierarchy",
            "Governance - Meta-roles",
            "Governance - Parametric Roles",
            "Governance - Object Templates",
            "Governance - Outlier Detection",
            "Governance - Enhanced Simulation",
            "Governance - NHIs",
            "Governance - Identity Merge",
            "Governance - Persona Management",
            "Governance - Semi-manual Resources",
            "Governance - License Management",
            "Governance - Provisioning Scripts",
            "Governance - Correlation Engine",
            "Governance - Audit Export",
        ];

        for tag_name in governance_tags {
            assert!(
                tags.iter().any(|t| t.name == tag_name),
                "Missing governance tag: {tag_name}"
            );
        }
    }

    /// Export `OpenAPI` spec to docs/api/openapi.json at workspace root.
    /// Run with: cargo test -p idp-api `export_openapi` -- --ignored
    #[test]
    #[ignore]
    fn export_openapi_to_file() {
        let doc = ApiDoc::openapi();
        let json = doc.to_pretty_json().expect("Should serialize to JSON");

        // Navigate to workspace root (two levels up from apps/idp-api)
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let workspace_root = std::path::Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(std::path::Path::new("."));
        let output_dir = workspace_root.join("docs/api");
        let output_path = output_dir.join("openapi.json");

        std::fs::create_dir_all(&output_dir).expect("Failed to create docs/api directory");
        std::fs::write(&output_path, &json).expect("Failed to write openapi.json");

        println!("OpenAPI spec exported to {}", output_path.display());
        println!("Spec size: {} bytes", json.len());
    }
}
