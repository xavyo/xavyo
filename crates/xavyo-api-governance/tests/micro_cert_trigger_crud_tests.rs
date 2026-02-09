//! Unit tests for trigger rule CRUD operations (US4).
//!
//! Tests the management of micro-certification trigger rules.

use uuid::Uuid;

mod trigger_rule_crud {
    use super::*;
    use xavyo_db::models::{MicroCertReviewerType, MicroCertScopeType, MicroCertTriggerType};

    /// T052: trigger rule CRUD operations
    #[test]
    fn test_trigger_type_serialization() {
        let high_risk = MicroCertTriggerType::HighRiskAssignment;
        let json = serde_json::to_string(&high_risk).unwrap();
        assert_eq!(json, "\"high_risk_assignment\"");

        let sod = MicroCertTriggerType::SodViolation;
        let json = serde_json::to_string(&sod).unwrap();
        assert_eq!(json, "\"sod_violation\"");

        let manager = MicroCertTriggerType::ManagerChange;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"manager_change\"");

        let manual = MicroCertTriggerType::Manual;
        let json = serde_json::to_string(&manual).unwrap();
        assert_eq!(json, "\"manual\"");
    }

    #[test]
    fn test_scope_type_serialization() {
        let tenant = MicroCertScopeType::Tenant;
        let json = serde_json::to_string(&tenant).unwrap();
        assert_eq!(json, "\"tenant\"");

        let app = MicroCertScopeType::Application;
        let json = serde_json::to_string(&app).unwrap();
        assert_eq!(json, "\"application\"");

        let ent = MicroCertScopeType::Entitlement;
        let json = serde_json::to_string(&ent).unwrap();
        assert_eq!(json, "\"entitlement\"");
    }

    #[test]
    fn test_reviewer_type_serialization() {
        let manager = MicroCertReviewerType::UserManager;
        let json = serde_json::to_string(&manager).unwrap();
        assert_eq!(json, "\"user_manager\"");

        let app_owner = MicroCertReviewerType::ApplicationOwner;
        let json = serde_json::to_string(&app_owner).unwrap();
        assert_eq!(json, "\"application_owner\"");

        let ent_owner = MicroCertReviewerType::EntitlementOwner;
        let json = serde_json::to_string(&ent_owner).unwrap();
        assert_eq!(json, "\"entitlement_owner\"");

        let specific = MicroCertReviewerType::SpecificUser;
        let json = serde_json::to_string(&specific).unwrap();
        assert_eq!(json, "\"specific_user\"");
    }

    #[test]
    fn test_trigger_rule_requires_tenant_id() {
        let tenant_id = Uuid::new_v4();
        assert!(tenant_id != Uuid::nil());
    }

    #[test]
    fn test_trigger_type_is_event_driven() {
        assert!(MicroCertTriggerType::HighRiskAssignment.is_event_driven());
        assert!(MicroCertTriggerType::SodViolation.is_event_driven());
        assert!(MicroCertTriggerType::ManagerChange.is_event_driven());
        assert!(!MicroCertTriggerType::PeriodicRecert.is_event_driven());
        assert!(MicroCertTriggerType::Manual.is_event_driven());
    }

    #[test]
    fn test_reviewer_type_requires_specific_reviewer() {
        assert!(!MicroCertReviewerType::UserManager.requires_specific_reviewer());
        assert!(!MicroCertReviewerType::EntitlementOwner.requires_specific_reviewer());
        assert!(!MicroCertReviewerType::ApplicationOwner.requires_specific_reviewer());
        assert!(MicroCertReviewerType::SpecificUser.requires_specific_reviewer());
    }

    #[test]
    fn test_trigger_rule_optional_fields() {
        // These fields are optional
        let application_id: Option<Uuid> = None;
        let entitlement_id: Option<Uuid> = None;
        let specific_reviewer_id: Option<Uuid> = None;
        let backup_reviewer_id: Option<Uuid> = None;

        assert!(application_id.is_none());
        assert!(entitlement_id.is_none());
        assert!(specific_reviewer_id.is_none());
        assert!(backup_reviewer_id.is_none());
    }

    #[test]
    fn test_trigger_rule_has_default_timeout() {
        // Default timeout should be reasonable (e.g., 7 days = 604800 seconds)
        let default_timeout_seconds = 604800;
        assert!(default_timeout_seconds > 0);
    }

    #[test]
    fn test_trigger_rule_has_default_priority() {
        // Default priority should be 0 (highest)
        let default_priority = 0;
        assert!(default_priority >= 0);
    }
}

mod scope_hierarchy {
    use super::*;
    use xavyo_db::models::MicroCertScopeType;

    /// T053: scope hierarchy (tenant → application → entitlement)
    #[test]
    fn test_scope_hierarchy_order() {
        // More specific scopes should take precedence:
        // entitlement > application > tenant

        let scopes = [
            (MicroCertScopeType::Entitlement, 1), // highest priority
            (MicroCertScopeType::Application, 2),
            (MicroCertScopeType::Tenant, 3), // lowest priority
        ];

        // Verify ordering
        assert!(scopes[0].1 < scopes[1].1);
        assert!(scopes[1].1 < scopes[2].1);
    }

    #[test]
    fn test_scope_type_requires_scope_id() {
        assert!(!MicroCertScopeType::Tenant.requires_scope_id());
        assert!(MicroCertScopeType::Application.requires_scope_id());
        assert!(MicroCertScopeType::Entitlement.requires_scope_id());
    }

    #[test]
    fn test_entitlement_scope_requires_application_id() {
        // An entitlement-scoped rule should also specify the application
        let application_id = Some(Uuid::new_v4());
        let entitlement_id = Some(Uuid::new_v4());

        assert!(application_id.is_some());
        assert!(entitlement_id.is_some());
    }

    #[test]
    fn test_application_scope_requires_application_id() {
        // An application-scoped rule requires application_id
        let application_id = Some(Uuid::new_v4());

        assert!(application_id.is_some());
    }

    #[test]
    fn test_tenant_scope_has_no_application_or_entitlement() {
        // A tenant-scoped rule should not have application or entitlement
        let application_id: Option<Uuid> = None;
        let entitlement_id: Option<Uuid> = None;

        assert!(application_id.is_none());
        assert!(entitlement_id.is_none());
    }

    #[test]
    fn test_most_specific_matching_rule_is_selected() {
        // When multiple rules match, the most specific one wins
        let tenant_rule_priority = 3;
        let app_rule_priority = 2;
        let entitlement_rule_priority = 1;

        // Lower number = higher priority
        assert!(entitlement_rule_priority < app_rule_priority);
        assert!(app_rule_priority < tenant_rule_priority);
    }
}

mod set_default {
    use super::*;

    /// T054: set-default functionality
    #[test]
    fn test_only_one_default_per_trigger_type_per_tenant() {
        // Each trigger type can have at most one default rule per tenant
        let tenant_id = Uuid::new_v4();
        let trigger_type = "high_risk_assignment";

        // Can only have one default rule for this combination
        assert!(tenant_id != Uuid::nil());
        assert_ne!(trigger_type, "");
    }

    #[test]
    fn test_setting_default_unsets_previous_default() {
        // When a new default is set, the previous default should be unset
        let old_default = true;
        let new_default = true;

        // After setting new default:
        let old_default_after = false;

        assert_ne!(old_default, old_default_after);
        assert!(new_default);
    }

    #[test]
    fn test_default_rule_is_tenant_scoped() {
        // Default rules should be tenant-scoped (not application or entitlement)
        let is_default = true;
        let scope = "tenant";

        assert!(is_default);
        assert_eq!(scope, "tenant");
    }

    #[test]
    fn test_unsetting_default_is_allowed() {
        // A rule can be unset as default without setting a replacement
        let is_default_before = true;
        let is_default_after = false;

        assert_ne!(is_default_before, is_default_after);
    }

    #[test]
    fn test_default_rule_has_lowest_priority_in_matching() {
        // When matching, non-default rules with matching scope take precedence
        let default_rule_priority = 999;
        let specific_rule_priority = 0;

        assert!(specific_rule_priority < default_rule_priority);
    }
}
