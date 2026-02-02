//! Unit tests for micro-certification trigger rule matching logic (T014).
//!
//! Tests the trigger rule selection algorithm that determines which rule
//! applies to a given event based on scope hierarchy and priority.

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::{
    GovMicroCertTrigger, MicroCertReviewerType, MicroCertScopeType, MicroCertTriggerType,
};

/// Helper to create a test trigger rule with customizable parameters.
fn create_trigger(
    trigger_type: MicroCertTriggerType,
    scope_type: MicroCertScopeType,
    scope_id: Option<Uuid>,
    priority: i32,
    is_active: bool,
    is_default: bool,
) -> GovMicroCertTrigger {
    GovMicroCertTrigger {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        name: format!("Test Rule {:?} {:?}", trigger_type, scope_type),
        trigger_type,
        scope_type,
        scope_id,
        reviewer_type: MicroCertReviewerType::UserManager,
        specific_reviewer_id: None,
        fallback_reviewer_id: None,
        timeout_secs: 86400,
        reminder_threshold_percent: 75,
        auto_revoke: true,
        revoke_triggering_assignment: true,
        is_active,
        is_default,
        priority,
        metadata: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

mod trigger_matching {
    use super::*;

    #[test]
    fn test_exact_entitlement_scope_matches_first() {
        // Given: Multiple rules with different scopes
        let tenant_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();

        let tenant_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        let app_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(app_id),
            0,
            true,
            false,
        );

        let entitlement_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Entitlement,
            Some(entitlement_id),
            0,
            true,
            false,
        );

        let rules = vec![
            tenant_rule.clone(),
            app_rule.clone(),
            entitlement_rule.clone(),
        ];

        // When: Finding the best matching rule for this entitlement
        let best = find_best_matching_rule(
            &rules,
            MicroCertTriggerType::HighRiskAssignment,
            Some(app_id),
            Some(entitlement_id),
        );

        // Then: Most specific (entitlement) scope should match
        assert!(best.is_some());
        assert_eq!(best.unwrap().scope_type, MicroCertScopeType::Entitlement);
    }

    #[test]
    fn test_application_scope_matches_when_no_entitlement_rule() {
        let app_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();

        let tenant_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        let app_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(app_id),
            0,
            true,
            false,
        );

        let rules = vec![tenant_rule.clone(), app_rule.clone()];

        let best = find_best_matching_rule(
            &rules,
            MicroCertTriggerType::HighRiskAssignment,
            Some(app_id),
            Some(entitlement_id),
        );

        assert!(best.is_some());
        assert_eq!(best.unwrap().scope_type, MicroCertScopeType::Application);
    }

    #[test]
    fn test_tenant_default_matches_when_no_specific_rules() {
        let app_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();
        let other_app_id = Uuid::new_v4();

        let tenant_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        // Rule for a different app
        let other_app_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(other_app_id),
            0,
            true,
            false,
        );

        let rules = vec![tenant_rule.clone(), other_app_rule.clone()];

        let best = find_best_matching_rule(
            &rules,
            MicroCertTriggerType::HighRiskAssignment,
            Some(app_id),
            Some(entitlement_id),
        );

        assert!(best.is_some());
        assert_eq!(best.unwrap().scope_type, MicroCertScopeType::Tenant);
    }

    #[test]
    fn test_priority_breaks_ties_within_same_scope() {
        let app_id = Uuid::new_v4();

        let low_priority = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(app_id),
            10,
            true,
            false,
        );

        let high_priority = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(app_id),
            100,
            true,
            false,
        );

        let rules = vec![low_priority.clone(), high_priority.clone()];

        let best = find_best_matching_rule(
            &rules,
            MicroCertTriggerType::HighRiskAssignment,
            Some(app_id),
            None,
        );

        assert!(best.is_some());
        assert_eq!(best.unwrap().priority, 100);
    }

    #[test]
    fn test_inactive_rules_are_ignored() {
        let app_id = Uuid::new_v4();

        let inactive_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Application,
            Some(app_id),
            100,
            false, // inactive
            false,
        );

        let active_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        let rules = vec![inactive_rule.clone(), active_rule.clone()];

        let best = find_best_matching_rule(
            &rules,
            MicroCertTriggerType::HighRiskAssignment,
            Some(app_id),
            None,
        );

        assert!(best.is_some());
        // Should skip inactive app rule and use tenant default
        assert_eq!(best.unwrap().scope_type, MicroCertScopeType::Tenant);
    }

    #[test]
    fn test_wrong_trigger_type_is_ignored() {
        let sod_rule = create_trigger(
            MicroCertTriggerType::SodViolation,
            MicroCertScopeType::Tenant,
            None,
            100,
            true,
            true,
        );

        let high_risk_rule = create_trigger(
            MicroCertTriggerType::HighRiskAssignment,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        let rules = vec![sod_rule.clone(), high_risk_rule.clone()];

        let best =
            find_best_matching_rule(&rules, MicroCertTriggerType::HighRiskAssignment, None, None);

        assert!(best.is_some());
        assert_eq!(
            best.unwrap().trigger_type,
            MicroCertTriggerType::HighRiskAssignment
        );
    }

    #[test]
    fn test_no_matching_rule_returns_none() {
        let sod_rule = create_trigger(
            MicroCertTriggerType::SodViolation,
            MicroCertScopeType::Tenant,
            None,
            0,
            true,
            true,
        );

        let rules = vec![sod_rule.clone()];

        let best =
            find_best_matching_rule(&rules, MicroCertTriggerType::HighRiskAssignment, None, None);

        assert!(best.is_none());
    }

    #[test]
    fn test_scope_hierarchy_order() {
        // Entitlement > Application > Tenant
        assert!(
            scope_priority(MicroCertScopeType::Entitlement)
                > scope_priority(MicroCertScopeType::Application)
        );
        assert!(
            scope_priority(MicroCertScopeType::Application)
                > scope_priority(MicroCertScopeType::Tenant)
        );
    }
}

// Helper functions that mirror the actual service logic

fn scope_priority(scope: MicroCertScopeType) -> i32 {
    match scope {
        MicroCertScopeType::Entitlement => 3,
        MicroCertScopeType::Application => 2,
        MicroCertScopeType::Tenant => 1,
    }
}

fn find_best_matching_rule(
    rules: &[GovMicroCertTrigger],
    trigger_type: MicroCertTriggerType,
    application_id: Option<Uuid>,
    entitlement_id: Option<Uuid>,
) -> Option<&GovMicroCertTrigger> {
    rules
        .iter()
        .filter(|r| r.is_active && r.trigger_type == trigger_type)
        .filter(|r| match r.scope_type {
            MicroCertScopeType::Entitlement => r.scope_id.is_some() && r.scope_id == entitlement_id,
            MicroCertScopeType::Application => r.scope_id.is_some() && r.scope_id == application_id,
            MicroCertScopeType::Tenant => true, // Tenant scope always matches
        })
        .max_by(|a, b| {
            // First compare by scope specificity
            let scope_cmp = scope_priority(a.scope_type).cmp(&scope_priority(b.scope_type));
            if scope_cmp != std::cmp::Ordering::Equal {
                return scope_cmp;
            }
            // Then by priority within same scope
            a.priority.cmp(&b.priority)
        })
}
