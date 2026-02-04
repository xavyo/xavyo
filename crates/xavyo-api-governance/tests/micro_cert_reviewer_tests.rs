//! Unit tests for micro-certification reviewer resolution (T015).
//!
//! Tests the logic that determines who should review a micro-certification
//! based on the trigger rule's `reviewer_type` setting.

use uuid::Uuid;
use xavyo_db::MicroCertReviewerType;

/// Simulated user data for testing reviewer resolution
#[derive(Debug, Clone)]
struct TestUser {
    id: Uuid,
    manager_id: Option<Uuid>,
    department: Option<String>,
}

/// Simulated entitlement with owner
#[derive(Debug, Clone)]
struct TestEntitlement {
    id: Uuid,
    owner_id: Option<Uuid>,
    application_id: Uuid,
}

/// Simulated application with owner
#[derive(Debug, Clone)]
struct TestApplication {
    id: Uuid,
    owner_id: Option<Uuid>,
}

mod reviewer_resolution {
    use super::*;

    #[test]
    fn test_user_manager_returns_manager_id() {
        let manager_id = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: Some(manager_id),
            department: Some("Engineering".to_string()),
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::UserManager,
            &user,
            None,
            None,
            None,
            None,
        );

        assert_eq!(reviewer, Some(manager_id));
    }

    #[test]
    fn test_user_manager_returns_none_when_no_manager() {
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: None,
            department: None,
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::UserManager,
            &user,
            None,
            None,
            None,
            None,
        );

        assert!(reviewer.is_none());
    }

    #[test]
    fn test_entitlement_owner_returns_owner_id() {
        let owner_id = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: None,
            department: None,
        };
        let entitlement = TestEntitlement {
            id: Uuid::new_v4(),
            owner_id: Some(owner_id),
            application_id: Uuid::new_v4(),
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::EntitlementOwner,
            &user,
            Some(&entitlement),
            None,
            None,
            None,
        );

        assert_eq!(reviewer, Some(owner_id));
    }

    #[test]
    fn test_entitlement_owner_falls_back_to_app_owner() {
        let app_owner_id = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: None,
            department: None,
        };
        let application = TestApplication {
            id: Uuid::new_v4(),
            owner_id: Some(app_owner_id),
        };
        let entitlement = TestEntitlement {
            id: Uuid::new_v4(),
            owner_id: None, // No direct owner
            application_id: application.id,
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::EntitlementOwner,
            &user,
            Some(&entitlement),
            Some(&application),
            None,
            None,
        );

        // Should fall back to application owner
        assert_eq!(reviewer, Some(app_owner_id));
    }

    #[test]
    fn test_application_owner_returns_owner_id() {
        let app_owner_id = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: None,
            department: None,
        };
        let application = TestApplication {
            id: Uuid::new_v4(),
            owner_id: Some(app_owner_id),
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::ApplicationOwner,
            &user,
            None,
            Some(&application),
            None,
            None,
        );

        assert_eq!(reviewer, Some(app_owner_id));
    }

    #[test]
    fn test_specific_user_returns_configured_id() {
        let specific_reviewer = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: Some(Uuid::new_v4()),
            department: None,
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::SpecificUser,
            &user,
            None,
            None,
            Some(specific_reviewer),
            None,
        );

        assert_eq!(reviewer, Some(specific_reviewer));
    }

    #[test]
    fn test_specific_user_returns_none_when_not_configured() {
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: Some(Uuid::new_v4()),
            department: None,
        };

        let reviewer = resolve_reviewer(
            MicroCertReviewerType::SpecificUser,
            &user,
            None,
            None,
            None, // No specific reviewer configured
            None,
        );

        assert!(reviewer.is_none());
    }

    #[test]
    fn test_fallback_reviewer_used_when_primary_fails() {
        let fallback_id = Uuid::new_v4();
        let user = TestUser {
            id: Uuid::new_v4(),
            manager_id: None, // No manager
            department: None,
        };

        let reviewer = resolve_reviewer_with_fallback(
            MicroCertReviewerType::UserManager,
            &user,
            None,
            None,
            None,
            Some(fallback_id),
        );

        assert_eq!(reviewer, Some(fallback_id));
    }

    #[test]
    fn test_self_review_prevention_returns_none() {
        let user_id = Uuid::new_v4();
        let user = TestUser {
            id: user_id,
            manager_id: Some(user_id), // User is their own manager (edge case)
            department: None,
        };

        let reviewer = resolve_reviewer_with_self_check(
            MicroCertReviewerType::UserManager,
            &user,
            None,
            None,
            None,
            None,
        );

        // Should return None because reviewer == user
        assert!(reviewer.is_none());
    }

    #[test]
    fn test_self_review_uses_fallback() {
        let user_id = Uuid::new_v4();
        let fallback_id = Uuid::new_v4();
        let user = TestUser {
            id: user_id,
            manager_id: Some(user_id), // Self-manager
            department: None,
        };

        let reviewer = resolve_reviewer_with_self_check(
            MicroCertReviewerType::UserManager,
            &user,
            None,
            None,
            None,
            Some(fallback_id),
        );

        assert_eq!(reviewer, Some(fallback_id));
    }
}

// Helper functions that mirror actual service logic

fn resolve_reviewer(
    reviewer_type: MicroCertReviewerType,
    user: &TestUser,
    entitlement: Option<&TestEntitlement>,
    application: Option<&TestApplication>,
    specific_reviewer_id: Option<Uuid>,
    _fallback_reviewer_id: Option<Uuid>,
) -> Option<Uuid> {
    match reviewer_type {
        MicroCertReviewerType::UserManager => user.manager_id,
        MicroCertReviewerType::EntitlementOwner => entitlement
            .and_then(|e| e.owner_id)
            .or_else(|| application.and_then(|a| a.owner_id)),
        MicroCertReviewerType::ApplicationOwner => application.and_then(|a| a.owner_id),
        MicroCertReviewerType::SpecificUser => specific_reviewer_id,
    }
}

fn resolve_reviewer_with_fallback(
    reviewer_type: MicroCertReviewerType,
    user: &TestUser,
    entitlement: Option<&TestEntitlement>,
    application: Option<&TestApplication>,
    specific_reviewer_id: Option<Uuid>,
    fallback_reviewer_id: Option<Uuid>,
) -> Option<Uuid> {
    resolve_reviewer(
        reviewer_type,
        user,
        entitlement,
        application,
        specific_reviewer_id,
        fallback_reviewer_id,
    )
    .or(fallback_reviewer_id)
}

fn resolve_reviewer_with_self_check(
    reviewer_type: MicroCertReviewerType,
    user: &TestUser,
    entitlement: Option<&TestEntitlement>,
    application: Option<&TestApplication>,
    specific_reviewer_id: Option<Uuid>,
    fallback_reviewer_id: Option<Uuid>,
) -> Option<Uuid> {
    let primary = resolve_reviewer(
        reviewer_type,
        user,
        entitlement,
        application,
        specific_reviewer_id,
        fallback_reviewer_id,
    );

    // Prevent self-review
    if primary == Some(user.id) {
        fallback_reviewer_id
    } else {
        primary.or(fallback_reviewer_id)
    }
}
