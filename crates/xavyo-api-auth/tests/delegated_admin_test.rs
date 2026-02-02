//! Tests for delegated administration service (F029).
//!
//! Unit tests for permission checking, scope validation, and API error handling.

use axum::http::StatusCode;
use chrono::Utc;
use std::collections::HashSet;
use uuid::Uuid;
use xavyo_api_auth::error::ApiAuthError;
use xavyo_api_auth::models::{
    AssignmentResponse, AuditLogEntryResponse, EffectivePermissions, PermissionResponse,
    RoleTemplateDetailResponse, RoleTemplateResponse, ScopeAssignment,
};

// ============================================================================
// Permission Checking Tests (T053 - US6)
// ============================================================================

mod permission_checking_tests {
    use super::*;

    #[test]
    fn test_direct_permission_match() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());
        permissions.insert("users:update".to_string());
        permissions.insert("groups:read".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Direct matches
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:update"));
        assert!(effective.has_permission("groups:read"));

        // Non-matching permissions
        assert!(!effective.has_permission("users:delete"));
        assert!(!effective.has_permission("users:create"));
        assert!(!effective.has_permission("groups:update"));
        assert!(!effective.has_permission("settings:read"));
    }

    #[test]
    fn test_wildcard_permission_match() {
        let mut permissions = HashSet::new();
        permissions.insert("users:*".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Wildcard should match any action in the category
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:create"));
        assert!(effective.has_permission("users:update"));
        assert!(effective.has_permission("users:delete"));
        assert!(effective.has_permission("users:manage"));

        // Should not match other categories
        assert!(!effective.has_permission("groups:read"));
        assert!(!effective.has_permission("settings:read"));
        assert!(!effective.has_permission("audit:read"));
    }

    #[test]
    fn test_multiple_wildcards() {
        let mut permissions = HashSet::new();
        permissions.insert("users:*".to_string());
        permissions.insert("groups:*".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Both wildcards should work
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:delete"));
        assert!(effective.has_permission("groups:read"));
        assert!(effective.has_permission("groups:manage"));

        // Other categories should not match
        assert!(!effective.has_permission("settings:read"));
        assert!(!effective.has_permission("security:manage"));
    }

    #[test]
    fn test_mixed_direct_and_wildcard() {
        let mut permissions = HashSet::new();
        permissions.insert("users:*".to_string());
        permissions.insert("groups:read".to_string());
        permissions.insert("audit:read".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Users should have full access via wildcard
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:create"));
        assert!(effective.has_permission("users:delete"));

        // Groups should only have read
        assert!(effective.has_permission("groups:read"));
        assert!(!effective.has_permission("groups:create"));
        assert!(!effective.has_permission("groups:delete"));

        // Audit should only have read
        assert!(effective.has_permission("audit:read"));
        assert!(!effective.has_permission("audit:write"));
    }

    #[test]
    fn test_empty_permissions() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![],
        };

        // No permissions should be granted
        assert!(!effective.has_permission("users:read"));
        assert!(!effective.has_permission("users:*"));
        assert!(!effective.has_permission("anything"));
    }

    #[test]
    fn test_permission_code_case_sensitivity() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Exact match
        assert!(effective.has_permission("users:read"));

        // Different case should not match
        assert!(!effective.has_permission("Users:read"));
        assert!(!effective.has_permission("USERS:READ"));
        assert!(!effective.has_permission("users:READ"));
    }

    #[test]
    fn test_permission_code_with_special_chars() {
        let mut permissions = HashSet::new();
        permissions.insert("api:read-only".to_string());
        permissions.insert("branding:update_logo".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        assert!(effective.has_permission("api:read-only"));
        assert!(effective.has_permission("branding:update_logo"));
        assert!(!effective.has_permission("api:read_only")); // Different separator
    }
}

// ============================================================================
// Scope Checking Tests (T054 - US6)
// ============================================================================

mod scope_checking_tests {
    use super::*;

    #[test]
    fn test_global_scope_when_no_scopes_defined() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![],
        };

        // No scopes means global access
        assert!(effective.is_in_scope("group", "any-group"));
        assert!(effective.is_in_scope("department", "any-department"));
        assert!(effective.is_in_scope("tenant", "any-tenant"));
        assert!(effective.is_in_scope("custom", "anything"));
    }

    #[test]
    fn test_single_scope_single_value() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec!["sales".to_string()],
            }],
        };

        assert!(effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("group", "marketing"));
        assert!(!effective.is_in_scope("group", "engineering"));
        assert!(!effective.is_in_scope("department", "sales")); // Different scope type
    }

    #[test]
    fn test_single_scope_multiple_values() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec![
                    "sales".to_string(),
                    "marketing".to_string(),
                    "support".to_string(),
                ],
            }],
        };

        assert!(effective.is_in_scope("group", "sales"));
        assert!(effective.is_in_scope("group", "marketing"));
        assert!(effective.is_in_scope("group", "support"));
        assert!(!effective.is_in_scope("group", "engineering"));
        assert!(!effective.is_in_scope("group", "hr"));
    }

    #[test]
    fn test_multiple_scopes() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![
                ScopeAssignment {
                    scope_type: "group".to_string(),
                    scope_value: vec!["sales".to_string()],
                },
                ScopeAssignment {
                    scope_type: "department".to_string(),
                    scope_value: vec!["north".to_string(), "south".to_string()],
                },
            ],
        };

        // Group scope
        assert!(effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("group", "marketing"));

        // Department scope
        assert!(effective.is_in_scope("department", "north"));
        assert!(effective.is_in_scope("department", "south"));
        assert!(!effective.is_in_scope("department", "east"));

        // Unknown scope type
        assert!(!effective.is_in_scope("region", "north"));
    }

    #[test]
    fn test_scope_type_case_sensitivity() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec!["sales".to_string()],
            }],
        };

        assert!(effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("Group", "sales"));
        assert!(!effective.is_in_scope("GROUP", "sales"));
    }

    #[test]
    fn test_scope_value_case_sensitivity() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec!["Sales".to_string()],
            }],
        };

        assert!(effective.is_in_scope("group", "Sales"));
        assert!(!effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("group", "SALES"));
    }

    #[test]
    fn test_uuid_scope_values() {
        let group_id = Uuid::new_v4().to_string();
        let other_id = Uuid::new_v4().to_string();

        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec![group_id.clone()],
            }],
        };

        assert!(effective.is_in_scope("group", &group_id));
        assert!(!effective.is_in_scope("group", &other_id));
    }

    #[test]
    fn test_empty_scope_value() {
        let effective = EffectivePermissions {
            permissions: HashSet::new(),
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec![],
            }],
        };

        // Empty scope_value means no access within that scope type
        assert!(!effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("group", ""));
    }
}

// ============================================================================
// Assignment Response Tests (T025 - US1)
// ============================================================================

mod assignment_tests {
    use super::*;

    #[test]
    fn test_assignment_response_creation() {
        let now = Utc::now();
        let response = AssignmentResponse {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            user_email: Some("user@example.com".to_string()),
            user_name: Some("Test User".to_string()),
            template_id: Uuid::new_v4(),
            template_name: Some("User Admin".to_string()),
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_by_name: Some("Admin User".to_string()),
            assigned_at: now,
            expires_at: None,
            revoked_at: None,
        };

        assert!(response.user_email.is_some());
        assert!(response.template_name.is_some());
        assert!(response.scope_type.is_none());
        assert!(response.revoked_at.is_none());
    }

    #[test]
    fn test_assignment_with_scope() {
        let now = Utc::now();
        let response = AssignmentResponse {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            user_email: None,
            user_name: None,
            template_id: Uuid::new_v4(),
            template_name: None,
            scope_type: Some("group".to_string()),
            scope_value: Some(vec!["sales".to_string(), "marketing".to_string()]),
            assigned_by: Uuid::new_v4(),
            assigned_by_name: None,
            assigned_at: now,
            expires_at: None,
            revoked_at: None,
        };

        assert_eq!(response.scope_type, Some("group".to_string()));
        assert_eq!(response.scope_value.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_assignment_with_expiration() {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);

        let response = AssignmentResponse {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            user_email: None,
            user_name: None,
            template_id: Uuid::new_v4(),
            template_name: None,
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_by_name: None,
            assigned_at: now,
            expires_at: Some(expires),
            revoked_at: None,
        };

        assert!(response.expires_at.is_some());
        assert!(response.expires_at.unwrap() > now);
    }

    #[test]
    fn test_revoked_assignment() {
        let now = Utc::now();
        let revoked = now - chrono::Duration::hours(1);

        let response = AssignmentResponse {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            user_email: None,
            user_name: None,
            template_id: Uuid::new_v4(),
            template_name: None,
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_by_name: None,
            assigned_at: now - chrono::Duration::days(7),
            expires_at: None,
            revoked_at: Some(revoked),
        };

        assert!(response.revoked_at.is_some());
    }
}

// ============================================================================
// Role Template Tests (T037 - US2)
// ============================================================================

mod template_tests {
    use super::*;

    #[test]
    fn test_role_template_response_creation() {
        let now = Utc::now();
        let response = RoleTemplateResponse {
            id: Uuid::new_v4(),
            name: "User Admin".to_string(),
            description: Some("Full user management permissions".to_string()),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(response.name, "User Admin");
        assert!(response.description.is_some());
        assert!(!response.is_system);
    }

    #[test]
    fn test_system_template() {
        let now = Utc::now();
        let response = RoleTemplateResponse {
            id: Uuid::new_v4(),
            name: "Super Admin".to_string(),
            description: Some("System-defined template with all permissions".to_string()),
            is_system: true,
            created_at: now,
            updated_at: now,
        };

        assert!(response.is_system);
    }

    #[test]
    fn test_template_detail_with_permissions() {
        let now = Utc::now();
        let permissions = vec![
            PermissionResponse {
                id: Uuid::new_v4(),
                code: "users:read".to_string(),
                name: "Read Users".to_string(),
                description: Some("View user list and details".to_string()),
                category: "users".to_string(),
            },
            PermissionResponse {
                id: Uuid::new_v4(),
                code: "users:update".to_string(),
                name: "Update Users".to_string(),
                description: Some("Modify user information".to_string()),
                category: "users".to_string(),
            },
        ];

        let detail = RoleTemplateDetailResponse {
            id: Uuid::new_v4(),
            name: "User Admin".to_string(),
            description: None,
            is_system: false,
            created_at: now,
            updated_at: now,
            permissions,
        };

        assert_eq!(detail.permissions.len(), 2);
        assert_eq!(detail.permissions[0].code, "users:read");
        assert_eq!(detail.permissions[1].category, "users");
    }

    #[test]
    fn test_permission_response_structure() {
        let permission = PermissionResponse {
            id: Uuid::new_v4(),
            code: "audit:read".to_string(),
            name: "Read Audit Log".to_string(),
            description: None,
            category: "audit".to_string(),
        };

        assert_eq!(permission.code, "audit:read");
        assert_eq!(permission.category, "audit");
        assert!(permission.description.is_none());
    }
}

// ============================================================================
// Audit Log Tests (T045 - US4)
// ============================================================================

mod audit_log_tests {
    use super::*;

    #[test]
    fn test_audit_log_entry_response() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: Some("admin@example.com".to_string()),
            admin_user_name: Some("Admin User".to_string()),
            action: "create".to_string(),
            resource_type: "template".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: None,
            new_value: Some(serde_json::json!({
                "name": "New Template",
                "permissions": ["users:read"]
            })),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            created_at: now,
        };

        assert_eq!(entry.action, "create");
        assert_eq!(entry.resource_type, "template");
        assert!(entry.old_value.is_none());
        assert!(entry.new_value.is_some());
    }

    #[test]
    fn test_audit_log_update_action() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: None,
            admin_user_name: None,
            action: "update".to_string(),
            resource_type: "template".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: Some(serde_json::json!({
                "name": "Old Name",
                "description": null
            })),
            new_value: Some(serde_json::json!({
                "name": "New Name",
                "description": "Updated description"
            })),
            ip_address: None,
            user_agent: None,
            created_at: now,
        };

        assert_eq!(entry.action, "update");
        assert!(entry.old_value.is_some());
        assert!(entry.new_value.is_some());

        let old = entry.old_value.as_ref().unwrap();
        let new = entry.new_value.as_ref().unwrap();
        assert_eq!(old["name"], "Old Name");
        assert_eq!(new["name"], "New Name");
    }

    #[test]
    fn test_audit_log_delete_action() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: None,
            admin_user_name: None,
            action: "delete".to_string(),
            resource_type: "assignment".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: Some(serde_json::json!({
                "user_id": "user-123",
                "template_id": "template-456"
            })),
            new_value: None,
            ip_address: None,
            user_agent: None,
            created_at: now,
        };

        assert_eq!(entry.action, "delete");
        assert!(entry.old_value.is_some());
        assert!(entry.new_value.is_none());
    }

    #[test]
    fn test_audit_log_assign_action() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: None,
            admin_user_name: None,
            action: "assign".to_string(),
            resource_type: "assignment".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: None,
            new_value: Some(serde_json::json!({
                "user_id": "user-123",
                "template_name": "User Admin",
                "scope_type": "group",
                "scope_value": ["sales"]
            })),
            ip_address: Some("10.0.0.1".to_string()),
            user_agent: None,
            created_at: now,
        };

        assert_eq!(entry.action, "assign");

        let new = entry.new_value.as_ref().unwrap();
        assert_eq!(new["scope_type"], "group");
    }

    #[test]
    fn test_audit_log_revoke_action() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: None,
            admin_user_name: None,
            action: "revoke".to_string(),
            resource_type: "assignment".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: Some(serde_json::json!({
                "user_id": "user-123",
                "template_id": "template-456"
            })),
            new_value: None,
            ip_address: None,
            user_agent: None,
            created_at: now,
        };

        assert_eq!(entry.action, "revoke");
    }
}

// ============================================================================
// API Error Tests (T053, T054 - US6)
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_permission_denied_error() {
        let error = ApiAuthError::PermissionDenied("users:delete".to_string());
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("permission-denied"));
        assert_eq!(problem.status, 403);
    }

    #[test]
    fn test_template_name_exists_error() {
        let error = ApiAuthError::TemplateNameExists;
        assert_eq!(error.status_code(), StatusCode::CONFLICT);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("template-name-exists"));
        assert_eq!(problem.status, 409);
    }

    #[test]
    fn test_template_not_found_error() {
        let error = ApiAuthError::TemplateNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("template-not-found"));
        assert_eq!(problem.status, 404);
    }

    #[test]
    fn test_assignment_not_found_error() {
        let error = ApiAuthError::AssignmentNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("assignment-not-found"));
        assert_eq!(problem.status, 404);
    }

    #[test]
    fn test_cannot_delete_system_template_error() {
        let error = ApiAuthError::CannotDeleteSystemTemplate;
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("cannot-delete-system-template"));
        assert_eq!(problem.status, 403);
    }

    #[test]
    fn test_scope_violation_error() {
        let error = ApiAuthError::ScopeViolation("User not in allowed scope".to_string());
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("scope-violation"));
        assert_eq!(problem.status, 403);
    }

    #[test]
    fn test_invalid_permission_error() {
        let error = ApiAuthError::InvalidPermission("users:nonexistent".to_string());
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("invalid-permission"));
        assert_eq!(problem.status, 400);
    }
}

// ============================================================================
// Super Admin Check Tests
// ============================================================================

mod super_admin_tests {
    use uuid::Uuid;
    use xavyo_api_auth::middleware::is_super_admin;
    use xavyo_auth::JwtClaims;
    use xavyo_core::TenantId;

    #[test]
    fn test_is_super_admin_with_role() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["super_admin"])
            .build();

        assert!(is_super_admin(&claims));
    }

    #[test]
    fn test_is_not_super_admin_with_user_role() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["user", "admin"])
            .build();

        assert!(!is_super_admin(&claims));
    }

    #[test]
    fn test_is_not_super_admin_with_empty_roles() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .build();

        assert!(!is_super_admin(&claims));
    }

    #[test]
    fn test_is_super_admin_with_multiple_roles() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["user", "admin", "super_admin"])
            .build();

        assert!(is_super_admin(&claims));
    }
}

// ============================================================================
// Effective Permissions Serialization Tests
// ============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_effective_permissions_default() {
        let effective = EffectivePermissions::default();

        assert!(effective.permissions.is_empty());
        assert!(effective.scopes.is_empty());
    }

    #[test]
    fn test_effective_permissions_serialization() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());
        permissions.insert("users:update".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![ScopeAssignment {
                scope_type: "group".to_string(),
                scope_value: vec!["sales".to_string()],
            }],
        };

        // Should be serializable
        let json = serde_json::to_string(&effective).expect("Should serialize");
        assert!(json.contains("users:read"));
        assert!(json.contains("sales"));
    }

    #[test]
    fn test_effective_permissions_deserialization() {
        let json = r#"{
            "permissions": ["users:read", "users:update"],
            "scopes": [{"scope_type": "group", "scope_value": ["sales"]}]
        }"#;

        let effective: EffectivePermissions =
            serde_json::from_str(json).expect("Should deserialize");

        assert_eq!(effective.permissions.len(), 2);
        assert!(effective.permissions.contains("users:read"));
        assert_eq!(effective.scopes.len(), 1);
        assert_eq!(effective.scopes[0].scope_type, "group");
    }

    #[test]
    fn test_scope_assignment_serialization() {
        let scope = ScopeAssignment {
            scope_type: "department".to_string(),
            scope_value: vec!["north".to_string(), "south".to_string()],
        };

        let json = serde_json::to_string(&scope).expect("Should serialize");
        let deserialized: ScopeAssignment =
            serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.scope_type, "department");
        assert_eq!(deserialized.scope_value.len(), 2);
    }
}
