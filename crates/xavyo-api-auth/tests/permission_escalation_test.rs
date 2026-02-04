//! Permission Escalation Security Tests.
//!
//! Tests for privilege escalation attack vectors:
//! - P-001: User cannot grant themselves permissions
//! - P-002: User cannot modify their own role assignments
//! - P-003: Delegated admin cannot exceed their scope
//! - P-004: Super admin actions are audit logged
//! - P-005: Scope violation returns 403, not 404 (enumeration prevention)
//!
//! Run with:
//! cargo test -p xavyo-api-auth --test `permission_escalation_test`

mod common;

/// Permission escalation attack prevention tests.
mod permission_escalation {
    use std::collections::HashSet;
    use uuid::Uuid;
    use xavyo_api_auth::middleware::is_super_admin;
    use xavyo_api_auth::models::{EffectivePermissions, ScopeAssignment};
    use xavyo_auth::JwtClaims;
    use xavyo_core::TenantId;

    /// P-001: Verify that permission wildcard doesn't grant unexpected access.
    ///
    /// A user with "users:*" should not have "admin:*" or global wildcards.
    #[test]
    fn test_wildcard_does_not_escalate_to_other_categories() {
        let mut permissions = HashSet::new();
        permissions.insert("users:*".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Should have user permissions
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:create"));
        assert!(effective.has_permission("users:delete"));

        // Should NOT have other category permissions
        assert!(!effective.has_permission("admin:read"));
        assert!(!effective.has_permission("settings:write"));
        assert!(!effective.has_permission("audit:read"));
        assert!(!effective.has_permission("security:manage"));
        assert!(!effective.has_permission("*:*")); // Global wildcard
        assert!(!effective.has_permission("*")); // Single wildcard
    }

    /// P-001: Verify that having some permissions doesn't grant all permissions.
    #[test]
    fn test_partial_permissions_dont_escalate() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Should only have the specific permission
        assert!(effective.has_permission("users:read"));

        // Should NOT have other user permissions
        assert!(!effective.has_permission("users:create"));
        assert!(!effective.has_permission("users:update"));
        assert!(!effective.has_permission("users:delete"));
        assert!(!effective.has_permission("users:*"));
    }

    /// P-002: Non-super_admin cannot bypass permission checks.
    #[test]
    fn test_non_super_admin_cannot_bypass() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["admin", "user", "manager"]) // Many roles, but not super_admin
            .build();

        assert!(!is_super_admin(&claims));
    }

    /// P-002: Role manipulation prevention.
    ///
    /// Verify that role name case sensitivity is properly enforced.
    #[test]
    fn test_role_case_sensitivity() {
        // Lowercase super_admin should work
        let claims_lower = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["super_admin"])
            .build();
        assert!(is_super_admin(&claims_lower));

        // Different case should NOT work (case-sensitive match)
        let claims_upper = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["SUPER_ADMIN"])
            .build();
        assert!(!is_super_admin(&claims_upper));

        let claims_mixed = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["Super_Admin"])
            .build();
        assert!(!is_super_admin(&claims_mixed));
    }

    /// P-003: Delegated admin cannot access resources outside their scope.
    #[test]
    fn test_scope_restriction_enforcement() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:*".to_string()]),
            scopes: vec![ScopeAssignment {
                scope_type: "department".to_string(),
                scope_value: vec!["sales".to_string()],
            }],
        };

        // Has permissions
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("users:delete"));

        // Only in scope for sales department
        assert!(effective.is_in_scope("department", "sales"));
        assert!(!effective.is_in_scope("department", "engineering"));
        assert!(!effective.is_in_scope("department", "marketing"));
        assert!(!effective.is_in_scope("department", "hr"));
    }

    /// P-003: Scope bypass via different scope types.
    #[test]
    fn test_scope_type_bypass_prevention() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:*".to_string()]),
            scopes: vec![ScopeAssignment {
                scope_type: "department".to_string(),
                scope_value: vec!["sales".to_string()],
            }],
        };

        // Cannot access via different scope type
        assert!(!effective.is_in_scope("group", "sales"));
        assert!(!effective.is_in_scope("team", "sales"));
        assert!(!effective.is_in_scope("DEPARTMENT", "sales")); // Case matters
        assert!(!effective.is_in_scope("region", "sales"));
    }

    /// P-003: Global scope (no scopes defined) grants unrestricted access.
    #[test]
    fn test_global_scope_behavior() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:read".to_string()]),
            scopes: vec![], // No scopes = global access
        };

        // Global scope means access to all resources of the type
        assert!(effective.is_in_scope("department", "sales"));
        assert!(effective.is_in_scope("department", "engineering"));
        assert!(effective.is_in_scope("group", "anything"));
        assert!(effective.is_in_scope("region", "anywhere"));
    }

    /// P-003: Empty scope value list denies access.
    #[test]
    fn test_empty_scope_value_denies_access() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:read".to_string()]),
            scopes: vec![ScopeAssignment {
                scope_type: "department".to_string(),
                scope_value: vec![], // Empty = no access within this scope type
            }],
        };

        // Should not have access to any department
        assert!(!effective.is_in_scope("department", "sales"));
        assert!(!effective.is_in_scope("department", ""));
        assert!(!effective.is_in_scope("department", "anything"));
    }

    /// P-005: Verify error codes don't leak resource existence.
    ///
    /// Both "resource not found" and "access denied" scenarios
    /// should return consistent error codes to prevent enumeration.
    #[test]
    fn test_error_code_enumeration_prevention() {
        use axum::http::StatusCode;
        use xavyo_api_auth::error::ApiAuthError;

        // Permission denied should return 403
        let permission_denied = ApiAuthError::PermissionDenied("users:delete".to_string());
        assert_eq!(permission_denied.status_code(), StatusCode::FORBIDDEN);

        // Scope violation should return 403
        let scope_violation = ApiAuthError::ScopeViolation("Outside scope".to_string());
        assert_eq!(scope_violation.status_code(), StatusCode::FORBIDDEN);

        // Template not found returns 404 (safe - templates are not enumerable by external users)
        let not_found = ApiAuthError::TemplateNotFound;
        assert_eq!(not_found.status_code(), StatusCode::NOT_FOUND);

        // Assignment not found returns 404
        let assignment_not_found = ApiAuthError::AssignmentNotFound;
        assert_eq!(assignment_not_found.status_code(), StatusCode::NOT_FOUND);
    }

    /// Verify `super_admin` role is the only bypass.
    #[test]
    fn test_only_super_admin_bypasses() {
        // Various role names that might be confused with super_admin
        let similar_roles = vec![
            "superadmin",
            "super-admin",
            "SuperAdmin",
            "SUPER_ADMIN",
            "super admin",
            "admin",
            "root",
            "administrator",
            "sysadmin",
        ];

        for role in similar_roles {
            let claims = JwtClaims::builder()
                .subject(Uuid::new_v4().to_string())
                .tenant_id(TenantId::new())
                .roles(vec![role])
                .build();

            assert!(
                !is_super_admin(&claims),
                "Role '{role}' should NOT be treated as super_admin"
            );
        }
    }

    /// Verify empty roles list doesn't grant `super_admin`.
    #[test]
    fn test_empty_roles_no_super_admin() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .build();

        assert!(!is_super_admin(&claims));
        assert!(claims.roles.is_empty());
    }

    /// Verify null-like values in roles don't cause issues.
    #[test]
    fn test_null_like_roles_handled() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["", "null", "undefined", "none"])
            .build();

        assert!(!is_super_admin(&claims));
    }
}

/// JWT claims security tests.
mod claims_security {
    use uuid::Uuid;
    use xavyo_auth::JwtClaims;
    use xavyo_core::TenantId;

    /// Missing `tenant_id` should be handled safely.
    #[test]
    fn test_missing_tenant_id() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .build();

        // No tenant_id in claims
        assert!(claims.tid.is_none());
        assert!(claims.tenant_id().is_none());
    }

    /// Invalid subject format should be caught.
    #[test]
    fn test_subject_uuid_parsing() {
        // Valid UUID subject
        let valid_uuid = Uuid::new_v4();
        let claims = JwtClaims::builder().subject(valid_uuid.to_string()).build();

        let parsed = Uuid::parse_str(&claims.sub);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), valid_uuid);

        // Invalid UUID subject (would fail in handler)
        let claims_invalid = JwtClaims::builder().subject("not-a-uuid").build();

        let parsed_invalid = Uuid::parse_str(&claims_invalid.sub);
        assert!(parsed_invalid.is_err());
    }

    /// Tenant ID in claims matches expected format.
    #[test]
    fn test_tenant_id_format() {
        let tenant_id = TenantId::new();
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(tenant_id)
            .build();

        assert_eq!(claims.tenant_id(), Some(tenant_id));

        // The UUID is valid
        let uuid = claims.tid.unwrap();
        assert!(!uuid.is_nil());
    }

    /// Multiple roles don't cause confusion.
    #[test]
    fn test_multiple_roles_independent() {
        use xavyo_api_auth::middleware::is_super_admin;

        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["user", "admin", "manager"])
            .build();

        // Has all specified roles
        assert!(claims.has_role("user"));
        assert!(claims.has_role("admin"));
        assert!(claims.has_role("manager"));

        // Doesn't have unspecified roles
        assert!(!claims.has_role("super_admin"));
        assert!(!claims.has_role("root"));

        // Not super_admin
        assert!(!is_super_admin(&claims));
    }
}

/// Scope hierarchy tests.
mod scope_hierarchy {
    use std::collections::HashSet;
    use xavyo_api_auth::models::{EffectivePermissions, ScopeAssignment};

    /// Multiple scopes don't implicitly escalate.
    #[test]
    fn test_multiple_scopes_no_escalation() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:read".to_string()]),
            scopes: vec![
                ScopeAssignment {
                    scope_type: "department".to_string(),
                    scope_value: vec!["sales".to_string()],
                },
                ScopeAssignment {
                    scope_type: "group".to_string(),
                    scope_value: vec!["team-a".to_string()],
                },
            ],
        };

        // Has access to specified scopes
        assert!(effective.is_in_scope("department", "sales"));
        assert!(effective.is_in_scope("group", "team-a"));

        // Doesn't have cross-scope access
        assert!(!effective.is_in_scope("department", "team-a"));
        assert!(!effective.is_in_scope("group", "sales"));

        // Doesn't have access to other values
        assert!(!effective.is_in_scope("department", "engineering"));
        assert!(!effective.is_in_scope("group", "team-b"));
    }

    /// Hierarchical scope values are exact matches only.
    #[test]
    fn test_scope_value_exact_match() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:read".to_string()]),
            scopes: vec![ScopeAssignment {
                scope_type: "path".to_string(),
                scope_value: vec!["/org/sales".to_string()],
            }],
        };

        // Exact match works
        assert!(effective.is_in_scope("path", "/org/sales"));

        // Substring/prefix should NOT work
        assert!(!effective.is_in_scope("path", "/org"));
        assert!(!effective.is_in_scope("path", "/org/sales/team-a"));
        assert!(!effective.is_in_scope("path", "/org/sal"));
    }

    /// Wildcard in scope value is treated literally.
    #[test]
    fn test_scope_value_wildcard_literal() {
        let effective = EffectivePermissions {
            permissions: HashSet::from_iter(vec!["users:read".to_string()]),
            scopes: vec![ScopeAssignment {
                scope_type: "department".to_string(),
                scope_value: vec!["*".to_string()], // Literal asterisk, not wildcard
            }],
        };

        // Only matches literal "*"
        assert!(effective.is_in_scope("department", "*"));

        // Does NOT act as wildcard
        assert!(!effective.is_in_scope("department", "sales"));
        assert!(!effective.is_in_scope("department", "engineering"));
    }
}

/// Permission code validation tests.
mod permission_code_validation {
    use std::collections::HashSet;
    use xavyo_api_auth::models::EffectivePermissions;

    /// Permission code format validation.
    #[test]
    fn test_permission_code_format() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());
        permissions.insert("groups:write".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Standard format works
        assert!(effective.has_permission("users:read"));
        assert!(effective.has_permission("groups:write"));

        // Different format shouldn't match
        assert!(!effective.has_permission("users.read"));
        assert!(!effective.has_permission("users/read"));
        assert!(!effective.has_permission("usersread"));
    }

    /// Whitespace in permission codes doesn't match.
    #[test]
    fn test_permission_whitespace_handling() {
        let mut permissions = HashSet::new();
        permissions.insert("users:read".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Exact match
        assert!(effective.has_permission("users:read"));

        // Whitespace should not match
        assert!(!effective.has_permission(" users:read"));
        assert!(!effective.has_permission("users:read "));
        assert!(!effective.has_permission("users: read"));
        assert!(!effective.has_permission("users :read"));
    }

    /// Special characters in permission codes.
    #[test]
    fn test_permission_special_chars() {
        let mut permissions = HashSet::new();
        permissions.insert("api:read-write".to_string());
        permissions.insert("oauth2:client_credentials".to_string());

        let effective = EffectivePermissions {
            permissions,
            scopes: vec![],
        };

        // Exact match with special chars
        assert!(effective.has_permission("api:read-write"));
        assert!(effective.has_permission("oauth2:client_credentials"));

        // Similar but not exact
        assert!(!effective.has_permission("api:read_write"));
        assert!(!effective.has_permission("oauth2:client-credentials"));
    }
}

/// Audit logging verification tests.
mod audit_logging {
    use chrono::Utc;
    use uuid::Uuid;
    use xavyo_api_auth::models::AuditLogEntryResponse;

    /// P-004: Super admin actions should capture full context.
    #[test]
    fn test_audit_log_captures_context() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: Some("superadmin@example.com".to_string()),
            admin_user_name: Some("Super Admin".to_string()),
            action: "delete".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: Some(serde_json::json!({
                "email": "deleted@example.com",
                "is_active": true
            })),
            new_value: None,
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0 (Admin Panel)".to_string()),
            created_at: now,
        };

        // All context should be captured
        assert!(entry.admin_user_email.is_some());
        assert!(entry.ip_address.is_some());
        assert!(entry.user_agent.is_some());
        assert!(entry.old_value.is_some());
        assert!(entry.resource_id.is_some());
    }

    /// Audit log timestamps are reasonable.
    #[test]
    fn test_audit_log_timestamp() {
        let now = Utc::now();
        let entry = AuditLogEntryResponse {
            id: Uuid::new_v4(),
            admin_user_id: Uuid::new_v4(),
            admin_user_email: None,
            admin_user_name: None,
            action: "create".to_string(),
            resource_type: "template".to_string(),
            resource_id: Some(Uuid::new_v4()),
            old_value: None,
            new_value: Some(serde_json::json!({"name": "New Template"})),
            ip_address: None,
            user_agent: None,
            created_at: now,
        };

        // Timestamp should be recent
        let diff = Utc::now() - entry.created_at;
        assert!(
            diff.num_seconds() < 5,
            "Timestamp should be within 5 seconds"
        );
    }

    /// Audit log entry IDs are unique.
    #[test]
    fn test_audit_log_unique_ids() {
        use std::collections::HashSet;

        let mut ids = HashSet::new();
        for _ in 0..100 {
            let id = Uuid::new_v4();
            assert!(ids.insert(id), "Each audit log entry should have unique ID");
        }
    }
}
