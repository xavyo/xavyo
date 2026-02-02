//! Unit tests for self-service profile operations (F027).

mod common;

// ============================================================================
// Profile Request/Response Tests
// ============================================================================

mod profile_request_tests {
    use chrono::Utc;
    use uuid::Uuid;
    use validator::Validate;

    // ProfileResponse tests
    #[test]
    fn test_profile_response_serialization() {
        use xavyo_api_auth::models::ProfileResponse;

        let response = ProfileResponse {
            id: Uuid::new_v4(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            email_verified: true,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"email\":\"user@example.com\""));
        assert!(json.contains("\"display_name\":\"Test User\""));
        assert!(json.contains("\"email_verified\":true"));
    }

    #[test]
    fn test_profile_response_with_nulls() {
        use xavyo_api_auth::models::ProfileResponse;

        let response = ProfileResponse {
            id: Uuid::new_v4(),
            email: "user@example.com".to_string(),
            display_name: None,
            first_name: None,
            last_name: None,
            avatar_url: None,
            email_verified: false,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"display_name\":null"));
        assert!(json.contains("\"avatar_url\":null"));
    }

    // UpdateProfileRequest tests
    #[test]
    fn test_update_profile_request_validation_valid() {
        use xavyo_api_auth::models::UpdateProfileRequest;

        let request = UpdateProfileRequest {
            display_name: Some("New Name".to_string()),
            first_name: Some("New".to_string()),
            last_name: Some("Name".to_string()),
            avatar_url: Some("https://example.com/new-avatar.png".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_profile_request_empty_display_name_fails() {
        use xavyo_api_auth::models::UpdateProfileRequest;

        let request = UpdateProfileRequest {
            display_name: Some("".to_string()),
            first_name: None,
            last_name: None,
            avatar_url: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_update_profile_request_invalid_avatar_url_fails() {
        use xavyo_api_auth::models::UpdateProfileRequest;

        let request = UpdateProfileRequest {
            display_name: None,
            first_name: None,
            last_name: None,
            avatar_url: Some("not-a-valid-url".to_string()),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_update_profile_request_all_none_valid() {
        use xavyo_api_auth::models::UpdateProfileRequest;

        let request = UpdateProfileRequest {
            display_name: None,
            first_name: None,
            last_name: None,
            avatar_url: None,
        };

        // All None fields should be valid (no-op update)
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_update_profile_request_display_name_too_long_fails() {
        use xavyo_api_auth::models::UpdateProfileRequest;

        let request = UpdateProfileRequest {
            display_name: Some("a".repeat(101)),
            first_name: None,
            last_name: None,
            avatar_url: None,
        };

        assert!(request.validate().is_err());
    }
}

// ============================================================================
// Email Change Request/Response Tests
// ============================================================================

mod email_change_tests {
    use chrono::{Duration, Utc};
    use validator::Validate;

    #[test]
    fn test_email_change_request_validation_valid() {
        use xavyo_api_auth::models::EmailChangeRequest;

        let request = EmailChangeRequest {
            new_email: "newemail@example.com".to_string(),
            current_password: "password123".to_string(),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_email_change_request_invalid_email_fails() {
        use xavyo_api_auth::models::EmailChangeRequest;

        let request = EmailChangeRequest {
            new_email: "not-an-email".to_string(),
            current_password: "password123".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_email_change_request_email_too_long_fails() {
        use xavyo_api_auth::models::EmailChangeRequest;

        let long_email = format!("{}@example.com", "a".repeat(250));
        let request = EmailChangeRequest {
            new_email: long_email,
            current_password: "password123".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_email_change_initiated_response_serialization() {
        use xavyo_api_auth::models::EmailChangeInitiatedResponse;

        let response = EmailChangeInitiatedResponse {
            message: "Verification email sent".to_string(),
            expires_at: Utc::now() + Duration::hours(24),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"message\":\"Verification email sent\""));
        assert!(json.contains("\"expires_at\":"));
    }

    #[test]
    fn test_email_verify_change_request_validation_valid() {
        use xavyo_api_auth::models::EmailVerifyChangeRequest;

        let request = EmailVerifyChangeRequest {
            token: "a".repeat(43),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_email_verify_change_request_token_too_short_fails() {
        use xavyo_api_auth::models::EmailVerifyChangeRequest;

        let request = EmailVerifyChangeRequest {
            token: "short".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_email_change_completed_response_serialization() {
        use xavyo_api_auth::models::EmailChangeCompletedResponse;

        let response = EmailChangeCompletedResponse {
            message: "Email changed successfully".to_string(),
            new_email: "newemail@example.com".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"message\":\"Email changed successfully\""));
        assert!(json.contains("\"new_email\":\"newemail@example.com\""));
    }
}

// ============================================================================
// Security Overview Tests
// ============================================================================

mod security_overview_tests {
    use chrono::Utc;

    #[test]
    fn test_security_overview_response_serialization() {
        use xavyo_api_auth::models::SecurityOverviewResponse;

        let response = SecurityOverviewResponse {
            mfa_enabled: true,
            mfa_methods: vec!["totp".to_string()],
            trusted_devices_count: 3,
            active_sessions_count: 2,
            last_password_change: Some(Utc::now()),
            recent_security_alerts_count: 1,
            password_expires_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"mfa_enabled\":true"));
        assert!(json.contains("\"mfa_methods\":[\"totp\"]"));
        assert!(json.contains("\"trusted_devices_count\":3"));
        assert!(json.contains("\"active_sessions_count\":2"));
        assert!(json.contains("\"recent_security_alerts_count\":1"));
    }

    #[test]
    fn test_security_overview_response_mfa_disabled() {
        use xavyo_api_auth::models::SecurityOverviewResponse;

        let response = SecurityOverviewResponse {
            mfa_enabled: false,
            mfa_methods: vec![],
            trusted_devices_count: 0,
            active_sessions_count: 1,
            last_password_change: None,
            recent_security_alerts_count: 0,
            password_expires_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"mfa_enabled\":false"));
        assert!(json.contains("\"mfa_methods\":[]"));
    }
}

// ============================================================================
// MFA Status Tests
// ============================================================================

mod mfa_status_tests {
    use chrono::Utc;
    use xavyo_api_auth::models::mfa_responses::{MfaMethod, MfaStatusResponse};

    #[test]
    fn test_mfa_status_response_totp_enabled() {
        let response = MfaStatusResponse {
            totp_enabled: true,
            webauthn_enabled: false,
            recovery_codes_remaining: 8,
            available_methods: vec![MfaMethod::Totp, MfaMethod::Recovery],
            setup_at: Some(Utc::now()),
            last_used_at: Some(Utc::now()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"totp_enabled\":true"));
        assert!(json.contains("\"webauthn_enabled\":false"));
        assert!(json.contains("\"recovery_codes_remaining\":8"));
    }

    #[test]
    fn test_mfa_status_response_totp_disabled() {
        let response = MfaStatusResponse {
            totp_enabled: false,
            webauthn_enabled: false,
            recovery_codes_remaining: 0,
            available_methods: vec![],
            setup_at: None,
            last_used_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"totp_enabled\":false"));
        assert!(json.contains("\"recovery_codes_remaining\":0"));
        // Optional fields should be omitted when None
        assert!(!json.contains("\"setup_at\""));
    }
}

// ============================================================================
// Password Change Tests
// ============================================================================

mod password_change_tests {
    use validator::Validate;

    #[test]
    fn test_password_change_request_validation_valid() {
        use xavyo_api_auth::models::PasswordChangeRequest;

        let request = PasswordChangeRequest {
            current_password: "oldpassword123".to_string(),
            new_password: "NewPassword123!".to_string(),
            revoke_other_sessions: true,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_password_change_request_new_password_too_short_fails() {
        use xavyo_api_auth::models::PasswordChangeRequest;

        let request = PasswordChangeRequest {
            current_password: "oldpassword123".to_string(),
            new_password: "short".to_string(),
            revoke_other_sessions: false,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_password_change_request_revoke_sessions_defaults_to_true() {
        // When deserialized from JSON without the field, it defaults to true
        let json = r#"{"current_password":"old","new_password":"newpassword123"}"#;
        let request: xavyo_api_auth::models::PasswordChangeRequest =
            serde_json::from_str(json).unwrap();

        // Defaults to true per security policy
        assert!(request.revoke_other_sessions);
    }
}

// ============================================================================
// Shortcut Handler Tests
// ============================================================================

mod shortcut_tests {
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_device_list_response_serialization() {
        use xavyo_api_auth::handlers::me::shortcuts::{DeviceInfo, DeviceListResponse};

        let response = DeviceListResponse {
            items: vec![
                DeviceInfo {
                    id: Uuid::new_v4(),
                    device_name: Some("Work Laptop".to_string()),
                    device_type: Some("desktop".to_string()),
                    is_trusted: true,
                    last_seen_at: Some(Utc::now()),
                },
                DeviceInfo {
                    id: Uuid::new_v4(),
                    device_name: Some("Mobile Phone".to_string()),
                    device_type: Some("mobile".to_string()),
                    is_trusted: false,
                    last_seen_at: Some(Utc::now()),
                },
            ],
            total: 2,
            current_device_id: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"device_name\":\"Work Laptop\""));
        assert!(json.contains("\"is_trusted\":true"));
        assert!(json.contains("\"total\":2"));
    }

    #[test]
    fn test_device_info_with_optional_fields() {
        use xavyo_api_auth::handlers::me::shortcuts::DeviceInfo;

        let device = DeviceInfo {
            id: Uuid::new_v4(),
            device_name: None,
            device_type: None,
            is_trusted: false,
            last_seen_at: None,
        };

        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("\"device_name\":null"));
        assert!(json.contains("\"device_type\":null"));
        assert!(json.contains("\"is_trusted\":false"));
    }
}

// ============================================================================
// Error Type Tests
// ============================================================================

mod error_tests {
    use xavyo_api_auth::error::ApiAuthError;

    #[test]
    fn test_email_already_exists_error() {
        let error = ApiAuthError::EmailAlreadyExists;
        let display = format!("{}", error);
        assert!(
            display.contains("email") || display.contains("already") || display.contains("exists")
        );
    }

    #[test]
    fn test_email_change_pending_error() {
        let error = ApiAuthError::EmailChangePending;
        let display = format!("{}", error);
        assert!(
            display.contains("pending") || display.contains("email") || display.contains("change")
        );
    }

    #[test]
    fn test_email_change_token_expired_error() {
        let error = ApiAuthError::EmailChangeTokenExpired;
        let display = format!("{}", error);
        assert!(display.contains("expired") || display.contains("token"));
    }

    #[test]
    fn test_email_change_token_invalid_error() {
        let error = ApiAuthError::EmailChangeTokenInvalid;
        let display = format!("{}", error);
        assert!(display.contains("invalid") || display.contains("token"));
    }

    #[test]
    fn test_same_email_error() {
        let error = ApiAuthError::SameEmail;
        let display = format!("{}", error);
        assert!(display.contains("same") || display.contains("email"));
    }
}
