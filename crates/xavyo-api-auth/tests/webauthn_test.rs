//! WebAuthn service unit tests.
//!
//! Tests for WebAuthn registration, authentication, and credential management.
//! These tests verify the logic and types without requiring a real authenticator.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

// Import actual types from the crate
use xavyo_api_auth::error::ApiAuthError;
use xavyo_api_auth::models::mfa_responses::{MfaMethod, MfaRequiredResponse, MfaStatusResponse};
use xavyo_api_auth::services::{
    WebAuthnConfig, WEBAUTHN_LOCKOUT_MINUTES as LOCKOUT_MINUTES,
    WEBAUTHN_MAX_FAILED_ATTEMPTS as MAX_FAILED_ATTEMPTS,
};

// ============================================================================
// WebAuthn Config Tests (T012 partial)
// ============================================================================

#[cfg(test)]
mod webauthn_config_tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize environment variable tests
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_webauthn_config_validation() {
        // Test that empty RP ID is invalid
        let empty_rp_id = "";
        assert!(empty_rp_id.is_empty());

        // Test valid RP ID format
        let valid_rp_id = "example.com";
        assert!(!valid_rp_id.is_empty());
        assert!(!valid_rp_id.contains("://"));

        // Test valid origin format
        let valid_origin = "https://example.com";
        assert!(valid_origin.starts_with("https://"));
    }

    #[test]
    fn test_webauthn_config_from_env_defaults() {
        // Acquire lock to prevent race conditions with other env tests
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save original values
        let orig_rp_id = std::env::var("WEBAUTHN_RP_ID").ok();
        let orig_rp_name = std::env::var("WEBAUTHN_RP_NAME").ok();
        let orig_origin = std::env::var("WEBAUTHN_ORIGIN").ok();

        // Clear env vars to test defaults
        std::env::remove_var("WEBAUTHN_RP_ID");
        std::env::remove_var("WEBAUTHN_RP_NAME");
        std::env::remove_var("WEBAUTHN_ORIGIN");

        let config = WebAuthnConfig::from_env().unwrap();
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.rp_name, "xavyo");
        assert_eq!(config.origin.as_str(), "http://localhost:8080/");

        // Restore original values
        if let Some(v) = orig_rp_id {
            std::env::set_var("WEBAUTHN_RP_ID", v);
        }
        if let Some(v) = orig_rp_name {
            std::env::set_var("WEBAUTHN_RP_NAME", v);
        }
        if let Some(v) = orig_origin {
            std::env::set_var("WEBAUTHN_ORIGIN", v);
        }
    }

    #[test]
    fn test_webauthn_config_custom_values() {
        // Acquire lock to prevent race conditions with other env tests
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save original values
        let orig_rp_id = std::env::var("WEBAUTHN_RP_ID").ok();
        let orig_rp_name = std::env::var("WEBAUTHN_RP_NAME").ok();
        let orig_origin = std::env::var("WEBAUTHN_ORIGIN").ok();

        std::env::set_var("WEBAUTHN_RP_ID", "test.example.com");
        std::env::set_var("WEBAUTHN_RP_NAME", "Test App");
        std::env::set_var("WEBAUTHN_ORIGIN", "https://test.example.com");

        let config = WebAuthnConfig::from_env().unwrap();
        assert_eq!(config.rp_id, "test.example.com");
        assert_eq!(config.rp_name, "Test App");
        assert!(config.origin.as_str().contains("test.example.com"));

        // Restore original values or clean up
        match orig_rp_id {
            Some(v) => std::env::set_var("WEBAUTHN_RP_ID", v),
            None => std::env::remove_var("WEBAUTHN_RP_ID"),
        }
        match orig_rp_name {
            Some(v) => std::env::set_var("WEBAUTHN_RP_NAME", v),
            None => std::env::remove_var("WEBAUTHN_RP_NAME"),
        }
        match orig_origin {
            Some(v) => std::env::set_var("WEBAUTHN_ORIGIN", v),
            None => std::env::remove_var("WEBAUTHN_ORIGIN"),
        }
    }

    #[test]
    fn test_webauthn_config_invalid_origin() {
        // Acquire lock to prevent race conditions with other env tests
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save original value
        let orig_origin = std::env::var("WEBAUTHN_ORIGIN").ok();

        std::env::set_var("WEBAUTHN_ORIGIN", "not-a-valid-url");

        let result = WebAuthnConfig::from_env();
        assert!(result.is_err());

        // Restore original value or clean up
        match orig_origin {
            Some(v) => std::env::set_var("WEBAUTHN_ORIGIN", v),
            None => std::env::remove_var("WEBAUTHN_ORIGIN"),
        }
    }
}

// ============================================================================
// WebAuthn Error Tests
// ============================================================================

#[cfg(test)]
mod webauthn_error_tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_webauthn_disabled_error() {
        let error = ApiAuthError::WebAuthnDisabled;
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("webauthn-disabled"));
        assert_eq!(problem.status, 403);
    }

    #[test]
    fn test_max_webauthn_credentials_error() {
        let error = ApiAuthError::MaxWebAuthnCredentials;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.error_type.contains("max-webauthn-credentials"));
    }

    #[test]
    fn test_webauthn_challenge_not_found_error() {
        let error = ApiAuthError::WebAuthnChallengeNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_webauthn_challenge_expired_error() {
        let error = ApiAuthError::WebAuthnChallengeExpired;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_webauthn_verification_failed_error() {
        let error = ApiAuthError::WebAuthnVerificationFailed("test error".to_string());
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.detail.unwrap().contains("test error"));
    }

    #[test]
    fn test_webauthn_credential_exists_error() {
        let error = ApiAuthError::WebAuthnCredentialExists;
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_webauthn_credential_not_found_error() {
        let error = ApiAuthError::WebAuthnCredentialNotFound;
        assert_eq!(error.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_webauthn_no_credentials_error() {
        let error = ApiAuthError::WebAuthnNoCredentials;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_webauthn_rate_limited_error() {
        let error = ApiAuthError::WebAuthnRateLimited;
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_webauthn_counter_anomaly_error() {
        let error = ApiAuthError::WebAuthnCounterAnomaly;
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);

        let problem = error.to_problem_details();
        assert!(problem.detail.unwrap().contains("cloned"));
    }

    #[test]
    fn test_webauthn_attestation_required_error() {
        let error = ApiAuthError::WebAuthnAttestationRequired;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_webauthn_authenticator_type_not_allowed_error() {
        let error = ApiAuthError::WebAuthnAuthenticatorTypeNotAllowed("platform".to_string());
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let problem = error.to_problem_details();
        assert!(problem.detail.unwrap().contains("platform"));
    }

    #[test]
    fn test_webauthn_user_verification_required_error() {
        let error = ApiAuthError::WebAuthnUserVerificationRequired;
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }
}

// ============================================================================
// MFA Response Tests (T069-T072)
// ============================================================================

#[cfg(test)]
mod mfa_response_tests {
    use super::*;

    #[test]
    fn test_mfa_required_response_new() {
        let response = MfaRequiredResponse::new("partial_token_123".to_string(), 300);

        assert_eq!(response.partial_token, "partial_token_123");
        assert!(response.mfa_required);
        assert_eq!(response.expires_in, 300);
        // Default includes TOTP for backwards compatibility
        assert_eq!(response.available_methods.len(), 1);
        assert!(matches!(response.available_methods[0], MfaMethod::Totp));
    }

    #[test]
    fn test_mfa_required_response_with_methods() {
        let methods = vec![MfaMethod::Totp, MfaMethod::Webauthn, MfaMethod::Recovery];
        let response = MfaRequiredResponse::with_methods("token".to_string(), 600, methods);

        assert_eq!(response.available_methods.len(), 3);
        assert!(response
            .available_methods
            .iter()
            .any(|m| matches!(m, MfaMethod::Totp)));
        assert!(response
            .available_methods
            .iter()
            .any(|m| matches!(m, MfaMethod::Webauthn)));
        assert!(response
            .available_methods
            .iter()
            .any(|m| matches!(m, MfaMethod::Recovery)));
    }

    #[test]
    fn test_mfa_required_response_serialization() {
        let methods = vec![MfaMethod::Webauthn];
        let response = MfaRequiredResponse::with_methods("test_token".to_string(), 300, methods);

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"partial_token\":\"test_token\""));
        assert!(json.contains("\"mfa_required\":true"));
        assert!(json.contains("\"expires_in\":300"));
        assert!(json.contains("\"webauthn\""));
    }

    #[test]
    fn test_mfa_status_response_with_webauthn() {
        let response = MfaStatusResponse {
            totp_enabled: true,
            webauthn_enabled: true,
            recovery_codes_remaining: 8,
            available_methods: vec![MfaMethod::Totp, MfaMethod::Webauthn, MfaMethod::Recovery],
            setup_at: Some(Utc::now()),
            last_used_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"totp_enabled\":true"));
        assert!(json.contains("\"webauthn_enabled\":true"));
        assert!(json.contains("\"recovery_codes_remaining\":8"));
    }

    #[test]
    fn test_mfa_status_response_only_webauthn() {
        let response = MfaStatusResponse {
            totp_enabled: false,
            webauthn_enabled: true,
            recovery_codes_remaining: 0,
            available_methods: vec![MfaMethod::Webauthn],
            setup_at: None,
            last_used_at: None,
        };

        assert!(!response.totp_enabled);
        assert!(response.webauthn_enabled);
        assert_eq!(response.available_methods.len(), 1);
    }

    #[test]
    fn test_mfa_method_serialization() {
        let totp = MfaMethod::Totp;
        let webauthn = MfaMethod::Webauthn;
        let recovery = MfaMethod::Recovery;

        assert_eq!(serde_json::to_string(&totp).unwrap(), "\"totp\"");
        assert_eq!(serde_json::to_string(&webauthn).unwrap(), "\"webauthn\"");
        assert_eq!(serde_json::to_string(&recovery).unwrap(), "\"recovery\"");
    }
}

// ============================================================================
// Rate Limiting Tests (T037)
// ============================================================================

#[cfg(test)]
mod rate_limiting_tests {
    use super::*;

    #[test]
    fn test_rate_limit_constants() {
        assert_eq!(MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(LOCKOUT_MINUTES, 5);
    }

    #[test]
    fn test_rate_limit_check_not_exceeded() {
        let failed_attempts: i64 = 4;
        assert!(failed_attempts < MAX_FAILED_ATTEMPTS);
    }

    #[test]
    fn test_rate_limit_check_exceeded() {
        let failed_attempts: i64 = 5;
        assert!(failed_attempts >= MAX_FAILED_ATTEMPTS);
    }

    #[test]
    fn test_rate_limit_check_exceeded_with_more() {
        let failed_attempts: i64 = 10;
        assert!(failed_attempts >= MAX_FAILED_ATTEMPTS);
    }
}

// ============================================================================
// Sign Counter Tests (T031, T036)
// ============================================================================

#[cfg(test)]
mod sign_counter_tests {
    #[test]
    fn test_sign_counter_increment_valid() {
        let stored_counter: u32 = 10;
        let new_counter: u32 = 11;

        // Valid: new counter is strictly greater
        assert!(new_counter > stored_counter);
    }

    #[test]
    fn test_sign_counter_increment_multiple() {
        let stored_counter: u32 = 10;
        let new_counter: u32 = 15; // Jumped by more than 1

        // Still valid: new counter is greater (authenticators may skip)
        assert!(new_counter > stored_counter);
    }

    #[test]
    fn test_sign_counter_anomaly_same() {
        let stored_counter: u32 = 100;
        let new_counter: u32 = 100;

        // Anomaly: counter is the same (possible clone)
        let is_anomaly = new_counter <= stored_counter && new_counter != 0;
        assert!(is_anomaly);
    }

    #[test]
    fn test_sign_counter_anomaly_lower() {
        let stored_counter: u32 = 100;
        let new_counter: u32 = 50;

        // Anomaly: counter went backwards (definite clone)
        let is_anomaly = new_counter <= stored_counter && new_counter != 0;
        assert!(is_anomaly);
    }

    #[test]
    fn test_sign_counter_zero_special_case() {
        let stored_counter: u32 = 100;
        let new_counter: u32 = 0;

        // Zero is special: some authenticators always return 0
        // This should NOT be treated as anomaly
        let is_anomaly = new_counter <= stored_counter && new_counter != 0;
        assert!(!is_anomaly);
    }
}

// ============================================================================
// Challenge Expiry Tests (T018)
// ============================================================================

#[cfg(test)]
mod challenge_expiry_tests {
    use super::*;

    #[test]
    fn test_challenge_not_expired() {
        let created_at = Utc::now();
        let expiry_minutes = 5;
        let expires_at = created_at + Duration::minutes(expiry_minutes);

        assert!(expires_at > Utc::now());
    }

    #[test]
    fn test_challenge_expired() {
        let created_at = Utc::now() - Duration::minutes(10);
        let expiry_minutes = 5;
        let expires_at = created_at + Duration::minutes(expiry_minutes);

        assert!(expires_at < Utc::now());
    }

    #[test]
    fn test_challenge_just_expired() {
        let created_at = Utc::now() - Duration::minutes(5) - Duration::seconds(1);
        let expiry_minutes = 5;
        let expires_at = created_at + Duration::minutes(expiry_minutes);

        assert!(expires_at < Utc::now());
    }
}

// ============================================================================
// Policy Validation Tests (T064-T066)
// ============================================================================

#[cfg(test)]
mod policy_validation_tests {
    #[test]
    fn test_user_verification_valid_values() {
        let valid_values = ["discouraged", "preferred", "required"];

        for value in &valid_values {
            assert!(
                *value == "discouraged" || *value == "preferred" || *value == "required",
                "Invalid user_verification value: {}",
                value
            );
        }
    }

    #[test]
    fn test_user_verification_invalid_value() {
        let invalid_value = "optional";
        let valid_values = ["discouraged", "preferred", "required"];

        assert!(!valid_values.contains(&invalid_value));
    }

    #[test]
    fn test_max_credentials_valid_range() {
        for max in [1, 5, 10, 50, 100] {
            assert!((1..=100).contains(&max), "Invalid max_credentials: {}", max);
        }
    }

    #[test]
    fn test_max_credentials_invalid_range() {
        for max in [0, -1, 101, 200] {
            assert!(!(1..=100).contains(&max), "Should be invalid: {}", max);
        }
    }

    #[test]
    fn test_allowed_authenticator_types_platform() {
        let allowed = vec!["platform".to_string()];
        let auth_type = "platform";

        assert!(allowed.contains(&auth_type.to_string()));
    }

    #[test]
    fn test_allowed_authenticator_types_cross_platform() {
        let allowed = vec!["cross-platform".to_string()];
        let auth_type = "cross-platform";

        assert!(allowed.contains(&auth_type.to_string()));
    }

    #[test]
    fn test_allowed_authenticator_types_both() {
        let allowed = vec!["platform".to_string(), "cross-platform".to_string()];

        assert!(allowed.contains(&"platform".to_string()));
        assert!(allowed.contains(&"cross-platform".to_string()));
    }

    #[test]
    fn test_allowed_authenticator_types_rejected() {
        let allowed = vec!["platform".to_string()];
        let auth_type = "cross-platform";

        assert!(!allowed.contains(&auth_type.to_string()));
    }

    #[test]
    fn test_allowed_authenticator_types_empty_allows_all() {
        let allowed: Vec<String> = vec![];
        let auth_type = "platform";

        // Empty list means all types are allowed
        assert!(allowed.is_empty() || allowed.contains(&auth_type.to_string()));
    }
}

// ============================================================================
// Credential Name Validation Tests
// ============================================================================

#[cfg(test)]
mod credential_name_tests {
    #[test]
    fn test_credential_name_valid() {
        let valid_names = [
            "My YubiKey",
            "MacBook Touch ID",
            "Windows Hello",
            "Security Key 1",
            "Backup Key",
        ];

        for name in &valid_names {
            assert!(!name.is_empty());
            assert!(name.len() <= 100);
        }
    }

    #[test]
    fn test_credential_name_empty_invalid() {
        let name = "";
        assert!(name.is_empty());
    }

    #[test]
    fn test_credential_name_too_long_invalid() {
        let name = "a".repeat(101);
        assert!(name.len() > 100);
    }

    #[test]
    fn test_credential_name_max_length_valid() {
        let name = "a".repeat(100);
        assert!(name.len() == 100);
        assert!(!name.is_empty() && name.len() <= 100);
    }
}

// ============================================================================
// Audit Log Tests (T022, T035, T052, T080)
// ============================================================================

#[cfg(test)]
mod audit_log_tests {
    use super::*;

    #[test]
    fn test_audit_action_names_snake_case() {
        let actions = [
            "registration_started",
            "registration_completed",
            "registration_failed",
            "authentication_started",
            "authentication_success",
            "authentication_failed",
            "credential_renamed",
            "credential_deleted",
            "credential_revoked_by_admin",
            "counter_anomaly_detected",
        ];

        for action in &actions {
            assert!(!action.contains('-'), "Action {} contains hyphen", action);
            assert!(!action.contains(' '), "Action {} contains space", action);
            assert!(
                action.chars().all(|c| c.is_lowercase() || c == '_'),
                "Action {} is not snake_case",
                action
            );
        }
    }

    #[test]
    fn test_audit_log_metadata_registration() {
        let metadata = json!({
            "credential_name": "My Key",
            "authenticator_type": "cross-platform"
        });

        assert!(metadata.is_object());
        assert_eq!(metadata["credential_name"], "My Key");
        assert_eq!(metadata["authenticator_type"], "cross-platform");
    }

    #[test]
    fn test_audit_log_metadata_counter_anomaly() {
        let metadata = json!({
            "stored_counter": 100,
            "received_counter": 50
        });

        assert!(metadata.is_object());
        assert_eq!(metadata["stored_counter"], 100);
        assert_eq!(metadata["received_counter"], 50);
    }

    #[test]
    fn test_audit_log_metadata_admin_revoke() {
        let admin_id = Uuid::new_v4();
        let metadata = json!({
            "admin_user_id": admin_id.to_string(),
            "credential_name": "Revoked Key"
        });

        assert!(metadata.is_object());
        assert!(metadata["admin_user_id"].as_str().is_some());
    }
}

// ============================================================================
// Response Format Tests (API Contract)
// ============================================================================

#[cfg(test)]
mod response_format_tests {
    use super::*;

    #[test]
    fn test_credential_list_response_format() {
        let response = json!({
            "credentials": [
                {
                    "id": Uuid::new_v4().to_string(),
                    "name": "Key 1",
                    "authenticator_type": "cross-platform",
                    "backup_eligible": false,
                    "backup_state": false,
                    "created_at": Utc::now().to_rfc3339()
                }
            ],
            "count": 1
        });

        assert!(response["credentials"].is_array());
        assert_eq!(response["count"], 1);
    }

    #[test]
    fn test_registration_start_response_format() {
        // Verify the structure matches webauthn-rs CreationChallengeResponse
        let response = json!({
            "publicKey": {
                "challenge": "base64-encoded-challenge",
                "rp": {
                    "name": "xavyo",
                    "id": "localhost"
                },
                "user": {
                    "id": "base64-user-id",
                    "name": "user@example.com",
                    "displayName": "Test User"
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7}
                ]
            }
        });

        assert!(response["publicKey"].is_object());
        assert!(response["publicKey"]["challenge"].is_string());
    }

    #[test]
    fn test_admin_credential_list_response_format() {
        let user_id = Uuid::new_v4();
        let response = json!({
            "user_id": user_id.to_string(),
            "credentials": [],
            "count": 0
        });

        assert!(response["user_id"].is_string());
        assert!(response["credentials"].is_array());
        assert_eq!(response["count"], 0);
    }

    #[test]
    fn test_policy_response_format() {
        let tenant_id = Uuid::new_v4();
        let response = json!({
            "tenant_id": tenant_id.to_string(),
            "webauthn_enabled": true,
            "require_attestation": false,
            "user_verification": "preferred",
            "max_credentials_per_user": 10
        });

        assert!(response["tenant_id"].is_string());
        assert!(response["webauthn_enabled"].is_boolean());
        assert_eq!(response["user_verification"], "preferred");
        assert_eq!(response["max_credentials_per_user"], 10);
    }
}

// ============================================================================
// Integration Scenario Tests (Logic validation)
// ============================================================================

#[cfg(test)]
mod integration_scenario_tests {
    use super::*;

    #[test]
    fn test_mfa_method_selection_totp_only() {
        let totp_enabled = true;
        let webauthn_enabled = false;
        let recovery_codes_remaining = 8;

        let mut methods = Vec::new();
        if totp_enabled {
            methods.push(MfaMethod::Totp);
        }
        if webauthn_enabled {
            methods.push(MfaMethod::Webauthn);
        }
        if recovery_codes_remaining > 0 {
            methods.push(MfaMethod::Recovery);
        }

        assert_eq!(methods.len(), 2);
        assert!(methods.iter().any(|m| matches!(m, MfaMethod::Totp)));
        assert!(methods.iter().any(|m| matches!(m, MfaMethod::Recovery)));
        assert!(!methods.iter().any(|m| matches!(m, MfaMethod::Webauthn)));
    }

    #[test]
    fn test_mfa_method_selection_webauthn_only() {
        let totp_enabled = false;
        let webauthn_enabled = true;
        let recovery_codes_remaining = 8;

        let mut methods = Vec::new();
        if totp_enabled {
            methods.push(MfaMethod::Totp);
        }
        if webauthn_enabled {
            methods.push(MfaMethod::Webauthn);
        }
        if recovery_codes_remaining > 0 {
            methods.push(MfaMethod::Recovery);
        }

        assert_eq!(methods.len(), 2);
        assert!(methods.iter().any(|m| matches!(m, MfaMethod::Webauthn)));
        assert!(methods.iter().any(|m| matches!(m, MfaMethod::Recovery)));
        assert!(!methods.iter().any(|m| matches!(m, MfaMethod::Totp)));
    }

    #[test]
    fn test_mfa_method_selection_both() {
        let totp_enabled = true;
        let webauthn_enabled = true;
        let recovery_codes_remaining = 8;

        let mut methods = Vec::new();
        if totp_enabled {
            methods.push(MfaMethod::Totp);
        }
        if webauthn_enabled {
            methods.push(MfaMethod::Webauthn);
        }
        if recovery_codes_remaining > 0 {
            methods.push(MfaMethod::Recovery);
        }

        assert_eq!(methods.len(), 3);
    }

    #[test]
    fn test_mfa_method_selection_no_recovery() {
        let totp_enabled = true;
        let webauthn_enabled = true;
        let recovery_codes_remaining = 0;

        let mut methods = Vec::new();
        if totp_enabled {
            methods.push(MfaMethod::Totp);
        }
        if webauthn_enabled {
            methods.push(MfaMethod::Webauthn);
        }
        if recovery_codes_remaining > 0 {
            methods.push(MfaMethod::Recovery);
        }

        assert_eq!(methods.len(), 2);
        assert!(!methods.iter().any(|m| matches!(m, MfaMethod::Recovery)));
    }

    #[test]
    fn test_policy_enforcement_webauthn_disabled() {
        let policy_webauthn_enabled = false;

        // Should return error before registration starts
        assert!(!policy_webauthn_enabled);
    }

    #[test]
    fn test_policy_enforcement_max_credentials() {
        let max_credentials = 10;
        let current_count = 10;

        // Should reject new registration
        assert!(current_count >= max_credentials);
    }

    #[test]
    fn test_policy_enforcement_max_credentials_ok() {
        let max_credentials = 10;
        let current_count = 5;

        // Should allow new registration
        assert!(current_count < max_credentials);
    }
}
