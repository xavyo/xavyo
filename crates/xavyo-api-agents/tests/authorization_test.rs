//! Authorization integration tests for F123 - Three-Layer Authorization.
//!
//! Tests for the can_operate_agent endpoint and user context in authorization.

mod common;

use uuid::Uuid;

#[cfg(test)]
mod can_operate_tests {
    use super::*;
    use xavyo_api_agents::models::requests::{CanOperateRequest, UserContext};
    use xavyo_api_agents::models::responses::CanOperateResponse;

    #[test]
    fn test_can_operate_request_serialization() {
        let request = CanOperateRequest {
            user_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));

        let deserialized: CanOperateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.user_id, deserialized.user_id);
    }

    #[test]
    fn test_can_operate_response_owner() {
        let response = CanOperateResponse {
            can_operate: true,
            reason: "User is agent owner".to_string(),
            permissions: vec!["full_access".to_string()],
        };

        assert!(response.can_operate);
        assert_eq!(response.reason, "User is agent owner");
        assert!(response.permissions.contains(&"full_access".to_string()));
    }

    #[test]
    fn test_can_operate_response_backup_owner() {
        let response = CanOperateResponse {
            can_operate: true,
            reason: "User is backup owner".to_string(),
            permissions: vec!["operate".to_string()],
        };

        assert!(response.can_operate);
        assert_eq!(response.reason, "User is backup owner");
        assert!(response.permissions.contains(&"operate".to_string()));
    }

    #[test]
    fn test_can_operate_response_denied() {
        let response = CanOperateResponse {
            can_operate: false,
            reason: "User is not owner or backup owner of this agent".to_string(),
            permissions: vec![],
        };

        assert!(!response.can_operate);
        assert!(response.permissions.is_empty());
    }

    #[test]
    fn test_can_operate_response_serialization() {
        let response = CanOperateResponse {
            can_operate: true,
            reason: "User is agent owner".to_string(),
            permissions: vec!["full_access".to_string(), "manage".to_string()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("can_operate"));
        assert!(json.contains("true"));
        assert!(json.contains("full_access"));

        let deserialized: CanOperateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.can_operate, deserialized.can_operate);
        assert_eq!(response.permissions.len(), 2);
    }

    #[test]
    fn test_user_context_in_authorization_request() {
        use xavyo_api_agents::models::requests::AuthorizationContext;

        let user_context = UserContext {
            user_id: Uuid::new_v4(),
            email: Some("operator@example.com".to_string()),
            roles: Some(vec!["workflow-operator".to_string(), "viewer".to_string()]),
        };

        let context = AuthorizationContext {
            conversation_id: Some("conv-abc".to_string()),
            session_id: Some("workflow-123-exec-456".to_string()),
            user_instruction: Some("Process the customer order".to_string()),
            user_context: Some(user_context),
        };

        // Verify user_context is properly set
        assert!(context.user_context.is_some());
        let uc = context.user_context.as_ref().unwrap();
        assert_eq!(uc.email.as_ref().unwrap(), "operator@example.com");
        assert_eq!(uc.roles.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_authorization_context_defaults() {
        use xavyo_api_agents::models::requests::AuthorizationContext;

        // Default should have all None
        let context = AuthorizationContext::default();

        assert!(context.conversation_id.is_none());
        assert!(context.session_id.is_none());
        assert!(context.user_instruction.is_none());
        assert!(context.user_context.is_none());
    }
}

#[cfg(test)]
mod three_layer_auth_tests {
    use super::*;
    use xavyo_api_agents::models::requests::UserContext;

    /// Test Layer 1: User-Agent relationship
    #[test]
    fn test_layer1_user_context_structure() {
        // Layer 1 validates user can operate the agent
        let user_context = UserContext {
            user_id: Uuid::new_v4(),
            email: Some("alice@company.com".to_string()),
            roles: Some(vec!["agent-operator".to_string()]),
        };

        // user_id is required
        assert!(!user_context.user_id.is_nil());
        // email and roles are optional
        assert!(user_context.email.is_some());
        assert!(user_context.roles.is_some());
    }

    /// Test Layer 1: Minimal user context (only required field)
    #[test]
    fn test_layer1_minimal_user_context() {
        let json = r#"{"user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}"#;
        let user_context: UserContext = serde_json::from_str(json).unwrap();

        assert_eq!(
            user_context.user_id,
            Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()
        );
        assert!(user_context.email.is_none());
        assert!(user_context.roles.is_none());
    }

    /// Test Layer 1: Full user context with all fields
    #[test]
    fn test_layer1_full_user_context() {
        let json = r#"{
            "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "email": "bob@example.com",
            "roles": ["admin", "operator", "viewer"]
        }"#;
        let user_context: UserContext = serde_json::from_str(json).unwrap();

        assert_eq!(user_context.email.as_ref().unwrap(), "bob@example.com");
        assert_eq!(user_context.roles.as_ref().unwrap().len(), 3);
    }

    /// Test that user_id is a valid UUID
    #[test]
    fn test_user_context_uuid_validation() {
        // Valid UUID
        let json = r#"{"user_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let result: Result<UserContext, _> = serde_json::from_str(json);
        assert!(result.is_ok());

        // Invalid UUID should fail deserialization
        let invalid_json = r#"{"user_id": "not-a-uuid"}"#;
        let result: Result<UserContext, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
}
