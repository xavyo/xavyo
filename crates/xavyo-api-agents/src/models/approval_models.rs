//! Request and response models for the Human-in-the-Loop Approval API (F092).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Query parameters for listing approval requests.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListApprovalsQuery {
    /// Filter by approval status: pending, approved, denied, expired
    pub status: Option<String>,
    /// Filter by agent ID
    pub agent_id: Option<Uuid>,
    /// Maximum number of results (default 50, max 100)
    pub limit: Option<i32>,
    /// Offset for pagination
    pub offset: Option<i32>,
}

/// Summary of an approval request for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApprovalSummary {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub agent_name: String,
    pub tool_id: Uuid,
    pub tool_name: String,
    pub status: String,
    pub risk_score: i32,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Full approval request details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub agent_name: String,
    pub tool_id: Uuid,
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub context: serde_json::Value,
    pub user_instruction: Option<String>,
    pub session_id: Option<String>,
    pub conversation_id: Option<String>,
    pub status: String,
    pub risk_score: i32,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

/// List response for approval requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApprovalListResponse {
    pub items: Vec<ApprovalSummary>,
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
}

/// Lightweight status response for agent polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApprovalStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

/// Request body for approving an approval request.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApproveRequest {
    #[serde(default)]
    pub conditions: Option<serde_json::Value>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request body for denying an approval request.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DenyRequest {
    pub reason: String,
}

/// Webhook payload sent when an approval is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWebhookPayload {
    pub event: String,
    pub approval_id: Uuid,
    pub agent_id: Uuid,
    pub agent_name: String,
    pub tool_id: Uuid,
    pub tool_name: String,
    pub risk_score: i32,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approval_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    #[test]
    fn test_approval_summary_serialization() {
        let summary = ApprovalSummary {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "sales-assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            status: "pending".to_string(),
            risk_score: 45,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: ApprovalSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(summary.id, deserialized.id);
        assert_eq!(summary.agent_name, deserialized.agent_name);
        assert_eq!(summary.tool_name, deserialized.tool_name);
        assert_eq!(summary.status, deserialized.status);
        assert_eq!(summary.risk_score, deserialized.risk_score);
    }

    #[test]
    fn test_approval_response_serialization() {
        let response = ApprovalResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "sales-assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            parameters: json!({"to": "customer@example.com"}),
            context: json!({"session_id": "sess-123"}),
            user_instruction: Some("Send follow-up email".to_string()),
            session_id: Some("sess-123".to_string()),
            conversation_id: Some("conv-456".to_string()),
            status: "approved".to_string(),
            risk_score: 45,
            requested_at: Utc::now() - Duration::minutes(2),
            expires_at: Utc::now() + Duration::minutes(3),
            decided_by: Some(Uuid::new_v4()),
            decided_at: Some(Utc::now()),
            decision_reason: Some("Reviewed and approved".to_string()),
            conditions: Some(json!({"session_only": true})),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"decided_by\""));
        assert!(json.contains("\"conditions\""));
    }

    #[test]
    fn test_approval_response_skips_none_fields() {
        let response = ApprovalResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "tool".to_string(),
            parameters: json!({}),
            context: json!({}),
            user_instruction: None,
            session_id: None,
            conversation_id: None,
            status: "pending".to_string(),
            risk_score: 0,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            conditions: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("\"decided_by\""));
        assert!(!json.contains("\"conditions\""));
        assert!(!json.contains("\"decision_reason\""));
    }

    #[test]
    fn test_approval_list_response_serialization() {
        let response = ApprovalListResponse {
            items: vec![],
            total: 0,
            limit: Some(50),
            offset: Some(0),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApprovalListResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response.total, deserialized.total);
        assert_eq!(response.limit, deserialized.limit);
        assert_eq!(response.offset, deserialized.offset);
    }

    #[test]
    fn test_approval_status_response_serialization() {
        let response = ApprovalStatusResponse {
            status: "approved".to_string(),
            decided_at: Some(Utc::now()),
            conditions: Some(json!({"max_calls": 5})),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"approved\""));
        assert!(json.contains("\"decided_at\""));
        assert!(json.contains("\"conditions\""));
    }

    #[test]
    fn test_approve_request_deserialization() {
        let json = r#"{"conditions": {"session_only": true}, "reason": "Looks good"}"#;
        let request: ApproveRequest = serde_json::from_str(json).unwrap();

        assert!(request.conditions.is_some());
        assert_eq!(request.reason, Some("Looks good".to_string()));
    }

    #[test]
    fn test_approve_request_empty() {
        let json = r#"{}"#;
        let request: ApproveRequest = serde_json::from_str(json).unwrap();

        assert!(request.conditions.is_none());
        assert!(request.reason.is_none());
    }

    #[test]
    fn test_deny_request_deserialization() {
        let json = r#"{"reason": "Content inappropriate"}"#;
        let request: DenyRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.reason, "Content inappropriate");
    }

    #[test]
    fn test_approval_webhook_payload_serialization() {
        let payload = ApprovalWebhookPayload {
            event: "approval_requested".to_string(),
            approval_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "sales-assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            risk_score: 45,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            approval_url: "https://api.example.com/v1/approvals/123".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"approval_requested\""));
        assert!(json.contains("\"approval_url\""));
    }
}
