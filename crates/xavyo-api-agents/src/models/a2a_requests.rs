//! A2A (Agent-to-Agent) Protocol request and response models.
//!
//! This module defines the DTOs for A2A asynchronous task management,
//! following the A2A protocol specification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Request body for POST /a2a/tasks - create a new task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CreateA2aTaskRequest {
    /// Target agent ID that will execute the task.
    pub target_agent_id: Uuid,

    /// Task type/skill identifier.
    pub task_type: String,

    /// Task input parameters.
    pub input: serde_json::Value,

    /// Optional webhook URL for completion notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

/// Response for POST /a2a/tasks - task created.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CreateA2aTaskResponse {
    /// Unique task identifier.
    pub task_id: Uuid,

    /// Initial task status (always "pending").
    pub status: String,

    /// Task creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Response for GET /a2a/tasks/{id} - task details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct A2aTaskResponse {
    /// Task identifier.
    pub id: Uuid,

    /// Agent that created the task.
    pub source_agent_id: Uuid,

    /// Agent executing the task.
    pub target_agent_id: Uuid,

    /// Task type/skill.
    pub task_type: String,

    /// Current task state.
    pub state: String,

    /// Task result (when completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error code (when failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Error message (when failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Task creation timestamp.
    pub created_at: DateTime<Utc>,

    /// When the task started execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// When the task reached a terminal state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Response for POST /a2a/tasks/{id}/cancel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CancelA2aTaskResponse {
    /// Task identifier.
    pub task_id: Uuid,

    /// New state (always "cancelled").
    pub state: String,

    /// Cancellation timestamp.
    pub cancelled_at: DateTime<Utc>,
}

/// Query parameters for GET /a2a/tasks - list tasks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ListA2aTasksQuery {
    /// Filter by task state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Filter by target agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_agent_id: Option<Uuid>,

    /// Maximum results (default: 100, max: 1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,

    /// Pagination offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
}

/// Response for GET /a2a/tasks - list tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct A2aTaskListResponse {
    /// List of tasks.
    pub tasks: Vec<A2aTaskResponse>,

    /// Total count matching filter.
    pub total: i64,

    /// Limit used in query.
    pub limit: i32,

    /// Offset used in query.
    pub offset: i32,
}

/// Webhook payload sent on task completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct A2aTaskWebhookPayload {
    /// Task identifier.
    pub task_id: Uuid,

    /// Terminal state (completed, failed, cancelled).
    pub state: String,

    /// Task result (when completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error code (when failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Error message (when failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Completion timestamp.
    pub completed_at: DateTime<Utc>,
}

/// A2A error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct A2aErrorResponse {
    /// Error code.
    pub error: String,

    /// Human-readable message.
    pub message: String,

    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl A2aErrorResponse {
    /// Create a new error response.
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Invalid state transition error.
    #[must_use]
    pub fn invalid_state_transition(current_state: &str) -> Self {
        Self::new(
            "invalid_state_transition",
            format!("Task cannot be cancelled: already in '{current_state}' state"),
        )
    }

    /// Task not found error.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new("not_found", "Task not found")
    }

    /// Target agent not found error.
    #[must_use]
    pub fn target_not_found() -> Self {
        Self::new("target_not_found", "Target agent not found")
    }

    /// Invalid callback URL error.
    #[must_use]
    pub fn invalid_callback_url() -> Self {
        Self::new("invalid_callback_url", "Callback URL format is invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_task_request_serialization() {
        let req = CreateA2aTaskRequest {
            target_agent_id: Uuid::new_v4(),
            task_type: "process_document".to_string(),
            input: serde_json::json!({ "url": "https://example.com/doc.pdf" }),
            callback_url: Some("https://myapp.example.com/webhooks/a2a".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("process_document"));
        assert!(json.contains("callback_url"));
    }

    #[test]
    fn test_task_response_without_optional_fields() {
        let resp = A2aTaskResponse {
            id: Uuid::new_v4(),
            source_agent_id: Uuid::new_v4(),
            target_agent_id: Uuid::new_v4(),
            task_type: "test".to_string(),
            state: "pending".to_string(),
            result: None,
            error_code: None,
            error_message: None,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("result"));
        assert!(!json.contains("error_code"));
        assert!(!json.contains("started_at"));
    }

    #[test]
    fn test_error_responses() {
        let err = A2aErrorResponse::invalid_state_transition("completed");
        assert_eq!(err.error, "invalid_state_transition");
        assert!(err.message.contains("completed"));
    }

    #[test]
    fn test_webhook_payload() {
        let payload = A2aTaskWebhookPayload {
            task_id: Uuid::new_v4(),
            state: "completed".to_string(),
            result: Some(serde_json::json!({ "summary": "Done" })),
            error_code: None,
            error_message: None,
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("completed"));
        assert!(json.contains("summary"));
    }
}
