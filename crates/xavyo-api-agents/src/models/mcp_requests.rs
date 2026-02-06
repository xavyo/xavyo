//! MCP (Model Context Protocol) request and response models.
//!
//! This module defines the DTOs for MCP tool discovery and invocation,
//! following the Model Context Protocol specification.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Response for GET /mcp/tools - list available tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpToolsResponse {
    /// List of tools available to the authenticated agent.
    pub tools: Vec<McpTool>,
}

/// MCP tool definition with JSON Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpTool {
    /// Unique tool name (e.g., "`send_email`").
    pub name: String,

    /// Human-readable description of what the tool does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema defining the tool's input parameters.
    pub input_schema: serde_json::Value,

    /// Tool status: "active", "deprecated", or "disabled".
    pub status: String,

    /// Whether this tool is deprecated (for MCP clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
}

/// Request body for POST /mcp/tools/{name}/call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpCallRequest {
    /// Tool-specific parameters matching the input schema.
    pub parameters: serde_json::Value,

    /// Optional context for audit and correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<McpContext>,
}

/// Optional context for MCP tool invocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpContext {
    /// Conversation or session ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,

    /// Session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Original user instruction (for audit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_instruction: Option<String>,
}

/// Response for successful tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpCallResponse {
    /// Unique identifier for this tool call (for audit).
    pub call_id: Uuid,

    /// Tool execution result.
    pub result: serde_json::Value,

    /// Execution latency in milliseconds.
    pub latency_ms: f64,
}

/// MCP error response (RFC 7807 compatible).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct McpErrorResponse {
    /// Error code identifying the type of error.
    pub error_code: McpErrorCode,

    /// Human-readable error message.
    pub message: String,

    /// Additional error details (e.g., validation errors per field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl McpErrorResponse {
    /// Create a new error response.
    pub fn new(error_code: McpErrorCode, message: impl Into<String>) -> Self {
        Self {
            error_code,
            message: message.into(),
            details: None,
        }
    }

    /// Add details to the error response.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// MCP error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum McpErrorCode {
    /// Parameters failed JSON Schema validation.
    InvalidParameters,

    /// Agent not authorized to use this tool.
    Unauthorized,

    /// Tool not found.
    NotFound,

    /// Rate limit exceeded for this agent/tool.
    RateLimitExceeded,

    /// Tool execution failed.
    ExecutionFailed,

    /// Tool execution timed out.
    Timeout,

    /// Internal server error.
    InternalError,
}

impl McpErrorCode {
    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidParameters => 400,
            Self::Unauthorized => 403,
            Self::NotFound => 404,
            Self::RateLimitExceeded => 429,
            Self::ExecutionFailed => 500,
            Self::Timeout => 504,
            Self::InternalError => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_tool_serialization() {
        let tool = McpTool {
            name: "send_email".to_string(),
            description: Some("Send an email".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "to": { "type": "string", "format": "email" }
                },
                "required": ["to"]
            }),
            status: "active".to_string(),
            deprecated: None,
        };

        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("send_email"));
        assert!(json.contains("input_schema"));
    }

    #[test]
    fn test_mcp_error_response() {
        let error = McpErrorResponse::new(McpErrorCode::InvalidParameters, "Validation failed")
            .with_details(serde_json::json!({ "to": "Invalid email format" }));

        assert_eq!(error.error_code, McpErrorCode::InvalidParameters);
        assert_eq!(error.error_code.status_code(), 400);
    }

    #[test]
    fn test_error_codes_status() {
        assert_eq!(McpErrorCode::Unauthorized.status_code(), 403);
        assert_eq!(McpErrorCode::NotFound.status_code(), 404);
        assert_eq!(McpErrorCode::RateLimitExceeded.status_code(), 429);
    }
}
