//! Audit log data models for the xavyo CLI
//!
//! This module provides data structures for representing audit log entries
//! returned from the API, including filtering and pagination support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ============================================================================
// AuditUser
// ============================================================================

/// Represents the user who performed an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditUser {
    /// User unique identifier
    pub id: Uuid,

    /// User email address
    pub email: String,

    /// User display name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

// ============================================================================
// AuditAction
// ============================================================================

/// Enumeration of possible audit action types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication
    Login,
    Logout,
    LoginFailed,
    MfaVerified,

    // CRUD operations
    Create,
    Read,
    Update,
    Delete,

    // Agent/Tool specific
    CredentialRotate,
    CredentialRevoke,
    Authorize,

    // Session management
    SessionCreate,
    SessionRevoke,

    // Configuration
    ConfigApply,
    ConfigExport,

    // Catch-all for unknown actions
    #[serde(other)]
    Other,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::LoginFailed => "login_failed",
            Self::MfaVerified => "mfa_verified",
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::CredentialRotate => "credential_rotate",
            Self::CredentialRevoke => "credential_revoke",
            Self::Authorize => "authorize",
            Self::SessionCreate => "session_create",
            Self::SessionRevoke => "session_revoke",
            Self::ConfigApply => "config_apply",
            Self::ConfigExport => "config_export",
            Self::Other => "other",
        };
        write!(f, "{}", s)
    }
}

impl AuditAction {
    /// Parse an action string into an AuditAction
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "login" => Self::Login,
            "logout" => Self::Logout,
            "login_failed" => Self::LoginFailed,
            "mfa_verified" => Self::MfaVerified,
            "create" => Self::Create,
            "read" => Self::Read,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "credential_rotate" => Self::CredentialRotate,
            "credential_revoke" => Self::CredentialRevoke,
            "authorize" => Self::Authorize,
            "session_create" => Self::SessionCreate,
            "session_revoke" => Self::SessionRevoke,
            "config_apply" => Self::ConfigApply,
            "config_export" => Self::ConfigExport,
            _ => Self::Other,
        }
    }

    /// Get all valid action type strings
    #[allow(dead_code)]
    pub fn all_types() -> &'static [&'static str] {
        &[
            "login",
            "logout",
            "login_failed",
            "mfa_verified",
            "create",
            "read",
            "update",
            "delete",
            "credential_rotate",
            "credential_revoke",
            "authorize",
            "session_create",
            "session_revoke",
            "config_apply",
            "config_export",
        ]
    }
}

// ============================================================================
// AuditEntry
// ============================================================================

/// Represents a single audit log record returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for the audit entry
    pub id: Uuid,

    /// When the event occurred (ISO 8601 format)
    pub timestamp: DateTime<Utc>,

    /// User who performed the action
    pub user: AuditUser,

    /// Type of action performed
    pub action: AuditAction,

    /// Type of resource affected
    pub resource_type: String,

    /// Identifier of the affected resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,

    /// Display name of the affected resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    /// IP address of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// User agent string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Additional metadata (action-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ============================================================================
// AuditFilter
// ============================================================================

/// Query parameters for filtering audit logs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditFilter {
    /// Filter by user identifier (email or UUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Filter by start date (inclusive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,

    /// Filter by end date (inclusive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,

    /// Filter by action type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Maximum entries to return (default: 50, max: 1000)
    pub limit: i32,

    /// Offset for pagination
    pub offset: i32,
}

impl AuditFilter {
    /// Create a new filter with default pagination
    pub fn new() -> Self {
        Self {
            user: None,
            since: None,
            until: None,
            action: None,
            limit: 50,
            offset: 0,
        }
    }

    /// Set user filter
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set since date filter
    pub fn with_since(mut self, since: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self
    }

    /// Set until date filter
    pub fn with_until(mut self, until: DateTime<Utc>) -> Self {
        self.until = Some(until);
        self
    }

    /// Set action type filter
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set limit
    pub fn with_limit(mut self, limit: i32) -> Self {
        self.limit = limit;
        self
    }

    /// Set offset
    pub fn with_offset(mut self, offset: i32) -> Self {
        self.offset = offset;
        self
    }

    /// Build query string for URL
    pub fn to_query_string(&self) -> String {
        let mut params = vec![
            format!("limit={}", self.limit),
            format!("offset={}", self.offset),
        ];

        if let Some(ref user) = self.user {
            params.push(format!("user={}", urlencoding::encode(user)));
        }

        if let Some(ref since) = self.since {
            params.push(format!("since={}", since.to_rfc3339()));
        }

        if let Some(ref until) = self.until {
            params.push(format!("until={}", until.to_rfc3339()));
        }

        if let Some(ref action) = self.action {
            params.push(format!("action={}", action));
        }

        params.join("&")
    }
}

// ============================================================================
// AuditListResponse
// ============================================================================

/// API response for audit list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListResponse {
    /// List of audit entries
    pub entries: Vec<AuditEntry>,

    /// Total count of matching entries (for pagination)
    pub total: i64,

    /// Whether more entries are available
    pub has_more: bool,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_display() {
        assert_eq!(AuditAction::Login.to_string(), "login");
        assert_eq!(AuditAction::Logout.to_string(), "logout");
        assert_eq!(AuditAction::Create.to_string(), "create");
        assert_eq!(AuditAction::Delete.to_string(), "delete");
        assert_eq!(
            AuditAction::CredentialRotate.to_string(),
            "credential_rotate"
        );
    }

    #[test]
    fn test_audit_action_parse() {
        assert_eq!(AuditAction::parse("login"), AuditAction::Login);
        assert_eq!(AuditAction::parse("LOGIN"), AuditAction::Login);
        assert_eq!(AuditAction::parse("unknown"), AuditAction::Other);
    }

    #[test]
    fn test_audit_filter_default() {
        let filter = AuditFilter::new();
        assert_eq!(filter.limit, 50);
        assert_eq!(filter.offset, 0);
        assert!(filter.user.is_none());
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
        assert!(filter.action.is_none());
    }

    #[test]
    fn test_audit_filter_builder() {
        let filter = AuditFilter::new()
            .with_user("alice@example.com")
            .with_action("login")
            .with_limit(100)
            .with_offset(50);

        assert_eq!(filter.user.as_deref(), Some("alice@example.com"));
        assert_eq!(filter.action.as_deref(), Some("login"));
        assert_eq!(filter.limit, 100);
        assert_eq!(filter.offset, 50);
    }

    #[test]
    fn test_audit_filter_query_string() {
        let filter = AuditFilter::new()
            .with_user("alice@example.com")
            .with_action("login")
            .with_limit(100);

        let query = filter.to_query_string();
        assert!(query.contains("limit=100"));
        assert!(query.contains("offset=0"));
        assert!(query.contains("user=alice%40example.com"));
        assert!(query.contains("action=login"));
    }

    #[test]
    fn test_audit_user_deserialize() {
        let json =
            r#"{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "email": "alice@example.com"}"#;
        let user: AuditUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.email, "alice@example.com");
        assert!(user.display_name.is_none());
    }

    #[test]
    fn test_audit_entry_deserialize() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "timestamp": "2026-02-04T10:30:00Z",
            "user": {
                "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
                "email": "alice@example.com"
            },
            "action": "login",
            "resource_type": "session"
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.action, AuditAction::Login);
        assert_eq!(entry.resource_type, "session");
        assert_eq!(entry.user.email, "alice@example.com");
    }

    #[test]
    fn test_audit_list_response_deserialize() {
        let json = r#"{
            "entries": [{
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "timestamp": "2026-02-04T10:30:00Z",
                "user": {
                    "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
                    "email": "alice@example.com"
                },
                "action": "login",
                "resource_type": "session"
            }],
            "total": 100,
            "has_more": true
        }"#;

        let response: AuditListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.entries.len(), 1);
        assert_eq!(response.total, 100);
        assert!(response.has_more);
    }

    #[test]
    fn test_audit_action_unknown() {
        let json = r#"{"action": "unknown_action"}"#;

        #[derive(Deserialize)]
        struct TestStruct {
            action: AuditAction,
        }

        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.action, AuditAction::Other);
    }

    #[test]
    fn test_all_action_types() {
        let types = AuditAction::all_types();
        assert!(types.contains(&"login"));
        assert!(types.contains(&"logout"));
        assert!(types.contains(&"create"));
        assert!(types.contains(&"delete"));
        assert!(!types.contains(&"other")); // other is the catch-all
    }
}
