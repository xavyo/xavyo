//! Audit log data models for the xavyo CLI
//!
//! This module provides data structures for representing login history entries
//! returned from the API, including filtering and pagination support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// AuditEntry (Login History)
// ============================================================================

/// Represents a single login history record returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for the entry
    pub id: Uuid,

    /// User ID who attempted login
    #[serde(default)]
    pub user_id: Option<Uuid>,

    /// User email
    #[serde(default)]
    pub email: Option<String>,

    /// Whether the login was successful
    #[serde(default)]
    pub success: bool,

    /// Authentication method used (password, mfa, etc.)
    #[serde(default)]
    pub auth_method: Option<String>,

    /// IP address of the client
    #[serde(default)]
    pub ip_address: Option<String>,

    /// User agent string
    #[serde(default)]
    pub user_agent: Option<String>,

    /// Whether this was a new device
    #[serde(default)]
    pub is_new_device: bool,

    /// Whether this was a new location
    #[serde(default)]
    pub is_new_location: bool,

    /// When the event occurred
    pub created_at: DateTime<Utc>,
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

/// API response for login history list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListResponse {
    /// List of login history entries
    pub items: Vec<AuditEntry>,

    /// Total count of matching entries (for pagination)
    #[serde(default)]
    pub total: i64,

    /// Cursor for next page
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_audit_entry_deserialize() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "user_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
            "email": "alice@example.com",
            "success": true,
            "auth_method": "password",
            "ip_address": "127.0.0.1",
            "user_agent": "curl/8.5.0",
            "is_new_device": false,
            "is_new_location": false,
            "created_at": "2026-02-04T10:30:00Z"
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.email.as_deref(), Some("alice@example.com"));
        assert!(entry.success);
        assert_eq!(entry.auth_method.as_deref(), Some("password"));
    }

    #[test]
    fn test_audit_list_response_deserialize() {
        let json = r#"{
            "items": [{
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "user_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
                "email": "alice@example.com",
                "success": true,
                "auth_method": "password",
                "ip_address": "127.0.0.1",
                "created_at": "2026-02-04T10:30:00Z"
            }],
            "total": 100,
            "next_cursor": "2026-02-04T10:30:00Z"
        }"#;

        let response: AuditListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.total, 100);
        assert!(response.next_cursor.is_some());
    }
}
