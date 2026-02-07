//! API Session models for remote session management
//!
//! These models represent authentication sessions returned by the server API.
//! Not to be confused with the local Session model for user/tenant context.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Device type for a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Desktop computer (Windows, macOS, Linux)
    Desktop,
    /// Mobile device (iOS, Android)
    Mobile,
    /// Command-line interface (xavyo-cli)
    Cli,
    /// Web browser session
    Browser,
    /// Unrecognized device type
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Desktop => write!(f, "desktop"),
            DeviceType::Mobile => write!(f, "mobile"),
            DeviceType::Cli => write!(f, "cli"),
            DeviceType::Browser => write!(f, "browser"),
            DeviceType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Geographic location derived from IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// City name (e.g., "Paris")
    pub city: Option<String>,

    /// Country name or code (e.g., "France", "FR")
    pub country: String,
}

impl Location {
    /// Format location as a display string
    pub fn display(&self) -> String {
        match &self.city {
            Some(city) => format!("{}, {}", city, self.country),
            None => self.country.clone(),
        }
    }
}

/// Represents an active authentication session from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSession {
    /// Unique session identifier
    pub id: Uuid,

    /// User-friendly device name (e.g., "MacBook Pro")
    pub device_name: String,

    /// Device category
    pub device_type: DeviceType,

    /// Operating system (e.g., "macOS 14.0", "Windows 11")
    #[serde(default)]
    pub os: Option<String>,

    /// Client application / browser (e.g., "xavyo-cli v0.1.0", "Chrome 120")
    #[serde(default, alias = "browser")]
    pub client: Option<String>,

    /// IP address of the session
    pub ip_address: String,

    /// Geographic location derived from IP
    #[serde(default)]
    pub location: Option<Location>,

    /// When the session was created (login time)
    pub created_at: DateTime<Utc>,

    /// Last API activity timestamp
    pub last_activity_at: DateTime<Utc>,

    /// Whether this is the current CLI session
    pub is_current: bool,
}

/// Response from list sessions API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListResponse {
    /// List of active sessions
    pub sessions: Vec<ApiSession>,

    /// Total number of sessions
    #[serde(default)]
    pub total: u32,

    /// Whether more sessions exist (pagination)
    #[serde(default)]
    pub has_more: bool,

    /// Cursor for next page
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Response from revoke session API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    /// Number of sessions revoked
    pub revoked_count: u32,

    /// IDs of revoked sessions
    pub session_ids: Vec<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_display() {
        assert_eq!(DeviceType::Desktop.to_string(), "desktop");
        assert_eq!(DeviceType::Mobile.to_string(), "mobile");
        assert_eq!(DeviceType::Cli.to_string(), "cli");
        assert_eq!(DeviceType::Browser.to_string(), "browser");
        assert_eq!(DeviceType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_device_type_serde() {
        let json = r#""desktop""#;
        let dt: DeviceType = serde_json::from_str(json).unwrap();
        assert_eq!(dt, DeviceType::Desktop);

        let json = r#""cli""#;
        let dt: DeviceType = serde_json::from_str(json).unwrap();
        assert_eq!(dt, DeviceType::Cli);
    }

    #[test]
    fn test_location_display() {
        let loc = Location {
            city: Some("Paris".to_string()),
            country: "France".to_string(),
        };
        assert_eq!(loc.display(), "Paris, France");

        let loc = Location {
            city: None,
            country: "France".to_string(),
        };
        assert_eq!(loc.display(), "France");
    }

    #[test]
    fn test_api_session_deserialization() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "device_name": "MacBook Pro",
            "device_type": "desktop",
            "os": "macOS 14.0",
            "client": "xavyo-cli v0.1.0",
            "ip_address": "192.168.1.1",
            "location": {
                "city": "Paris",
                "country": "France"
            },
            "created_at": "2026-02-04T10:00:00Z",
            "last_activity_at": "2026-02-04T12:00:00Z",
            "is_current": true
        }"#;

        let session: ApiSession = serde_json::from_str(json).unwrap();
        assert_eq!(session.device_name, "MacBook Pro");
        assert_eq!(session.device_type, DeviceType::Desktop);
        assert!(session.is_current);
        assert_eq!(
            session.location.as_ref().unwrap().city,
            Some("Paris".to_string())
        );
    }

    #[test]
    fn test_session_list_response_deserialization() {
        let json = r#"{
            "sessions": [],
            "total": 0,
            "has_more": false
        }"#;

        let response: SessionListResponse = serde_json::from_str(json).unwrap();
        assert!(response.sessions.is_empty());
        assert_eq!(response.total, 0);
        assert!(!response.has_more);
        assert!(response.next_cursor.is_none());
    }

    #[test]
    fn test_revoke_response_deserialization() {
        let json = r#"{
            "revoked_count": 2,
            "session_ids": [
                "550e8400-e29b-41d4-a716-446655440001",
                "550e8400-e29b-41d4-a716-446655440002"
            ]
        }"#;

        let response: RevokeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.revoked_count, 2);
        assert_eq!(response.session_ids.len(), 2);
    }
}
