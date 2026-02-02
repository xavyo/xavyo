//! Shared types and enums for SIEM integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// SIEM destination type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationType {
    /// Syslog over TCP with TLS
    SyslogTcpTls,
    /// Syslog over UDP
    SyslogUdp,
    /// HTTP POST webhook
    Webhook,
    /// Splunk HTTP Event Collector
    SplunkHec,
}

impl DestinationType {
    /// Default port for this destination type.
    pub fn default_port(&self) -> u16 {
        match self {
            Self::SyslogTcpTls => 6514,
            Self::SyslogUdp => 514,
            Self::Webhook => 443,
            Self::SplunkHec => 8088,
        }
    }

    /// String representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SyslogTcpTls => "syslog_tcp_tls",
            Self::SyslogUdp => "syslog_udp",
            Self::Webhook => "webhook",
            Self::SplunkHec => "splunk_hec",
        }
    }

    /// Parse from database string.
    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "syslog_tcp_tls" => Some(Self::SyslogTcpTls),
            "syslog_udp" => Some(Self::SyslogUdp),
            "webhook" => Some(Self::Webhook),
            "splunk_hec" => Some(Self::SplunkHec),
            _ => None,
        }
    }
}

/// Export format for SIEM events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Common Event Format v0
    Cef,
    /// RFC 5424 structured syslog
    SyslogRfc5424,
    /// JSON structured output
    Json,
    /// CSV (batch export only)
    Csv,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cef => "cef",
            Self::SyslogRfc5424 => "syslog_rfc5424",
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "cef" => Some(Self::Cef),
            "syslog_rfc5424" => Some(Self::SyslogRfc5424),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

/// Delivery status for export events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    DeadLetter,
    Dropped,
}

impl DeliveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::DeadLetter => "dead_letter",
            Self::Dropped => "dropped",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "delivered" => Some(Self::Delivered),
            "failed" => Some(Self::Failed),
            "dead_letter" => Some(Self::DeadLetter),
            "dropped" => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation — deliveries proceed
    Closed,
    /// Tripped — deliveries blocked
    Open,
    /// Probing — single delivery attempt allowed
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "closed" => Some(Self::Closed),
            "open" => Some(Self::Open),
            "half_open" => Some(Self::HalfOpen),
            _ => None,
        }
    }
}

/// Batch export status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchExportStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl BatchExportStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "processing" => Some(Self::Processing),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Event category for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    UserLifecycle,
    GroupChanges,
    AccessRequests,
    Provisioning,
    Administrative,
    Security,
    Entitlement,
    SodViolation,
}

impl EventCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::UserLifecycle => "user_lifecycle",
            Self::GroupChanges => "group_changes",
            Self::AccessRequests => "access_requests",
            Self::Provisioning => "provisioning",
            Self::Administrative => "administrative",
            Self::Security => "security",
            Self::Entitlement => "entitlement",
            Self::SodViolation => "sod_violation",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "authentication" => Some(Self::Authentication),
            "user_lifecycle" => Some(Self::UserLifecycle),
            "group_changes" => Some(Self::GroupChanges),
            "access_requests" => Some(Self::AccessRequests),
            "provisioning" => Some(Self::Provisioning),
            "administrative" => Some(Self::Administrative),
            "security" => Some(Self::Security),
            "entitlement" => Some(Self::Entitlement),
            "sod_violation" => Some(Self::SodViolation),
            _ => None,
        }
    }

    /// CEF severity mapping based on event category.
    /// 0-3: low/informational, 4-6: medium, 7-10: high
    pub fn default_severity(&self) -> u8 {
        match self {
            Self::SodViolation => 9,
            Self::Security => 8,
            Self::Authentication => 5,
            Self::AccessRequests => 4,
            Self::Entitlement => 4,
            Self::UserLifecycle => 3,
            Self::GroupChanges => 3,
            Self::Administrative => 3,
            Self::Provisioning => 2,
        }
    }
}

/// A SIEM event ready for formatting and delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// Unique event identifier
    pub event_id: Uuid,
    /// Event type / class identifier (e.g., "AUTH_FAILURE", "USER_CREATED")
    pub event_type: String,
    /// Event category
    pub category: EventCategory,
    /// Tenant identifier
    pub tenant_id: Uuid,
    /// Actor who performed the action
    pub actor_id: Option<Uuid>,
    /// Actor email/username
    pub actor_email: Option<String>,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Severity (0-10 CEF scale)
    pub severity: u8,
    /// Human-readable event name
    pub event_name: String,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Target user (for user-affecting events)
    pub target_user: Option<String>,
    /// Target resource
    pub target_resource: Option<String>,
    /// Action performed
    pub action: String,
    /// Outcome (Success/Failure)
    pub outcome: String,
    /// Reason for outcome (e.g., "InvalidCredentials")
    pub reason: Option<String>,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// Request ID
    pub request_id: Option<String>,
    /// Additional metadata as key-value pairs
    pub metadata: HashMap<String, String>,
}

impl SiemEvent {
    /// Get severity label for display.
    pub fn severity_label(&self) -> &'static str {
        match self.severity {
            0 => "Informational",
            1..=3 => "Low",
            4..=6 => "Medium",
            7..=8 => "High",
            9..=10 => "Critical",
            _ => "Unknown",
        }
    }
}

/// Product information for CEF/syslog headers.
pub const PRODUCT_VENDOR: &str = "Xavyo";
pub const PRODUCT_NAME: &str = "IDP";
pub const PRODUCT_VERSION: &str = "1.0.0";

/// IANA Private Enterprise Number placeholder for syslog structured data.
pub const SYSLOG_PEN: &str = "99999";

/// Default syslog hostname.
pub const SYSLOG_HOSTNAME: &str = "idp.xavyo.net";

/// Default syslog app name.
pub const SYSLOG_APP_NAME: &str = "xavyo";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_type_roundtrip() {
        for dt in [
            DestinationType::SyslogTcpTls,
            DestinationType::SyslogUdp,
            DestinationType::Webhook,
            DestinationType::SplunkHec,
        ] {
            let s = dt.as_str();
            assert_eq!(DestinationType::from_str_value(s), Some(dt));
        }
    }

    #[test]
    fn test_export_format_roundtrip() {
        for fmt in [
            ExportFormat::Cef,
            ExportFormat::SyslogRfc5424,
            ExportFormat::Json,
            ExportFormat::Csv,
        ] {
            let s = fmt.as_str();
            assert_eq!(ExportFormat::from_str_value(s), Some(fmt));
        }
    }

    #[test]
    fn test_delivery_status_roundtrip() {
        for status in [
            DeliveryStatus::Pending,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::DeadLetter,
            DeliveryStatus::Dropped,
        ] {
            let s = status.as_str();
            assert_eq!(DeliveryStatus::from_str_value(s), Some(status));
        }
    }

    #[test]
    fn test_circuit_state_roundtrip() {
        for state in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let s = state.as_str();
            assert_eq!(CircuitState::from_str_value(s), Some(state));
        }
    }

    #[test]
    fn test_event_category_severity() {
        assert!(EventCategory::SodViolation.default_severity() >= 7);
        assert!(EventCategory::Security.default_severity() >= 7);
        assert!((4..=6).contains(&EventCategory::Authentication.default_severity()));
        assert!(EventCategory::Provisioning.default_severity() <= 3);
    }

    #[test]
    fn test_severity_label() {
        let mut event = SiemEvent {
            event_id: Uuid::new_v4(),
            event_type: "TEST".to_string(),
            category: EventCategory::Authentication,
            tenant_id: Uuid::new_v4(),
            actor_id: None,
            actor_email: None,
            timestamp: Utc::now(),
            severity: 0,
            event_name: "Test".to_string(),
            source_ip: None,
            target_user: None,
            target_resource: None,
            action: "test".to_string(),
            outcome: "Success".to_string(),
            reason: None,
            session_id: None,
            request_id: None,
            metadata: HashMap::new(),
        };
        assert_eq!(event.severity_label(), "Informational");
        event.severity = 2;
        assert_eq!(event.severity_label(), "Low");
        event.severity = 5;
        assert_eq!(event.severity_label(), "Medium");
        event.severity = 8;
        assert_eq!(event.severity_label(), "High");
        event.severity = 10;
        assert_eq!(event.severity_label(), "Critical");
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(DestinationType::SyslogTcpTls.default_port(), 6514);
        assert_eq!(DestinationType::SyslogUdp.default_port(), 514);
        assert_eq!(DestinationType::Webhook.default_port(), 443);
        assert_eq!(DestinationType::SplunkHec.default_port(), 8088);
    }
}
