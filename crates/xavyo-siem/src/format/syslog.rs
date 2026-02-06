//! RFC 5424 syslog formatter.

use crate::format::{EventFormatter, FormatError};
use crate::models::{SiemEvent, SYSLOG_APP_NAME, SYSLOG_HOSTNAME, SYSLOG_PEN};

/// Syslog facility codes.
/// Default: `AUTH_PRIV` (10)
#[allow(dead_code)]
const DEFAULT_FACILITY: u8 = 10;

/// RFC 5424 syslog formatter.
pub struct SyslogFormatter {
    facility: u8,
    hostname: String,
}

impl SyslogFormatter {
    #[must_use]
    pub fn new(facility: u8, hostname: Option<String>) -> Self {
        Self {
            facility,
            hostname: hostname.unwrap_or_else(|| SYSLOG_HOSTNAME.to_string()),
        }
    }

    /// Calculate PRI value: facility * 8 + severity
    fn calculate_pri(&self, severity: u8) -> u16 {
        u16::from(self.facility) * 8 + u16::from(Self::map_severity(severity))
    }

    /// Map CEF severity (0-10) to syslog severity (0-7).
    /// Syslog: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
    fn map_severity(cef_severity: u8) -> u8 {
        match cef_severity {
            9..=10 => 2, // Critical
            7..=8 => 3,  // Error
            5..=6 => 4,  // Warning
            3..=4 => 5,  // Notice
            1..=2 => 6,  // Informational
            0 => 7,      // Debug
            _ => 6,      // Default: Informational
        }
    }

    /// Format structured data element per RFC 5424.
    /// [xavyo@PEN key="value" ...]
    fn format_structured_data(event: &SiemEvent) -> String {
        let mut sd = format!("[xavyo@{SYSLOG_PEN}");

        sd.push_str(&format!(
            " tenant_id=\"{}\"",
            Self::escape_sd_value(&event.tenant_id.to_string())
        ));

        if let Some(ref session_id) = event.session_id {
            sd.push_str(&format!(
                " session_id=\"{}\"",
                Self::escape_sd_value(&session_id.to_string())
            ));
        }

        sd.push_str(&format!(
            " action=\"{}\"",
            Self::escape_sd_value(&event.action)
        ));
        sd.push_str(&format!(
            " outcome=\"{}\"",
            Self::escape_sd_value(&event.outcome)
        ));

        if let Some(ref ip) = event.source_ip {
            sd.push_str(&format!(" source_ip=\"{}\"", Self::escape_sd_value(ip)));
        }

        if let Some(ref target) = event.target_user {
            sd.push_str(&format!(
                " target_user=\"{}\"",
                Self::escape_sd_value(target)
            ));
        }

        sd.push(']');
        sd
    }

    /// Escape SD-VALUE per RFC 5424: escape \, ", ]
    fn escape_sd_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(']', "\\]")
    }

    /// Format timestamp as ISO 8601 with milliseconds per RFC 5424.
    fn format_timestamp(event: &SiemEvent) -> String {
        event.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    }
}

impl EventFormatter for SyslogFormatter {
    fn format(&self, event: &SiemEvent) -> Result<String, FormatError> {
        let pri = self.calculate_pri(event.severity);
        let timestamp = Self::format_timestamp(event);
        let structured_data = Self::format_structured_data(event);

        // Build human-readable message
        let msg = if let Some(ref target) = event.target_user {
            if let Some(ref ip) = event.source_ip {
                format!("{} for user {} from {}", event.event_name, target, ip)
            } else {
                format!("{} for user {}", event.event_name, target)
            }
        } else {
            event.event_name.clone()
        };

        // RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
        let output = format!(
            "<{}>1 {} {} {} {} {} {} {}",
            pri,
            timestamp,
            self.hostname,
            SYSLOG_APP_NAME,
            std::process::id(),
            event.event_type,
            structured_data,
            msg
        );

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventCategory;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn sample_event() -> SiemEvent {
        SiemEvent {
            event_id: Uuid::new_v4(),
            event_type: "AUTH_FAILURE".to_string(),
            category: EventCategory::Authentication,
            tenant_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            actor_id: Some(Uuid::new_v4()),
            actor_email: Some("test@example.com".to_string()),
            timestamp: Utc::now(),
            severity: 6,
            event_name: "Authentication Failed".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            target_user: Some("test@example.com".to_string()),
            target_resource: None,
            action: "Login".to_string(),
            outcome: "Failure".to_string(),
            reason: Some("InvalidCredentials".to_string()),
            session_id: Some(Uuid::new_v4()),
            request_id: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_syslog_message_structure() {
        let formatter = SyslogFormatter::new(10, None);
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        // Should start with <PRI>1
        assert!(output.starts_with('<'));
        assert!(output.contains(">1 "));
        assert!(output.contains("idp.xavyo.net"));
        assert!(output.contains("xavyo"));
        assert!(output.contains("AUTH_FAILURE"));
    }

    #[test]
    fn test_syslog_pri_calculation() {
        let formatter = SyslogFormatter::new(10, None);
        // facility=10 (AUTH_PRIV), severity=6 → syslog_severity=4 (Warning)
        // PRI = 10*8 + 4 = 84
        let pri = formatter.calculate_pri(6);
        assert_eq!(pri, 84);
    }

    #[test]
    fn test_syslog_pri_with_different_facilities() {
        // facility=4 (AUTH), severity=9 → syslog_severity=2 (Critical)
        let formatter = SyslogFormatter::new(4, None);
        let pri = formatter.calculate_pri(9);
        assert_eq!(pri, 4 * 8 + 2); // 34
    }

    #[test]
    fn test_syslog_severity_mapping() {
        assert_eq!(SyslogFormatter::map_severity(10), 2); // Critical
        assert_eq!(SyslogFormatter::map_severity(9), 2); // Critical
        assert_eq!(SyslogFormatter::map_severity(8), 3); // Error
        assert_eq!(SyslogFormatter::map_severity(5), 4); // Warning
        assert_eq!(SyslogFormatter::map_severity(3), 5); // Notice
        assert_eq!(SyslogFormatter::map_severity(1), 6); // Informational
        assert_eq!(SyslogFormatter::map_severity(0), 7); // Debug
    }

    #[test]
    fn test_syslog_structured_data_format() {
        let event = sample_event();
        let sd = SyslogFormatter::format_structured_data(&event);

        assert!(sd.starts_with("[xavyo@99999"));
        assert!(sd.ends_with(']'));
        assert!(sd.contains("tenant_id=\"550e8400-e29b-41d4-a716-446655440000\""));
        assert!(sd.contains("action=\"Login\""));
        assert!(sd.contains("outcome=\"Failure\""));
        assert!(sd.contains("source_ip=\"192.168.1.100\""));
        assert!(sd.contains("target_user=\"test@example.com\""));
    }

    #[test]
    fn test_syslog_timestamp_format() {
        let event = sample_event();
        let ts = SyslogFormatter::format_timestamp(&event);
        // Should be ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn test_syslog_sd_value_escaping() {
        assert_eq!(
            SyslogFormatter::escape_sd_value(r#"value with " and ] and \"#),
            r#"value with \" and \] and \\"#
        );
    }

    #[test]
    fn test_syslog_message_includes_human_readable() {
        let formatter = SyslogFormatter::new(10, None);
        let event = sample_event();
        let output = formatter.format(&event).unwrap();

        assert!(
            output.contains("Authentication Failed for user test@example.com from 192.168.1.100")
        );
    }
}
