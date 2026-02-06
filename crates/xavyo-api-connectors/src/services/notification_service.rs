//! Notification Service for F046 Schema Discovery.
//!
//! Sends notifications when schema changes are detected during automatic refreshes.
//! Currently supports email notifications via the configured SMTP service.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use xavyo_connector::schema::DiffSummary;

/// Errors that can occur during notification operations.
#[derive(Error, Debug)]
pub enum NotificationError {
    /// SMTP configuration error.
    #[error("SMTP configuration error: {0}")]
    ConfigurationError(String),

    /// Failed to send email.
    #[error("Failed to send email: {0}")]
    SendFailed(String),

    /// Template rendering error.
    #[error("Template error: {0}")]
    TemplateError(String),
}

/// Result type for notification operations.
pub type NotificationResult<T> = Result<T, NotificationError>;

/// Configuration for the notification service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Whether notifications are enabled.
    pub enabled: bool,
    /// SMTP host.
    pub smtp_host: Option<String>,
    /// SMTP port.
    pub smtp_port: Option<u16>,
    /// From email address.
    pub from_email: Option<String>,
    /// From name.
    pub from_name: Option<String>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: None,
            smtp_port: Some(587),
            from_email: None,
            from_name: Some("xavyo".to_string()),
        }
    }
}

/// Schema change notification details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaChangeNotification {
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name.
    pub connector_name: String,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Previous schema version.
    pub from_version: i32,
    /// New schema version.
    pub to_version: i32,
    /// Diff summary.
    pub summary: DiffSummary,
    /// Recipient email.
    pub recipient_email: String,
}

/// Service for sending schema change notifications.
pub struct NotificationService {
    config: NotificationConfig,
}

impl NotificationService {
    /// Create a new notification service.
    #[must_use]
    pub fn new(config: NotificationConfig) -> Self {
        Self { config }
    }

    /// Create a disabled notification service.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(NotificationConfig::default())
    }

    /// Check if notifications are enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Send a schema change notification.
    #[instrument(skip(self, notification))]
    pub async fn send_schema_change_notification(
        &self,
        notification: &SchemaChangeNotification,
    ) -> NotificationResult<()> {
        if !self.config.enabled {
            debug!("Notifications disabled, skipping");
            return Ok(());
        }

        // Validate configuration
        let _smtp_host = self.config.smtp_host.as_ref().ok_or_else(|| {
            NotificationError::ConfigurationError("SMTP host not configured".to_string())
        })?;

        let _from_email = self.config.from_email.as_ref().ok_or_else(|| {
            NotificationError::ConfigurationError("From email not configured".to_string())
        })?;

        // Build email subject
        let subject = format!(
            "Schema changes detected for connector: {}",
            notification.connector_name
        );

        // Build email body
        let body = format!(
            r#"Schema changes have been detected for connector "{}" (ID: {}).

Version: {} -> {}

Summary:
- Object classes added: {}
- Object classes removed: {}
- Attributes added: {}
- Attributes removed: {}
- Attributes modified: {}
- Breaking changes: {}

Please review the changes in the xavyo administration console.

This is an automated message. Do not reply to this email.
"#,
            notification.connector_name,
            notification.connector_id,
            notification.from_version,
            notification.to_version,
            notification.summary.object_classes_added,
            notification.summary.object_classes_removed,
            notification.summary.attributes_added,
            notification.summary.attributes_removed,
            notification.summary.attributes_modified,
            if notification.summary.has_breaking_changes {
                "Yes"
            } else {
                "No"
            }
        );

        info!(
            connector_id = %notification.connector_id,
            recipient = %notification.recipient_email,
            subject = %subject,
            "Sending schema change notification"
        );

        // SMTP sending is not yet implemented (requires lettre integration).
        // Return an error so callers know the email was NOT actually sent.
        warn!(
            connector_id = %notification.connector_id,
            recipient = %notification.recipient_email,
            subject = %subject,
            "Email notification skipped: SMTP not configured. \
             Schema change notification was NOT delivered to recipient."
        );

        debug!(body = %body, "Notification body that was not sent");

        Err(NotificationError::SendFailed(
            "Email notification skipped: SMTP sending not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_config_default() {
        let config = NotificationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.smtp_port, Some(587));
        assert_eq!(config.from_name, Some("xavyo".to_string()));
    }

    #[test]
    fn test_notification_service_disabled() {
        let service = NotificationService::disabled();
        assert!(!service.is_enabled());
    }

    #[test]
    fn test_schema_change_notification() {
        let notification = SchemaChangeNotification {
            connector_id: Uuid::new_v4(),
            connector_name: "Test LDAP".to_string(),
            tenant_id: Uuid::new_v4(),
            from_version: 1,
            to_version: 2,
            summary: DiffSummary {
                object_classes_added: 1,
                object_classes_removed: 0,
                attributes_added: 5,
                attributes_removed: 1,
                attributes_modified: 3,
                has_breaking_changes: true,
            },
            recipient_email: "admin@example.com".to_string(),
        };

        assert_eq!(notification.from_version, 1);
        assert_eq!(notification.to_version, 2);
        assert!(notification.summary.has_breaking_changes);
    }

    #[tokio::test]
    async fn test_send_notification_disabled() {
        let service = NotificationService::disabled();
        let notification = SchemaChangeNotification {
            connector_id: Uuid::new_v4(),
            connector_name: "Test".to_string(),
            tenant_id: Uuid::new_v4(),
            from_version: 1,
            to_version: 2,
            summary: DiffSummary::default(),
            recipient_email: "test@example.com".to_string(),
        };

        // Should succeed (no-op) when disabled
        let result = service.send_schema_change_notification(&notification).await;
        assert!(result.is_ok());
    }
}
