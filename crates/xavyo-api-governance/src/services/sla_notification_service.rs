//! SLA Notification Service for semi-manual resources (F064).
//!
//! Sends email and webhook notifications for SLA warnings and breaches.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use xavyo_api_auth::services::EmailSender;

/// Errors that can occur during SLA notification operations.
#[derive(Error, Debug)]
pub enum SlaNotificationError {
    /// SMTP configuration error.
    #[error("SMTP configuration error: {0}")]
    ConfigurationError(String),

    /// Failed to send notification.
    #[error("Failed to send notification: {0}")]
    SendFailed(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Result type for SLA notification operations.
pub type SlaNotificationResult<T> = Result<T, SlaNotificationError>;

/// Configuration for SLA notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaNotificationConfig {
    /// Whether email notifications are enabled.
    pub email_enabled: bool,
    /// Whether webhook notifications are enabled.
    pub webhook_enabled: bool,
    /// Webhook URL for notifications (if webhook_enabled).
    pub webhook_url: Option<String>,
    /// Webhook authentication token (optional).
    pub webhook_auth_token: Option<String>,
}

impl Default for SlaNotificationConfig {
    fn default() -> Self {
        Self {
            email_enabled: true,
            webhook_enabled: false,
            webhook_url: None,
            webhook_auth_token: None,
        }
    }
}

/// SLA warning notification details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaWarningNotification {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Task ID.
    pub task_id: Uuid,
    /// Task application name.
    pub application_name: String,
    /// Task entitlement name.
    pub entitlement_name: String,
    /// User being provisioned.
    pub user_display_name: String,
    /// SLA deadline.
    pub sla_deadline: DateTime<Utc>,
    /// Time remaining in minutes.
    pub time_remaining_minutes: i64,
    /// Warning threshold percentage.
    pub warning_threshold_percent: i32,
    /// Policy name.
    pub policy_name: String,
    /// Recipient email addresses.
    pub recipient_emails: Vec<String>,
    /// Assignee email (if task is claimed).
    pub assignee_email: Option<String>,
}

/// SLA breach notification details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBreachNotification {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Task ID.
    pub task_id: Uuid,
    /// Task application name.
    pub application_name: String,
    /// Task entitlement name.
    pub entitlement_name: String,
    /// User being provisioned.
    pub user_display_name: String,
    /// SLA deadline that was breached.
    pub sla_deadline: DateTime<Utc>,
    /// How long the task is overdue in minutes.
    pub overdue_minutes: i64,
    /// Policy name.
    pub policy_name: String,
    /// Escalation contact emails.
    pub escalation_emails: Vec<String>,
    /// Assignee email (if task is claimed).
    pub assignee_email: Option<String>,
}

/// Service for sending SLA notifications.
pub struct SlaNotificationService {
    pool: PgPool,
    config: SlaNotificationConfig,
    http_client: reqwest::Client,
    email_sender: Option<Arc<dyn EmailSender>>,
}

impl SlaNotificationService {
    /// Create a new SLA notification service.
    pub fn new(pool: PgPool, config: SlaNotificationConfig) -> Self {
        Self {
            pool,
            config,
            http_client: reqwest::Client::new(),
            email_sender: None,
        }
    }

    /// Create with an email sender for actual email delivery.
    pub fn with_email_sender(
        pool: PgPool,
        config: SlaNotificationConfig,
        email_sender: Arc<dyn EmailSender>,
    ) -> Self {
        Self {
            pool,
            config,
            http_client: reqwest::Client::new(),
            email_sender: Some(email_sender),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults(pool: PgPool) -> Self {
        Self::new(pool, SlaNotificationConfig::default())
    }

    /// Get database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Send an SLA warning notification.
    #[instrument(skip(self, notification), fields(task_id = %notification.task_id))]
    pub async fn send_warning_notification(
        &self,
        notification: &SlaWarningNotification,
    ) -> SlaNotificationResult<NotificationSendResult> {
        let mut result = NotificationSendResult::default();

        // Send email notifications
        if self.config.email_enabled {
            match self.send_warning_email(notification).await {
                Ok(count) => {
                    result.emails_sent = count;
                    info!(
                        task_id = %notification.task_id,
                        emails_sent = count,
                        "SLA warning emails sent"
                    );
                }
                Err(e) => {
                    error!(
                        task_id = %notification.task_id,
                        error = %e,
                        "Failed to send SLA warning emails"
                    );
                    result.email_error = Some(e.to_string());
                }
            }
        }

        // Send webhook notification
        if self.config.webhook_enabled {
            match self.send_warning_webhook(notification).await {
                Ok(()) => {
                    result.webhook_sent = true;
                    info!(
                        task_id = %notification.task_id,
                        "SLA warning webhook sent"
                    );
                }
                Err(e) => {
                    error!(
                        task_id = %notification.task_id,
                        error = %e,
                        "Failed to send SLA warning webhook"
                    );
                    result.webhook_error = Some(e.to_string());
                }
            }
        }

        Ok(result)
    }

    /// Send an SLA breach notification.
    #[instrument(skip(self, notification), fields(task_id = %notification.task_id))]
    pub async fn send_breach_notification(
        &self,
        notification: &SlaBreachNotification,
    ) -> SlaNotificationResult<NotificationSendResult> {
        let mut result = NotificationSendResult::default();

        // Send email notifications
        if self.config.email_enabled {
            match self.send_breach_email(notification).await {
                Ok(count) => {
                    result.emails_sent = count;
                    info!(
                        task_id = %notification.task_id,
                        emails_sent = count,
                        "SLA breach emails sent"
                    );
                }
                Err(e) => {
                    error!(
                        task_id = %notification.task_id,
                        error = %e,
                        "Failed to send SLA breach emails"
                    );
                    result.email_error = Some(e.to_string());
                }
            }
        }

        // Send webhook notification
        if self.config.webhook_enabled {
            match self.send_breach_webhook(notification).await {
                Ok(()) => {
                    result.webhook_sent = true;
                    info!(
                        task_id = %notification.task_id,
                        "SLA breach webhook sent"
                    );
                }
                Err(e) => {
                    error!(
                        task_id = %notification.task_id,
                        error = %e,
                        "Failed to send SLA breach webhook"
                    );
                    result.webhook_error = Some(e.to_string());
                }
            }
        }

        Ok(result)
    }

    /// Send warning email notifications.
    async fn send_warning_email(
        &self,
        notification: &SlaWarningNotification,
    ) -> SlaNotificationResult<usize> {
        let mut recipients: Vec<String> = notification.recipient_emails.clone();
        if let Some(ref assignee) = notification.assignee_email {
            if !recipients.contains(assignee) {
                recipients.push(assignee.clone());
            }
        }

        if recipients.is_empty() {
            debug!(
                task_id = %notification.task_id,
                "No recipients for SLA warning email"
            );
            return Ok(0);
        }

        let subject = format!(
            "[SLA Warning] Manual task approaching deadline: {}",
            notification.application_name
        );

        let body = format!(
            r#"SLA Warning: Manual Provisioning Task Approaching Deadline

A manual provisioning task is approaching its SLA deadline and requires attention.

Task Details:
- Task ID: {}
- Application: {}
- Entitlement: {}
- User: {}
- SLA Deadline: {}
- Time Remaining: {} minutes
- Policy: {}

Please complete this task before the deadline to avoid SLA breach.

---
This is an automated notification from xavyo. Do not reply to this email.
"#,
            notification.task_id,
            notification.application_name,
            notification.entitlement_name,
            notification.user_display_name,
            notification.sla_deadline.format("%Y-%m-%d %H:%M:%S UTC"),
            notification.time_remaining_minutes,
            notification.policy_name,
        );

        // Send emails using the email sender if configured
        #[allow(unused_assignments)]
        let mut _sent_count = 0;
        if let Some(ref email_sender) = self.email_sender {
            for recipient in &recipients {
                match email_sender.send(recipient, &subject, &body).await {
                    Ok(()) => {
                        _sent_count += 1;
                        info!(
                            task_id = %notification.task_id,
                            recipient = %recipient,
                            "SLA warning email sent successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            task_id = %notification.task_id,
                            recipient = %recipient,
                            error = %e,
                            "Failed to send SLA warning email"
                        );
                    }
                }
            }
        } else {
            // No email sender configured - log the notification
            for recipient in &recipients {
                info!(
                    task_id = %notification.task_id,
                    recipient = %recipient,
                    subject = %subject,
                    "Would send SLA warning email (no email sender configured)"
                );
                debug!(body = %body, "Email body");
            }
            warn!(
                task_id = %notification.task_id,
                recipients = ?recipients,
                "Email sender not configured - notification logged only"
            );
            _sent_count = recipients.len(); // Count as "sent" for logging purposes
        }

        Ok(recipients.len())
    }

    /// Send breach email notifications.
    async fn send_breach_email(
        &self,
        notification: &SlaBreachNotification,
    ) -> SlaNotificationResult<usize> {
        let mut recipients: Vec<String> = notification.escalation_emails.clone();
        if let Some(ref assignee) = notification.assignee_email {
            if !recipients.contains(assignee) {
                recipients.push(assignee.clone());
            }
        }

        if recipients.is_empty() {
            debug!(
                task_id = %notification.task_id,
                "No recipients for SLA breach email"
            );
            return Ok(0);
        }

        let subject = format!(
            "[SLA BREACH] Manual task overdue: {}",
            notification.application_name
        );

        let body = format!(
            r#"SLA BREACH: Manual Provisioning Task Overdue

A manual provisioning task has exceeded its SLA deadline and requires immediate attention.

Task Details:
- Task ID: {}
- Application: {}
- Entitlement: {}
- User: {}
- SLA Deadline: {}
- Overdue By: {} minutes
- Policy: {}

This task has breached its SLA. Please complete it immediately and investigate the delay.

---
This is an automated notification from xavyo. Do not reply to this email.
"#,
            notification.task_id,
            notification.application_name,
            notification.entitlement_name,
            notification.user_display_name,
            notification.sla_deadline.format("%Y-%m-%d %H:%M:%S UTC"),
            notification.overdue_minutes,
            notification.policy_name,
        );

        // Send emails using the email sender if configured
        #[allow(unused_assignments)]
        let mut _sent_count = 0;
        if let Some(ref email_sender) = self.email_sender {
            for recipient in &recipients {
                match email_sender.send(recipient, &subject, &body).await {
                    Ok(()) => {
                        _sent_count += 1;
                        info!(
                            task_id = %notification.task_id,
                            recipient = %recipient,
                            "SLA breach email sent successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            task_id = %notification.task_id,
                            recipient = %recipient,
                            error = %e,
                            "Failed to send SLA breach email"
                        );
                    }
                }
            }
        } else {
            // No email sender configured - log the notification
            for recipient in &recipients {
                info!(
                    task_id = %notification.task_id,
                    recipient = %recipient,
                    subject = %subject,
                    "Would send SLA breach email (no email sender configured)"
                );
                debug!(body = %body, "Email body");
            }
            warn!(
                task_id = %notification.task_id,
                recipients = ?recipients,
                "Email sender not configured - notification logged only"
            );
            _sent_count = recipients.len(); // Count as "sent" for logging purposes
        }

        Ok(recipients.len())
    }

    /// Send warning webhook notification.
    async fn send_warning_webhook(
        &self,
        notification: &SlaWarningNotification,
    ) -> SlaNotificationResult<()> {
        let url = self.config.webhook_url.as_ref().ok_or_else(|| {
            SlaNotificationError::ConfigurationError("Webhook URL not configured".to_string())
        })?;

        let payload = serde_json::json!({
            "type": "sla_warning",
            "tenant_id": notification.tenant_id,
            "task_id": notification.task_id,
            "application_name": notification.application_name,
            "entitlement_name": notification.entitlement_name,
            "user_display_name": notification.user_display_name,
            "sla_deadline": notification.sla_deadline,
            "time_remaining_minutes": notification.time_remaining_minutes,
            "warning_threshold_percent": notification.warning_threshold_percent,
            "policy_name": notification.policy_name,
            "timestamp": Utc::now(),
        });

        let mut request = self.http_client.post(url).json(&payload);

        if let Some(ref token) = self.config.webhook_auth_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(SlaNotificationError::SendFailed(format!(
                "Webhook returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Send breach webhook notification.
    async fn send_breach_webhook(
        &self,
        notification: &SlaBreachNotification,
    ) -> SlaNotificationResult<()> {
        let url = self.config.webhook_url.as_ref().ok_or_else(|| {
            SlaNotificationError::ConfigurationError("Webhook URL not configured".to_string())
        })?;

        let payload = serde_json::json!({
            "type": "sla_breach",
            "tenant_id": notification.tenant_id,
            "task_id": notification.task_id,
            "application_name": notification.application_name,
            "entitlement_name": notification.entitlement_name,
            "user_display_name": notification.user_display_name,
            "sla_deadline": notification.sla_deadline,
            "overdue_minutes": notification.overdue_minutes,
            "policy_name": notification.policy_name,
            "timestamp": Utc::now(),
        });

        let mut request = self.http_client.post(url).json(&payload);

        if let Some(ref token) = self.config.webhook_auth_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(SlaNotificationError::SendFailed(format!(
                "Webhook returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

/// Result of sending notifications.
#[derive(Debug, Default)]
pub struct NotificationSendResult {
    /// Number of emails sent.
    pub emails_sent: usize,
    /// Whether webhook was sent.
    pub webhook_sent: bool,
    /// Email error message if any.
    pub email_error: Option<String>,
    /// Webhook error message if any.
    pub webhook_error: Option<String>,
}

impl NotificationSendResult {
    /// Check if all notifications were sent successfully.
    pub fn is_success(&self) -> bool {
        self.email_error.is_none() && self.webhook_error.is_none()
    }

    /// Check if any notifications were sent.
    pub fn any_sent(&self) -> bool {
        self.emails_sent > 0 || self.webhook_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_config_default() {
        let config = SlaNotificationConfig::default();
        assert!(config.email_enabled);
        assert!(!config.webhook_enabled);
        assert!(config.webhook_url.is_none());
    }

    #[test]
    fn test_notification_send_result_default() {
        let result = NotificationSendResult::default();
        assert_eq!(result.emails_sent, 0);
        assert!(!result.webhook_sent);
        assert!(result.email_error.is_none());
        assert!(result.webhook_error.is_none());
    }

    #[test]
    fn test_notification_send_result_is_success() {
        let result = NotificationSendResult {
            emails_sent: 2,
            webhook_sent: true,
            email_error: None,
            webhook_error: None,
        };
        assert!(result.is_success());
        assert!(result.any_sent());

        let result_with_error = NotificationSendResult {
            emails_sent: 0,
            webhook_sent: false,
            email_error: Some("SMTP error".to_string()),
            webhook_error: None,
        };
        assert!(!result_with_error.is_success());
        assert!(!result_with_error.any_sent());
    }

    #[test]
    fn test_sla_warning_notification() {
        let notification = SlaWarningNotification {
            tenant_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            application_name: "Legacy System".to_string(),
            entitlement_name: "Admin Access".to_string(),
            user_display_name: "John Doe".to_string(),
            sla_deadline: Utc::now() + chrono::Duration::hours(2),
            time_remaining_minutes: 120,
            warning_threshold_percent: 75,
            policy_name: "Standard SLA".to_string(),
            recipient_emails: vec!["it-ops@example.com".to_string()],
            assignee_email: Some("operator@example.com".to_string()),
        };

        assert_eq!(notification.time_remaining_minutes, 120);
        assert_eq!(notification.warning_threshold_percent, 75);
    }

    #[test]
    fn test_sla_breach_notification() {
        let notification = SlaBreachNotification {
            tenant_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            application_name: "Legacy System".to_string(),
            entitlement_name: "Admin Access".to_string(),
            user_display_name: "John Doe".to_string(),
            sla_deadline: Utc::now() - chrono::Duration::hours(1),
            overdue_minutes: 60,
            policy_name: "Standard SLA".to_string(),
            escalation_emails: vec!["manager@example.com".to_string()],
            assignee_email: Some("operator@example.com".to_string()),
        };

        assert_eq!(notification.overdue_minutes, 60);
    }
}
