//! Email service for sending password reset and verification emails.
//!
//! Provides a trait-based abstraction for email sending, allowing easy
//! swapping between SMTP, mock (for testing), and other implementations.

use async_trait::async_trait;
use lettre::{
    message::header::ContentType,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use parking_lot::Mutex;
use std::sync::Arc;
use xavyo_core::TenantId;

/// Errors that can occur during email sending.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    /// Failed to build the email message.
    #[error("Failed to build email: {0}")]
    BuildError(String),

    /// Failed to send the email.
    #[error("Failed to send email: {0}")]
    SendError(String),

    /// Invalid email address.
    #[error("Invalid email address: {0}")]
    InvalidAddress(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Configuration for email sending.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (typically 587 for TLS).
    pub smtp_port: u16,
    /// SMTP username for authentication.
    pub smtp_username: String,
    /// SMTP password for authentication.
    pub smtp_password: String,
    /// Email address to send from.
    pub from_address: String,
    /// Display name for the sender.
    pub from_name: String,
    /// Base URL for frontend links (e.g., `https://app.xavyo.com`).
    pub frontend_base_url: String,
    /// Path for password reset page (e.g., "/auth/reset-password").
    pub password_reset_path: String,
    /// Path for email verification page (e.g., "/auth/verify-email").
    pub email_verify_path: String,
    /// Path for magic link verification page (e.g., "/auth/passwordless/verify").
    pub magic_link_path: String,
}

impl EmailConfig {
    /// Create a new email configuration from environment variables.
    ///
    /// Required environment variables:
    /// - `EMAIL_SMTP_HOST`
    /// - `EMAIL_SMTP_PORT`
    /// - `EMAIL_SMTP_USERNAME`
    /// - `EMAIL_SMTP_PASSWORD`
    /// - `EMAIL_FROM_ADDRESS`
    /// - `EMAIL_FROM_NAME`
    /// - `FRONTEND_BASE_URL`
    ///
    /// Optional environment variables (with defaults):
    /// - `PASSWORD_RESET_PATH` (default: "/auth/reset-password")
    /// - `EMAIL_VERIFY_PATH` (default: "/auth/verify-email")
    pub fn from_env() -> Result<Self, EmailError> {
        Ok(Self {
            smtp_host: std::env::var("EMAIL_SMTP_HOST")
                .map_err(|_| EmailError::ConfigError("EMAIL_SMTP_HOST not set".to_string()))?,
            smtp_port: std::env::var("EMAIL_SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .map_err(|_| EmailError::ConfigError("Invalid EMAIL_SMTP_PORT".to_string()))?,
            smtp_username: std::env::var("EMAIL_SMTP_USERNAME")
                .map_err(|_| EmailError::ConfigError("EMAIL_SMTP_USERNAME not set".to_string()))?,
            smtp_password: std::env::var("EMAIL_SMTP_PASSWORD")
                .map_err(|_| EmailError::ConfigError("EMAIL_SMTP_PASSWORD not set".to_string()))?,
            from_address: std::env::var("EMAIL_FROM_ADDRESS")
                .map_err(|_| EmailError::ConfigError("EMAIL_FROM_ADDRESS not set".to_string()))?,
            from_name: std::env::var("EMAIL_FROM_NAME").unwrap_or_else(|_| "xavyo".to_string()),
            frontend_base_url: std::env::var("FRONTEND_BASE_URL")
                .map_err(|_| EmailError::ConfigError("FRONTEND_BASE_URL not set".to_string()))?,
            password_reset_path: std::env::var("PASSWORD_RESET_PATH")
                .unwrap_or_else(|_| "/auth/reset-password".to_string()),
            email_verify_path: std::env::var("EMAIL_VERIFY_PATH")
                .unwrap_or_else(|_| "/auth/verify-email".to_string()),
            magic_link_path: std::env::var("MAGIC_LINK_PATH")
                .unwrap_or_else(|_| "/auth/passwordless/verify".to_string()),
        })
    }

    /// Build the password reset URL.
    #[must_use]
    pub fn password_reset_url(&self, token: &str) -> String {
        format!(
            "{}{}?token={}",
            self.frontend_base_url, self.password_reset_path, token
        )
    }

    /// Build the email verification URL.
    #[must_use]
    pub fn email_verify_url(&self, token: &str) -> String {
        format!(
            "{}{}?token={}",
            self.frontend_base_url, self.email_verify_path, token
        )
    }

    /// Build the magic link verification URL.
    #[must_use]
    pub fn magic_link_url(&self, token: &str) -> String {
        format!(
            "{}{}?token={}",
            self.frontend_base_url, self.magic_link_path, token
        )
    }
}

/// Trait for sending emails.
///
/// Implementations can use SMTP, mock (for testing), or other backends.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send a password reset email.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `token` - The password reset token (not hashed)
    /// * `tenant_id` - The tenant ID (for logging/context)
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError>;

    /// Send an email verification email.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `token` - The email verification token (not hashed)
    /// * `tenant_id` - The tenant ID (for logging/context)
    async fn send_verification(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError>;

    /// Send a magic link email for passwordless authentication.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `token` - The magic link token (not hashed)
    /// * `tenant_id` - The tenant ID (for logging/context)
    async fn send_magic_link(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError>;

    /// Send an email OTP code for passwordless authentication.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `code` - The 6-digit OTP code (plaintext)
    /// * `tenant_id` - The tenant ID (for logging/context)
    async fn send_email_otp(
        &self,
        to: &str,
        code: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError>;

    /// Send a generic email with custom subject and body.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `subject` - Email subject
    /// * `body` - Email body (plain text)
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError>;
}

/// SMTP-based email sender implementation.
pub struct SmtpEmailSender {
    config: EmailConfig,
}

impl SmtpEmailSender {
    /// Create a new SMTP email sender.
    #[must_use] 
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    /// Create the SMTP transport.
    fn create_transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, EmailError> {
        let creds = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone(),
        );

        let tls_params = TlsParameters::new(self.config.smtp_host.clone())
            .map_err(|e| EmailError::ConfigError(format!("TLS configuration error: {e}")))?;

        AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_host)
            .map_err(|e| EmailError::ConfigError(format!("SMTP relay error: {e}")))?
            .port(self.config.smtp_port)
            .tls(Tls::Required(tls_params))
            .credentials(creds)
            .build()
            .pipe(Ok)
    }

    /// Build the "From" header mailbox.
    fn sender_mailbox(&self) -> Result<lettre::message::Mailbox, EmailError> {
        format!("{} <{}>", self.config.from_name, self.config.from_address)
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid from address: {e}")))
    }

    /// Build the password reset email body.
    fn password_reset_body(&self, token: &str) -> String {
        let url = self.config.password_reset_url(token);
        format!(
            r"Hi,

We received a request to reset your password for your Xavyo account.

Click the link below to reset your password:
{url}

This link will expire in 1 hour.

If you didn't request this, you can safely ignore this email.

- The xavyo Team"
        )
    }

    /// Build the magic link email body.
    fn magic_link_body(&self, token: &str) -> String {
        let url = self.config.magic_link_url(token);
        format!(
            r"Hi,

You requested to sign in to your Xavyo account using a magic link.

Click the link below to sign in:
{url}

This link will expire in 15 minutes and can only be used once.

If you didn't request this, you can safely ignore this email.

- The xavyo Team"
        )
    }

    /// Build the email OTP email body.
    fn email_otp_body(&self, code: &str) -> String {
        format!(
            r"Hi,

You requested to sign in to your Xavyo account using a one-time code.

Your verification code is: {code}

This code will expire in 10 minutes. You have 5 attempts to enter it correctly.

If you didn't request this, you can safely ignore this email.

- The xavyo Team"
        )
    }

    /// Build the email verification email body.
    fn verification_body(&self, token: &str) -> String {
        let url = self.config.email_verify_url(token);
        format!(
            r"Hi,

Welcome to Xavyo! Please verify your email address by clicking the link below:

{url}

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.

- The xavyo Team"
        )
    }
}

/// Extension trait to make method chaining easier.
trait Pipe: Sized {
    fn pipe<T, F: FnOnce(Self) -> T>(self, f: F) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let from = self.sender_mailbox()?;
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid recipient: {e}")))?;

        let body = self.password_reset_body(token);

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject("Reset your Xavyo password")
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| EmailError::BuildError(format!("Failed to build email: {e}")))?;

        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| EmailError::SendError(format!("Failed to send email: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Password reset email sent"
        );

        Ok(())
    }

    async fn send_verification(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let from = self.sender_mailbox()?;
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid recipient: {e}")))?;

        let body = self.verification_body(token);

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject("Verify your email address")
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| EmailError::BuildError(format!("Failed to build email: {e}")))?;

        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| EmailError::SendError(format!("Failed to send email: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Verification email sent"
        );

        Ok(())
    }

    async fn send_magic_link(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let from = self.sender_mailbox()?;
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid recipient: {e}")))?;

        let body = self.magic_link_body(token);

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject("Sign in to Xavyo")
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| EmailError::BuildError(format!("Failed to build email: {e}")))?;

        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| EmailError::SendError(format!("Failed to send email: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Magic link email sent"
        );

        Ok(())
    }

    async fn send_email_otp(
        &self,
        to: &str,
        code: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let from = self.sender_mailbox()?;
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid recipient: {e}")))?;

        let body = self.email_otp_body(code);

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject("Your Xavyo verification code")
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| EmailError::BuildError(format!("Failed to build email: {e}")))?;

        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| EmailError::SendError(format!("Failed to send email: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Email OTP sent"
        );

        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError> {
        let from = self.sender_mailbox()?;
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|e| EmailError::InvalidAddress(format!("Invalid recipient: {e}")))?;

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| EmailError::BuildError(format!("Failed to build email: {e}")))?;

        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| EmailError::SendError(format!("Failed to send email: {e}")))?;

        tracing::info!(recipient = to, subject = subject, "Email sent");

        Ok(())
    }
}

/// A mock email sender for testing.
///
/// Records all sent emails for verification in tests.
#[derive(Debug, Clone, Default)]
pub struct MockEmailSender {
    /// Sent password reset emails: (to, token, `tenant_id`)
    pub password_resets: Arc<Mutex<Vec<(String, String, TenantId)>>>,
    /// Sent verification emails: (to, token, `tenant_id`)
    pub verifications: Arc<Mutex<Vec<(String, String, TenantId)>>>,
    /// Sent magic link emails: (to, token, `tenant_id`)
    pub magic_links: Arc<Mutex<Vec<(String, String, TenantId)>>>,
    /// Sent email OTP emails: (to, code, `tenant_id`)
    pub email_otps: Arc<Mutex<Vec<(String, String, TenantId)>>>,
    /// Whether to simulate sending failures.
    pub should_fail: Arc<Mutex<bool>>,
}

impl MockEmailSender {
    /// Create a new mock email sender.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether sends should fail.
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock() = should_fail;
    }

    /// Get all password reset emails sent.
    #[must_use] 
    pub fn get_password_resets(&self) -> Vec<(String, String, TenantId)> {
        self.password_resets.lock().clone()
    }

    /// Get all verification emails sent.
    #[must_use] 
    pub fn get_verifications(&self) -> Vec<(String, String, TenantId)> {
        self.verifications.lock().clone()
    }

    /// Get all magic link emails sent.
    #[must_use] 
    pub fn get_magic_links(&self) -> Vec<(String, String, TenantId)> {
        self.magic_links.lock().clone()
    }

    /// Get all email OTP emails sent.
    #[must_use] 
    pub fn get_email_otps(&self) -> Vec<(String, String, TenantId)> {
        self.email_otps.lock().clone()
    }

    /// Clear all recorded emails.
    pub fn clear(&self) {
        self.password_resets.lock().clear();
        self.verifications.lock().clear();
        self.magic_links.lock().clear();
        self.email_otps.lock().clear();
    }

    /// Get the last password reset token sent to a specific email.
    #[must_use] 
    pub fn get_last_reset_token(&self, email: &str) -> Option<String> {
        self.password_resets
            .lock()
            .iter()
            .rev()
            .find(|(to, _, _)| to == email)
            .map(|(_, token, _)| token.clone())
    }

    /// Get the last verification token sent to a specific email.
    #[must_use] 
    pub fn get_last_verification_token(&self, email: &str) -> Option<String> {
        self.verifications
            .lock()
            .iter()
            .rev()
            .find(|(to, _, _)| to == email)
            .map(|(_, token, _)| token.clone())
    }
}

#[async_trait]
impl EmailSender for MockEmailSender {
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        if *self.should_fail.lock() {
            return Err(EmailError::SendError("Mock failure".to_string()));
        }

        self.password_resets
            .lock()
            .push((to.to_string(), token.to_string(), tenant_id));

        tracing::debug!(
            tenant_id = %tenant_id,
            recipient = to,
            "[MOCK] Password reset email recorded"
        );

        Ok(())
    }

    async fn send_verification(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        if *self.should_fail.lock() {
            return Err(EmailError::SendError("Mock failure".to_string()));
        }

        self.verifications
            .lock()
            .push((to.to_string(), token.to_string(), tenant_id));

        tracing::debug!(
            tenant_id = %tenant_id,
            recipient = to,
            "[MOCK] Verification email recorded"
        );

        Ok(())
    }

    async fn send_magic_link(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        if *self.should_fail.lock() {
            return Err(EmailError::SendError("Mock failure".to_string()));
        }

        self.magic_links
            .lock()
            .push((to.to_string(), token.to_string(), tenant_id));

        tracing::debug!(
            tenant_id = %tenant_id,
            recipient = to,
            "[MOCK] Magic link email recorded"
        );

        Ok(())
    }

    async fn send_email_otp(
        &self,
        to: &str,
        code: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        if *self.should_fail.lock() {
            return Err(EmailError::SendError("Mock failure".to_string()));
        }

        self.email_otps
            .lock()
            .push((to.to_string(), code.to_string(), tenant_id));

        tracing::debug!(
            tenant_id = %tenant_id,
            recipient = to,
            "[MOCK] Email OTP recorded"
        );

        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, _body: &str) -> Result<(), EmailError> {
        if *self.should_fail.lock() {
            return Err(EmailError::SendError("Mock failure".to_string()));
        }

        tracing::debug!(
            recipient = to,
            subject = subject,
            "[MOCK] Generic email recorded"
        );

        Ok(())
    }
}

/// Blanket implementation for Arc<dyn EmailSender> to allow using Arc-wrapped
/// trait objects as `EmailSender`.
#[async_trait]
impl EmailSender for Arc<dyn EmailSender> {
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        (**self).send_password_reset(to, token, tenant_id).await
    }

    async fn send_verification(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        (**self).send_verification(to, token, tenant_id).await
    }

    async fn send_magic_link(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        (**self).send_magic_link(to, token, tenant_id).await
    }

    async fn send_email_otp(
        &self,
        to: &str,
        code: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        (**self).send_email_otp(to, code, tenant_id).await
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError> {
        (**self).send(to, subject, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_config_urls() {
        let config = EmailConfig {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            from_address: "noreply@example.com".to_string(),
            from_name: "Test".to_string(),
            frontend_base_url: "https://app.xavyo.com".to_string(),
            password_reset_path: "/auth/reset-password".to_string(),
            email_verify_path: "/auth/verify-email".to_string(),
            magic_link_path: "/auth/passwordless/verify".to_string(),
        };

        let reset_url = config.password_reset_url("abc123");
        assert_eq!(
            reset_url,
            "https://app.xavyo.com/auth/reset-password?token=abc123"
        );

        let verify_url = config.email_verify_url("xyz789");
        assert_eq!(
            verify_url,
            "https://app.xavyo.com/auth/verify-email?token=xyz789"
        );

        let magic_url = config.magic_link_url("ml_token");
        assert_eq!(
            magic_url,
            "https://app.xavyo.com/auth/passwordless/verify?token=ml_token"
        );
    }

    #[tokio::test]
    async fn test_mock_email_sender() {
        let sender = MockEmailSender::new();
        let tenant_id = TenantId::new();

        // Send password reset
        sender
            .send_password_reset("user@example.com", "token123", tenant_id)
            .await
            .unwrap();

        let resets = sender.get_password_resets();
        assert_eq!(resets.len(), 1);
        assert_eq!(resets[0].0, "user@example.com");
        assert_eq!(resets[0].1, "token123");

        // Send verification
        sender
            .send_verification("user@example.com", "verify456", tenant_id)
            .await
            .unwrap();

        let verifications = sender.get_verifications();
        assert_eq!(verifications.len(), 1);
        assert_eq!(verifications[0].0, "user@example.com");
        assert_eq!(verifications[0].1, "verify456");
    }

    #[tokio::test]
    async fn test_mock_email_sender_failure() {
        let sender = MockEmailSender::new();
        sender.set_should_fail(true);

        let result = sender
            .send_password_reset("user@example.com", "token", TenantId::new())
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EmailError::SendError(_)));
    }

    #[tokio::test]
    async fn test_mock_get_last_token() {
        let sender = MockEmailSender::new();
        let tenant_id = TenantId::new();

        sender
            .send_password_reset("user@example.com", "token1", tenant_id)
            .await
            .unwrap();
        sender
            .send_password_reset("user@example.com", "token2", tenant_id)
            .await
            .unwrap();
        sender
            .send_password_reset("other@example.com", "token3", tenant_id)
            .await
            .unwrap();

        assert_eq!(
            sender.get_last_reset_token("user@example.com"),
            Some("token2".to_string())
        );
        assert_eq!(
            sender.get_last_reset_token("other@example.com"),
            Some("token3".to_string())
        );
        assert_eq!(sender.get_last_reset_token("unknown@example.com"), None);
    }
}
