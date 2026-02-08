//! AWS SES email sender implementation.
//!
//! Uses the AWS SDK for SESv2 to send transactional emails. Supports
//! IAM role-based auth (recommended for EC2/ECS/EKS) and explicit
//! credentials via standard AWS environment variables.

use async_trait::async_trait;
use aws_sdk_sesv2::{
    config::Region,
    types::{Body, Content, Destination, EmailContent, Message},
    Client,
};
use xavyo_core::TenantId;

use super::email_service::{EmailConfig, EmailError, EmailSender};

/// Configuration for AWS SES email sending.
#[derive(Debug, Clone)]
pub struct SesEmailConfig {
    /// Shared email config (from_address, frontend_base_url, paths).
    pub base: EmailConfig,
    /// AWS region for SES (e.g., "us-east-1").
    pub region: String,
    /// Optional SES configuration set name (for tracking/metrics).
    pub configuration_set: Option<String>,
}

impl SesEmailConfig {
    /// Create from environment variables.
    ///
    /// Required: `EMAIL_SES_REGION`, `EMAIL_FROM_ADDRESS`, `FRONTEND_BASE_URL`
    /// Optional: `EMAIL_SES_CONFIGURATION_SET`, `EMAIL_FROM_NAME`,
    ///           `PASSWORD_RESET_PATH`, `EMAIL_VERIFY_PATH`, `MAGIC_LINK_PATH`
    ///
    /// AWS credentials are resolved via the standard credential chain
    /// (env vars, IAM role, instance profile).
    pub fn from_env() -> Result<Self, EmailError> {
        let region = std::env::var("EMAIL_SES_REGION")
            .map_err(|_| EmailError::ConfigError("EMAIL_SES_REGION not set".to_string()))?;
        let configuration_set = std::env::var("EMAIL_SES_CONFIGURATION_SET").ok();

        let base = EmailConfig {
            smtp_host: String::new(),
            smtp_port: 0,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_tls: false,
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
        };

        Ok(Self {
            base,
            region,
            configuration_set,
        })
    }
}

/// AWS SES email sender using the SESv2 API.
pub struct SesEmailSender {
    client: Client,
    config: SesEmailConfig,
}

impl SesEmailSender {
    /// Create a new SES email sender.
    ///
    /// Loads AWS credentials from the standard credential chain
    /// (environment variables, IAM role, instance profile, etc.).
    pub async fn new(config: SesEmailConfig) -> Self {
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;
        let client = Client::new(&aws_config);
        Self { client, config }
    }

    /// Send an email via SES.
    async fn send_ses_email(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError> {
        let from = format!(
            "{} <{}>",
            self.config.base.from_name, self.config.base.from_address
        );

        let destination = Destination::builder().to_addresses(to).build();

        let subject_content = Content::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .map_err(|e| EmailError::BuildError(format!("Failed to build subject: {e}")))?;

        let body_content = Content::builder()
            .data(body)
            .charset("UTF-8")
            .build()
            .map_err(|e| EmailError::BuildError(format!("Failed to build body: {e}")))?;

        let message = Message::builder()
            .subject(subject_content)
            .body(Body::builder().text(body_content).build())
            .build();

        let email_content = EmailContent::builder().simple(message).build();

        let mut req = self
            .client
            .send_email()
            .from_email_address(from)
            .destination(destination)
            .content(email_content);

        if let Some(config_set) = &self.config.configuration_set {
            req = req.configuration_set_name(config_set);
        }

        req.send()
            .await
            .map_err(|e| EmailError::SendError(format!("SES send failed: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl EmailSender for SesEmailSender {
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let body = self.config.base.password_reset_body(token);
        self.send_ses_email(to, "Reset your Xavyo password", &body)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Password reset email sent via SES"
        );

        Ok(())
    }

    async fn send_verification(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let body = self.config.base.verification_body(token);
        self.send_ses_email(to, "Verify your email address", &body)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Verification email sent via SES"
        );

        Ok(())
    }

    async fn send_magic_link(
        &self,
        to: &str,
        token: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let body = self.config.base.magic_link_body(token);
        self.send_ses_email(to, "Sign in to Xavyo", &body).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Magic link email sent via SES"
        );

        Ok(())
    }

    async fn send_email_otp(
        &self,
        to: &str,
        code: &str,
        tenant_id: TenantId,
    ) -> Result<(), EmailError> {
        let body = self.config.base.email_otp_body(code);
        self.send_ses_email(to, "Your Xavyo verification code", &body)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            recipient = to,
            "Email OTP sent via SES"
        );

        Ok(())
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError> {
        self.send_ses_email(to, subject, body).await?;

        tracing::info!(recipient = to, subject = subject, "Email sent via SES");

        Ok(())
    }
}
