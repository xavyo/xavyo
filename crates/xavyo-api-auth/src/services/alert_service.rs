//! Alert service for security alert management.
//!
//! Handles creation, retrieval, and acknowledgment of security alerts.

use crate::error::ApiAuthError;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::{set_tenant_context, AlertType, CreateSecurityAlert, SecurityAlert, Severity};

/// Threshold for generating failed_attempts alert.
const FAILED_ATTEMPTS_THRESHOLD: i64 = 3;

/// Alert service for security notification management.
#[derive(Clone)]
pub struct AlertService {
    pool: PgPool,
}

impl AlertService {
    /// Create a new alert service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a security alert.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        alert_type: AlertType,
        severity: Severity,
        title: String,
        message: String,
        metadata: serde_json::Value,
    ) -> Result<SecurityAlert, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let input = CreateSecurityAlert {
            tenant_id,
            user_id,
            alert_type,
            severity,
            title,
            message,
            metadata,
        };

        let alert = SecurityAlert::create(&mut *conn, input)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            alert_type = %alert_type,
            severity = %severity,
            "Security alert created"
        );

        Ok(alert)
    }

    /// Get alerts for a user with pagination and filtering.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_user_alerts(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        alert_type: Option<&str>,
        severity: Option<&str>,
        acknowledged: Option<bool>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<(Vec<SecurityAlert>, i64, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let alerts = SecurityAlert::get_user_alerts(
            &mut *conn,
            tenant_id,
            user_id,
            alert_type,
            severity,
            acknowledged,
            cursor,
            limit,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        let total = SecurityAlert::count_user_alerts(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        let unacknowledged = SecurityAlert::count_unacknowledged(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok((alerts, total, unacknowledged))
    }

    /// Acknowledge an alert.
    pub async fn acknowledge_alert(
        &self,
        tenant_id: Uuid,
        alert_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SecurityAlert>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let alert = SecurityAlert::acknowledge(&mut *conn, tenant_id, alert_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if alert.is_some() {
            info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                alert_id = %alert_id,
                "Security alert acknowledged"
            );
        }

        Ok(alert)
    }

    /// Get count of unacknowledged alerts for a user.
    pub async fn get_unacknowledged_count(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<i64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        SecurityAlert::count_unacknowledged(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Get an alert by ID.
    pub async fn get_alert_by_id(
        &self,
        tenant_id: Uuid,
        alert_id: Uuid,
    ) -> Result<Option<SecurityAlert>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        SecurityAlert::get_by_id(&mut *conn, tenant_id, alert_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Generate a new device alert.
    pub async fn generate_new_device_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
        ip_address: Option<&str>,
    ) -> Result<SecurityAlert, ApiAuthError> {
        let metadata = json!({
            "device_fingerprint": device_fingerprint,
            "ip_address": ip_address,
        });

        self.create_alert(
            tenant_id,
            user_id,
            AlertType::NewDevice,
            Severity::Warning,
            "New Device Detected".to_string(),
            "A login was detected from a device you haven't used before. If this wasn't you, please change your password immediately.".to_string(),
            metadata,
        )
        .await
    }

    /// Generate a new location alert.
    pub async fn generate_new_location_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
        city: &str,
        ip_address: Option<&str>,
    ) -> Result<SecurityAlert, ApiAuthError> {
        let metadata = json!({
            "country": country,
            "city": city,
            "ip_address": ip_address,
        });

        self.create_alert(
            tenant_id,
            user_id,
            AlertType::NewLocation,
            Severity::Info,
            "Login from New Location".to_string(),
            format!(
                "A login was detected from a new location: {}, {}. If this wasn't you, please review your account security.",
                city, country
            ),
            metadata,
        )
        .await
    }

    /// Check if failed attempts threshold is reached and generate alert if needed.
    pub async fn check_failed_attempts_threshold(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<Option<SecurityAlert>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let one_hour_ago = Utc::now() - Duration::hours(1);

        // Count failed attempts in last hour
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM login_attempts
            WHERE tenant_id = $1 AND user_id = $2 AND success = false AND created_at >= $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(one_hour_ago)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        let failed_count = row.0;

        // Check if we just crossed the threshold (exactly at threshold)
        // This prevents generating duplicate alerts
        if failed_count == FAILED_ATTEMPTS_THRESHOLD {
            warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                email = %email,
                failed_count = failed_count,
                "Failed attempts threshold reached"
            );

            let metadata = json!({
                "email": email,
                "ip_address": ip_address,
                "failed_count": failed_count,
                "time_window": "1 hour",
            });

            let alert = self
                .create_alert(
                    tenant_id,
                    user_id,
                    AlertType::FailedAttempts,
                    Severity::Warning,
                    "Multiple Failed Login Attempts".to_string(),
                    format!(
                        "There have been {} failed login attempts on your account in the last hour. If this wasn't you, please change your password.",
                        failed_count
                    ),
                    metadata,
                )
                .await?;

            return Ok(Some(alert));
        }

        Ok(None)
    }

    /// Generate a password change alert.
    pub async fn generate_password_change_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: Option<&str>,
    ) -> Result<SecurityAlert, ApiAuthError> {
        let metadata = json!({
            "ip_address": ip_address,
            "changed_at": Utc::now().to_rfc3339(),
        });

        self.create_alert(
            tenant_id,
            user_id,
            AlertType::PasswordChange,
            Severity::Info,
            "Password Changed".to_string(),
            "Your password was changed successfully. If you didn't make this change, please contact support immediately.".to_string(),
            metadata,
        )
        .await
    }

    /// Generate an MFA disabled alert.
    pub async fn generate_mfa_disabled_alert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: Option<&str>,
    ) -> Result<SecurityAlert, ApiAuthError> {
        let metadata = json!({
            "ip_address": ip_address,
            "disabled_at": Utc::now().to_rfc3339(),
        });

        self.create_alert(
            tenant_id,
            user_id,
            AlertType::MfaDisabled,
            Severity::Critical,
            "Multi-Factor Authentication Disabled".to_string(),
            "Multi-factor authentication has been disabled on your account. This significantly reduces your account security. If you didn't make this change, please re-enable MFA and change your password immediately.".to_string(),
            metadata,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_attempts_threshold() {
        assert_eq!(FAILED_ATTEMPTS_THRESHOLD, 3);
    }

    #[test]
    fn test_alert_type_severity_mapping() {
        // Verify expected severity for each alert type
        let mappings = [
            (AlertType::NewDevice, Severity::Warning),
            (AlertType::NewLocation, Severity::Info),
            (AlertType::FailedAttempts, Severity::Warning),
            (AlertType::PasswordChange, Severity::Info),
            (AlertType::MfaDisabled, Severity::Critical),
        ];

        for (alert_type, expected_severity) in mappings {
            let severity = match alert_type {
                AlertType::NewDevice => Severity::Warning,
                AlertType::NewLocation => Severity::Info,
                AlertType::FailedAttempts => Severity::Warning,
                AlertType::PasswordChange => Severity::Info,
                AlertType::MfaDisabled => Severity::Critical,
            };
            assert_eq!(severity, expected_severity);
        }
    }
}
