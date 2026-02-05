//! Audit service for login history and audit trail management.
//!
//! Handles login attempt recording, user login history, and admin audit queries.

use crate::error::ApiAuthError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;
use xavyo_db::{
    set_tenant_context, AuthMethod, CreateLoginAttempt, LoginAttempt, UserDevice, UserLocation,
};

/// Login attempt statistics for admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttemptStats {
    /// Total number of login attempts.
    pub total_attempts: i64,
    /// Number of successful attempts.
    pub successful_attempts: i64,
    /// Number of failed attempts.
    pub failed_attempts: i64,
    /// Success rate as percentage (0-100).
    pub success_rate: f64,
    /// Breakdown by failure reason.
    pub failure_reasons: Vec<FailureReasonCount>,
    /// Distribution by hour of day.
    pub hourly_distribution: Vec<HourlyCount>,
    /// Number of unique users.
    pub unique_users: i64,
    /// Number of logins from new devices.
    pub new_device_logins: i64,
    /// Number of logins from new locations.
    pub new_location_logins: i64,
}

/// Count of a specific failure reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureReasonCount {
    pub reason: String,
    pub count: i64,
}

/// Count of attempts for a specific hour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyCount {
    pub hour: i32,
    pub count: i64,
}

/// Input for recording a login attempt.
#[derive(Debug, Clone)]
pub struct RecordLoginAttemptInput {
    pub user_id: Option<Uuid>,
    pub email: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub auth_method: AuthMethod,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
}

/// Result of recording a login attempt.
#[derive(Debug, Clone)]
pub struct RecordLoginAttemptResult {
    pub attempt: LoginAttempt,
    pub is_new_device: bool,
    pub is_new_location: bool,
}

/// Audit service for login history management.
#[derive(Clone)]
pub struct AuditService {
    pool: PgPool,
}

impl AuditService {
    /// Create a new audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a login attempt with device and location tracking.
    pub async fn record_login_attempt(
        &self,
        tenant_id: Uuid,
        input: RecordLoginAttemptInput,
    ) -> Result<RecordLoginAttemptResult, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let mut is_new_device = false;
        let mut is_new_location = false;

        // Check for new device if we have user_id and device_fingerprint
        if let (Some(user_id), Some(fingerprint)) =
            (input.user_id, input.device_fingerprint.as_ref())
        {
            if input.success {
                let (_, device_is_new) =
                    UserDevice::record_login(&mut *conn, tenant_id, user_id, fingerprint)
                        .await
                        .map_err(ApiAuthError::Database)?;
                is_new_device = device_is_new;
            } else {
                // For failed attempts, just check if device exists
                is_new_device = !UserDevice::exists(&mut *conn, tenant_id, user_id, fingerprint)
                    .await
                    .map_err(ApiAuthError::Database)?;
            }
        }

        // Check for new location if we have user_id and geo data
        if let (Some(user_id), Some(country), Some(city)) = (
            input.user_id,
            input.geo_country.as_ref(),
            input.geo_city.as_ref(),
        ) {
            if input.success {
                let (_, location_is_new) =
                    UserLocation::record_login(&mut *conn, tenant_id, user_id, country, city)
                        .await
                        .map_err(ApiAuthError::Database)?;
                is_new_location = location_is_new;
            } else {
                // For failed attempts, just check if location exists
                is_new_location =
                    !UserLocation::exists(&mut *conn, tenant_id, user_id, country, city)
                        .await
                        .map_err(ApiAuthError::Database)?;
            }
        }

        // Create the login attempt record
        let create_input = CreateLoginAttempt {
            tenant_id,
            user_id: input.user_id,
            email: input.email.clone(),
            success: input.success,
            failure_reason: input.failure_reason,
            auth_method: input.auth_method,
            ip_address: input.ip_address,
            user_agent: input.user_agent,
            device_fingerprint: input.device_fingerprint,
            geo_country: input.geo_country,
            geo_city: input.geo_city,
            is_new_device,
            is_new_location,
        };

        let attempt = LoginAttempt::create(&mut *conn, create_input)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            user_id = ?input.user_id,
            email = %input.email,
            success = input.success,
            is_new_device = is_new_device,
            is_new_location = is_new_location,
            "Login attempt recorded"
        );

        Ok(RecordLoginAttemptResult {
            attempt,
            is_new_device,
            is_new_location,
        })
    }

    /// Get login history for a user.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_user_login_history(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        success: Option<bool>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<(Vec<LoginAttempt>, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let attempts = LoginAttempt::get_user_history_filtered(
            &mut *conn, tenant_id, user_id, success, start_date, end_date, cursor, limit,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        let total = LoginAttempt::count_user_history(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok((attempts, total))
    }

    /// Get login attempts for a tenant (admin query).
    #[allow(clippy::too_many_arguments)]
    pub async fn get_tenant_login_attempts(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        email_filter: Option<&str>,
        success: Option<bool>,
        auth_method: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<(Vec<LoginAttempt>, i64), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let attempts = LoginAttempt::get_tenant_attempts(
            &mut *conn,
            tenant_id,
            user_id,
            email_filter,
            success,
            auth_method,
            start_date,
            end_date,
            cursor,
            limit,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        let total = LoginAttempt::count_tenant_attempts(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok((attempts, total))
    }

    /// Get login attempt statistics for a tenant.
    pub async fn get_login_attempt_stats(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<LoginAttemptStats, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get basic counts
        let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE success = true) as successful,
                COUNT(*) FILTER (WHERE success = false) as failed,
                COUNT(*) FILTER (WHERE is_new_device = true) as new_device,
                COUNT(*) FILTER (WHERE is_new_location = true) as new_location
            FROM login_attempts
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            ",
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        let (total, successful, failed, new_device, new_location) = counts;

        // Get unique users count
        let unique_users: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(DISTINCT user_id)
            FROM login_attempts
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3 AND user_id IS NOT NULL
            ",
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        // Get failure reasons breakdown
        let failure_rows: Vec<(String, i64)> = sqlx::query_as(
            r"
            SELECT failure_reason, COUNT(*) as count
            FROM login_attempts
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
              AND success = false AND failure_reason IS NOT NULL
            GROUP BY failure_reason
            ORDER BY count DESC
            ",
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        let failure_reasons: Vec<FailureReasonCount> = failure_rows
            .into_iter()
            .map(|(reason, count)| FailureReasonCount { reason, count })
            .collect();

        // Get hourly distribution
        let hourly_rows: Vec<(i32, i64)> = sqlx::query_as(
            r"
            SELECT EXTRACT(HOUR FROM created_at)::int as hour, COUNT(*) as count
            FROM login_attempts
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            GROUP BY hour
            ORDER BY hour
            ",
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        let hourly_distribution: Vec<HourlyCount> = hourly_rows
            .into_iter()
            .map(|(hour, count)| HourlyCount { hour, count })
            .collect();

        let success_rate = if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Ok(LoginAttemptStats {
            total_attempts: total,
            successful_attempts: successful,
            failed_attempts: failed,
            success_rate,
            failure_reasons,
            hourly_distribution,
            unique_users: unique_users.0,
            new_device_logins: new_device,
            new_location_logins: new_location,
        })
    }

    /// Check if a device is new for a user.
    pub async fn check_new_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let exists = UserDevice::exists(&mut *conn, tenant_id, user_id, device_fingerprint)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(!exists)
    }

    /// Check if a location is new for a user.
    pub async fn check_new_location(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
        city: &str,
    ) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let exists = UserLocation::exists(&mut *conn, tenant_id, user_id, country, city)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(!exists)
    }

    /// Count failed login attempts for a user in the last hour.
    pub async fn count_recent_failed_attempts(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let one_hour_ago = Utc::now() - Duration::hours(1);

        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM login_attempts
            WHERE tenant_id = $1 AND user_id = $2 AND success = false AND created_at >= $3
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(one_hour_ago)
        .fetch_one(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_attempt_stats_success_rate() {
        let stats = LoginAttemptStats {
            total_attempts: 100,
            successful_attempts: 80,
            failed_attempts: 20,
            success_rate: 80.0,
            failure_reasons: vec![],
            hourly_distribution: vec![],
            unique_users: 50,
            new_device_logins: 5,
            new_location_logins: 2,
        };

        assert_eq!(stats.success_rate, 80.0);
    }

    #[test]
    fn test_login_attempt_stats_zero_total() {
        let total = 0i64;
        let successful = 0i64;
        let success_rate = if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        assert_eq!(success_rate, 0.0);
    }
}
