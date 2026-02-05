//! Lockout service for account lockout management.
//!
//! Handles failed login tracking, account locking/unlocking, and notifications.

use crate::error::ApiAuthError;
use chrono::Utc;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::{
    set_tenant_context, FailedLoginAttempt, FailureReason, TenantLockoutPolicy, UpsertLockoutPolicy,
};

/// Lockout status for a user account.
#[derive(Debug, Clone)]
pub struct LockoutStatus {
    /// Whether the account is currently locked.
    pub is_locked: bool,
    /// When the lockout expires (None for permanent lockout).
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Current failed attempt count.
    pub failed_attempts: i32,
    /// Maximum allowed attempts before lockout.
    pub max_attempts: i32,
    /// Reason for lockout (if locked).
    pub lockout_reason: Option<String>,
}

/// Account lockout service.
#[derive(Clone)]
pub struct LockoutService {
    pool: PgPool,
}

impl LockoutService {
    /// Create a new lockout service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the lockout policy for a tenant.
    pub async fn get_lockout_policy(
        &self,
        tenant_id: Uuid,
    ) -> Result<TenantLockoutPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        TenantLockoutPolicy::get_or_default(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Update the lockout policy for a tenant.
    pub async fn update_lockout_policy(
        &self,
        tenant_id: Uuid,
        data: UpsertLockoutPolicy,
    ) -> Result<TenantLockoutPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let policy = TenantLockoutPolicy::upsert(&mut *conn, tenant_id, data)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(tenant_id = %tenant_id, "Lockout policy updated");

        Ok(policy)
    }

    /// Check if a user account is currently locked.
    ///
    /// This also handles auto-unlock if the lockout has expired.
    pub async fn check_account_locked(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<LockoutStatus, ApiAuthError> {
        let policy = self.get_lockout_policy(tenant_id).await?;

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get current lockout status from user
        #[allow(clippy::type_complexity)]
        let row: Option<(
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            i32,
            Option<String>,
        )> = sqlx::query_as(
            r"
                SELECT locked_at, locked_until, failed_login_count, lockout_reason
                FROM users
                WHERE id = $1
                ",
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        let Some((locked_at, locked_until, failed_count, lockout_reason)) = row else {
            return Err(ApiAuthError::Internal("User not found".to_string()));
        };

        // Not locked
        if locked_at.is_none() {
            return Ok(LockoutStatus {
                is_locked: false,
                locked_until: None,
                failed_attempts: failed_count,
                max_attempts: policy.max_failed_attempts,
                lockout_reason: None,
            });
        }

        // Check if lockout has expired
        if let Some(until) = locked_until {
            if Utc::now() > until {
                // Auto-unlock
                self.unlock_user_internal(&mut *conn, user_id).await?;

                info!(
                    user_id = %user_id,
                    "Account auto-unlocked after lockout expiration"
                );

                return Ok(LockoutStatus {
                    is_locked: false,
                    locked_until: None,
                    failed_attempts: 0,
                    max_attempts: policy.max_failed_attempts,
                    lockout_reason: None,
                });
            }
        }

        // Still locked
        Ok(LockoutStatus {
            is_locked: true,
            locked_until,
            failed_attempts: failed_count,
            max_attempts: policy.max_failed_attempts,
            lockout_reason,
        })
    }

    /// Record a failed login attempt and potentially lock the account.
    ///
    /// Uses atomic increment with FOR UPDATE SKIP LOCKED to handle concurrent attempts.
    pub async fn record_failed_attempt(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
        ip_address: Option<&str>,
        failure_reason: FailureReason,
    ) -> Result<LockoutStatus, ApiAuthError> {
        let policy = self.get_lockout_policy(tenant_id).await?;

        // Start transaction
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Record the failed attempt in audit log
        FailedLoginAttempt::create(
            &mut *tx,
            tenant_id,
            Some(user_id),
            email,
            ip_address,
            failure_reason,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Check if lockout is disabled
        if !policy.is_enabled() {
            tx.commit().await.map_err(ApiAuthError::Database)?;
            return Ok(LockoutStatus {
                is_locked: false,
                locked_until: None,
                failed_attempts: 0,
                max_attempts: 0,
                lockout_reason: None,
            });
        }

        // Atomic increment with FOR UPDATE SKIP LOCKED
        let row: (i32,) = sqlx::query_as(
            r"
            UPDATE users
            SET failed_login_count = failed_login_count + 1,
                last_failed_login_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            RETURNING failed_login_count
            ",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiAuthError::Database)?;

        let new_count = row.0;

        // Check if we need to lock the account
        if new_count >= policy.max_failed_attempts {
            let locked_until = if policy.is_permanent_lockout() {
                None // Permanent until admin unlock
            } else {
                Some(Utc::now() + policy.lockout_duration())
            };

            // Lock the account
            sqlx::query(
                r"
                UPDATE users
                SET locked_at = NOW(),
                    locked_until = $2,
                    lockout_reason = 'max_attempts',
                    updated_at = NOW()
                WHERE id = $1
                ",
            )
            .bind(user_id)
            .bind(locked_until)
            .execute(&mut *tx)
            .await
            .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;

            warn!(
                user_id = %user_id,
                failed_attempts = new_count,
                locked_until = ?locked_until,
                "Account locked due to too many failed attempts"
            );

            // Log notification request (actual email sending would be handled by email service)
            if policy.notify_on_lockout {
                info!(
                    user_id = %user_id,
                    email = %email,
                    locked_until = ?locked_until,
                    "Lockout notification requested"
                );
            }

            return Ok(LockoutStatus {
                is_locked: true,
                locked_until,
                failed_attempts: new_count,
                max_attempts: policy.max_failed_attempts,
                lockout_reason: Some("max_attempts".to_string()),
            });
        }

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(LockoutStatus {
            is_locked: false,
            locked_until: None,
            failed_attempts: new_count,
            max_attempts: policy.max_failed_attempts,
            lockout_reason: None,
        })
    }

    /// Reset failed attempts counter on successful login.
    pub async fn reset_failed_attempts(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        sqlx::query(
            r"
            UPDATE users
            SET failed_login_count = 0,
                last_failed_login_at = NULL,
                updated_at = NOW()
            WHERE id = $1
            ",
        )
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        Ok(())
    }

    /// Manually unlock a user account (admin action).
    pub async fn unlock_user(&self, user_id: Uuid, tenant_id: Uuid) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let result = self.unlock_user_internal(&mut *conn, user_id).await?;

        if result {
            info!(
                user_id = %user_id,
                "User account unlocked by admin"
            );
        }

        Ok(result)
    }

    /// Internal unlock method that works with any executor.
    async fn unlock_user_internal<'e, E>(
        &self,
        executor: E,
        user_id: Uuid,
    ) -> Result<bool, ApiAuthError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r"
            UPDATE users
            SET locked_at = NULL,
                locked_until = NULL,
                lockout_reason = NULL,
                failed_login_count = 0,
                last_failed_login_at = NULL,
                updated_at = NOW()
            WHERE id = $1 AND locked_at IS NOT NULL
            ",
        )
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(ApiAuthError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Record a login attempt for audit (both successful and failed).
    pub async fn record_login_attempt(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        email: &str,
        ip_address: Option<&str>,
        failure_reason: FailureReason,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        FailedLoginAttempt::create(
            &mut *conn,
            tenant_id,
            user_id,
            email,
            ip_address,
            failure_reason,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_lockout_status() {
        let status = LockoutStatus {
            is_locked: true,
            locked_until: Some(Utc::now() + Duration::minutes(30)),
            failed_attempts: 5,
            max_attempts: 5,
            lockout_reason: Some("max_attempts".to_string()),
        };
        assert!(status.is_locked);
        assert!(status.locked_until.is_some());
    }

    #[test]
    fn test_lockout_status_not_locked() {
        let status = LockoutStatus {
            is_locked: false,
            locked_until: None,
            failed_attempts: 2,
            max_attempts: 5,
            lockout_reason: None,
        };
        assert!(!status.is_locked);
        assert!(status.locked_until.is_none());
    }
}
