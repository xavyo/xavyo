//! Session management service.
//!
//! Handles session creation, validation, and revocation with policy enforcement.

use crate::error::ApiAuthError;
use crate::models::SessionPolicyConfig;
use crate::services::org_policy_service::OrgPolicyService;
use crate::services::user_agent_parser::{parse_user_agent, DeviceInfo};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::{
    models::org_security_policy::OrgPolicyType, set_tenant_context, CreateSession, RevokeReason,
    Session, SessionInfo, TenantSessionPolicy, UpsertSessionPolicy,
};

/// Throttle interval for activity updates (in seconds).
const ACTIVITY_UPDATE_THROTTLE_SECONDS: u64 = 60;

/// Session management service.
#[derive(Clone)]
pub struct SessionService {
    pool: PgPool,
    /// Cache for activity update throttling (`session_id` -> `last_update_time`).
    activity_cache: std::sync::Arc<RwLock<HashMap<Uuid, Instant>>>,
}

impl SessionService {
    /// Create a new session service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            activity_cache: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session for a user.
    ///
    /// This will also enforce `max_concurrent_sessions` policy if set.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        refresh_token_id: Option<Uuid>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<Session, ApiAuthError> {
        // Get tenant policy
        let policy = self.get_tenant_policy(tenant_id).await?;

        // Parse user agent if tracking is enabled
        let device_info = if policy.track_device_info {
            user_agent.map(parse_user_agent).unwrap_or_default()
        } else {
            DeviceInfo::default()
        };

        // Start transaction
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Enforce max concurrent sessions
        if policy.max_concurrent_sessions > 0 {
            let active_count = Session::count_active_by_user(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;

            if active_count >= i64::from(policy.max_concurrent_sessions) {
                // Revoke oldest session
                if let Some(oldest) = Session::find_oldest_active(&mut *tx, user_id)
                    .await
                    .map_err(ApiAuthError::Database)?
                {
                    Session::revoke(&mut *tx, oldest.id, RevokeReason::MaxSessions)
                        .await
                        .map_err(ApiAuthError::Database)?;

                    info!(
                        user_id = %user_id,
                        session_id = %oldest.id,
                        "Revoked oldest session due to max_concurrent_sessions limit"
                    );
                }
            }
        }

        // Calculate expiry
        let expires_at = Utc::now() + Duration::hours(i64::from(policy.absolute_timeout_hours));

        // Create session
        let create_data = CreateSession {
            user_id,
            tenant_id,
            refresh_token_id,
            device_id: None,
            device_name: Some(device_info.device_name),
            device_type: Some(device_info.device_type),
            browser: device_info.browser,
            browser_version: device_info.browser_version,
            os: device_info.os,
            os_version: device_info.os_version,
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            expires_at,
        };

        let session = Session::create(&mut *tx, create_data)
            .await
            .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        info!(
            user_id = %user_id,
            session_id = %session.id,
            device_name = ?session.device_name,
            "Created new session"
        );

        Ok(session)
    }

    /// Get all active sessions for a user.
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        current_session_id: Option<Uuid>,
    ) -> Result<Vec<SessionInfo>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let sessions = Session::find_active_by_user(&mut *conn, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .map(|s| {
                let is_current = current_session_id.is_some_and(|id| id == s.id);
                let mut info: SessionInfo = s.into();
                info.is_current = is_current;
                info
            })
            .collect();

        Ok(session_infos)
    }

    /// Get a specific session by ID.
    pub async fn get_session(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Session>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        Session::find_by_id(&mut *conn, session_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Get session by refresh token ID.
    pub async fn get_session_by_refresh_token(
        &self,
        refresh_token_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Session>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        Session::find_by_refresh_token(&mut *conn, refresh_token_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Revoke a specific session.
    pub async fn revoke_session(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
        reason: RevokeReason,
    ) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let result = Session::revoke(&mut *conn, session_id, reason)
            .await
            .map_err(ApiAuthError::Database)?;

        if result {
            info!(session_id = %session_id, reason = %reason, "Session revoked");
        }

        Ok(result)
    }

    /// Revoke all sessions for a user except the current one.
    pub async fn revoke_all_except_current(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        current_session_id: Uuid,
    ) -> Result<u64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let count = Session::revoke_all_except(
            &mut *conn,
            user_id,
            current_session_id,
            RevokeReason::UserLogout,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        info!(
            user_id = %user_id,
            revoked_count = count,
            "Revoked all sessions except current"
        );

        Ok(count)
    }

    /// Update session activity timestamp (with throttling).
    ///
    /// This method throttles updates to avoid excessive database writes.
    /// Updates are only performed if more than `ACTIVITY_UPDATE_THROTTLE_SECONDS`
    /// have passed since the last update.
    pub async fn update_activity(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), ApiAuthError> {
        // Check throttle
        {
            let cache = self.activity_cache.read().unwrap();
            if let Some(last_update) = cache.get(&session_id) {
                if last_update.elapsed().as_secs() < ACTIVITY_UPDATE_THROTTLE_SECONDS {
                    return Ok(()); // Skip update, too recent
                }
            }
        }

        // Perform update
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        Session::update_activity(&mut *conn, session_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Update throttle cache
        {
            let mut cache = self.activity_cache.write().unwrap();
            cache.insert(session_id, Instant::now());

            // Cleanup old entries periodically (every 1000 inserts)
            if cache.len() > 10000 {
                let threshold = Instant::now()
                    .checked_sub(std::time::Duration::from_secs(
                        ACTIVITY_UPDATE_THROTTLE_SECONDS * 2,
                    ))
                    .unwrap();
                cache.retain(|_, v| *v > threshold);
            }
        }

        Ok(())
    }

    /// Check if a session is valid (active and not idle).
    pub async fn is_session_valid(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, ApiAuthError> {
        let session = self.get_session(session_id, tenant_id).await?;

        let Some(session) = session else {
            return Ok(false);
        };

        if !session.is_active() {
            return Ok(false);
        }

        // Check idle timeout
        let policy = self.get_tenant_policy(tenant_id).await?;
        if session.is_idle(i64::from(policy.idle_timeout_minutes)) {
            // Revoke the session due to idle timeout
            warn!(
                session_id = %session_id,
                "Session idle timeout exceeded, revoking"
            );
            self.revoke_session(session_id, tenant_id, RevokeReason::IdleTimeout)
                .await?;
            return Ok(false);
        }

        Ok(true)
    }

    /// Get session policy for a tenant.
    pub async fn get_tenant_policy(
        &self,
        tenant_id: Uuid,
    ) -> Result<TenantSessionPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        TenantSessionPolicy::get_or_default(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Get the effective session policy for a user, considering org-level overrides.
    ///
    /// Resolves the user's organization memberships and returns a session policy
    /// that combines tenant-level and org-level settings using the most restrictive
    /// combination.
    pub async fn get_effective_session_policy(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<TenantSessionPolicy, ApiAuthError> {
        let tenant_policy = self.get_tenant_policy(tenant_id).await?;
        let org_service = OrgPolicyService::new(Arc::new(self.pool.clone()));

        match org_service
            .get_effective_policy_for_user(tenant_id, user_id, OrgPolicyType::Session)
            .await
        {
            Ok((config, sources)) => {
                // Check if we got an actual org policy (not just tenant default)
                let has_org_policy = sources.iter().any(|s| {
                    !matches!(
                        s,
                        xavyo_db::models::org_security_policy::PolicySource::TenantDefault
                    )
                });

                if has_org_policy {
                    let org_config: SessionPolicyConfig =
                        serde_json::from_value(config).map_err(|e| {
                            ApiAuthError::Internal(format!(
                                "Invalid org session policy config: {e}"
                            ))
                        })?;

                    // Apply org overrides using most-restrictive logic
                    Ok(TenantSessionPolicy {
                        absolute_timeout_hours: tenant_policy
                            .absolute_timeout_hours
                            .min(org_config.max_duration_hours),
                        idle_timeout_minutes: match (
                            tenant_policy.idle_timeout_minutes,
                            org_config.idle_timeout_minutes,
                        ) {
                            (0, 0) => 0,
                            (0, m) | (m, 0) => m,
                            (a, b) => a.min(b),
                        },
                        max_concurrent_sessions: match (
                            tenant_policy.max_concurrent_sessions,
                            org_config.concurrent_session_limit,
                        ) {
                            (0, 0) => 0,
                            (0, l) | (l, 0) => l,
                            (a, b) => a.min(b),
                        },
                        ..tenant_policy
                    })
                } else {
                    Ok(tenant_policy)
                }
            }
            Err(_) => {
                // If org policy resolution fails, fall back to tenant policy
                Ok(tenant_policy)
            }
        }
    }

    /// Update session policy for a tenant.
    pub async fn update_tenant_policy(
        &self,
        tenant_id: Uuid,
        data: UpsertSessionPolicy,
    ) -> Result<TenantSessionPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let policy = TenantSessionPolicy::upsert(&mut *conn, tenant_id, data)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(tenant_id = %tenant_id, "Session policy updated");

        Ok(policy)
    }

    /// Revoke all sessions for a user (e.g., on password change).
    pub async fn revoke_all_user_sessions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        reason: RevokeReason,
    ) -> Result<u64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let count = Session::revoke_all_for_user(&mut *conn, user_id, reason)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            user_id = %user_id,
            reason = %reason,
            revoked_count = count,
            "Revoked all user sessions"
        );

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_service_creation() {
        // Basic test that service can be conceptually created
        // Full tests require database setup
        assert_eq!(ACTIVITY_UPDATE_THROTTLE_SECONDS, 60);
    }
}
