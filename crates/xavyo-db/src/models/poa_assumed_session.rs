//! Power of Attorney Assumed Session model.
//!
//! Tracks when an attorney assumes a donor's identity and when they drop it.
//! Part of F-061 Power of Attorney / Identity Assumption feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

/// An assumed identity session.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PoaAssumedSession {
    /// Unique identifier for the session.
    pub id: Uuid,

    /// The tenant this session belongs to.
    pub tenant_id: Uuid,

    /// Link to the PoA grant being used.
    pub poa_id: Uuid,

    /// The attorney who assumed the identity.
    pub attorney_id: Uuid,

    /// When the identity was assumed.
    pub assumed_at: DateTime<Utc>,

    /// When the identity was dropped (if dropped).
    pub dropped_at: Option<DateTime<Utc>>,

    /// JWT ID for session tracking.
    pub session_token_jti: String,

    /// Client IP address (stored as String, INET type maps to String in SQLx).
    pub ip_address: Option<String>,

    /// Client user agent.
    pub user_agent: Option<String>,

    /// Whether the session is currently active.
    pub is_active: bool,

    /// Reason for termination (dropped, revoked, expired).
    pub terminated_reason: Option<String>,
}

impl PoaAssumedSession {
    /// Get the IP address as parsed `IpAddr` (if present and valid).
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_address.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Request to create a new assumed session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePoaAssumedSession {
    pub poa_id: Uuid,
    pub attorney_id: Uuid,
    pub session_token_jti: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl CreatePoaAssumedSession {
    /// Create a new assumed session request.
    pub fn new(poa_id: Uuid, attorney_id: Uuid, session_token_jti: String) -> Self {
        Self {
            poa_id,
            attorney_id,
            session_token_jti,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the IP address.
    pub fn with_ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }

    /// Set the user agent.
    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }
}

/// Filter options for listing assumed sessions.
#[derive(Debug, Clone, Default)]
pub struct AssumedSessionFilter {
    /// Filter by PoA ID.
    pub poa_id: Option<Uuid>,
    /// Filter by attorney ID.
    pub attorney_id: Option<Uuid>,
    /// Filter by active status.
    pub is_active: Option<bool>,
}

impl PoaAssumedSession {
    /// Find a session by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_assumed_sessions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a session by JWT ID.
    pub async fn find_by_jti(pool: &sqlx::PgPool, jti: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_assumed_sessions
            WHERE session_token_jti = $1
            ",
        )
        .bind(jti)
        .fetch_optional(pool)
        .await
    }

    /// Find active session for an attorney.
    pub async fn find_active_for_attorney(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        attorney_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_assumed_sessions
            WHERE tenant_id = $1
              AND attorney_id = $2
              AND is_active = TRUE
            ORDER BY assumed_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(attorney_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all active sessions for a PoA.
    pub async fn find_active_for_poa(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_assumed_sessions
            WHERE tenant_id = $1
              AND poa_id = $2
              AND is_active = TRUE
            ORDER BY assumed_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .fetch_all(pool)
        .await
    }

    /// List sessions with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AssumedSessionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM poa_assumed_sessions
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.poa_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND poa_id = ${param_count}"));
        }
        if filter.attorney_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attorney_id = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY assumed_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, PoaAssumedSession>(&query).bind(tenant_id);

        if let Some(poa_id) = filter.poa_id {
            q = q.bind(poa_id);
        }
        if let Some(attorney_id) = filter.attorney_id {
            q = q.bind(attorney_id);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new assumed session.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePoaAssumedSession,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO poa_assumed_sessions (
                tenant_id, poa_id, attorney_id, session_token_jti, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.poa_id)
        .bind(input.attorney_id)
        .bind(input.session_token_jti)
        .bind(input.ip_address)
        .bind(input.user_agent)
        .fetch_one(pool)
        .await
    }

    /// Drop an assumed session (user-initiated).
    pub async fn drop_session(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE poa_assumed_sessions
            SET is_active = FALSE, dropped_at = NOW(), terminated_reason = 'dropped'
            WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Terminate a session by JTI (for revocation).
    pub async fn terminate_by_jti(
        pool: &sqlx::PgPool,
        jti: &str,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE poa_assumed_sessions
            SET is_active = FALSE, dropped_at = NOW(), terminated_reason = $2
            WHERE session_token_jti = $1 AND is_active = TRUE
            RETURNING *
            ",
        )
        .bind(jti)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Terminate all active sessions for a PoA.
    pub async fn terminate_all_for_poa(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
        reason: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE poa_assumed_sessions
            SET is_active = FALSE, dropped_at = NOW(), terminated_reason = $3
            WHERE tenant_id = $1 AND poa_id = $2 AND is_active = TRUE
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .bind(reason)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Terminate all active sessions for an attorney.
    pub async fn terminate_all_for_attorney(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        attorney_id: Uuid,
        reason: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE poa_assumed_sessions
            SET is_active = FALSE, dropped_at = NOW(), terminated_reason = $3
            WHERE tenant_id = $1 AND attorney_id = $2 AND is_active = TRUE
            ",
        )
        .bind(tenant_id)
        .bind(attorney_id)
        .bind(reason)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active sessions for a PoA.
    pub async fn count_active_for_poa(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM poa_assumed_sessions
            WHERE tenant_id = $1 AND poa_id = $2 AND is_active = TRUE
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_request() {
        let request = CreatePoaAssumedSession::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-jti-12345".to_string(),
        )
        .with_ip_address("192.168.1.1".parse().unwrap())
        .with_user_agent("Mozilla/5.0".to_string());

        assert_eq!(request.session_token_jti, "test-jti-12345");
        assert_eq!(request.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_session_filter_default() {
        let filter = AssumedSessionFilter::default();
        assert!(filter.poa_id.is_none());
        assert!(filter.attorney_id.is_none());
        assert!(filter.is_active.is_none());
    }

    #[test]
    fn test_ip_addr_parsing() {
        // Simulate a session with IP address
        let session = PoaAssumedSession {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            poa_id: Uuid::new_v4(),
            attorney_id: Uuid::new_v4(),
            assumed_at: Utc::now(),
            dropped_at: None,
            session_token_jti: "test-jti".to_string(),
            ip_address: Some("10.0.0.1".to_string()),
            user_agent: None,
            is_active: true,
            terminated_reason: None,
        };

        let ip = session.ip_addr();
        assert!(ip.is_some());
        assert_eq!(ip.unwrap().to_string(), "10.0.0.1");
    }
}
