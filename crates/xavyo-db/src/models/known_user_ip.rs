//! Known user IP model for Storm-2372 remediation.
//!
//! Tracks IP addresses that users have successfully authenticated from,
//! used to calculate risk scores by detecting new or unfamiliar locations.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A known IP address record for a user.
///
/// Tracks IPs that users have successfully authenticated from,
/// along with usage statistics and trust status.
#[derive(Debug, Clone, FromRow)]
pub struct KnownUserIp {
    /// Unique identifier for this record.
    pub id: Uuid,

    /// Tenant owning this record.
    pub tenant_id: Uuid,

    /// User whose IP this is.
    pub user_id: Uuid,

    /// The IP address (IPv4 or IPv6).
    pub ip_address: String,

    /// Country code extracted from this IP (ISO 3166-1 alpha-2).
    pub country_code: Option<String>,

    /// When this IP was first seen for this user.
    pub first_seen_at: DateTime<Utc>,

    /// When this IP was last seen for this user.
    pub last_seen_at: DateTime<Utc>,

    /// Number of successful authentications from this IP.
    pub access_count: i32,

    /// Whether this IP is trusted (verified by user or admin).
    pub is_trusted: bool,
}

impl KnownUserIp {
    /// Check if this IP has been seen many times (established).
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.access_count >= 5
    }

    /// Check if this IP was seen recently (within 30 days).
    #[must_use]
    pub fn is_recent(&self) -> bool {
        let age = Utc::now() - self.last_seen_at;
        age.num_days() <= 30
    }

    /// Find a known IP for a user.
    pub async fn find_by_user_ip(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM known_user_ips
            WHERE tenant_id = $1 AND user_id = $2 AND ip_address = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(ip_address)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Get all known IPs for a user.
    pub async fn find_by_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM known_user_ips
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY last_seen_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
    }

    /// Get all distinct countries for a user's known IPs.
    pub async fn get_known_countries(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let records = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT country_code FROM known_user_ips
            WHERE tenant_id = $1 AND user_id = $2 AND country_code IS NOT NULL
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    /// Record or update a user IP address.
    ///
    /// If the IP exists, updates last_seen_at and increments access_count.
    /// If it doesn't exist, creates a new record.
    pub async fn record_access(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: &str,
        country_code: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO known_user_ips (tenant_id, user_id, ip_address, country_code)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, user_id, ip_address) DO UPDATE
            SET last_seen_at = NOW(),
                access_count = known_user_ips.access_count + 1,
                country_code = COALESCE($4, known_user_ips.country_code)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(ip_address)
        .bind(country_code)
        .fetch_one(&mut *conn)
        .await
    }

    /// Mark an IP as trusted.
    pub async fn set_trusted(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        trusted: bool,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r#"
            UPDATE known_user_ips
            SET is_trusted = $3
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(trusted)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Delete a known IP record.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let result = sqlx::query(
            r#"
            DELETE FROM known_user_ips
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Cleanup old IP records not seen in the specified days.
    pub async fn cleanup_old(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM known_user_ips
            WHERE last_seen_at < NOW() - make_interval(days => $1)
              AND is_trusted = FALSE
            "#,
        )
        .bind(days as i32)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_is_established() {
        let low_count = KnownUserIp {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            country_code: Some("US".to_string()),
            first_seen_at: Utc::now() - Duration::days(30),
            last_seen_at: Utc::now(),
            access_count: 3,
            is_trusted: false,
        };
        assert!(
            !low_count.is_established(),
            "3 accesses should not be established"
        );

        let high_count = KnownUserIp {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            country_code: Some("US".to_string()),
            first_seen_at: Utc::now() - Duration::days(30),
            last_seen_at: Utc::now(),
            access_count: 10,
            is_trusted: false,
        };
        assert!(
            high_count.is_established(),
            "10 accesses should be established"
        );
    }

    #[test]
    fn test_is_recent() {
        let recent = KnownUserIp {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            country_code: Some("US".to_string()),
            first_seen_at: Utc::now() - Duration::days(60),
            last_seen_at: Utc::now() - Duration::days(5), // 5 days ago
            access_count: 5,
            is_trusted: false,
        };
        assert!(recent.is_recent(), "IP seen 5 days ago should be recent");

        let old = KnownUserIp {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            country_code: Some("US".to_string()),
            first_seen_at: Utc::now() - Duration::days(90),
            last_seen_at: Utc::now() - Duration::days(45), // 45 days ago
            access_count: 5,
            is_trusted: false,
        };
        assert!(!old.is_recent(), "IP seen 45 days ago should not be recent");
    }
}
