//! User location model for location tracking.
//!
//! Tracks known geo-locations per user for new location detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A known location for a user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserLocation {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The user who owns this location.
    pub user_id: Uuid,

    /// ISO 3166-1 alpha-2 country code.
    pub country: String,

    /// City name.
    pub city: String,

    /// When the location was first seen.
    pub first_seen_at: DateTime<Utc>,

    /// When the location was last seen.
    pub last_seen_at: DateTime<Utc>,

    /// Number of logins from this location.
    pub login_count: i32,
}

impl UserLocation {
    /// Check if a location exists for a user.
    pub async fn exists<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
        city: &str,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM user_locations
                WHERE tenant_id = $1 AND user_id = $2 AND country = $3 AND city = $4
            )
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(country)
        .bind(city)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Get a location by country and city.
    pub async fn get_by_location<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
        city: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM user_locations
            WHERE tenant_id = $1 AND user_id = $2 AND country = $3 AND city = $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(country)
        .bind(city)
        .fetch_optional(executor)
        .await
    }

    /// Record a location login (upsert with ON CONFLICT).
    ///
    /// Returns (location, is_new) where is_new indicates if this was a new location.
    pub async fn record_login<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
        city: &str,
    ) -> Result<(Self, bool), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Use INSERT with ON CONFLICT and check if it was an insert or update
        let location: Self = sqlx::query_as(
            r#"
            INSERT INTO user_locations (tenant_id, user_id, country, city)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, user_id, country, city)
            DO UPDATE SET last_seen_at = NOW(), login_count = user_locations.login_count + 1
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(country)
        .bind(city)
        .fetch_one(executor)
        .await?;

        // Check if it's a new location (login_count = 1)
        let is_new = location.login_count == 1;
        Ok((location, is_new))
    }

    /// Get all locations for a user.
    pub async fn get_user_locations<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM user_locations
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY last_seen_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Count locations for a user.
    pub async fn count_user_locations<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM user_locations
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Delete a location.
    pub async fn delete<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM user_locations
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
