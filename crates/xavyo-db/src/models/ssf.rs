//! Shared Signals Framework storage (OpenID SSF 1.0 §8) — streams + subjects.
//!
//! xavyo acts as an SSF Transmitter. These models persist receiver streams and
//! the subjects registered on them. Tenant-scoped per CLAUDE.md §2 — the caller
//! sets the tenant context for RLS and passes `tenant_id` to every call.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Stream status values (SSF §8.1.2).
pub const STREAM_STATUS_ENABLED: &str = "enabled";
pub const STREAM_STATUS_PAUSED: &str = "paused";
pub const STREAM_STATUS_DISABLED: &str = "disabled";

/// A registered SSF stream (a receiver's subscription to security events).
#[derive(Debug, Clone, FromRow)]
pub struct SsfStream {
    /// Unique stream identifier.
    pub stream_id: Uuid,
    /// Tenant isolation (RLS-enforced).
    pub tenant_id: Uuid,
    /// Receiver audience (the SET `aud`).
    pub aud: String,
    /// Delivery method URN (v1: push, `urn:ietf:rfc:8935`).
    pub delivery_method: String,
    /// Push delivery endpoint SETs are POSTed to.
    pub endpoint_url: String,
    /// Optional bearer token presented to the receiver endpoint on delivery.
    pub delivery_authorization_header: Option<String>,
    /// CAEP event type URIs the receiver requested.
    pub events_requested: Vec<String>,
    /// CAEP event type URIs the transmitter will deliver.
    pub events_delivered: Vec<String>,
    /// Stream status: `enabled` | `paused` | `disabled`.
    pub status: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a stream.
#[derive(Debug, Clone)]
pub struct CreateSsfStream {
    pub tenant_id: Uuid,
    pub aud: String,
    pub delivery_method: String,
    pub endpoint_url: String,
    pub delivery_authorization_header: Option<String>,
    pub events_requested: Vec<String>,
    pub events_delivered: Vec<String>,
    pub description: Option<String>,
}

impl SsfStream {
    /// Create a stream (status defaults to `enabled`).
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn create<'e, E>(executor: E, input: CreateSsfStream) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO ssf_streams (
                tenant_id, aud, delivery_method, endpoint_url,
                delivery_authorization_header, events_requested, events_delivered, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.aud)
        .bind(&input.delivery_method)
        .bind(&input.endpoint_url)
        .bind(&input.delivery_authorization_header)
        .bind(&input.events_requested)
        .bind(&input.events_delivered)
        .bind(&input.description)
        .fetch_one(executor)
        .await
    }

    /// Fetch a stream by id within the tenant.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn get<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as("SELECT * FROM ssf_streams WHERE tenant_id = $1 AND stream_id = $2")
            .bind(tenant_id)
            .bind(stream_id)
            .fetch_optional(executor)
            .await
    }

    /// List all streams for a tenant.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn list_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as("SELECT * FROM ssf_streams WHERE tenant_id = $1 ORDER BY created_at")
            .bind(tenant_id)
            .fetch_all(executor)
            .await
    }

    /// List enabled streams in the tenant that deliver a given CAEP event type —
    /// the transmitter's fan-out query.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn list_enabled_for_event<'e, E>(
        executor: E,
        tenant_id: Uuid,
        event_uri: &str,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM ssf_streams
            WHERE tenant_id = $1
              AND status = 'enabled'
              AND $2 = ANY(events_delivered)
            ",
        )
        .bind(tenant_id)
        .bind(event_uri)
        .fetch_all(executor)
        .await
    }

    /// Update a stream's status (SSF §8.1.2). Returns the updated row, or `None`
    /// if no such stream exists in the tenant.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn update_status<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
        status: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            UPDATE ssf_streams
            SET status = $3, updated_at = now()
            WHERE tenant_id = $1 AND stream_id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(stream_id)
        .bind(status)
        .fetch_optional(executor)
        .await
    }

    /// Delete a stream. Returns `true` if a row was removed.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn delete<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query("DELETE FROM ssf_streams WHERE tenant_id = $1 AND stream_id = $2")
            .bind(tenant_id)
            .bind(stream_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

/// A subject registered to a stream for event delivery.
#[derive(Debug, Clone, FromRow)]
pub struct SsfSubject {
    /// Unique row id.
    pub id: Uuid,
    /// The stream this subject is registered on.
    pub stream_id: Uuid,
    /// Tenant isolation (RLS-enforced).
    pub tenant_id: Uuid,
    /// The RFC 9493 Subject Identifier (its JSON object).
    pub subject: serde_json::Value,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl SsfSubject {
    /// Register a subject on a stream.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn add<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
        subject: &serde_json::Value,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO ssf_subjects (stream_id, tenant_id, subject)
            VALUES ($1, $2, $3)
            RETURNING *
            ",
        )
        .bind(stream_id)
        .bind(tenant_id)
        .bind(subject)
        .fetch_one(executor)
        .await
    }

    /// Remove a subject from a stream (matched by exact JSON equality). Returns
    /// the number of rows removed.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn remove<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
        subject: &serde_json::Value,
    ) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r"
            DELETE FROM ssf_subjects
            WHERE tenant_id = $1 AND stream_id = $2 AND subject = $3
            ",
        )
        .bind(tenant_id)
        .bind(stream_id)
        .bind(subject)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// List the subjects registered on a stream.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn list_for_stream<'e, E>(
        executor: E,
        tenant_id: Uuid,
        stream_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            "SELECT * FROM ssf_subjects WHERE tenant_id = $1 AND stream_id = $2 ORDER BY created_at",
        )
        .bind(tenant_id)
        .bind(stream_id)
        .fetch_all(executor)
        .await
    }
}
