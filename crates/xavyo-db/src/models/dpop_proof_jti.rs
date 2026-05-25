//! DPoP proof replay cache (RFC 9449 §11.1).
//!
//! Records the `jti` of each accepted DPoP proof for the proof acceptance
//! window so a replayed proof is detected and rejected. Tenant-scoped per
//! CLAUDE.md §2 — the caller MUST set the tenant context for RLS and pass the
//! `tenant_id` of the access token being presented/issued.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Replay-cache operations for DPoP proof `jti`s.
pub struct DpopProofJti;

impl DpopProofJti {
    /// Atomically record a proof `jti` as seen, returning whether it was NEW.
    ///
    /// Returns `Ok(true)` if the `jti` had not been seen for this tenant (the
    /// proof is fresh — accept it) and `Ok(false)` if it was already present
    /// (a **replay** — reject it). Uses `INSERT … ON CONFLICT DO NOTHING
    /// RETURNING` so the check-and-record is a single atomic statement (no
    /// check-then-insert race).
    ///
    /// `expires_at` should be `now + proof acceptance window`; expired rows are
    /// vacuumed by [`Self::cleanup_expired`].
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn record_if_new<'e, E>(
        executor: E,
        tenant_id: Uuid,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let inserted: Option<(String,)> = sqlx::query_as(
            r"
            INSERT INTO dpop_proof_jtis (jti, tenant_id, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, jti) DO NOTHING
            RETURNING jti
            ",
        )
        .bind(jti)
        .bind(tenant_id)
        .bind(expires_at)
        .fetch_optional(executor)
        .await?;

        Ok(inserted.is_some())
    }

    /// Delete proof records past their expiry. Returns the number removed.
    /// Intended for a periodic cleanup job.
    ///
    /// # Errors
    /// Propagates the underlying `sqlx` error.
    pub async fn cleanup_expired<'e, E>(executor: E) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query("DELETE FROM dpop_proof_jtis WHERE expires_at < now()")
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }
}
