//! NHI inactivity detection service.
//!
//! Detects inactive NHI entities and enforces grace periods:
//! - Flag NHIs that exceed their inactivity threshold
//! - Set grace period deadlines
//! - Auto-suspend NHIs after grace period expiration
//! - Detect orphaned NHIs (owner deactivated, no backup owner)

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::NhiApiError;
use crate::services::nhi_lifecycle_service::NhiLifecycleService;
use xavyo_nhi::NhiLifecycleState;

/// An NHI entity that has exceeded its inactivity threshold.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InactiveEntity {
    pub id: Uuid,
    pub name: String,
    pub nhi_type: String,
    pub days_inactive: i64,
    pub threshold_days: i32,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub grace_period_ends_at: Option<DateTime<Utc>>,
}

/// An NHI entity whose owner is missing or inactive.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OrphanEntity {
    pub id: Uuid,
    pub name: String,
    pub nhi_type: String,
    pub owner_id: Option<Uuid>,
    pub reason: String,
}

/// Result of an auto-suspend operation.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AutoSuspendResult {
    pub suspended: Vec<Uuid>,
    pub failed: Vec<AutoSuspendFailure>,
}

/// A failed auto-suspend attempt.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AutoSuspendFailure {
    pub id: Uuid,
    pub error: String,
}

/// Service for detecting inactive and orphaned NHI entities.
pub struct NhiInactivityService;

// Internal row type for inactive entity query.
#[derive(Debug, sqlx::FromRow)]
struct InactiveRow {
    id: Uuid,
    name: String,
    nhi_type: String,
    last_activity_at: Option<DateTime<Utc>>,
    threshold: i32,
    grace_period_ends_at: Option<DateTime<Utc>>,
}

// Internal row type for orphan entity query.
#[derive(Debug, sqlx::FromRow)]
struct OrphanRow {
    id: Uuid,
    name: String,
    nhi_type: String,
    owner_id: Option<Uuid>,
    owner_exists: Option<bool>,
    owner_active: Option<bool>,
}

impl NhiInactivityService {
    /// Detect inactive NHI entities that exceed their inactivity threshold.
    ///
    /// Returns entities that are:
    /// - In `active` lifecycle state
    /// - Have an `inactivity_threshold_days` configured
    /// - Have a `last_activity_at` older than the threshold
    /// - Do NOT yet have a grace period set
    pub async fn detect_inactive(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<InactiveEntity>, NhiApiError> {
        let rows: Vec<InactiveRow> = sqlx::query_as(
            r"SELECT id, name, nhi_type::text as nhi_type, last_activity_at,
                     COALESCE(inactivity_threshold_days, 90) as threshold,
                     grace_period_ends_at
              FROM nhi_identities
              WHERE tenant_id = $1
                AND lifecycle_state = 'active'
                AND inactivity_threshold_days IS NOT NULL
                AND last_activity_at IS NOT NULL
                AND last_activity_at < NOW() - (inactivity_threshold_days || ' days')::interval
                AND grace_period_ends_at IS NULL
              ORDER BY last_activity_at ASC
              LIMIT 100",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(NhiApiError::Database)?;

        let now = Utc::now();
        Ok(rows
            .into_iter()
            .map(|row| {
                let days_inactive = row
                    .last_activity_at
                    .map(|la| (now - la).num_days())
                    .unwrap_or(0);
                InactiveEntity {
                    id: row.id,
                    name: row.name,
                    nhi_type: row.nhi_type,
                    days_inactive,
                    threshold_days: row.threshold,
                    last_activity_at: row.last_activity_at,
                    grace_period_ends_at: row.grace_period_ends_at,
                }
            })
            .collect())
    }

    /// Initiate a grace period for an NHI entity.
    ///
    /// Sets the `grace_period_ends_at` field to `NOW() + grace_days days`.
    /// Only applies to entities in `active` lifecycle state.
    pub async fn initiate_grace_period(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        grace_days: i32,
    ) -> Result<(), NhiApiError> {
        if !(1..=365).contains(&grace_days) {
            return Err(NhiApiError::BadRequest(
                "grace_days must be between 1 and 365".into(),
            ));
        }

        let result = sqlx::query(
            r"UPDATE nhi_identities
              SET grace_period_ends_at = NOW() + ($3 || ' days')::interval,
                  updated_at = NOW()
              WHERE tenant_id = $1 AND id = $2
                AND lifecycle_state = 'active'
                AND grace_period_ends_at IS NULL",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(grace_days)
        .execute(pool)
        .await
        .map_err(NhiApiError::Database)?;

        if result.rows_affected() == 0 {
            // Determine why: entity missing or grace period already active?
            let existing: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
                r"SELECT grace_period_ends_at FROM nhi_identities
                  WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'active'",
            )
            .bind(tenant_id)
            .bind(nhi_id)
            .fetch_optional(pool)
            .await
            .map_err(NhiApiError::Database)?;

            return match existing {
                Some(Some(_)) => Err(NhiApiError::Conflict(
                    "Grace period already active for this NHI".into(),
                )),
                _ => Err(NhiApiError::NotFound),
            };
        }

        Ok(())
    }

    /// Auto-suspend entities whose grace period has expired.
    ///
    /// Finds active entities with expired grace periods and transitions them
    /// to `Suspended` state with reason "Inactivity auto-suspension".
    pub async fn auto_suspend_expired(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<AutoSuspendResult, NhiApiError> {
        let expired: Vec<Uuid> = sqlx::query_scalar(
            r"SELECT id FROM nhi_identities
              WHERE tenant_id = $1
                AND lifecycle_state = 'active'
                AND grace_period_ends_at IS NOT NULL
                AND grace_period_ends_at < NOW()
              LIMIT 100",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(NhiApiError::Database)?;

        let mut suspended = Vec::new();
        let mut failed = Vec::new();

        for nhi_id in expired {
            match NhiLifecycleService::transition(
                pool,
                tenant_id,
                nhi_id,
                NhiLifecycleState::Suspended,
                Some("Inactivity auto-suspension".into()),
            )
            .await
            {
                Ok(_) => {
                    // Clear the grace period after successful suspension
                    sqlx::query(
                        r"UPDATE nhi_identities
                          SET grace_period_ends_at = NULL, updated_at = NOW()
                          WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant_id)
                    .bind(nhi_id)
                    .execute(pool)
                    .await
                    .map_err(NhiApiError::Database)?;
                    suspended.push(nhi_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to auto-suspend NHI {nhi_id}: {e}");
                    failed.push(AutoSuspendFailure {
                        id: nhi_id,
                        error: e.to_string(),
                    });
                }
            }
        }

        Ok(AutoSuspendResult { suspended, failed })
    }

    /// Detect orphaned NHI entities.
    ///
    /// An NHI is orphaned when:
    /// - It has no owner (owner_id IS NULL), OR
    /// - Its owner does not exist in the users table, OR
    /// - Its owner is not in `active` lifecycle state
    ///
    /// AND it has no backup owner set.
    pub async fn detect_orphans(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<OrphanEntity>, NhiApiError> {
        let rows: Vec<OrphanRow> = sqlx::query_as(
            r"SELECT i.id, i.name, i.nhi_type::text as nhi_type, i.owner_id,
                     (o.id IS NOT NULL) as owner_exists,
                     (o.lifecycle_state = 'active') as owner_active
              FROM nhi_identities i
              LEFT JOIN users o ON i.owner_id = o.id AND o.tenant_id = $1
              WHERE i.tenant_id = $1
                AND i.lifecycle_state = 'active'
                AND i.backup_owner_id IS NULL
                AND (
                  i.owner_id IS NULL
                  OR o.id IS NULL
                  OR o.lifecycle_state != 'active'
                )
              ORDER BY i.name ASC
              LIMIT 100",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(NhiApiError::Database)?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let reason = if row.owner_id.is_none() {
                    "No owner assigned".to_string()
                } else if !row.owner_exists.unwrap_or(false) {
                    "Owner user does not exist".to_string()
                } else if !row.owner_active.unwrap_or(false) {
                    "Owner user is not active".to_string()
                } else {
                    "Unknown".to_string()
                };
                OrphanEntity {
                    id: row.id,
                    name: row.name,
                    nhi_type: row.nhi_type,
                    owner_id: row.owner_id,
                    reason,
                }
            })
            .collect())
    }
}
