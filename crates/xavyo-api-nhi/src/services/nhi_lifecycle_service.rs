//! NHI lifecycle transition service.
//!
//! Manages uniform lifecycle state transitions for all NHI types:
//! active -> inactive, suspended, deprecated
//! inactive -> active
//! suspended -> active
//! deprecated -> archived (terminal)

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::NhiIdentity;
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;

/// Service for lifecycle state transitions on NHI identities.
pub struct NhiLifecycleService;

impl NhiLifecycleService {
    /// Validate and execute a lifecycle state transition.
    ///
    /// All operations run within a single database transaction so that
    /// cascade effects (permission revocation)
    /// are atomic with the state change. If any step fails, all changes
    /// are rolled back.
    pub async fn transition(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        target_state: NhiLifecycleState,
        reason: Option<String>,
    ) -> Result<NhiIdentity, NhiApiError> {
        let mut tx = pool.begin().await.map_err(NhiApiError::Database)?;

        // 1. Find and lock the identity (FOR UPDATE prevents concurrent transitions)
        let identity: NhiIdentity = sqlx::query_as(
            "SELECT * FROM nhi_identities WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

        // 2. Validate transition
        if !identity.lifecycle_state.can_transition_to(target_state) {
            return Err(NhiApiError::InvalidTransition(format!(
                "cannot transition from {} to {}",
                identity.lifecycle_state, target_state
            )));
        }

        // 3. For archive: revoke tool permissions
        if target_state == NhiLifecycleState::Archived {
            sqlx::query(
                "DELETE FROM nhi_tool_permissions WHERE tenant_id = $1 AND (agent_nhi_id = $2 OR tool_nhi_id = $2)",
            )
            .bind(tenant_id)
            .bind(nhi_id)
            .execute(&mut *tx)
            .await
            .map_err(NhiApiError::Database)?;
        }

        // 3b. For suspend/deactivate/deprecate/archive: revoke all vault leases
        if matches!(
            target_state,
            NhiLifecycleState::Suspended
                | NhiLifecycleState::Inactive
                | NhiLifecycleState::Deprecated
                | NhiLifecycleState::Archived
        ) {
            let reason = format!("nhi_lifecycle_transition_to_{target_state}");
            let revoked = sqlx::query(
                r"
                UPDATE nhi_secret_leases l
                SET status = 'revoked', revoked_at = NOW(), revocation_reason = $3
                FROM nhi_vaulted_secrets s
                WHERE l.secret_id = s.id
                  AND s.tenant_id = $1
                  AND s.nhi_id = $2
                  AND l.status = 'active'
                ",
            )
            .bind(tenant_id)
            .bind(nhi_id)
            .bind(&reason)
            .execute(&mut *tx)
            .await
            .map_err(NhiApiError::Database)?;

            if revoked.rows_affected() > 0 {
                tracing::info!(
                    nhi_id = %nhi_id,
                    target_state = %target_state,
                    leases_revoked = revoked.rows_affected(),
                    "revoked vault leases on lifecycle transition"
                );
            }
        }

        // 4. Determine the reason to store:
        //    - For suspend: use provided reason
        //    - For reactivate (from suspended): clear the suspension_reason (None)
        //    - For other transitions: clear the suspension_reason (None)
        let effective_reason = if target_state == NhiLifecycleState::Suspended {
            reason
        } else {
            None
        };

        // 5. Execute the state transition
        let updated: NhiIdentity = sqlx::query_as(
            r"
            UPDATE nhi_identities
            SET lifecycle_state = $3,
                suspension_reason = $4,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(target_state)
        .bind(&effective_reason)
        .fetch_optional(&mut *tx)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

        // 6. Commit — all operations succeed or none do
        tx.commit().await.map_err(NhiApiError::Database)?;

        Ok(updated)
    }
}
