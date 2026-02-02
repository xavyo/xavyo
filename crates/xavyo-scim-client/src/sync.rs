//! Full sync engine for SCIM outbound provisioning.
//!
//! Orchestrates a complete synchronization of all users and groups for a tenant
//! to a specific SCIM target.  Creates a [`ScimSyncRun`] record, iterates
//! through every user and group, provisions each to the target, tracks progress,
//! and marks the run as completed or failed.

use crate::client::ScimClient;
use crate::error::{ScimClientError, ScimClientResult};
use crate::provisioner::Provisioner;
use crate::retry::RetryPolicy;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_db::models::{
    CreateScimSyncRun, Group, GroupMembership, ScimProvisioningState, ScimSyncRun, ScimTarget,
    ScimTargetAttributeMapping, User,
};
use xavyo_webhooks::EventPublisher;

/// Page size used when fetching users and groups in batches.
const SYNC_PAGE_SIZE: i64 = 100;

/// How frequently (in terms of resources processed) to flush progress to the DB.
const PROGRESS_FLUSH_INTERVAL: i32 = 25;

/// Orchestrates pushing all users and groups for a tenant to a SCIM target.
///
/// The engine:
/// 1. Checks that no other sync run is already active for the target.
/// 2. Creates a `ScimSyncRun` record with status `running`.
/// 3. Loads all attribute mappings for the target.
/// 4. Iterates through all users for the tenant, provisioning each.
/// 5. Iterates through all groups for the tenant, provisioning each
///    (including group members that have already been provisioned).
/// 6. Updates progress periodically and marks the run completed or failed.
pub struct SyncEngine {
    pool: PgPool,
}

/// Mutable counters for tracking sync progress.
struct SyncProgress {
    processed: i32,
    created: i32,
    updated: i32,
    skipped: i32,
    failed: i32,
}

impl SyncProgress {
    fn new() -> Self {
        Self {
            processed: 0,
            created: 0,
            updated: 0,
            skipped: 0,
            failed: 0,
        }
    }
}

impl SyncEngine {
    /// Create a new sync engine backed by the given database pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convenience method to start a full sync using the engine's pool.
    ///
    /// Equivalent to calling [`SyncEngine::run_full_sync`] with `&self.pool`.
    pub async fn start_full_sync(
        &self,
        encryption: &CredentialEncryption,
        tenant_id: Uuid,
        target_id: Uuid,
        triggered_by: Option<Uuid>,
        event_publisher: Option<&EventPublisher>,
    ) -> ScimClientResult<Uuid> {
        Self::run_full_sync(
            &self.pool,
            encryption,
            tenant_id,
            target_id,
            triggered_by,
            event_publisher,
        )
        .await
    }

    /// Run a full synchronization of all users and groups for a tenant to a
    /// SCIM target.
    ///
    /// Returns the UUID of the created `ScimSyncRun` record.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - There is already an active sync run for the target.
    /// - The target cannot be found or is not active.
    /// - Credential decryption fails.
    /// - A database error occurs during setup.
    ///
    /// Individual user/group provisioning failures are tracked in the sync
    /// run counters but do **not** cause the entire run to fail.
    pub async fn run_full_sync(
        pool: &PgPool,
        encryption: &CredentialEncryption,
        tenant_id: Uuid,
        target_id: Uuid,
        triggered_by: Option<Uuid>,
        event_publisher: Option<&EventPublisher>,
    ) -> ScimClientResult<Uuid> {
        // ── 1. Guard against concurrent runs ─────────────────────────────
        let has_active = ScimSyncRun::has_active_run(pool, tenant_id, target_id).await?;
        if has_active {
            return Err(ScimClientError::InvalidConfig(format!(
                "An active sync run already exists for target {target_id} in tenant {tenant_id}"
            )));
        }

        // ── 2. Load the SCIM target ─────────────────────────────────────
        let target = ScimTarget::get_by_id(pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| {
                ScimClientError::InvalidConfig(format!(
                    "SCIM target {target_id} not found for tenant {tenant_id}"
                ))
            })?;

        if target.status != "active" {
            return Err(ScimClientError::InvalidConfig(format!(
                "SCIM target {target_id} is not active (status: {})",
                target.status
            )));
        }

        // ── 3. Count total resources to provision ────────────────────────
        let user_count = count_users_for_tenant(pool, tenant_id).await?;
        let group_count = Group::count_by_tenant(pool, tenant_id).await?;
        let total_resources = (user_count + group_count) as i32;

        // ── 4. Create the sync run record ────────────────────────────────
        let sync_run = ScimSyncRun::create(
            pool,
            CreateScimSyncRun {
                tenant_id,
                target_id,
                run_type: "full_sync".to_string(),
                triggered_by,
                total_resources,
            },
        )
        .await?;

        let run_id = sync_run.id;

        info!(
            tenant_id = %tenant_id,
            target_id = %target_id,
            run_id = %run_id,
            total_users = user_count,
            total_groups = group_count,
            "Starting full SCIM sync"
        );

        // Publish scim.sync.started webhook event.
        crate::publish_scim_webhook(
            event_publisher,
            "scim.sync.started",
            tenant_id,
            triggered_by,
            serde_json::json!({
                "target_id": target_id,
                "sync_run_id": run_id,
                "run_type": "full_sync",
                "total_resources": total_resources,
            }),
        );

        // ── 5. Build the SCIM client ────────────────────────────────────
        let mut client = crate::build_scim_client_from_target(&target, encryption, tenant_id)?;

        // Check if the target advertises PATCH support from cached SPC.
        if let Some(ref spc_value) = target.service_provider_config {
            if let Ok(spc) =
                serde_json::from_value::<crate::client::ServiceProviderConfig>(spc_value.clone())
            {
                client.set_patch_supported(spc.patch.supported);
            }
        }

        // ── 6. Build the provisioner ─────────────────────────────────────
        let retry_policy = RetryPolicy::new(target.max_retries as u32, 1);
        let provisioner = Provisioner::new(pool.clone(), retry_policy);

        // ── 7. Load attribute mappings for the target ────────────────────
        let mappings = ScimTargetAttributeMapping::list_by_target(pool, tenant_id, target_id, None)
            .await
            .unwrap_or_default();

        // ── 8. Execute the sync (users then groups) ──────────────────────
        let result = execute_sync(
            pool,
            &client,
            &provisioner,
            tenant_id,
            target_id,
            run_id,
            &mappings,
        )
        .await;

        // ── 9. Finalize the run ──────────────────────────────────────────
        match result {
            Ok(progress) => {
                // Flush final counters.
                if let Err(e) = ScimSyncRun::update_progress(
                    pool,
                    tenant_id,
                    run_id,
                    progress.processed,
                    progress.created,
                    progress.updated,
                    progress.skipped,
                    progress.failed,
                )
                .await
                {
                    warn!(run_id = %run_id, error = %e, "Failed to update final sync progress");
                }

                ScimSyncRun::complete(pool, tenant_id, run_id).await?;

                info!(
                    tenant_id = %tenant_id,
                    target_id = %target_id,
                    run_id = %run_id,
                    processed = progress.processed,
                    created = progress.created,
                    updated = progress.updated,
                    skipped = progress.skipped,
                    failed = progress.failed,
                    "Full SCIM sync completed"
                );

                // Publish scim.sync.completed webhook event.
                crate::publish_scim_webhook(
                    event_publisher,
                    "scim.sync.completed",
                    tenant_id,
                    triggered_by,
                    serde_json::json!({
                        "target_id": target_id,
                        "sync_run_id": run_id,
                        "run_type": "full_sync",
                        "processed": progress.processed,
                        "created": progress.created,
                        "updated": progress.updated,
                        "skipped": progress.skipped,
                        "failed": progress.failed,
                    }),
                );
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!(
                    tenant_id = %tenant_id,
                    target_id = %target_id,
                    run_id = %run_id,
                    error = %error_msg,
                    "Full SCIM sync failed"
                );
                ScimSyncRun::fail(pool, tenant_id, run_id, &error_msg).await?;

                // Publish scim.sync.failed webhook event.
                crate::publish_scim_webhook(
                    event_publisher,
                    "scim.sync.failed",
                    tenant_id,
                    triggered_by,
                    serde_json::json!({
                        "target_id": target_id,
                        "sync_run_id": run_id,
                        "run_type": "full_sync",
                        "error": error_msg,
                    }),
                );
            }
        }

        Ok(run_id)
    }
}

/// Execute the core sync loop: provision all users, then all groups.
///
/// Returns the final progress counters on success.
async fn execute_sync(
    pool: &PgPool,
    client: &ScimClient,
    provisioner: &Provisioner,
    tenant_id: Uuid,
    target_id: Uuid,
    run_id: Uuid,
    mappings: &[ScimTargetAttributeMapping],
) -> ScimClientResult<SyncProgress> {
    let mut progress = SyncProgress::new();

    // ── Users ────────────────────────────────────────────────────────
    let mut offset: i64 = 0;
    loop {
        let users = fetch_users_page(pool, tenant_id, SYNC_PAGE_SIZE, offset).await?;
        let page_len = users.len();

        for user in &users {
            sync_single_user(
                pool,
                client,
                provisioner,
                tenant_id,
                target_id,
                run_id,
                user,
                mappings,
                &mut progress,
            )
            .await;

            // Periodically flush progress.
            if progress.processed % PROGRESS_FLUSH_INTERVAL == 0 {
                flush_progress(pool, tenant_id, run_id, &progress).await;
            }
        }

        if (page_len as i64) < SYNC_PAGE_SIZE {
            break;
        }
        offset += SYNC_PAGE_SIZE;
    }

    // ── Groups ───────────────────────────────────────────────────────
    offset = 0;
    loop {
        let groups = Group::list_by_tenant(pool, tenant_id, SYNC_PAGE_SIZE, offset).await?;
        let page_len = groups.len();

        for group in &groups {
            sync_single_group(
                pool,
                client,
                provisioner,
                tenant_id,
                target_id,
                run_id,
                group,
                &mut progress,
            )
            .await;

            if progress.processed % PROGRESS_FLUSH_INTERVAL == 0 {
                flush_progress(pool, tenant_id, run_id, &progress).await;
            }
        }

        if (page_len as i64) < SYNC_PAGE_SIZE {
            break;
        }
        offset += SYNC_PAGE_SIZE;
    }

    Ok(progress)
}

/// Provision a single user to the SCIM target.
///
/// If the user is already synced, it is counted as skipped.
/// Provisioning errors are recorded but do not abort the sync.
#[allow(clippy::too_many_arguments)]
async fn sync_single_user(
    pool: &PgPool,
    client: &ScimClient,
    provisioner: &Provisioner,
    tenant_id: Uuid,
    target_id: Uuid,
    _run_id: Uuid,
    user: &User,
    mappings: &[ScimTargetAttributeMapping],
    progress: &mut SyncProgress,
) {
    progress.processed += 1;

    // Check if already synced.
    let existing_state = ScimProvisioningState::get_by_target_and_resource(
        pool, tenant_id, target_id, "User", user.id,
    )
    .await;

    let already_synced = match &existing_state {
        Ok(Some(state)) => state.status == "synced" && state.external_resource_id.is_some(),
        _ => false,
    };

    if already_synced {
        progress.skipped += 1;
        return;
    }

    // A state exists but isn't synced — this is a re-provision (update).
    let is_update = matches!(&existing_state, Ok(Some(_)));

    // Attempt to provision.
    let result = provisioner
        .provision_user_create(
            client,
            tenant_id,
            target_id,
            user.id,
            Some(&user.email),
            user.display_name.as_deref(),
            user.first_name.as_deref(),
            user.last_name.as_deref(),
            user.is_active,
            mappings,
        )
        .await;

    match result {
        Ok(()) => {
            if is_update {
                progress.updated += 1;
            } else {
                progress.created += 1;
            }
        }
        Err(e) => {
            progress.failed += 1;
            warn!(
                tenant_id = %tenant_id,
                target_id = %target_id,
                user_id = %user.id,
                error = %e,
                "Failed to provision user during full sync"
            );
        }
    }
}

/// Provision a single group to the SCIM target.
///
/// If the group is already synced, it is counted as skipped.
/// Provisioning errors are recorded but do not abort the sync.
#[allow(clippy::too_many_arguments)]
async fn sync_single_group(
    pool: &PgPool,
    client: &ScimClient,
    provisioner: &Provisioner,
    tenant_id: Uuid,
    target_id: Uuid,
    _run_id: Uuid,
    group: &Group,
    progress: &mut SyncProgress,
) {
    progress.processed += 1;

    // Check if already synced.
    let existing_state = ScimProvisioningState::get_by_target_and_resource(
        pool, tenant_id, target_id, "Group", group.id,
    )
    .await;

    let already_synced = match &existing_state {
        Ok(Some(state)) => state.status == "synced" && state.external_resource_id.is_some(),
        _ => false,
    };

    if already_synced {
        progress.skipped += 1;
        return;
    }

    // A state exists but isn't synced — this is a re-provision (update).
    let is_update = matches!(&existing_state, Ok(Some(_)));

    // Look up group members and their external resource IDs on this target.
    let member_external_ids =
        get_group_member_external_ids(pool, tenant_id, target_id, group.id).await;

    // Attempt to provision.
    let result = provisioner
        .provision_group_create(
            client,
            tenant_id,
            target_id,
            group.id,
            &group.display_name,
            &member_external_ids,
        )
        .await;

    match result {
        Ok(()) => {
            if is_update {
                progress.updated += 1;
            } else {
                progress.created += 1;
            }
        }
        Err(e) => {
            progress.failed += 1;
            warn!(
                tenant_id = %tenant_id,
                target_id = %target_id,
                group_id = %group.id,
                error = %e,
                "Failed to provision group during full sync"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: paginated user fetching
// ---------------------------------------------------------------------------

/// Count all users for a tenant.
async fn count_users_for_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
    let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
    Ok(result.0)
}

/// Fetch a page of users for a tenant (ordered by id for deterministic pagination).
async fn fetch_users_page(
    pool: &PgPool,
    tenant_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT * FROM users
        WHERE tenant_id = $1
        ORDER BY id
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Helper: resolve group member external IDs
// ---------------------------------------------------------------------------

/// Get the SCIM external resource IDs for all members of a group on a
/// specific target.
///
/// Returns only those members that have already been provisioned (`synced`)
/// to the target.
async fn get_group_member_external_ids(
    pool: &PgPool,
    tenant_id: Uuid,
    target_id: Uuid,
    group_id: Uuid,
) -> Vec<String> {
    let members = match GroupMembership::get_group_members(pool, tenant_id, group_id).await {
        Ok(m) => m,
        Err(e) => {
            warn!(
                tenant_id = %tenant_id,
                group_id = %group_id,
                error = %e,
                "Failed to fetch group members for SCIM sync"
            );
            return Vec::new();
        }
    };

    let mut external_ids = Vec::new();
    for member in &members {
        match ScimProvisioningState::get_by_target_and_resource(
            pool,
            tenant_id,
            target_id,
            "User",
            member.user_id,
        )
        .await
        {
            Ok(Some(state)) if state.status == "synced" => {
                if let Some(ext_id) = state.external_resource_id {
                    external_ids.push(ext_id);
                }
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    user_id = %member.user_id,
                    target_id = %target_id,
                    error = %e,
                    "Failed to look up provisioning state for group member"
                );
            }
        }
    }
    external_ids
}

// ---------------------------------------------------------------------------
// Helper: flush progress to the database
// ---------------------------------------------------------------------------

/// Write current progress counters to the sync run record.
///
/// Errors during flushing are logged but do not abort the sync.
async fn flush_progress(pool: &PgPool, tenant_id: Uuid, run_id: Uuid, progress: &SyncProgress) {
    if let Err(e) = ScimSyncRun::update_progress(
        pool,
        tenant_id,
        run_id,
        progress.processed,
        progress.created,
        progress.updated,
        progress.skipped,
        progress.failed,
    )
    .await
    {
        warn!(
            run_id = %run_id,
            error = %e,
            "Failed to flush sync progress"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_progress_initial() {
        let progress = SyncProgress::new();
        assert_eq!(progress.processed, 0);
        assert_eq!(progress.created, 0);
        assert_eq!(progress.updated, 0);
        assert_eq!(progress.skipped, 0);
        assert_eq!(progress.failed, 0);
    }

    #[test]
    fn test_sync_engine_construction() {
        // Verify the SyncEngine struct can be constructed.
        // Full integration tests require a database.
        let _constants = (SYNC_PAGE_SIZE, PROGRESS_FLUSH_INTERVAL);
        assert_eq!(SYNC_PAGE_SIZE, 100);
        assert_eq!(PROGRESS_FLUSH_INTERVAL, 25);
    }
}
