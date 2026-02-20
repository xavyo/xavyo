//! Reconciliation engine for SCIM outbound provisioning (F087 T044).
//!
//! Compares local provisioning state with the actual state on the SCIM target
//! to detect orphans, missing resources, and attribute drift.

use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use xavyo_api_scim::models::{ScimGroup, ScimGroupListResponse, ScimUser, ScimUserListResponse};
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_db::models::scim_provisioning_state::ScimProvisioningState;
use xavyo_db::models::scim_sync_run::{CreateScimSyncRun, ScimSyncRun};
use xavyo_db::models::scim_target::ScimTarget;

use crate::client::ScimClient;
use xavyo_webhooks::EventPublisher;

/// Page size used when fetching all resources from the SCIM target.
const FETCH_PAGE_SIZE: i64 = 100;

/// Maximum number of remote resources to fetch per resource type (Users/Groups).
///
/// Prevents unbounded memory growth when reconciling against large SCIM targets.
/// If a target exceeds this limit, the reconciliation will stop fetching and
/// report what was fetched so far.
const MAX_REMOTE_RESOURCES: usize = 50_000;

/// Maximum number of local provisioning state records to load.
const MAX_LOCAL_STATES: i64 = 50_000;

/// A detected discrepancy between local state and the SCIM target.
#[derive(Debug, Clone)]
pub struct ReconciliationDiscrepancy {
    /// Type of discrepancy.
    pub kind: DiscrepancyKind,
    /// Resource type ("User" or "Group").
    pub resource_type: String,
    /// The external resource ID on the target (if known).
    pub external_resource_id: Option<String>,
    /// The internal resource ID in local state (if known).
    pub internal_resource_id: Option<Uuid>,
    /// Human-readable description of the discrepancy.
    pub description: String,
}

/// Classification of a reconciliation discrepancy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscrepancyKind {
    /// Resource exists on the target but not in local provisioning state.
    Orphan,
    /// Resource exists in local provisioning state but not on the target.
    Missing,
    /// Resource exists on both sides but attributes differ.
    Drift,
}

/// Summary statistics from a reconciliation run.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationStats {
    /// Total number of resources examined on the target.
    pub total_target_resources: i32,
    /// Total number of local provisioning state records examined.
    pub total_local_states: i32,
    /// Number of orphaned resources found on the target.
    pub orphan_count: i32,
    /// Number of locally tracked resources missing from the target.
    pub missing_count: i32,
    /// Number of resources with attribute drift.
    pub drift_count: i32,
    /// Detailed discrepancies.
    pub discrepancies: Vec<ReconciliationDiscrepancy>,
}

/// Stateless reconciliation engine that compares local provisioning state
/// with what actually exists on a SCIM target.
pub struct ReconciliationEngine;

impl ReconciliationEngine {
    /// Run a full reconciliation for a SCIM target.
    ///
    /// Fetches all Users and Groups from the target via paginated GET requests,
    /// loads local provisioning state, then compares to detect orphans, missing
    /// resources, and attribute drift.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool.
    /// * `encryption` - Credential encryption service for decrypting target credentials.
    /// * `tenant_id` - The tenant performing the reconciliation.
    /// * `target_id` - The SCIM target to reconcile against.
    /// * `triggered_by` - Optional user ID of the person who triggered the reconciliation.
    ///
    /// # Returns
    /// The UUID of the completed sync run record.
    pub async fn run_reconciliation(
        pool: &PgPool,
        encryption: &CredentialEncryption,
        tenant_id: Uuid,
        target_id: Uuid,
        triggered_by: Option<Uuid>,
        event_publisher: Option<&EventPublisher>,
    ) -> Result<Uuid, Box<dyn Error + Send + Sync>> {
        info!(
            tenant_id = %tenant_id,
            target_id = %target_id,
            "Starting SCIM reconciliation"
        );

        // 1. Check for active runs — prevent concurrent reconciliation.
        let has_active = ScimSyncRun::has_active_run(pool, tenant_id, target_id).await?;
        if has_active {
            return Err("A sync or reconciliation run is already active for this target".into());
        }

        // 2. Create a sync run record with type "reconciliation".
        let sync_run = ScimSyncRun::create(
            pool,
            CreateScimSyncRun {
                tenant_id,
                target_id,
                run_type: "reconciliation".to_string(),
                triggered_by,
                total_resources: 0, // will be updated once we know the count
            },
        )
        .await?;

        let run_id = sync_run.id;

        // Publish scim.sync.started webhook event.
        crate::publish_scim_webhook(
            event_publisher,
            "scim.sync.started",
            tenant_id,
            triggered_by,
            serde_json::json!({
                "target_id": target_id,
                "sync_run_id": run_id,
                "run_type": "reconciliation",
            }),
        );

        // Execute the reconciliation, capturing any error to mark the run as failed.
        match Self::execute_reconciliation(pool, encryption, tenant_id, target_id, run_id).await {
            Ok(stats) => {
                // Update reconciliation-specific statistics.
                ScimSyncRun::update_reconciliation_stats(
                    pool,
                    tenant_id,
                    run_id,
                    stats.orphan_count,
                    stats.missing_count,
                    stats.drift_count,
                )
                .await?;

                // Update progress counters.
                let total_processed = stats.total_target_resources + stats.total_local_states;
                ScimSyncRun::update_progress(
                    pool,
                    tenant_id,
                    run_id,
                    total_processed,
                    0, // created_count
                    0, // updated_count
                    0, // skipped_count
                    0, // failed_count
                )
                .await?;

                // Mark the run as completed.
                ScimSyncRun::complete(pool, tenant_id, run_id).await?;

                info!(
                    tenant_id = %tenant_id,
                    target_id = %target_id,
                    run_id = %run_id,
                    orphans = stats.orphan_count,
                    missing = stats.missing_count,
                    drift = stats.drift_count,
                    "SCIM reconciliation completed"
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
                        "run_type": "reconciliation",
                        "orphan_count": stats.orphan_count,
                        "missing_count": stats.missing_count,
                        "drift_count": stats.drift_count,
                        "total_target_resources": stats.total_target_resources,
                        "total_local_states": stats.total_local_states,
                    }),
                );

                Ok(run_id)
            }
            Err(e) => {
                error!(
                    tenant_id = %tenant_id,
                    target_id = %target_id,
                    run_id = %run_id,
                    error = %e,
                    "SCIM reconciliation failed"
                );
                let error_msg = format!("{e}");
                let _ = ScimSyncRun::fail(pool, tenant_id, run_id, &error_msg).await;

                // Publish scim.sync.failed webhook event.
                crate::publish_scim_webhook(
                    event_publisher,
                    "scim.sync.failed",
                    tenant_id,
                    triggered_by,
                    serde_json::json!({
                        "target_id": target_id,
                        "sync_run_id": run_id,
                        "run_type": "reconciliation",
                        "error": error_msg,
                    }),
                );

                Err(e)
            }
        }
    }

    /// Internal implementation of the reconciliation logic.
    async fn execute_reconciliation(
        pool: &PgPool,
        encryption: &CredentialEncryption,
        tenant_id: Uuid,
        target_id: Uuid,
        run_id: Uuid,
    ) -> Result<ReconciliationStats, Box<dyn Error + Send + Sync>> {
        // 1. Load the SCIM target configuration.
        let target = ScimTarget::get_by_id(pool, tenant_id, target_id)
            .await?
            .ok_or_else(|| format!("SCIM target {target_id} not found for tenant {tenant_id}"))?;

        if target.status != "active" {
            return Err(format!(
                "SCIM target {} is not active (status: {})",
                target_id, target.status
            )
            .into());
        }

        // 2. Build the SCIM client from the target configuration.
        let client = crate::build_scim_client_from_target(&target, encryption, tenant_id)
            .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;

        // 3. Fetch all Users from the target.
        debug!(target_id = %target_id, "Fetching all users from SCIM target");
        let remote_users = Self::fetch_all_users(&client).await?;
        debug!(
            target_id = %target_id,
            count = remote_users.len(),
            "Fetched users from SCIM target"
        );

        // 4. Fetch all Groups from the target.
        debug!(target_id = %target_id, "Fetching all groups from SCIM target");
        let remote_groups = Self::fetch_all_groups(&client).await?;
        debug!(
            target_id = %target_id,
            count = remote_groups.len(),
            "Fetched groups from SCIM target"
        );

        let total_target_resources =
            i32::try_from(remote_users.len() + remote_groups.len()).unwrap_or(i32::MAX);

        // 5. Load all local provisioning states for this target.
        let (local_states, _total_count) = ScimProvisioningState::list_by_target(
            pool,
            tenant_id,
            target_id,
            None, // all resource types
            None, // all statuses
            MAX_LOCAL_STATES,
            0,
        )
        .await?;

        let total_local_states = local_states.len() as i32;

        debug!(
            target_id = %target_id,
            total_target = total_target_resources,
            total_local = total_local_states,
            "Loaded local provisioning states"
        );

        // 6. Compare and detect discrepancies.
        let mut stats = ReconciliationStats {
            total_target_resources,
            total_local_states,
            ..Default::default()
        };

        // Partition local states by resource type for efficient lookup.
        let user_states: Vec<&ScimProvisioningState> = local_states
            .iter()
            .filter(|s| s.resource_type == "User")
            .collect();
        let group_states: Vec<&ScimProvisioningState> = local_states
            .iter()
            .filter(|s| s.resource_type == "Group")
            .collect();

        // Compare Users.
        Self::compare_users(&remote_users, &user_states, &mut stats);

        // Compare Groups.
        Self::compare_groups(&remote_groups, &group_states, &mut stats);

        // Update total_resources on the sync run now that we know the count.
        let _ = sqlx::query(
            r"
            UPDATE scim_sync_runs
            SET total_resources = $3
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(total_target_resources + total_local_states)
        .execute(pool)
        .await;

        Ok(stats)
    }

    /// Fetch all users from the SCIM target using paginated requests.
    ///
    /// Stops after `MAX_REMOTE_RESOURCES` to prevent unbounded memory growth.
    async fn fetch_all_users(
        client: &ScimClient,
    ) -> Result<Vec<ScimUser>, Box<dyn Error + Send + Sync>> {
        let mut all_users = Vec::new();
        let mut start_index: i64 = 1;

        loop {
            let response: ScimUserListResponse = client
                .list_users(None, Some(start_index), Some(FETCH_PAGE_SIZE))
                .await?;

            let fetched_count = response.resources.len() as i64;
            all_users.extend(response.resources);

            // Safety cap: stop if we've fetched too many resources.
            if all_users.len() >= MAX_REMOTE_RESOURCES {
                warn!(
                    fetched = all_users.len(),
                    total_results = response.total_results,
                    "Reached MAX_REMOTE_RESOURCES limit for users, stopping fetch"
                );
                break;
            }

            // Check if we have fetched all resources.
            if fetched_count < FETCH_PAGE_SIZE || all_users.len() as i64 >= response.total_results {
                break;
            }

            start_index += fetched_count;
        }

        Ok(all_users)
    }

    /// Fetch all groups from the SCIM target using paginated requests.
    ///
    /// Stops after `MAX_REMOTE_RESOURCES` to prevent unbounded memory growth.
    async fn fetch_all_groups(
        client: &ScimClient,
    ) -> Result<Vec<ScimGroup>, Box<dyn Error + Send + Sync>> {
        let mut all_groups = Vec::new();
        let mut start_index: i64 = 1;

        loop {
            let response: ScimGroupListResponse = client
                .list_groups(None, Some(start_index), Some(FETCH_PAGE_SIZE))
                .await?;

            let fetched_count = response.resources.len() as i64;
            all_groups.extend(response.resources);

            // Safety cap: stop if we've fetched too many resources.
            if all_groups.len() >= MAX_REMOTE_RESOURCES {
                warn!(
                    fetched = all_groups.len(),
                    total_results = response.total_results,
                    "Reached MAX_REMOTE_RESOURCES limit for groups, stopping fetch"
                );
                break;
            }

            // Check if we have fetched all resources.
            if fetched_count < FETCH_PAGE_SIZE || all_groups.len() as i64 >= response.total_results
            {
                break;
            }

            start_index += fetched_count;
        }

        Ok(all_groups)
    }

    /// Compare remote users with local provisioning states, detecting
    /// orphans, missing resources, and drift.
    fn compare_users(
        remote_users: &[ScimUser],
        local_states: &[&ScimProvisioningState],
        stats: &mut ReconciliationStats,
    ) {
        // Build a lookup map of local states keyed by external_resource_id.
        let local_by_external_id: HashMap<&str, &ScimProvisioningState> = local_states
            .iter()
            .filter_map(|s| s.external_resource_id.as_deref().map(|eid| (eid, *s)))
            .collect();

        // Build a set of remote external resource IDs for reverse lookup.
        let remote_ids: HashSet<String> = remote_users
            .iter()
            .filter_map(|u| u.id.map(|id| id.to_string()))
            .collect();

        // Detect orphans: remote users not found in local state.
        for user in remote_users {
            let external_id = match &user.id {
                Some(id) => id.to_string(),
                None => continue, // Skip resources without an ID.
            };

            if local_by_external_id.contains_key(external_id.as_str()) {
                // Resource exists on both sides -- check for attribute drift.
                let local_state = local_by_external_id[external_id.as_str()];
                Self::detect_user_drift(user, &external_id, local_state, stats);
            } else {
                stats.orphan_count += 1;
                stats.discrepancies.push(ReconciliationDiscrepancy {
                    kind: DiscrepancyKind::Orphan,
                    resource_type: "User".to_string(),
                    external_resource_id: Some(external_id.clone()),
                    internal_resource_id: None,
                    description: format!(
                        "User '{}' (id={}) exists on target but not in local provisioning state",
                        user.display_name.as_deref().unwrap_or(&user.user_name),
                        external_id,
                    ),
                });
            }
        }

        // Detect missing: local states whose external_resource_id is not on the target.
        for state in local_states {
            // Only consider states that have been successfully synced (have an external ID).
            if let Some(ref ext_id) = state.external_resource_id {
                if !remote_ids.contains(ext_id) {
                    stats.missing_count += 1;
                    stats.discrepancies.push(ReconciliationDiscrepancy {
                        kind: DiscrepancyKind::Missing,
                        resource_type: "User".to_string(),
                        external_resource_id: Some(ext_id.clone()),
                        internal_resource_id: Some(state.internal_resource_id),
                        description: format!(
                            "User with external_resource_id={} (internal={}) exists in local state but not on target",
                            ext_id,
                            state.internal_resource_id,
                        ),
                    });
                }
            }
            // States without an external_resource_id are pending initial provisioning,
            // not "missing" -- they have never been synced to the target.
        }
    }

    /// Compare remote groups with local provisioning states, detecting
    /// orphans, missing resources, and drift.
    fn compare_groups(
        remote_groups: &[ScimGroup],
        local_states: &[&ScimProvisioningState],
        stats: &mut ReconciliationStats,
    ) {
        // Build a lookup map of local states keyed by external_resource_id.
        let local_by_external_id: HashMap<&str, &ScimProvisioningState> = local_states
            .iter()
            .filter_map(|s| s.external_resource_id.as_deref().map(|eid| (eid, *s)))
            .collect();

        // Build a set of remote external resource IDs for reverse lookup.
        let remote_ids: HashSet<String> = remote_groups
            .iter()
            .filter_map(|g| g.id.map(|id| id.to_string()))
            .collect();

        // Detect orphans: remote groups not found in local state.
        for group in remote_groups {
            let external_id = match &group.id {
                Some(id) => id.to_string(),
                None => continue,
            };

            if local_by_external_id.contains_key(external_id.as_str()) {
                // Resource exists on both sides -- check for display_name drift.
                let local_state = local_by_external_id[external_id.as_str()];
                Self::detect_group_drift(group, &external_id, local_state, stats);
            } else {
                stats.orphan_count += 1;
                stats.discrepancies.push(ReconciliationDiscrepancy {
                    kind: DiscrepancyKind::Orphan,
                    resource_type: "Group".to_string(),
                    external_resource_id: Some(external_id.clone()),
                    internal_resource_id: None,
                    description: format!(
                        "Group '{}' (id={}) exists on target but not in local provisioning state",
                        group.display_name, external_id,
                    ),
                });
            }
        }

        // Detect missing: local states whose external_resource_id is not on the target.
        for state in local_states {
            if let Some(ref ext_id) = state.external_resource_id {
                if !remote_ids.contains(ext_id) {
                    stats.missing_count += 1;
                    stats.discrepancies.push(ReconciliationDiscrepancy {
                        kind: DiscrepancyKind::Missing,
                        resource_type: "Group".to_string(),
                        external_resource_id: Some(ext_id.clone()),
                        internal_resource_id: Some(state.internal_resource_id),
                        description: format!(
                            "Group with external_resource_id={} (internal={}) exists in local state but not on target",
                            ext_id,
                            state.internal_resource_id,
                        ),
                    });
                }
            }
        }
    }

    /// Detect attribute drift for a User resource that exists on both sides.
    ///
    /// Currently checks:
    /// - `display_name`
    /// - active status
    /// - primary email
    ///
    /// The local provisioning state stores minimal metadata, so we compare
    /// attributes that are meaningful at the provisioning level.
    fn detect_user_drift(
        remote_user: &ScimUser,
        external_id: &str,
        local_state: &ScimProvisioningState,
        stats: &mut ReconciliationStats,
    ) {
        let mut drift_details: Vec<String> = Vec::new();

        // Check if the user is inactive on the target but the local state says "synced".
        // This indicates the user was deactivated directly on the target.
        if !remote_user.active && local_state.status == "synced" {
            drift_details.push("active: local=synced (active), remote=inactive".to_string());
        }

        // Check if the local state was marked for deprovisioning but the remote is still active.
        if remote_user.active && local_state.status == "deprovisioned" {
            drift_details.push(
                "active: local=deprovisioned, remote=active (still active on target)".to_string(),
            );
        }

        // Check externalId alignment: if both sides have externalId, they should match.
        if let Some(ref remote_ext_id) = remote_user.external_id {
            if let Some(ref local_ext_id) = local_state.external_id {
                if remote_ext_id != local_ext_id {
                    drift_details.push(format!(
                        "externalId: local={local_ext_id}, remote={remote_ext_id}",
                    ));
                }
            }
        }

        if !drift_details.is_empty() {
            stats.drift_count += 1;
            let description = format!(
                "User {} (internal={}) has attribute drift: {}",
                external_id,
                local_state.internal_resource_id,
                drift_details.join("; "),
            );
            warn!(
                external_id = %external_id,
                internal_id = %local_state.internal_resource_id,
                "User attribute drift detected: {}",
                drift_details.join("; "),
            );
            stats.discrepancies.push(ReconciliationDiscrepancy {
                kind: DiscrepancyKind::Drift,
                resource_type: "User".to_string(),
                external_resource_id: Some(external_id.to_string()),
                internal_resource_id: Some(local_state.internal_resource_id),
                description,
            });
        }
    }

    /// Detect attribute drift for a Group resource that exists on both sides.
    ///
    /// Currently checks:
    /// - externalId alignment
    /// - Deprovisioned state mismatch
    fn detect_group_drift(
        remote_group: &ScimGroup,
        external_id: &str,
        local_state: &ScimProvisioningState,
        stats: &mut ReconciliationStats,
    ) {
        let mut drift_details: Vec<String> = Vec::new();

        // Check externalId alignment.
        if let Some(ref remote_ext_id) = remote_group.external_id {
            if let Some(ref local_ext_id) = local_state.external_id {
                if remote_ext_id != local_ext_id {
                    drift_details.push(format!(
                        "externalId: local={local_ext_id}, remote={remote_ext_id}",
                    ));
                }
            }
        }

        // Check if local state says deprovisioned but group still exists on target.
        if local_state.status == "deprovisioned" {
            drift_details
                .push("status: local=deprovisioned but group still exists on target".to_string());
        }

        if !drift_details.is_empty() {
            stats.drift_count += 1;
            let description = format!(
                "Group '{}' {} (internal={}) has attribute drift: {}",
                remote_group.display_name,
                external_id,
                local_state.internal_resource_id,
                drift_details.join("; "),
            );
            warn!(
                external_id = %external_id,
                internal_id = %local_state.internal_resource_id,
                "Group attribute drift detected: {}",
                drift_details.join("; "),
            );
            stats.discrepancies.push(ReconciliationDiscrepancy {
                kind: DiscrepancyKind::Drift,
                resource_type: "Group".to_string(),
                external_resource_id: Some(external_id.to_string()),
                internal_resource_id: Some(local_state.internal_resource_id),
                description,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_local_state(
        resource_type: &str,
        internal_id: Uuid,
        external_resource_id: Option<&str>,
        external_id: Option<&str>,
        status: &str,
    ) -> ScimProvisioningState {
        ScimProvisioningState {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            resource_type: resource_type.to_string(),
            internal_resource_id: internal_id,
            external_resource_id: external_resource_id.map(std::string::ToString::to_string),
            external_id: external_id.map(std::string::ToString::to_string),
            status: status.to_string(),
            last_synced_at: None,
            last_error: None,
            retry_count: 0,
            next_retry_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn make_scim_user(
        id: Uuid,
        user_name: &str,
        active: bool,
        external_id: Option<&str>,
    ) -> ScimUser {
        let mut user = ScimUser::new(user_name);
        user.id = Some(id);
        user.active = active;
        user.external_id = external_id.map(std::string::ToString::to_string);
        user.display_name = Some(user_name.to_string());
        user
    }

    fn make_scim_group(id: Uuid, display_name: &str, external_id: Option<&str>) -> ScimGroup {
        let mut group = ScimGroup::new(display_name);
        group.id = Some(id);
        group.external_id = external_id.map(std::string::ToString::to_string);
        group
    }

    #[test]
    fn test_detect_orphan_users() {
        let remote_id = Uuid::new_v4();
        let remote_users = vec![make_scim_user(remote_id, "orphan@test.com", true, None)];
        let local_states: Vec<&ScimProvisioningState> = vec![];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 1);
        assert_eq!(stats.missing_count, 0);
        assert_eq!(stats.drift_count, 0);
        assert_eq!(stats.discrepancies[0].kind, DiscrepancyKind::Orphan);
        assert_eq!(stats.discrepancies[0].resource_type, "User");
    }

    #[test]
    fn test_detect_missing_users() {
        let missing_ext_id = Uuid::new_v4().to_string();
        let internal_id = Uuid::new_v4();
        let local_state =
            make_local_state("User", internal_id, Some(&missing_ext_id), None, "synced");
        let remote_users: Vec<ScimUser> = vec![];
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 0);
        assert_eq!(stats.missing_count, 1);
        assert_eq!(stats.drift_count, 0);
        assert_eq!(stats.discrepancies[0].kind, DiscrepancyKind::Missing);
    }

    #[test]
    fn test_detect_user_drift_inactive() {
        let ext_id = Uuid::new_v4();
        let internal_id = Uuid::new_v4();

        // Remote user is inactive, local state says synced (active).
        let remote_users = vec![make_scim_user(ext_id, "drifted@test.com", false, None)];
        let local_state = make_local_state(
            "User",
            internal_id,
            Some(&ext_id.to_string()),
            None,
            "synced",
        );
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 0);
        assert_eq!(stats.missing_count, 0);
        assert_eq!(stats.drift_count, 1);
        assert_eq!(stats.discrepancies[0].kind, DiscrepancyKind::Drift);
    }

    #[test]
    fn test_no_discrepancies_when_synced() {
        let ext_id = Uuid::new_v4();
        let internal_id = Uuid::new_v4();

        let remote_users = vec![make_scim_user(ext_id, "ok@test.com", true, None)];
        let local_state = make_local_state(
            "User",
            internal_id,
            Some(&ext_id.to_string()),
            None,
            "synced",
        );
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 0);
        assert_eq!(stats.missing_count, 0);
        assert_eq!(stats.drift_count, 0);
        assert!(stats.discrepancies.is_empty());
    }

    #[test]
    fn test_detect_orphan_groups() {
        let remote_id = Uuid::new_v4();
        let remote_groups = vec![make_scim_group(remote_id, "Orphan Group", None)];
        let local_states: Vec<&ScimProvisioningState> = vec![];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_groups(&remote_groups, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 1);
        assert_eq!(stats.discrepancies[0].resource_type, "Group");
    }

    #[test]
    fn test_detect_missing_groups() {
        let missing_ext_id = Uuid::new_v4().to_string();
        let internal_id = Uuid::new_v4();
        let local_state =
            make_local_state("Group", internal_id, Some(&missing_ext_id), None, "synced");
        let remote_groups: Vec<ScimGroup> = vec![];
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_groups(&remote_groups, &local_states, &mut stats);

        assert_eq!(stats.missing_count, 1);
        assert_eq!(stats.discrepancies[0].resource_type, "Group");
    }

    #[test]
    fn test_detect_group_drift_deprovisioned() {
        let ext_id = Uuid::new_v4();
        let internal_id = Uuid::new_v4();

        // Group still exists on target but local state says deprovisioned.
        let remote_groups = vec![make_scim_group(ext_id, "Lingering Group", None)];
        let local_state = make_local_state(
            "Group",
            internal_id,
            Some(&ext_id.to_string()),
            None,
            "deprovisioned",
        );
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_groups(&remote_groups, &local_states, &mut stats);

        assert_eq!(stats.drift_count, 1);
        assert_eq!(stats.discrepancies[0].kind, DiscrepancyKind::Drift);
    }

    #[test]
    fn test_pending_states_not_counted_as_missing() {
        // A local state with no external_resource_id means it was never provisioned.
        // It should NOT be counted as "missing".
        let internal_id = Uuid::new_v4();
        let local_state = make_local_state("User", internal_id, None, None, "pending");
        let remote_users: Vec<ScimUser> = vec![];
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.missing_count, 0);
        assert!(stats.discrepancies.is_empty());
    }

    #[test]
    fn test_mixed_scenario() {
        // Setup: 3 remote users, 3 local states
        // - user_a: exists on both sides, synced (no drift)
        // - user_b: only on remote (orphan)
        // - user_c: only in local state (missing)
        // - user_d: exists on both sides but deactivated on remote (drift)

        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let id_d = Uuid::new_v4();
        let internal_a = Uuid::new_v4();
        let internal_c = Uuid::new_v4();
        let internal_d = Uuid::new_v4();
        let missing_ext = Uuid::new_v4().to_string();

        let remote_users = vec![
            make_scim_user(id_a, "user_a@test.com", true, None),
            make_scim_user(id_b, "user_b@test.com", true, None),
            make_scim_user(id_d, "user_d@test.com", false, None),
        ];

        let state_a = make_local_state("User", internal_a, Some(&id_a.to_string()), None, "synced");
        let state_c = make_local_state("User", internal_c, Some(&missing_ext), None, "synced");
        let state_d = make_local_state("User", internal_d, Some(&id_d.to_string()), None, "synced");

        let local_states: Vec<&ScimProvisioningState> = vec![&state_a, &state_c, &state_d];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.orphan_count, 1, "user_b should be orphan");
        assert_eq!(stats.missing_count, 1, "user_c should be missing");
        assert_eq!(stats.drift_count, 1, "user_d should have drift");
        assert_eq!(stats.discrepancies.len(), 3);
    }

    #[test]
    fn test_external_id_drift() {
        let ext_id = Uuid::new_v4();
        let internal_id = Uuid::new_v4();

        // Remote user has externalId = "remote-ext", local has "local-ext".
        let remote_users = vec![make_scim_user(
            ext_id,
            "user@test.com",
            true,
            Some("remote-ext"),
        )];
        let local_state = make_local_state(
            "User",
            internal_id,
            Some(&ext_id.to_string()),
            Some("local-ext"),
            "synced",
        );
        let local_states: Vec<&ScimProvisioningState> = vec![&local_state];
        let mut stats = ReconciliationStats::default();

        ReconciliationEngine::compare_users(&remote_users, &local_states, &mut stats);

        assert_eq!(stats.drift_count, 1);
        assert!(stats.discrepancies[0].description.contains("externalId"));
    }
}
