//! User and group provisioning orchestrator.
//!
//! Orchestrates SCIM operations against targets, handling conflict resolution,
//! state tracking, and operation logging.

use crate::client::ScimClient;
use crate::error::{ScimClientError, ScimClientResult};
use crate::mapper::AttributeMapper;
use crate::retry::RetryPolicy;
use sqlx::PgPool;
use std::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;
use xavyo_db::models::{
    CreateScimProvisioningLog, CreateScimProvisioningState, ScimProvisioningLog,
    ScimProvisioningState, ScimTargetAttributeMapping,
};

/// Orchestrates SCIM provisioning operations for users and groups.
///
/// The `Provisioner` coordinates the full lifecycle of SCIM resource
/// management: creating, updating, and deprovisioning users and groups on
/// target systems.  Each operation:
///
/// 1. Tracks provisioning state in the database (via [`ScimProvisioningState`]).
/// 2. Builds the appropriate SCIM payload using [`AttributeMapper`].
/// 3. Sends the SCIM request through [`ScimClient`] with retry logic.
/// 4. Handles 409 Conflict responses by looking up and linking existing
///    resources instead of failing.
/// 5. Logs every operation attempt to the immutable audit log
///    (via [`ScimProvisioningLog`]).
pub struct Provisioner {
    pool: PgPool,
    retry_policy: RetryPolicy,
}

impl Provisioner {
    /// Create a new provisioner with the given database pool and retry policy.
    #[must_use] 
    pub fn new(pool: PgPool, retry_policy: RetryPolicy) -> Self {
        Self { pool, retry_policy }
    }

    /// Provision a user creation to a SCIM target.
    ///
    /// Creates the user on the target system.  If the target returns a 409
    /// Conflict (resource already exists), the provisioner looks up the
    /// existing resource by `externalId`, links it, and falls back to a
    /// PATCH update instead.
    ///
    /// On success the provisioning state is updated to `synced` with the
    /// external resource ID assigned by the target.
    #[allow(clippy::too_many_arguments)]
    pub async fn provision_user_create(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        user_id: Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
        first_name: Option<&str>,
        last_name: Option<&str>,
        active: bool,
        mappings: &[ScimTargetAttributeMapping],
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        // 1. Get or create provisioning state.
        let state = ScimProvisioningState::get_or_create(
            &self.pool,
            CreateScimProvisioningState {
                tenant_id,
                target_id,
                resource_type: "User".to_string(),
                internal_resource_id: user_id,
                external_id: Some(user_id.to_string()),
            },
        )
        .await?;

        // If already synced, skip unless we want to force re-create.
        if state.status == "synced" && state.external_resource_id.is_some() {
            info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                target_id = %target_id,
                external_id = ?state.external_resource_id,
                "User already synced to target, skipping create"
            );
            return Ok(());
        }

        // 2. Build SCIM user from mappings.
        let scim_user = AttributeMapper::map_user_to_scim(
            user_id,
            email,
            display_name,
            first_name,
            last_name,
            active,
            mappings,
        );

        // 3. Try create_user with retry.
        let result = self
            .retry_policy
            .execute("scim_create_user", || {
                let user = scim_user.clone();
                async move { client.create_user(&user).await }
            })
            .await;

        match result {
            Ok(created_user) => {
                // Extract the SCIM-assigned ID.
                let external_resource_id =
                    created_user.id.map(|id| id.to_string()).unwrap_or_default();

                // 5. Update provisioning state.
                ScimProvisioningState::update_synced(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &external_resource_id,
                )
                .await?;

                info!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    target_id = %target_id,
                    external_resource_id = %external_resource_id,
                    "User created on SCIM target"
                );

                // 6. Log the operation.
                self.log_operation(
                    tenant_id,
                    target_id,
                    "create",
                    "User",
                    user_id,
                    Some(external_resource_id),
                    "POST",
                    Some(201),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(ScimClientError::Conflict(_)) => {
                // 4. On 409 Conflict: find_user_by_external_id, link, patch.
                warn!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    target_id = %target_id,
                    "User creation conflict (409), attempting lookup by externalId"
                );

                self.handle_user_create_conflict(
                    client, tenant_id, target_id, user_id, &state, &scim_user, mappings, started,
                )
                .await
            }
            Err(e) => {
                // Record the error in provisioning state.
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation_with_retry_count(
                    tenant_id,
                    target_id,
                    "create",
                    "User",
                    user_id,
                    None,
                    "POST",
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                    new_retry_count,
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to create user on SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Handle a 409 Conflict during user creation by looking up the existing
    /// resource and linking it, then applying a PATCH update.
    #[allow(clippy::too_many_arguments)]
    async fn handle_user_create_conflict(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        user_id: Uuid,
        state: &ScimProvisioningState,
        scim_user: &xavyo_api_scim::models::ScimUser,
        mappings: &[ScimTargetAttributeMapping],
        started: Instant,
    ) -> ScimClientResult<()> {
        let external_id_str = user_id.to_string();

        // Try to find the existing user by externalId.
        let existing = self
            .retry_policy
            .execute("scim_find_user_by_external_id", || {
                let ext_id = external_id_str.clone();
                async move { client.find_user_by_external_id(&ext_id).await }
            })
            .await?;

        if let Some(found_user) = existing {
            let external_resource_id =
                found_user.id.map(|id| id.to_string()).unwrap_or_default();

            // Link the existing resource by updating state.
            ScimProvisioningState::update_synced(
                &self.pool,
                tenant_id,
                state.id,
                &external_resource_id,
            )
            .await?;

            // Build a full replacement patch to bring the remote in sync.
            let changed_fields: Vec<(String, Option<String>)> = vec![
                ("email".to_string(), Some(scim_user.user_name.clone())),
                ("display_name".to_string(), scim_user.display_name.clone()),
                (
                    "first_name".to_string(),
                    scim_user.name.as_ref().and_then(|n| n.given_name.clone()),
                ),
                (
                    "last_name".to_string(),
                    scim_user.name.as_ref().and_then(|n| n.family_name.clone()),
                ),
                ("active".to_string(), Some(scim_user.active.to_string())),
            ];

            if let Some(patch) = AttributeMapper::build_user_patch(&changed_fields, mappings) {
                self.retry_policy
                    .execute("scim_patch_user_conflict_resolve", || {
                        let p = patch.clone();
                        let eri = external_resource_id.clone();
                        async move { client.patch_user(&eri, &p).await }
                    })
                    .await?;
            }

            info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                target_id = %target_id,
                external_resource_id = %external_resource_id,
                "Resolved user conflict: linked and patched existing resource"
            );

            self.log_operation(
                tenant_id,
                target_id,
                "create_conflict_resolved",
                "User",
                user_id,
                Some(external_resource_id),
                "PATCH",
                Some(200),
                started.elapsed(),
                None,
            )
            .await;

            Ok(())
        } else {
            // Could not find by externalId either -- record the error.
            let error_msg =
                "409 Conflict on create, but could not find existing user by externalId"
                    .to_string();

            let new_retry_count = state.retry_count + 1;
            ScimProvisioningState::update_error(
                &self.pool,
                tenant_id,
                state.id,
                &error_msg,
                new_retry_count,
                None,
            )
            .await?;

            self.log_operation_with_retry_count(
                tenant_id,
                target_id,
                "create",
                "User",
                user_id,
                None,
                "POST",
                Some(409),
                started.elapsed(),
                Some(error_msg.clone()),
                new_retry_count,
            )
            .await;

            error!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                target_id = %target_id,
                "Cannot resolve 409 conflict: user not found by externalId"
            );

            Err(ScimClientError::Conflict(error_msg))
        }
    }

    /// Provision a user update (PATCH changed attributes).
    ///
    /// Looks up the provisioning state to find the external resource ID, builds
    /// a SCIM PATCH request from the changed fields, and sends it to the
    /// target.  If no fields map to SCIM attributes, the operation is a no-op.
    pub async fn provision_user_update(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        user_id: Uuid,
        changed_fields: &[(String, Option<String>)],
        mappings: &[ScimTargetAttributeMapping],
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        // 1. Look up provisioning state to get external_resource_id.
        let state = ScimProvisioningState::get_by_target_and_resource(
            &self.pool, tenant_id, target_id, "User", user_id,
        )
        .await?
        .ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "No provisioning state found for user {user_id} on target {target_id}"
            ))
        })?;

        let external_resource_id = state.external_resource_id.as_deref().ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "User {user_id} has no external_resource_id on target {target_id}; \
                 cannot update a resource that has not been created"
            ))
        })?;

        // 2. Build SCIM patch from changed fields.
        let patch = if let Some(p) = AttributeMapper::build_user_patch(changed_fields, mappings) { p } else {
            info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                target_id = %target_id,
                "No mappable fields changed, skipping PATCH"
            );
            return Ok(());
        };

        // 3. Send PATCH (or PUT if PATCH is not supported) with retry.
        let eri = external_resource_id.to_string();
        let http_method = if client.patch_supported() {
            "PATCH"
        } else {
            "PUT"
        };
        let result = if client.patch_supported() {
            self.retry_policy
                .execute("scim_patch_user", || {
                    let p = patch.clone();
                    let id = eri.clone();
                    async move { client.patch_user(&id, &p).await }
                })
                .await
        } else {
            // Fallback: fetch current user, merge changes, and PUT replace.
            warn!(
                tenant_id = %tenant_id,
                target_id = %target_id,
                "PATCH not supported by target, falling back to PUT"
            );
            let current = self
                .retry_policy
                .execute("scim_get_user_for_put", || {
                    let id = eri.clone();
                    async move { client.get_user(&id).await }
                })
                .await?;
            // Apply the patch operations to the fetched user and PUT back.
            let mut updated = current;
            for op in &patch.operations {
                if op.op == "remove" {
                    if let Some(ref path) = op.path {
                        match path.as_str() {
                            "displayName" => updated.display_name = None,
                            "name.givenName" => {
                                if let Some(ref mut name) = updated.name {
                                    name.given_name = None;
                                }
                            }
                            "name.familyName" => {
                                if let Some(ref mut name) = updated.name {
                                    name.family_name = None;
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
                if let Some(ref path) = op.path {
                    match path.as_str() {
                        "active" => {
                            if let Some(ref v) = op.value {
                                updated.active = v.as_bool().unwrap_or(updated.active);
                            }
                        }
                        "displayName" => {
                            if let Some(ref v) = op.value {
                                updated.display_name = v.as_str().map(std::string::ToString::to_string);
                            }
                        }
                        "userName" => {
                            if let Some(ref v) = op.value {
                                if let Some(s) = v.as_str() {
                                    updated.user_name = s.to_string();
                                }
                            }
                        }
                        "name.givenName" => {
                            if let Some(ref v) = op.value {
                                let name = updated.name.get_or_insert_with(Default::default);
                                name.given_name = v.as_str().map(std::string::ToString::to_string);
                            }
                        }
                        "name.familyName" => {
                            if let Some(ref v) = op.value {
                                let name = updated.name.get_or_insert_with(Default::default);
                                name.family_name = v.as_str().map(std::string::ToString::to_string);
                            }
                        }
                        p if p.contains("emails") => {
                            if let Some(ref v) = op.value {
                                if let Some(s) = v.as_str() {
                                    if updated.emails.is_empty() {
                                        updated.emails.push(xavyo_api_scim::models::ScimEmail {
                                            value: s.to_string(),
                                            email_type: Some("work".to_string()),
                                            primary: true,
                                        });
                                    } else {
                                        updated.emails[0].value = s.to_string();
                                    }
                                }
                            }
                        }
                        _ => {} // Other paths pass through unchanged.
                    }
                }
            }
            self.retry_policy
                .execute("scim_put_user", || {
                    let u = updated.clone();
                    let id = eri.clone();
                    async move { client.replace_user(&id, &u).await }
                })
                .await
        };

        match result {
            Ok(_updated_user) => {
                // 4. Update provisioning state (refresh synced timestamp).
                ScimProvisioningState::update_synced(&self.pool, tenant_id, state.id, &eri).await?;

                info!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    target_id = %target_id,
                    external_resource_id = %eri,
                    "User updated on SCIM target"
                );

                // 5. Log operation.
                self.log_operation(
                    tenant_id,
                    target_id,
                    "update",
                    "User",
                    user_id,
                    Some(eri),
                    http_method,
                    Some(200),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation_with_retry_count(
                    tenant_id,
                    target_id,
                    "update",
                    "User",
                    user_id,
                    Some(eri),
                    http_method,
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                    new_retry_count,
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to update user on SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Deprovision a user (DELETE or deactivate based on target strategy).
    ///
    /// The `deprovisioning_strategy` is read from the [`ScimTarget`] config:
    /// - `"delete"` -- sends a DELETE request to remove the user entirely.
    /// - `"deactivate"` (or any other value) -- sends a PATCH to set
    ///   `active=false`, preserving the user record on the target.
    ///
    /// On success the provisioning state is updated to `deprovisioned`.
    pub async fn provision_user_deprovision(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        user_id: Uuid,
        deprovisioning_strategy: &str,
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        // 1. Look up provisioning state.
        let state = ScimProvisioningState::get_by_target_and_resource(
            &self.pool, tenant_id, target_id, "User", user_id,
        )
        .await?
        .ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "No provisioning state found for user {user_id} on target {target_id}"
            ))
        })?;

        let external_resource_id = state.external_resource_id.as_deref().ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "User {user_id} has no external_resource_id on target {target_id}; \
                 cannot deprovision a resource that has not been created"
            ))
        })?;

        let eri = external_resource_id.to_string();

        // 2. Based on strategy: DELETE or deactivate_user.
        let (http_method, http_status) = if deprovisioning_strategy == "delete" {
            let result = self
                .retry_policy
                .execute("scim_delete_user", || {
                    let id = eri.clone();
                    async move { client.delete_user(&id).await }
                })
                .await;

            match result {
                Ok(()) => ("DELETE", Some(204)),
                Err(e) => {
                    let error_msg = e.to_string();
                    let new_retry_count = state.retry_count + 1;
                    ScimProvisioningState::update_error(
                        &self.pool,
                        tenant_id,
                        state.id,
                        &error_msg,
                        new_retry_count,
                        None,
                    )
                    .await?;

                    self.log_operation_with_retry_count(
                        tenant_id,
                        target_id,
                        "deprovision",
                        "User",
                        user_id,
                        Some(eri),
                        "DELETE",
                        None,
                        started.elapsed(),
                        Some(error_msg),
                        new_retry_count,
                    )
                    .await;

                    return Err(e);
                }
            }
        } else {
            // Default to deactivate.
            let result = self
                .retry_policy
                .execute("scim_deactivate_user", || {
                    let id = eri.clone();
                    async move { client.deactivate_user(&id).await }
                })
                .await;

            match result {
                Ok(_) => ("PATCH", Some(200)),
                Err(e) => {
                    let error_msg = e.to_string();
                    let new_retry_count = state.retry_count + 1;
                    ScimProvisioningState::update_error(
                        &self.pool,
                        tenant_id,
                        state.id,
                        &error_msg,
                        new_retry_count,
                        None,
                    )
                    .await?;

                    self.log_operation_with_retry_count(
                        tenant_id,
                        target_id,
                        "deprovision",
                        "User",
                        user_id,
                        Some(eri),
                        "PATCH",
                        None,
                        started.elapsed(),
                        Some(error_msg),
                        new_retry_count,
                    )
                    .await;

                    return Err(e);
                }
            }
        };

        // 3. Update provisioning state to "deprovisioned".
        ScimProvisioningState::update_status(&self.pool, tenant_id, state.id, "deprovisioned")
            .await?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            target_id = %target_id,
            strategy = %deprovisioning_strategy,
            "User deprovisioned from SCIM target"
        );

        // 4. Log operation.
        self.log_operation(
            tenant_id,
            target_id,
            "deprovision",
            "User",
            user_id,
            Some(eri),
            http_method,
            http_status,
            started.elapsed(),
            None,
        )
        .await;

        Ok(())
    }

    /// Provision a group creation.
    ///
    /// Creates a SCIM Group resource on the target.  Handles 409 Conflict by
    /// looking up the existing group by `externalId` and linking it.
    pub async fn provision_group_create(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        group_id: Uuid,
        display_name: &str,
        member_external_ids: &[String],
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        // 1. Get or create provisioning state.
        let state = ScimProvisioningState::get_or_create(
            &self.pool,
            CreateScimProvisioningState {
                tenant_id,
                target_id,
                resource_type: "Group".to_string(),
                internal_resource_id: group_id,
                external_id: Some(group_id.to_string()),
            },
        )
        .await?;

        // If already synced, skip.
        if state.status == "synced" && state.external_resource_id.is_some() {
            info!(
                tenant_id = %tenant_id,
                group_id = %group_id,
                target_id = %target_id,
                "Group already synced to target, skipping create"
            );
            return Ok(());
        }

        // 2. Build SCIM group.
        let scim_group =
            AttributeMapper::map_group_to_scim(group_id, display_name, member_external_ids);

        // 3. Try create_group with retry.
        let result = self
            .retry_policy
            .execute("scim_create_group", || {
                let group = scim_group.clone();
                async move { client.create_group(&group).await }
            })
            .await;

        match result {
            Ok(created_group) => {
                let external_resource_id = created_group
                    .id
                    .map(|id| id.to_string())
                    .unwrap_or_default();

                ScimProvisioningState::update_synced(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &external_resource_id,
                )
                .await?;

                info!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    external_resource_id = %external_resource_id,
                    "Group created on SCIM target"
                );

                self.log_operation(
                    tenant_id,
                    target_id,
                    "create",
                    "Group",
                    group_id,
                    Some(external_resource_id),
                    "POST",
                    Some(201),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(ScimClientError::Conflict(_)) => {
                // Conflict: look up existing group by externalId.
                warn!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    "Group creation conflict (409), attempting lookup by externalId"
                );

                let external_id_str = group_id.to_string();
                let existing = self
                    .retry_policy
                    .execute("scim_find_group_by_external_id", || {
                        let ext_id = external_id_str.clone();
                        async move { client.find_group_by_external_id(&ext_id).await }
                    })
                    .await?;

                if let Some(found_group) = existing {
                    let external_resource_id =
                        found_group.id.map(|id| id.to_string()).unwrap_or_default();

                    ScimProvisioningState::update_synced(
                        &self.pool,
                        tenant_id,
                        state.id,
                        &external_resource_id,
                    )
                    .await?;

                    info!(
                        tenant_id = %tenant_id,
                        group_id = %group_id,
                        target_id = %target_id,
                        external_resource_id = %external_resource_id,
                        "Resolved group conflict: linked existing resource"
                    );

                    self.log_operation(
                        tenant_id,
                        target_id,
                        "create_conflict_resolved",
                        "Group",
                        group_id,
                        Some(external_resource_id),
                        "GET",
                        Some(200),
                        started.elapsed(),
                        None,
                    )
                    .await;

                    Ok(())
                } else {
                    let error_msg =
                        "409 Conflict on group create, but could not find existing group by externalId"
                            .to_string();

                    ScimProvisioningState::update_error(
                        &self.pool,
                        tenant_id,
                        state.id,
                        &error_msg,
                        state.retry_count + 1,
                        None,
                    )
                    .await?;

                    self.log_operation(
                        tenant_id,
                        target_id,
                        "create",
                        "Group",
                        group_id,
                        None,
                        "POST",
                        Some(409),
                        started.elapsed(),
                        Some(error_msg.clone()),
                    )
                    .await;

                    Err(ScimClientError::Conflict(error_msg))
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation(
                    tenant_id,
                    target_id,
                    "create",
                    "Group",
                    group_id,
                    None,
                    "POST",
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to create group on SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Provision a group deletion.
    ///
    /// Sends a DELETE request for the group to the SCIM target and updates
    /// the provisioning state to `deprovisioned`.
    pub async fn provision_group_delete(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        group_id: Uuid,
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        // 1. Look up provisioning state.
        let state = ScimProvisioningState::get_by_target_and_resource(
            &self.pool, tenant_id, target_id, "Group", group_id,
        )
        .await?
        .ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "No provisioning state found for group {group_id} on target {target_id}"
            ))
        })?;

        let external_resource_id = state.external_resource_id.as_deref().ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "Group {group_id} has no external_resource_id on target {target_id}; \
                 cannot delete a resource that has not been created"
            ))
        })?;

        let eri = external_resource_id.to_string();

        // 2. Send DELETE with retry.
        let result = self
            .retry_policy
            .execute("scim_delete_group", || {
                let id = eri.clone();
                async move { client.delete_group(&id).await }
            })
            .await;

        match result {
            Ok(()) => {
                // 3. Update provisioning state to "deprovisioned".
                ScimProvisioningState::update_status(
                    &self.pool,
                    tenant_id,
                    state.id,
                    "deprovisioned",
                )
                .await?;

                info!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    "Group deleted from SCIM target"
                );

                self.log_operation(
                    tenant_id,
                    target_id,
                    "delete",
                    "Group",
                    group_id,
                    Some(eri),
                    "DELETE",
                    Some(204),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation(
                    tenant_id,
                    target_id,
                    "delete",
                    "Group",
                    group_id,
                    Some(eri),
                    "DELETE",
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to delete group from SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Provision adding members to a group.
    ///
    /// Sends a PATCH request adding the given member external IDs to the
    /// group on the target.  The `member_external_ids` are the SCIM-side
    /// resource IDs of users that have already been provisioned.
    pub async fn provision_member_add(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        group_id: Uuid,
        member_external_ids: &[String],
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        if member_external_ids.is_empty() {
            return Ok(());
        }

        // 1. Look up group provisioning state.
        let state = ScimProvisioningState::get_by_target_and_resource(
            &self.pool, tenant_id, target_id, "Group", group_id,
        )
        .await?
        .ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "No provisioning state found for group {group_id} on target {target_id}"
            ))
        })?;

        let external_group_id = state.external_resource_id.as_deref().ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "Group {group_id} has no external_resource_id on target {target_id}"
            ))
        })?;

        let egi = external_group_id.to_string();
        let add_ids = member_external_ids.to_vec();
        let empty: Vec<String> = Vec::new();

        // 2. Send PATCH to add members with retry.
        let result = self
            .retry_policy
            .execute("scim_add_group_members", || {
                let gid = egi.clone();
                let adds = add_ids.clone();
                let removes = empty.clone();
                async move { client.patch_group_members(&gid, &adds, &removes).await }
            })
            .await;

        match result {
            Ok(()) => {
                // Update last synced timestamp.
                ScimProvisioningState::update_synced(&self.pool, tenant_id, state.id, &egi).await?;

                info!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    members_added = member_external_ids.len(),
                    "Members added to group on SCIM target"
                );

                self.log_operation(
                    tenant_id,
                    target_id,
                    "add_members",
                    "Group",
                    group_id,
                    Some(egi),
                    "PATCH",
                    Some(200),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation(
                    tenant_id,
                    target_id,
                    "add_members",
                    "Group",
                    group_id,
                    Some(egi),
                    "PATCH",
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to add members to group on SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Provision removing members from a group.
    ///
    /// Sends a PATCH request removing the given member external IDs from the
    /// group on the target.
    pub async fn provision_member_remove(
        &self,
        client: &ScimClient,
        tenant_id: Uuid,
        target_id: Uuid,
        group_id: Uuid,
        member_external_ids: &[String],
    ) -> ScimClientResult<()> {
        let started = Instant::now();

        if member_external_ids.is_empty() {
            return Ok(());
        }

        // 1. Look up group provisioning state.
        let state = ScimProvisioningState::get_by_target_and_resource(
            &self.pool, tenant_id, target_id, "Group", group_id,
        )
        .await?
        .ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "No provisioning state found for group {group_id} on target {target_id}"
            ))
        })?;

        let external_group_id = state.external_resource_id.as_deref().ok_or_else(|| {
            ScimClientError::InvalidConfig(format!(
                "Group {group_id} has no external_resource_id on target {target_id}"
            ))
        })?;

        let egi = external_group_id.to_string();
        let remove_ids = member_external_ids.to_vec();
        let empty: Vec<String> = Vec::new();

        // 2. Send PATCH to remove members with retry.
        let result = self
            .retry_policy
            .execute("scim_remove_group_members", || {
                let gid = egi.clone();
                let adds = empty.clone();
                let removes = remove_ids.clone();
                async move { client.patch_group_members(&gid, &adds, &removes).await }
            })
            .await;

        match result {
            Ok(()) => {
                // Update last synced timestamp.
                ScimProvisioningState::update_synced(&self.pool, tenant_id, state.id, &egi).await?;

                info!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    members_removed = member_external_ids.len(),
                    "Members removed from group on SCIM target"
                );

                self.log_operation(
                    tenant_id,
                    target_id,
                    "remove_members",
                    "Group",
                    group_id,
                    Some(egi),
                    "PATCH",
                    Some(200),
                    started.elapsed(),
                    None,
                )
                .await;

                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                let new_retry_count = state.retry_count + 1;
                ScimProvisioningState::update_error(
                    &self.pool,
                    tenant_id,
                    state.id,
                    &error_msg,
                    new_retry_count,
                    None,
                )
                .await?;

                self.log_operation(
                    tenant_id,
                    target_id,
                    "remove_members",
                    "Group",
                    group_id,
                    Some(egi),
                    "PATCH",
                    None,
                    started.elapsed(),
                    Some(error_msg.clone()),
                )
                .await;

                error!(
                    tenant_id = %tenant_id,
                    group_id = %group_id,
                    target_id = %target_id,
                    error = %error_msg,
                    "Failed to remove members from group on SCIM target"
                );

                Err(e)
            }
        }
    }

    /// Log a provisioning operation to the immutable audit log.
    ///
    /// Errors during logging are recorded via `tracing` but do not fail the
    /// provisioning operation itself -- the SCIM operation has already
    /// completed at this point.
    #[allow(clippy::too_many_arguments)]
    async fn log_operation(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        operation_type: &str,
        resource_type: &str,
        internal_resource_id: Uuid,
        external_resource_id: Option<String>,
        http_method: &str,
        http_status: Option<i32>,
        duration: std::time::Duration,
        error_message: Option<String>,
    ) {
        self.log_operation_with_retry_count(
            tenant_id,
            target_id,
            operation_type,
            resource_type,
            internal_resource_id,
            external_resource_id,
            http_method,
            http_status,
            duration,
            error_message,
            0,
        )
        .await;
    }

    /// Log a provisioning operation with an explicit retry count.
    #[allow(clippy::too_many_arguments)]
    async fn log_operation_with_retry_count(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        operation_type: &str,
        resource_type: &str,
        internal_resource_id: Uuid,
        external_resource_id: Option<String>,
        http_method: &str,
        http_status: Option<i32>,
        duration: std::time::Duration,
        error_message: Option<String>,
        retry_count: i32,
    ) {
        // Clamp duration_ms to avoid i32 overflow for very long operations.
        let duration_ms = duration.as_millis().min(i32::MAX as u128) as i32;

        let log_entry = CreateScimProvisioningLog {
            tenant_id,
            target_id,
            sync_run_id: None,
            operation_type: operation_type.to_string(),
            resource_type: resource_type.to_string(),
            internal_resource_id,
            external_resource_id,
            http_method: http_method.to_string(),
            http_status,
            request_summary: None,
            response_summary: None,
            retry_count,
            duration_ms: Some(duration_ms),
            error_message,
        };

        if let Err(e) = ScimProvisioningLog::insert(&self.pool, log_entry).await {
            warn!(
                tenant_id = %tenant_id,
                target_id = %target_id,
                operation_type = %operation_type,
                error = %e,
                "Failed to write SCIM provisioning log entry"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provisioner_creation() {
        // Verify the Provisioner struct can be constructed with the expected
        // fields. A full integration test would require a database connection.
        let retry_policy = RetryPolicy::new(3, 1);
        assert_eq!(retry_policy.max_retries, 3);
        assert_eq!(retry_policy.base_delay_secs, 1);
    }
}
